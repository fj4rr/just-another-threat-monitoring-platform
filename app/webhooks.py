"""Outbound webhooks: signed JSON for your own receivers, or ready-made Slack / Discord / Teams messages.

* Events: new high-severity item, watched entity mentioned, indicator turned malicious, job failed.
  ``emit()`` only queues a ``WebhookDelivery`` row; the ``webhooks`` scheduler job sends it, retrying
  with back-off (1 min, 5 min, 30 min, 2 h, 6 h) before giving up.
* Signature (generic hooks): ``X-JATMP-Signature: sha256=HMAC(secret, "<timestamp>.<body>")`` plus
  ``X-JATMP-Timestamp``, ``X-JATMP-Event`` and ``X-JATMP-Delivery``. The secret is derived from the install's
  session secret and a per-hook salt, so the database holds nothing that could forge a signature.
* SSRF: targets must resolve to public addresses (checked at creation and again before every delivery)
  unless an admin allows private ones; redirects are not followed.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import time
from datetime import timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import __version__, settings, sharing
from .config import load_config
from .models import Entity, Item, Watch, Webhook, WebhookDelivery, utcnow

log = logging.getLogger(__name__)

EVENTS = {
    "item.high_severity": "New item at or above the severity threshold",
    "entity.watched": "A watched family / actor / CVE / IOC is mentioned in a new item",
    "ioc.malicious": "An indicator's verdict turned malicious",
    "job.failed": "A collector, enrichment or digest run failed",
}
KINDS = {"generic": "Generic JSON (signed)", "slack": "Slack incoming webhook", "discord": "Discord webhook",
         "teams": "Microsoft Teams incoming webhook"}
BACKOFF = (60, 300, 1800, 7200, 21600)
TIMEOUT = 10


def secret_for(hook: Webhook) -> str:
    key = str(load_config().get("secret_key") or "").encode()
    return hmac.new(key, f"webhook:{hook.salt}".encode(), hashlib.sha256).hexdigest()


def new_salt() -> str:
    return secrets.token_hex(16)


# --------------------------------------------------------------------------- SSRF guard
def check_url(url: str, allow_private: bool | None = None) -> str | None:
    """Error message, or None when the URL is an acceptable webhook target."""
    allow_private = bool(settings.get("webhooks_allow_private")) if allow_private is None else allow_private
    try:
        parts = urlsplit((url or "").strip())
    except ValueError:
        return "not a valid URL"
    if parts.scheme not in ("https", "http"):
        return "the URL must start with https:// (or http://)"
    if not parts.hostname:
        return "the URL has no host"
    if parts.username or parts.password:
        return "credentials in the URL are not allowed"
    if allow_private:
        return None
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80),
                                   type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return f"cannot resolve {parts.hostname}"
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%")[0])
        if not addr.is_global:
            return f"{parts.hostname} resolves to a private / local address ({addr}); an admin can allow this under Settings → Sharing"
    return None


# --------------------------------------------------------------------------- queueing
def emit(db: Session, event: str, data: dict) -> int:
    """Queue ``event`` for every enabled hook subscribed to it (the caller commits). Returns rows queued."""
    hooks = [h for h in db.execute(select(Webhook).where(Webhook.enabled)).scalars() if event in (h.events or [])]
    for h in hooks:
        db.add(WebhookDelivery(webhook_id=h.id, event=event, payload={
            "event": event, "created_at": utcnow().isoformat(timespec="seconds") + "Z", "data": data}))
    if hooks:
        db.flush()
    return len(hooks)


def _link(path: str) -> str | None:
    base = str(settings.get("public_base_url") or "").rstrip("/")
    return f"{base}{path}" if base else None


def item_payload(item: Item) -> dict:
    names = [f"{link.entity.type}:{link.entity.display}" for link in item.entity_links
             if link.entity.type in ("malware", "actor", "cve")][:10]
    return {"id": item.id, "title": item.title, "url": item.url or None, "severity": item.severity,
            "source": item.source.name, "source_type": item.source.category, "tlp": sharing.item_tlp(item),
            "published_at": item.published_at.isoformat(timespec="seconds") + "Z", "entities": names,
            "link": _link(f"/items/{item.id}")}


def on_new_items(db: Session, item_ids: list[int]) -> int:
    """High-severity and watched-entity events for freshly ingested items."""
    if not item_ids or not db.execute(select(Webhook.id).where(Webhook.enabled).limit(1)).first():
        return 0
    threshold = int(settings.get("webhook_min_severity") or 70)
    watched = {eid for (eid,) in db.execute(select(Watch.entity_id).distinct())}
    n = 0
    for item in db.execute(select(Item).where(Item.id.in_(item_ids))).unique().scalars():
        if not sharing.item_shareable(item):
            continue
        p = item_payload(item)
        if threshold and item.severity >= threshold:
            n += emit(db, "item.high_severity", {**p, "summary": f"[{item.severity}] {item.title}"})
        for link in item.entity_links:
            if link.entity_id in watched:
                e = link.entity
                n += emit(db, "entity.watched", {**p, "watched": {"id": e.id, "type": e.type, "value": e.display},
                                                 "summary": f"Watched {e.type} {e.display} mentioned: {item.title}"})
    return n


def on_ioc_malicious(db: Session, ent: Entity) -> int:
    if not db.execute(select(Entity.id).where(Entity.id == ent.id, sharing.shareable_entity_clause())).first():
        return 0
    return emit(db, "ioc.malicious", {"id": ent.id, "type": ent.type, "value": ent.value,
                                      "summary": f"{ent.type} {ent.display} confirmed malicious",
                                      "link": _link(f"/entities/{ent.id}")})


def on_job_failed(db: Session, title: str, body: str) -> int:
    return emit(db, "job.failed", {"summary": title, "detail": body[:500]})


# --------------------------------------------------------------------------- formatting & delivery
def _text(payload: dict) -> tuple[str, str, str | None]:
    d = payload.get("data") or {}
    title = d.get("summary") or payload.get("event", "")
    detail = d.get("detail") or ""
    if d.get("source"):
        detail = f"{d['source']} · severity {d.get('severity')}" + (f" · {', '.join(d['entities'])}" if d.get("entities") else "")
    return title, detail, d.get("link") or d.get("url")


def render_body(hook: Webhook, payload: dict) -> bytes:
    if hook.kind == "generic":
        return json.dumps(payload, separators=(",", ":"), default=str).encode()
    title, detail, link = _text(payload)
    if hook.kind == "slack":
        text = f"*{title}*" + (f"\n{detail}" if detail else "") + (f"\n<{link}|Open>" if link else "")
        body = {"text": text}
    elif hook.kind == "discord":
        body = {"username": "JATMP", "embeds": [{"title": title[:256], "description": detail[:2000],
                                                 **({"url": link} if link else {})}]}
    else:  # teams (MessageCard)
        body = {"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": title[:200],
                "title": title, "text": detail or " ",
                **({"potentialAction": [{"@type": "OpenUri", "name": "Open",
                                         "targets": [{"os": "default", "uri": link}]}]} if link else {})}
    return json.dumps(body).encode()


def sign(secret: str, ts: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()


def send(hook: Webhook, delivery: WebhookDelivery, http: httpx.Client | None = None) -> tuple[int | None, str]:
    err = check_url(hook.url)
    if err:
        return None, err
    body = render_body(hook, delivery.payload)
    ts = str(int(time.time()))
    headers = {"Content-Type": "application/json", "User-Agent": f"JATMP-Webhooks/{__version__}",
               "X-JATMP-Event": delivery.event, "X-JATMP-Delivery": str(delivery.id), "X-JATMP-Timestamp": ts,
               "X-JATMP-Signature": sign(secret_for(hook), ts, body)}
    own = http is None
    http = http or httpx.Client(timeout=TIMEOUT, follow_redirects=False)
    try:
        r = http.post(hook.url, content=body, headers=headers)
        return r.status_code, "" if 200 <= r.status_code < 300 else f"HTTP {r.status_code}: {r.text[:200]}"
    except httpx.HTTPError as e:
        return None, f"{type(e).__name__}: {e}"[:300]
    finally:
        if own:
            http.close()


def attempt(db: Session, delivery: WebhookDelivery, http: httpx.Client | None = None) -> bool:
    hook = db.get(Webhook, delivery.webhook_id)
    if hook is None:
        db.delete(delivery)
        return False
    code, err = send(hook, delivery, http)
    now = utcnow()
    delivery.attempts += 1
    delivery.response_code, delivery.error = code, err
    if not err:
        delivery.status, delivery.delivered_at = "ok", now
    elif delivery.attempts >= len(BACKOFF):
        delivery.status = "failed"
    else:
        delivery.next_attempt_at = now + timedelta(seconds=BACKOFF[delivery.attempts - 1])
    hook.last_status = "ok" if not err else "failed"
    hook.last_delivery_at = now
    return not err


def deliver_pending(db: Session, limit: int = 50, http: httpx.Client | None = None) -> str:
    rows = db.execute(select(WebhookDelivery).where(WebhookDelivery.status == "pending",
                                                    WebhookDelivery.next_attempt_at <= utcnow())
                      .order_by(WebhookDelivery.id).limit(limit)).scalars().all()
    ok = 0
    for d in rows:
        ok += attempt(db, d, http)
        db.commit()
    return f"{ok}/{len(rows)} delivered"
