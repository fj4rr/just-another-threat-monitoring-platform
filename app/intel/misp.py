"""MISP, both ways, over the plain REST API (no PyMISP dependency).

* Pull (``MISPCollector``): events changed since the last run become items, attributes become indicators,
  galaxy clusters (threat actors, malware) end up in the text and tags so the extractor links them, and the
  event's TLP tag becomes the item's TLP.
* Push: an item or a malware family / actor becomes a MISP event with TLP and family tags and the
  indicators as attributes (``to_ids`` for malicious / suspicious ones). Pushes go through the sharing rules
  and are recorded on the item / entity, so a second click links to the existing event instead of
  duplicating it. Items that came *from* MISP are never pushed back (no echo loops).
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import __version__, settings, sharing
from ..models import Entity, Item, utcnow
from . import NotConfigured, make_ioc

log = logging.getLogger(__name__)

# MISP attribute type -> JATMP indicator type (composite types keep the indicator part)
ATTR_TYPES = {
    "ip-dst": "ip", "ip-src": "ip", "ip-dst|port": "ip", "ip-src|port": "ip", "domain": "domain",
    "hostname": "domain", "domain|ip": "domain", "url": "url", "md5": "md5", "sha1": "sha1", "sha256": "sha256",
    "filename|md5": "md5", "filename|sha1": "sha1", "filename|sha256": "sha256",
}
# JATMP indicator type -> MISP attribute type and category for pushes
PUSH_TYPES = {"ip": ("ip-dst", "Network activity"), "domain": ("domain", "Network activity"),
              "url": ("url", "Network activity"), "md5": ("md5", "Payload delivery"),
              "sha1": ("sha1", "Payload delivery"), "sha256": ("sha256", "Payload delivery")}
ACTOR_GALAXIES = ("threat-actor", "mitre-intrusion-set", "microsoft-activity-group")
MALWARE_GALAXIES = ("malpedia", "mitre-malware", "ransomware", "android", "rat", "stealer", "botnet", "backdoor",
                    "banker", "mitre-tool", "tool")


class PushRefused(Exception):
    pass


class MISP:
    name = "misp"

    def __init__(self):
        self.url = str(settings.get("misp_url") or "").rstrip("/")
        self.key = str(settings.get("misp_api_key") or "")
        if not self.url or not self.key:
            raise NotConfigured("MISP URL and automation key are not set (Settings → MISP)")
        if not self.url.lower().startswith(("https://", "http://")):
            raise NotConfigured("MISP URL must start with https://")

    def _req(self, method: str, path: str, body: dict | None = None):
        headers = {"Authorization": self.key, "Accept": "application/json", "Content-Type": "application/json",
                   "User-Agent": f"JATMP/{__version__}"}
        with httpx.Client(timeout=60, verify=bool(settings.get("misp_verify_tls")), headers=headers) as c:
            r = c.request(method, self.url + path, json=body)
        if r.status_code in (401, 403):
            raise RuntimeError(f"MISP rejected the key ({r.status_code})")
        if r.status_code >= 400:
            raise RuntimeError(f"MISP {path}: HTTP {r.status_code} {r.text[:200]}")
        return r.json()

    def test(self) -> str:
        v = self._req("GET", "/servers/getVersion")
        return f"MISP {v.get('version', '?')} reachable, key accepted"

    def search_events(self, since: datetime, tags: list[str] | None = None, limit: int = 50, page: int = 1) -> list[dict]:
        body = {"returnFormat": "json", "timestamp": int(since.replace(tzinfo=UTC).timestamp()), "limit": limit,
                "page": page, "includeEventTags": True, "includeGalaxy": True}
        if tags:
            body["tags"] = tags
        data = self._req("POST", "/events/restSearch", body)
        rows = data.get("response", data) if isinstance(data, dict) else data
        return [r.get("Event", r) for r in rows or [] if isinstance(r, dict)]

    def add_event(self, event: dict) -> dict:
        data = self._req("POST", "/events/add", {"Event": event})
        return data.get("Event", data)

    def event_url(self, event_id) -> str:
        return f"{self.url}/events/view/{event_id}"


# --------------------------------------------------------------------------- pull
def event_to_raw(ev: dict, base_url: str = ""):
    from ..processing.pipeline import RawItem

    tags = [t.get("name", "") for t in ev.get("Tag") or [] if isinstance(t, dict)]
    actors, malware = [], []
    for g in ev.get("Galaxy") or []:
        gtype = str(g.get("type") or "")
        for c in g.get("GalaxyCluster") or []:
            val = c.get("value")
            if not val:
                continue
            if gtype in ACTOR_GALAXIES:
                actors.append(val)
            elif gtype in MALWARE_GALAXIES:
                malware.append(val)
    tlp = next((sharing.norm_tlp(t) for t in tags if t.lower().startswith("tlp:") and sharing.norm_tlp(t)), "")
    attrs = list(ev.get("Attribute") or [])
    for obj in ev.get("Object") or []:
        attrs += obj.get("Attribute") or []
    indicators, seen = [], set()
    for a in attrs[:2000]:
        kind = ATTR_TYPES.get(a.get("type", ""))
        val = str(a.get("value") or "")
        if not kind or not val:
            continue
        if "|" in a.get("type", ""):
            parts = val.split("|")
            val = parts[0] if a["type"].startswith(("ip-", "domain|")) else parts[-1]
        ex = make_ioc(val, kind)
        if ex and (ex.type, ex.value) not in seen:
            seen.add((ex.type, ex.value))
            indicators.append(ex)
        if len(indicators) >= 500:
            break
    ts = ev.get("timestamp") or ev.get("publish_timestamp")
    try:
        published = datetime.fromtimestamp(int(ts), UTC).replace(tzinfo=None) if ts else None
    except (TypeError, ValueError):
        published = None
    if published is None and ev.get("date"):
        try:
            published = datetime.fromisoformat(str(ev["date"]))
        except ValueError:
            published = None
    level = {"1": "high", "2": "medium", "3": "low", "4": "undefined"}.get(str(ev.get("threat_level_id")), "")
    body = "\n".join(filter(None, [
        ev.get("info", ""),
        f"Threat level: {level}" if level else "",
        f"Threat actors: {', '.join(actors)}" if actors else "",
        f"Malware: {', '.join(malware)}" if malware else "",
        f"Organisation: {(ev.get('Orgc') or {}).get('name')}" if (ev.get("Orgc") or {}).get("name") else "",
        f"{len(indicators)} indicator(s)",
    ]))
    return RawItem(
        external_id=str(ev.get("uuid") or ev.get("id") or ""), title=str(ev.get("info") or "(MISP event)")[:1000],
        url=f"{base_url}/events/view/{ev.get('id')}" if base_url and ev.get("id") else "",
        author=str((ev.get("Orgc") or {}).get("name") or ""), content=body, published_at=published, kind="pulse",
        tags=[t for t in tags if not t.lower().startswith("tlp:")][:30] + malware[:10] + actors[:10],
        raw={"tlp": tlp, "misp_uuid": ev.get("uuid"), "misp_event_id": ev.get("id")}, indicators=indicators)


# --------------------------------------------------------------------------- push
def _distribution() -> dict:
    dist = str(settings.get("misp_distribution") or "0")
    out = {"distribution": dist}
    if dist == "4":
        out["sharing_group_id"] = str(int(settings.get("misp_sharing_group_id") or 0))
    return out


def _attribute(e: Entity, comment: str = "") -> dict | None:
    t = PUSH_TYPES.get(e.type)
    if not t:
        return None
    verdict = (e.verdict or "unknown") if e.enriched_at else "pending"
    return {"type": t[0], "category": t[1], "value": e.value, "to_ids": verdict in ("malicious", "suspicious"),
            "comment": (comment + f" JATMP verdict: {verdict}").strip()[:250]}


def _family_tags(names: list[tuple[str, str]]) -> list[dict]:
    return [{"name": f'jatmp:{t}="{n}"'} for t, n in names[:20]]


def push_item(db: Session, item: Item, client: MISP | None = None) -> dict:
    if item.source.kind == "misp":
        raise PushRefused("this item came from MISP; it is not pushed back")
    if not sharing.item_shareable(item):
        raise PushRefused(f"sharing rules forbid it (TLP:{sharing.item_tlp(item)} or a source marked not shared)")
    client = client or MISP()
    done = (item.raw or {}).get("misp_pushed")
    if done:
        return {**done, "created": False, "url": client.event_url(done["id"])}
    ents = [link.entity for link in item.entity_links]
    attrs = [a for a in (_attribute(e) for e in ents) if a]
    if item.url:
        attrs.insert(0, {"type": "link", "category": "External analysis", "value": item.url, "to_ids": False,
                         "comment": f"{item.source.name}"})
    sev = item.severity or 0
    event = {
        "info": f"JATMP: {item.title}"[:500], "date": item.published_at.strftime("%Y-%m-%d"),
        "threat_level_id": "1" if sev >= 70 else "2" if sev >= 40 else "3", "analysis": "0", **_distribution(),
        "Tag": [{"name": f"tlp:{sharing.item_tlp(item).lower()}"}, {"name": "jatmp"}]
               + _family_tags([(e.type, e.display) for e in ents if e.type in ("malware", "actor")]),
        "Attribute": attrs[:1000],
    }
    created = client.add_event(event)
    rec = {"id": created.get("id"), "uuid": created.get("uuid"), "at": utcnow().isoformat(timespec="seconds")}
    item.raw = {**(item.raw or {}), "misp_pushed": rec}
    return {**rec, "created": True, "url": client.event_url(rec["id"])}


def push_entity(db: Session, ent: Entity, client: MISP | None = None) -> dict:
    from ..routers.pages import _ioc_filter_for_entity

    if ent.type not in ("malware", "actor"):
        raise PushRefused("only malware families and threat actors can be pushed as an event")
    client = client or MISP()
    iocs = db.execute(select(Entity).where(Entity.type.in_(tuple(PUSH_TYPES)), _ioc_filter_for_entity(ent.id),
                                           sharing.shareable_entity_clause())
                      .order_by(Entity.last_seen.desc()).limit(1000)).scalars().all()
    if not iocs:
        raise PushRefused("no shareable indicators for this entity yet")
    event = {
        "info": f"JATMP: indicators for {ent.display} ({ent.type})"[:500], "date": utcnow().strftime("%Y-%m-%d"),
        "threat_level_id": "2", "analysis": "1", **_distribution(),
        "Tag": [{"name": f"tlp:{(settings.get('api_max_tlp') or 'GREEN').lower()}"}, {"name": "jatmp"}]
               + _family_tags([(ent.type, ent.display)]),
        "Attribute": [a for a in (_attribute(e) for e in iocs) if a],
    }
    created = client.add_event(event)
    rec = {"id": created.get("id"), "uuid": created.get("uuid"), "at": utcnow().isoformat(timespec="seconds"),
           "indicators": len(event["Attribute"])}
    ent.meta = {**(ent.meta or {}), "misp_pushed": rec}
    return {**rec, "created": True, "url": client.event_url(rec["id"])}


def autopush(db: Session, item_ids: list[int]) -> str:
    threshold = int(settings.get("misp_autopush_min_severity") or 0)
    if threshold <= 0:
        return "auto-push off"
    client = MISP()
    pushed = 0
    for item in db.execute(select(Item).where(Item.id.in_(item_ids), Item.severity >= threshold)).unique().scalars():
        try:
            if push_item(db, item, client).get("created"):
                pushed += 1
            db.commit()
        except PushRefused:
            continue
    if pushed:
        from .. import notify

        notify.notify(db, "info", f"Pushed {pushed} item(s) to MISP", f"severity ≥ {threshold}", "/feed?days=1")
        db.commit()
    return f"pushed {pushed} item(s) to MISP"
