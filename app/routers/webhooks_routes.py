"""Settings → Webhooks (admin)."""
from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import webhooks
from ..auth import audit, require, verify_csrf
from ..db import get_db
from ..models import User, Webhook, WebhookDelivery
from ..web import render

router = APIRouter(prefix="/settings/webhooks")


def webhooks_ctx(db: Session) -> dict:
    hooks = db.execute(select(Webhook).order_by(Webhook.id)).scalars().all()
    names = {h.id: h.name for h in hooks}
    deliveries = db.execute(select(WebhookDelivery).order_by(WebhookDelivery.id.desc()).limit(25)).scalars().all()
    return {"hooks": hooks, "hook_names": names, "deliveries": deliveries, "hook_events": webhooks.EVENTS,
            "hook_kinds": webhooks.KINDS, "new_secret": None}


def _back(msg: str):
    return RedirectResponse(f"/settings?tab=webhooks&msg={quote(msg)}", status_code=303)


def _page(request: Request, user: User, db: Session, msg: str = "", error: str = "", **extra):
    from .settings_routes import settings_ctx

    ctx = {**settings_ctx(db, user, "webhooks", msg), **webhooks_ctx(db), "error": error, **extra}
    return render(request, "settings.html", ctx, status_code=400 if error else 200)


@router.post("", dependencies=[Depends(verify_csrf)])
async def create(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    form = await request.form()
    url = str(form.get("url") or "").strip()[:2000]
    kind = str(form.get("kind") or "generic")
    events = [e for e in form.getlist("events") if e in webhooks.EVENTS]
    if kind not in webhooks.KINDS:
        kind = "generic"
    err = webhooks.check_url(url) or ("" if events else "pick at least one event")
    if err:
        return _page(request, user, db, error=f"Webhook not saved: {err}")
    hook = Webhook(name=str(form.get("name") or "Webhook").strip()[:128], url=url, kind=kind, events=events,
                   salt=webhooks.new_salt())
    db.add(hook)
    db.flush()
    audit(db, user, "webhook_created", f"{hook.name} → {kind}", request)
    db.commit()
    secret = webhooks.secret_for(hook) if kind == "generic" else None
    return _page(request, user, db, msg="Webhook saved", new_secret=secret, new_secret_for=hook.name)


@router.post("/{hook_id}", dependencies=[Depends(verify_csrf)])
async def update(hook_id: int, request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    hook = db.get(Webhook, hook_id)
    if not hook:
        raise HTTPException(404, "webhook not found")
    action = str((await request.form()).get("action") or "")
    if action == "delete":
        audit(db, user, "webhook_deleted", hook.name, request)
        db.delete(hook)
        db.commit()
        return _back("Webhook deleted")
    if action == "toggle":
        hook.enabled = not hook.enabled
        db.commit()
        return _back("Webhook " + ("enabled" if hook.enabled else "disabled"))
    if action == "rotate":
        hook.salt = webhooks.new_salt()
        audit(db, user, "webhook_secret_rotated", hook.name, request)
        db.commit()
        return _page(request, user, db, msg="New signing secret created; the old one no longer validates",
                     new_secret=webhooks.secret_for(hook), new_secret_for=hook.name)
    if action == "test":
        d = WebhookDelivery(webhook_id=hook.id, event="ping", payload={
            "event": "ping", "created_at": "", "data": {"summary": "JATMP test message",
                                                        "detail": f"Webhook “{hook.name}” is set up correctly."}})
        db.add(d)
        db.flush()
        ok = webhooks.attempt(db, d)
        d.status = "ok" if ok else "failed"  # a test is never retried
        db.commit()
        return _back("Test delivered" if ok else f"Test failed: {d.error}")
    raise HTTPException(400, "unknown action")
