"""API key management (Profile → API keys). Admins can also revoke anyone's key from the admin page."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import apikeys
from ..auth import audit, current_user, verify_csrf
from ..db import get_db
from ..models import ApiKey, User, utcnow
from ..web import render

router = APIRouter(prefix="/profile/api-keys")
EXPIRY_CHOICES = ((30, "30 days"), (90, "90 days"), (365, "1 year"), (0, "Never"))


def keys_ctx(db: Session, user: User) -> dict:
    keys = db.execute(select(ApiKey).where(ApiKey.user_id == user.id).order_by(ApiKey.created_at.desc())).scalars().all()
    return {"api_keys": keys, "key_status": apikeys.status, "scope_help": apikeys.SCOPES,
            "my_scopes": sorted(apikeys.allowed_scopes(user)), "expiry_choices": EXPIRY_CHOICES, "new_token": None}


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_key(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    form = await request.form()
    scopes = [s for s in form.getlist("scopes") if isinstance(s, str)]
    try:
        days = int(form.get("expires_days") or 90)
    except ValueError:
        days = 90
    days = days if days in dict(EXPIRY_CHOICES) else 90
    key, token = apikeys.create(db, user, str(form.get("name") or ""), scopes, days)
    audit(db, user, "api_key_created", f"{key.name} ({key.prefix}) scopes={','.join(key.scopes)}", request)
    db.commit()
    ctx = keys_ctx(db, user)
    ctx["new_token"] = token  # shown exactly once; only its hash is stored
    return render(request, "profile.html", {"user": user, "msg": None, "error": None, **ctx})


@router.post("/{key_id}/revoke", dependencies=[Depends(verify_csrf)])
def revoke_key(key_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    key = db.get(ApiKey, key_id)
    if not key or (key.user_id != user.id and user.role != "admin"):
        raise HTTPException(404, "API key not found")
    if key.revoked_at is None:
        key.revoked_at = utcnow()
        audit(db, user, "api_key_revoked", f"{key.name} ({key.prefix}) of user #{key.user_id}", request)
        db.commit()
    back = request.headers.get("referer", "")
    return RedirectResponse("/admin#api-keys" if "/admin" in back else "/profile#api-keys", status_code=303)
