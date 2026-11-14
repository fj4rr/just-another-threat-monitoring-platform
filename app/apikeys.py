"""API keys for the REST API (``Authorization: Bearer jatmp_<prefix>_<secret>``).

The secret is 256 random bits shown once at creation; only its SHA-256 is stored (a slow hash adds nothing
for a random secret of this size). Keys belong to a user, carry scopes, may expire, can be revoked, and are
rate limited per key.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import settings
from .models import ApiKey, User, utcnow

SCOPES = {
    "read": "Read items, entities, IOCs and trends (/api/v1/...)",
    "export": "Download IOC export feeds (CSV, JSON, plain-text blocklists)",
    "write": "Reserved for write endpoints (analyst and admin only)",
}
ROLE_SCOPES = {"viewer": {"read", "export"}, "analyst": set(SCOPES), "admin": set(SCOPES)}
TOKEN_PREFIX = "jatmp"  # noqa: S105 - public token prefix, not a secret


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def allowed_scopes(user: User) -> set[str]:
    return ROLE_SCOPES.get(user.role, {"read"})


def create(db: Session, user: User, name: str, scopes: list[str], expires_days: int = 0) -> tuple[ApiKey, str]:
    scopes = sorted({s for s in scopes if s in SCOPES} & allowed_scopes(user)) or ["read"]
    prefix = secrets.token_hex(4)
    while db.execute(select(ApiKey.id).where(ApiKey.prefix == prefix)).first():
        prefix = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    key = ApiKey(user_id=user.id, name=(name or "API key").strip()[:128], prefix=prefix, secret_hash=_hash(secret),
                 scopes=scopes, expires_at=utcnow() + timedelta(days=expires_days) if expires_days > 0 else None)
    db.add(key)
    db.flush()
    return key, f"{TOKEN_PREFIX}_{prefix}_{secret}"


def parse(token: str) -> tuple[str, str] | None:
    parts = (token or "").strip().split("_", 2)
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def verify(db: Session, token: str) -> ApiKey | None:
    parsed = parse(token)
    if not parsed:
        return None
    key = db.execute(select(ApiKey).where(ApiKey.prefix == parsed[0])).scalar_one_or_none()
    if key is None or not hmac.compare_digest(key.secret_hash, _hash(parsed[1])):
        return None
    if key.revoked_at is not None or (key.expires_at is not None and key.expires_at < utcnow()):
        return None
    return key


def status(key: ApiKey) -> str:
    if key.revoked_at:
        return "revoked"
    if key.expires_at and key.expires_at < utcnow():
        return "expired"
    return "active"


# ---- per-key rate limit (fixed one-minute window, in memory: the app runs as a single process)
_windows: dict[int, tuple[int, int]] = {}
_lock = threading.Lock()


def rate_ok(key_id: int) -> tuple[bool, int]:
    """(allowed, seconds until the window resets)."""
    limit = int(settings.get("api_rate_limit") or 120)
    now = int(time.time())
    window = now // 60
    with _lock:
        w, n = _windows.get(key_id, (window, 0))
        if w != window:
            w, n = window, 0
        n += 1
        _windows[key_id] = (w, n)
        if len(_windows) > 10_000:
            _windows.clear()
    return n <= limit, 60 - now % 60
