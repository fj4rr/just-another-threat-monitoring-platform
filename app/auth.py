"""Authentication & authorization.

single-user mode: no login; every request runs as the built-in local admin.
multi-user mode : session login, roles admin > analyst > viewer.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import is_multi_user
from .db import get_db
from .models import AuditLog, User

ROLES = ("viewer", "analyst", "admin")
LOCAL_USER = "local"
# OWASP (2023+) recommendation for PBKDF2-HMAC-SHA256. Older hashes keep their stored
# iteration count and still verify; they are upgraded transparently on next login.
_ITER = 600_000


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, _ITER)
    return f"pbkdf2_sha256${_ITER}${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, it, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(dk.hex(), digest)
    except (ValueError, TypeError):
        return False


def needs_rehash(stored: str) -> bool:
    try:
        return int(stored.split("$")[1]) < _ITER
    except (IndexError, ValueError):
        return True


def password_problems(pw: str) -> str | None:
    if len(pw) < 10:
        return "Password must be at least 10 characters."
    if len(pw) > 256:
        return "Password is too long (max 256 characters)."
    if pw.lower() == pw or pw.upper() == pw or not any(c.isdigit() for c in pw):
        return "Use upper- and lower-case letters and at least one digit."
    return None


def safe_next(target: str | None, fallback: str = "/") -> str:
    """Only allow same-origin relative paths as post-login redirect targets."""
    t = (target or "").strip()
    if not t.startswith("/") or t.startswith(("//", "/\\")) or "\n" in t or "\r" in t:
        return fallback
    return t


# ---- brute-force protection (in-memory; per username+ip)
_WINDOW, _MAX_ATTEMPTS, _MAX_KEYS = 900, 5, 10_000
_fails: dict[str, list[float]] = {}
_fails_lock = threading.Lock()


def _prune(now: float) -> None:
    for k in [k for k, ts in _fails.items() if not ts or now - ts[-1] > _WINDOW]:
        _fails.pop(k, None)
    if len(_fails) > _MAX_KEYS:  # pathological flood of distinct usernames: drop the oldest
        for k in sorted(_fails, key=lambda k: _fails[k][-1])[: len(_fails) - _MAX_KEYS]:
            _fails.pop(k, None)


def login_locked(key: str) -> bool:
    now = time.time()
    with _fails_lock:
        attempts = [t for t in _fails.get(key, []) if now - t < _WINDOW]
        if attempts:
            _fails[key] = attempts
        else:
            _fails.pop(key, None)
        return len(attempts) >= _MAX_ATTEMPTS


def record_fail(key: str) -> None:
    now = time.time()
    with _fails_lock:
        _fails.setdefault(key, []).append(now)
        _prune(now)


def clear_fails(key: str) -> None:
    with _fails_lock:
        _fails.pop(key, None)


# ---- CSRF (synchronizer token stored in the session)
def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session["csrf"] = tok
    return tok


async def verify_csrf(request: Request) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    expected = request.session.get("csrf")
    sent = request.headers.get("x-csrf-token")
    if not sent:
        ctype = request.headers.get("content-type", "")
        if "form" in ctype:
            form = await request.form()
            sent = form.get("csrf_token")
    if not expected or not sent or not hmac.compare_digest(str(sent), str(expected)):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


# ---- current user
class LoginRequired(Exception):
    pass


def local_user(db: Session) -> User:
    user = db.execute(select(User).where(User.username == LOCAL_USER)).scalar_one_or_none()
    if user is None:
        user = User(username=LOCAL_USER, display_name="Local analyst", role="admin", password_hash="")
        db.add(user)
        db.commit()
    return user


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    if not is_multi_user():
        return local_user(db)
    uid = request.session.get("uid")
    user = db.get(User, uid) if uid else None
    if user is None or not user.is_active or user.username == LOCAL_USER:
        request.session.pop("uid", None)
        raise LoginRequired()
    return user


def require(role: str):
    need = ROLES.index(role)

    def dep(user: User = Depends(current_user)) -> User:
        if ROLES.index(user.role if user.role in ROLES else "viewer") < need:
            raise HTTPException(status_code=403, detail=f"{role} role required")
        return user

    return dep


def audit(db: Session, user: User | None, action: str, detail: str = "", request: Request | None = None) -> None:
    ip = request.client.host if request is not None and request.client else ""
    db.add(AuditLog(user_id=user.id if user else None, username=user.username if user else "",
                    action=action, detail=detail[:2000], ip=ip))
