"""Notification center: small helpers around the Notification table.

Notifications are created by background jobs (batch summaries, failing sources, quota hits, digest ready)
and read through ``/api/notifications``. ``user_id=None`` means "everyone". Read state is a per-user
watermark (``User.notif_read_at``): everything created before it counts as read.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from .models import Notification, User, utcnow

LEVELS = ("success", "info", "warning", "error")


def _safe_link(link: str) -> str:
    link = (link or "").strip()
    return link if link.startswith("/") and not link.startswith(("//", "/\\")) else ""


def notify(db: Session, level: str, title: str, body: str = "", link: str = "", key: str = "",
           user_id: int | None = None) -> Notification | None:
    """Add a notification (caller commits). With ``key``, a second call with the same key is a no-op."""
    if key and db.execute(select(Notification.id).where(Notification.key == key[:128]).limit(1)).first():
        return None
    n = Notification(level=level if level in LEVELS else "info", title=title[:256], body=(body or "")[:2000],
                     link=_safe_link(link)[:512], key=key[:128], user_id=user_id)
    db.add(n)
    db.flush()  # the session does not autoflush: make the key visible to a second call in the same session
    return n


def visible(user: User):
    return or_(Notification.user_id.is_(None), Notification.user_id == user.id)


def unread_count(db: Session, user: User) -> int:
    q = select(func.count(Notification.id)).where(visible(user))
    if user.notif_read_at:
        q = q.where(Notification.created_at > user.notif_read_at)
    return db.scalar(q) or 0


def latest(db: Session, user: User) -> Notification | None:
    return db.execute(select(Notification).where(visible(user)).order_by(Notification.id.desc()).limit(1)).scalar()


def as_dict(n: Notification, user: User) -> dict:
    return {
        "id": n.id, "level": n.level, "title": n.title, "body": n.body, "link": n.link,
        "created_at": n.created_at.isoformat() + "Z",
        "unread": not user.notif_read_at or n.created_at > user.notif_read_at,
    }


def mark_all_read(db: Session, user: User) -> None:
    user.notif_read_at = utcnow()


def prune(db: Session, days: int = 30) -> int:
    res = db.execute(delete(Notification).where(Notification.created_at < utcnow() - timedelta(days=days)))
    return res.rowcount or 0
