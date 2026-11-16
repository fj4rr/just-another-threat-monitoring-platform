"""Install logic shared by the web setup wizard and the CLI installer (install.py)."""
from __future__ import annotations

from sqlalchemy import select

from . import settings
from .auth import LOCAL_USER, hash_password, password_problems
from .collectors import DEFAULT_SOURCES, source_key
from .config import load_config, save_config
from .db import init_db, session_scope
from .models import Source, User


def perform_install(
    *,
    mode: str,
    app_name: str = "JATMP",
    admin_username: str = "",
    admin_password: str = "",
    seed_sources: bool = True,
    api_keys: dict | None = None,
    llm: dict | None = None,
) -> None:
    if mode not in ("single", "multi"):
        raise ValueError("mode must be 'single' or 'multi'")
    if mode == "multi":
        if not admin_username or not admin_password:
            raise ValueError("multi-user mode requires an admin username and password")
        problem = password_problems(admin_password)
        if problem:
            raise ValueError(problem)
    init_db()
    with session_scope() as db:
        if mode == "multi":
            existing = db.execute(select(User).where(User.username == admin_username)).scalar_one_or_none()
            if existing:
                existing.password_hash = hash_password(admin_password)
                existing.role, existing.is_active = "admin", True
            else:
                db.add(User(username=admin_username, display_name=admin_username,
                            password_hash=hash_password(admin_password), role="admin"))
        else:
            if not db.execute(select(User).where(User.username == LOCAL_USER)).scalar_one_or_none():
                db.add(User(username=LOCAL_USER, display_name="Local analyst", role="admin"))
        if seed_sources and not db.execute(select(Source.id).limit(1)).first():
            for s in DEFAULT_SOURCES:
                db.add(Source(**s))
    for k, v in (api_keys or {}).items():
        if v and k in settings.SCHEMA:
            settings.set(k, str(v).strip())
    for k, v in (llm or {}).items():
        if k in settings.SCHEMA and v not in (None, ""):
            settings.set(k, settings.coerce_form_value(k, v))
    # every current built-in source counts as offered, also when the user chose not to seed them
    mark_builtin_seen()
    cfg = load_config()
    cfg.update({"installed": True, "mode": mode, "app_name": app_name or "JATMP"})
    save_config(cfg)


SEEN_KEY = "builtin_sources_seen"  # setting: keys of the built-in sources this install has been given once


def builtin_keys() -> list[str]:
    return [source_key(s["kind"], s["config"]) for s in DEFAULT_SOURCES]


def mark_builtin_seen(extra: list[str] | None = None) -> None:
    seen = set(settings.get(SEEN_KEY) or []) | set(builtin_keys()) | set(extra or [])
    settings.set(SEEN_KEY, sorted(seen))


def seed_missing_sources(db, only_new: bool = False) -> list[Source]:
    """Add default sources that an existing install doesn't have yet (matched by kind + target).

    ``only_new`` (the automatic run at start-up) skips built-in sources this install was already given once, so a
    source the user deleted does not come back; the manual button and ``manage.py seed-sources`` add every
    missing one."""
    have = {source_key(s.kind, s.config) for s in db.execute(select(Source)).scalars()}
    seen = set(settings.get(SEEN_KEY) or []) if only_new else set()
    added = []
    for spec in DEFAULT_SOURCES:
        key = source_key(spec["kind"], spec["config"])
        if key not in have and key not in seen:
            src = Source(**spec)
            db.add(src)
            added.append(src)
    db.flush()
    return added


def auto_seed_sources() -> list[str]:
    """Start-up: add the built-in sources introduced since this install last saw the list, and say so in a
    notification. The first run after upgrading from 0.9.0 or older (nothing recorded yet) adds every missing
    built-in source, like pressing *Add new built-in sources*."""
    from . import notify

    with session_scope() as db:
        added = seed_missing_sources(db, only_new=True)
        names = [s.name for s in added]
        if added:
            enabled = sum(1 for s in added if s.enabled is not False)
            body = ", ".join(names[:12]) + (f" and {len(names) - 12} more" if len(names) > 12 else "")
            notify.notify(db, "info", f"{len(added)} new built-in source(s) added ({enabled} enabled)", body,
                          "/settings?tab=sources", key=f"autoseed:{len(builtin_keys())}:{len(added)}")
    mark_builtin_seen()
    return names
