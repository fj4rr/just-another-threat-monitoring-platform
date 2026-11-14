"""Historical backfill: crawl further back than the live collectors do.

Each collector declares what it can reach (``Collector.backfill_capability``) and pages back on its own
(``Collector.backfill``): WordPress REST or Internet Archive snapshots for RSS, cursors for Bluesky /
Mastodon / OTX / MISP, full lists for ransomware.live country / group sources, 7 days for ThreatFox.
Backfilled items are stored with ``origin = "backfill"``: trends and "new" flags use publication dates, so
history never shows up as trending now, and backfilled indicators are not enriched unless enabled (free
provider quotas stay with live data). The job itself lives in app/jobs.py (``run_backfill``).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import settings
from .collectors import REGISTRY, SkipCollector
from .collectors.base import BackfillCapability
from .intel import NotConfigured
from .models import Item, Source, utcnow

PRESETS = ((7, "7 days"), (30, "30 days"), (90, "90 days"), (365, "1 year"))
MAX_DAYS = 3 * 365


def capability(src: Source) -> BackfillCapability:
    cls = REGISTRY.get(src.kind)
    if cls is None:
        return BackfillCapability(False, note=f"unknown collector kind {src.kind}")
    try:
        return cls(src).backfill_capability()
    except (SkipCollector, NotConfigured) as e:
        return BackfillCapability(False, note=str(e))


def window(days: int = 0, since: str = "", until: str = "") -> tuple[datetime, datetime]:
    """Naive-UTC [since, until] from a preset or explicit YYYY-MM-DD dates."""
    end = utcnow()
    if until:
        end = min(end, datetime.fromisoformat(until) + timedelta(days=1) - timedelta(seconds=1))
    start = datetime.fromisoformat(since) if since else end - timedelta(days=max(1, days or 30))
    start = max(start, end - timedelta(days=MAX_DAYS))
    if start >= end:
        raise ValueError("the start of the range must be before its end")
    return start, end


def effective_since(since: datetime, until: datetime, cap: BackfillCapability) -> tuple[datetime, str]:
    """Clamp the start to what the provider reaches and to the deletion retention (no point fetching items
    that housekeeping deletes tonight)."""
    notes = []
    if cap.max_days and since < until - timedelta(days=cap.max_days):
        since = until - timedelta(days=cap.max_days)
        notes.append(f"provider reaches {cap.max_days} days back")
    keep = int(settings.get("retention_days") or 0)
    if keep and since < utcnow() - timedelta(days=keep):
        since = utcnow() - timedelta(days=keep)
        notes.append(f"retention deletes items older than {keep} days")
    return since, "; ".join(notes)


def _rate_estimate(db: Session, src: Source, since: datetime, until: datetime) -> int | None:
    """Items per day over the last 30 days, times the window."""
    recent = db.scalar(select(func.count(Item.id)).where(Item.source_id == src.id,
                                                         Item.published_at >= utcnow() - timedelta(days=30))) or 0
    if not recent:
        return None
    return int(recent / 30 * max(1, (until - since).days))


def _probe(src: Source, since: datetime, until: datetime) -> dict:
    """Network part of an estimate (thread-safe: no database access)."""
    if src.kind != "rss":
        return {}
    try:
        coll = REGISTRY["rss"](src)
        root = coll.wordpress_root()
        if root:
            return {"method": f"WordPress API ({root})", "estimate": coll.wordpress_count(root, since, until),
                    "exact": True}
        return {"method": "Internet Archive snapshots of the feed"}
    except Exception as e:
        return {"method": "Internet Archive snapshots of the feed", "probe_error": f"{type(e).__name__}: {e}"[:200]}


def estimate(db: Session, sources: list[Source], since: datetime, until: datetime) -> list[dict]:
    rows, probe = [], []
    for src in sources:
        cap = capability(src)
        row = {"id": src.id, "name": src.name, "kind": src.kind, "supported": cap.supported,
               "method": cap.method, "note": cap.note, "estimate": None, "exact": False}
        if cap.supported:
            s_eff, clamp = effective_since(since, until, cap)
            row["from"] = s_eff.strftime("%Y-%m-%d")
            row["clamp"] = clamp
            row["have"] = db.scalar(select(func.count(Item.id)).where(
                Item.source_id == src.id, Item.published_at >= s_eff, Item.published_at <= until)) or 0
            row["_since"] = s_eff
            probe.append((row, src))
        rows.append(row)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda rs: _probe(rs[1], rs[0]["_since"], until), probe))
    for (row, src), res in zip(probe, results, strict=True):
        row.update({k: v for k, v in res.items() if v is not None})
        if row["estimate"] is None:
            row["estimate"] = _rate_estimate(db, src, row["_since"], until)
        row.pop("_since", None)
    return rows


def storage_stats(db: Session) -> dict:
    from .config import DATA_DIR, database_url

    url = database_url()
    size = None
    if url.startswith("sqlite"):
        f = DATA_DIR / "jatmp.db"
        size = sum(p.stat().st_size for p in (f, f.with_name("jatmp.db-wal")) if p.exists())
    else:
        try:
            size = db.scalar(select(func.pg_database_size(func.current_database())))
        except Exception:
            db.rollback()
    by = dict(db.execute(select(Item.origin, func.count(Item.id)).group_by(Item.origin)).all())
    return {
        "engine": url.split(":", 1)[0].split("+")[0], "bytes": size,
        "items": sum(by.values()), "live": by.get("live", 0) + by.get(None, 0), "backfill": by.get("backfill", 0),
        "slimmed": db.scalar(select(func.count(Item.id)).where(Item.slimmed_at.is_not(None))) or 0,
        "oldest": db.scalar(select(func.min(Item.published_at))),
    }
