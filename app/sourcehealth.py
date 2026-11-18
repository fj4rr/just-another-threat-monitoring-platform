"""Source health (PM review 2026-11, item 8): sources that fail or go quiet without anyone noticing.

Per enabled source:

* **last new item**: the latest live item it brought in (backfills do not count);
* **this week vs usual**: live items collected in the last 7 days against the weekly average of the 4 weeks before;
* **usual gap**: the median time between its runs that brought something new (last 30 days of run history);
* **failing since**: when the current streak of failed runs started;
* **average text length** of its items (30 days): feeds that only carry a summary give the extractor little to
  work with (item 9 of the same review).

``check()`` raises a notification, once per source, condition and day, when a source has been quiet for
``QUIET_FACTOR`` times its usual gap (and at least ``QUIET_MIN``), or has been failing for ``FAILING_ALERT``.
"""
from __future__ import annotations

import itertools
import statistics
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import CollectorRun, Item, Source, utcnow

QUIET_FACTOR = 3  # no new item for this many usual gaps -> "quiet"
QUIET_MIN = timedelta(hours=12)  # never call a source quiet sooner than this
FAILING_ALERT = timedelta(hours=24)  # a failure streak this long gets its own notification
BASELINE_WEEKS = 4
MIN_GAPS = 3  # fewer productive runs than this in the history: no usual gap yet
SUMMARY_ONLY_CHARS = 400  # average text shorter than this: the feed carries summaries only
RUN_HISTORY = timedelta(days=30)  # collector_runs are kept for 30 days


def _live():
    return func.coalesce(Item.origin, "live") != "backfill"


def _fmt(td: timedelta | None) -> str:
    if td is None:
        return ""
    h = td.total_seconds() / 3600
    if h < 1:
        return f"{max(1, round(h * 60))} min"
    if h < 48:
        return f"{round(h)} h"
    return f"{round(h / 24)} days"


def report(db: Session, now: datetime | None = None) -> dict[int, dict]:
    """Health of every source, by source id."""
    now = now or utcnow()
    week_ago, base_start = now - timedelta(days=7), now - timedelta(days=7 * (BASELINE_WEEKS + 1))
    last_new = dict(db.execute(select(Item.source_id, func.max(Item.collected_at)).where(_live())
                               .group_by(Item.source_id)).all())
    week = dict(db.execute(select(Item.source_id, func.count(Item.id)).where(_live(), Item.collected_at >= week_ago)
                           .group_by(Item.source_id)).all())
    base = dict(db.execute(select(Item.source_id, func.count(Item.id))
                           .where(_live(), Item.collected_at >= base_start, Item.collected_at < week_ago)
                           .group_by(Item.source_id)).all())
    text = dict(db.execute(select(Item.source_id, func.avg(func.length(Item.content)))
                           .where(_live(), Item.collected_at >= now - timedelta(days=30), Item.slimmed_at.is_(None))
                           .group_by(Item.source_id)).all())
    runs: dict[int, list[tuple]] = {}
    for sid, at, status, new in db.execute(
            select(CollectorRun.source_id, CollectorRun.finished_at, CollectorRun.status, CollectorRun.new_items)
            .where(CollectorRun.source_id.is_not(None), CollectorRun.job.like("source:%"),
                   CollectorRun.finished_at.is_not(None), CollectorRun.finished_at >= now - RUN_HISTORY)
            .order_by(CollectorRun.finished_at)):
        runs.setdefault(sid, []).append((at, status, new or 0))

    out: dict[int, dict] = {}
    for src in db.execute(select(Source)).scalars():
        hist = runs.get(src.id, [])
        productive = [at for at, status, new in hist if status == "ok" and new > 0]
        gaps = [b - a for a, b in itertools.pairwise(productive)]
        usual_gap = statistics.median(gaps) if len(gaps) >= MIN_GAPS else None
        failing_since = None
        if src.last_status == "error":
            for at, status, _ in reversed(hist):
                if status != "error":
                    break
                failing_since = at
            failing_since = failing_since or src.last_run
        last = last_new.get(src.id)
        usual_week = round(base.get(src.id, 0) / BASELINE_WEEKS, 1)
        silent = (now - last) if last else None
        quiet = bool(src.enabled and usual_gap and silent is not None
                     and silent > max(QUIET_MIN, usual_gap * QUIET_FACTOR) and src.last_status != "error")
        failing_long = bool(src.enabled and failing_since and now - failing_since >= FAILING_ALERT)
        avg_text = int(text.get(src.id) or 0)
        state = ("disabled" if not src.enabled else "failing" if src.last_status == "error" else
                 "quiet" if quiet else "low" if usual_week >= 5 and week.get(src.id, 0) < usual_week * 0.3 else "ok")
        out[src.id] = {
            "state": state, "last_new": last, "silent": _fmt(silent), "week": week.get(src.id, 0),
            "usual_week": usual_week, "usual_gap": usual_gap, "usual_gap_text": _fmt(usual_gap),
            "failing_since": failing_since, "failing_for": _fmt(now - failing_since) if failing_since else "",
            "failing_long": failing_long, "quiet": quiet, "avg_text": avg_text,
            "summary_only": bool(avg_text and avg_text < SUMMARY_ONLY_CHARS and src.category == "news"),
        }
    return out


def check(db: Session) -> int:
    """Notify about quiet sources and long failure streaks (once per source, condition and day). Caller commits."""
    from . import notify

    day = utcnow().date().isoformat()
    sent = 0
    names = {s.id: s.name for s in db.execute(select(Source)).scalars()}
    for sid, h in report(db).items():
        if h["quiet"]:
            sent += bool(notify.notify(
                db, "warning", f"Source quiet: {names[sid]}",
                f"No new item for {h['silent']}; it usually brings something every {h['usual_gap_text']}. The feed "
                "may have moved, changed format or started blocking the client.", "/settings?tab=sources",
                key=f"srcquiet:{sid}:{day}"))
        if h["failing_long"]:
            sent += bool(notify.notify(
                db, "error", f"Source still failing: {names[sid]}",
                f"Every run has failed for {h['failing_for']}. Last error is on the Sources tab.",
                "/settings?tab=sources", key=f"srcfailing:{sid}:{day}"))
    return sent
