"""Background jobs (APScheduler): collectors, enrichment, digest, housekeeping."""
from __future__ import annotations

import logging
import traceback
from datetime import UTC, datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import delete, func, select, update

from . import settings
from .collectors import REGISTRY, SkipCollector
from .db import SessionLocal
from .models import CollectorRun, Entity, EntityLink, Insight, Item, ItemEntity, Source, utcnow

log = logging.getLogger(__name__)
scheduler = BackgroundScheduler(timezone="UTC", job_defaults={"coalesce": True, "max_instances": 1,
                                                             "misfire_grace_time": 600})


def _start_run(db, job: str, source_id: int | None = None) -> CollectorRun:
    run = CollectorRun(job=job, source_id=source_id)
    db.add(run)
    db.commit()
    return run


def _finish(db, run: CollectorRun, status: str, msg: str = "", new: int = 0) -> None:
    run.status, run.message, run.new_items, run.finished_at = status, msg[:4000], new, utcnow()
    db.commit()


def run_source(source_id: int) -> str:
    db = SessionLocal()
    try:
        src = db.get(Source, source_id)
        if not src:
            return "source not found"
        cls = REGISTRY.get(src.kind)
        if not cls:
            return f"unknown collector kind {src.kind}"
        run = _start_run(db, f"source:{src.id}", src.id)
        try:
            raws = cls(src).fetch()
            from .processing.pipeline import ingest

            new_ids = ingest(db, src, raws)
            src.last_status, src.last_error = "ok", ""
            src.last_run = utcnow()
            db.commit()
            _finish(db, run, "ok", f"fetched {len(raws)}, new {len(new_ids)}", len(new_ids))
            _maybe_auto_summarize(new_ids)
            return f"{src.name}: {len(new_ids)} new / {len(raws)} fetched"
        except SkipCollector as e:
            db.rollback()
            src = db.get(Source, source_id)
            src.last_status, src.last_error, src.last_run = "skipped", str(e), utcnow()
            db.commit()
            _finish(db, run, "skipped", str(e))
            return f"{src.name}: skipped ({e})"
        except Exception as e:
            db.rollback()
            log.warning("collector %s failed: %s", source_id, e)
            src = db.get(Source, source_id)
            src.last_status, src.last_error, src.last_run = "error", f"{type(e).__name__}: {e}"[:2000], utcnow()
            db.commit()
            _finish(db, run, "error", traceback.format_exc()[-3000:])
            return f"{src.name}: error {e}"
    finally:
        db.close()


def _maybe_auto_summarize(item_ids: list[int]) -> None:
    from .llm import client

    if not item_ids or not settings.get("llm_auto_summarize") or not client.is_configured():
        return
    from .llm.insights import summarize_item

    db = SessionLocal()
    try:
        for iid in item_ids[:10]:
            item = db.get(Item, iid)
            if item and item.severity >= 40 and not item.llm_summary:
                try:
                    summarize_item(db, item)
                    db.commit()
                except Exception as e:
                    db.rollback()
                    log.warning("auto-summarize failed: %s", e)
                    break
    finally:
        db.close()


def run_enrichment() -> str:
    if not settings.get("enrichment_enabled"):
        return "enrichment disabled"
    from .processing.enrichment import run_batch

    db = SessionLocal()
    run = _start_run(db, "enrichment")
    try:
        msg = run_batch(db)
        db.commit()
        _finish(db, run, "ok", msg)
        return msg
    except Exception as e:
        db.rollback()
        _finish(db, run, "error", f"{e}\n{traceback.format_exc()[-2000:]}")
        return f"error: {e}"
    finally:
        db.close()


def run_digest(force: bool = False) -> str:
    from .llm import client
    from .llm.insights import daily_digest

    if not client.is_configured():
        return "LLM not configured"
    if not force and not settings.get("llm_daily_digest"):
        return "digest disabled"
    db = SessionLocal()
    run = _start_run(db, "digest")
    try:
        ins = daily_digest(db)
        db.commit()
        _finish(db, run, "ok", ins.title)
        return ins.title
    except Exception as e:
        db.rollback()
        _finish(db, run, "error", str(e))
        return f"error: {e}"
    finally:
        db.close()


def run_rescore() -> str:
    """Recompute the severity of every item with the current scoring rules, using the
    entities already linked to it (no re-extraction, no network)."""
    from .processing.enrichment import VERDICT_BONUS
    from .processing.severity import reasons_to_json, score_item

    db = SessionLocal()
    run = _start_run(db, "rescore")
    n = 0
    try:
        for item in db.execute(select(Item)).scalars():
            ents = [link.entity for link in item.entity_links]
            score, reasons = score_item(item.title, f"{item.content}\n{' '.join(item.tags or [])}", ents, item.kind)
            detail = reasons_to_json(reasons)
            # keep the enrichment feedback that was applied to the old score
            confirmed = max((VERDICT_BONUS.get(e.verdict or "", 0) for e in ents), default=0)
            if confirmed:
                best = max(ents, key=lambda e: VERDICT_BONUS.get(e.verdict or "", 0))
                detail.append({"label": f"indicator confirmed {best.verdict} ({best.type})", "points": confirmed})
                score = min(100, score + confirmed)
            item.severity, item.severity_detail = score, detail
            n += 1
            if n % 500 == 0:
                db.commit()
        db.commit()
        _finish(db, run, "ok", f"re-scored {n} item(s)")
        return f"re-scored {n} item(s)"
    except Exception as e:
        db.rollback()
        _finish(db, run, "error", str(e))
        return f"error: {e}"
    finally:
        db.close()


def run_housekeeping() -> str:
    days = int(settings.get("retention_days") or 0)
    db = SessionLocal()
    try:
        cutoff = utcnow() - timedelta(days=30)
        db.execute(delete(CollectorRun).where(CollectorRun.started_at < cutoff))
        n = 0
        if days > 0:
            res = db.execute(delete(Item).where(Item.published_at < utcnow() - timedelta(days=days)))
            n = res.rowcount or 0
            # item_entities rows cascade away; keep mention counters truthful and drop IOCs that
            # nothing references any more (families/actors/CVEs are kept as history)
            counts = select(ItemEntity.entity_id, func.count().label("n")).group_by(ItemEntity.entity_id).subquery()
            db.execute(update(Entity).values(mention_count=0))
            db.execute(update(Entity).where(Entity.id == counts.c.entity_id).values(mention_count=counts.c.n))
            linked = select(EntityLink.src_id).union(select(EntityLink.dst_id))
            db.execute(delete(Entity).where(Entity.mention_count == 0, Entity.id.not_in(linked),
                                            Entity.type.in_(("md5", "sha1", "sha256", "ip", "domain", "url"))))
        db.execute(delete(Insight).where(Insight.kind == "answer", Insight.created_at < utcnow() - timedelta(days=90)))
        db.commit()
        return f"removed {n} old item(s)"
    finally:
        db.close()


# --------------------------------------------------------------------------- scheduling
def schedule_source(src: Source) -> None:
    job_id = f"source:{src.id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    if src.enabled:
        scheduler.add_job(run_source, "interval", minutes=max(5, src.interval_minutes or 30),
                          id=job_id, args=[src.id], next_run_time=_now() + timedelta(seconds=5 + src.id * 3))


def unschedule_source(source_id: int) -> None:
    if scheduler.get_job(f"source:{source_id}"):
        scheduler.remove_job(f"source:{source_id}")


def _now() -> datetime:
    return datetime.now(UTC)


def run_now(func, *args) -> None:
    scheduler.add_job(func, "date", args=list(args), run_date=_now() + timedelta(seconds=1),
                      id=None, max_instances=3)


def start() -> None:
    if scheduler.running:
        return
    db = SessionLocal()
    try:
        for src in db.execute(select(Source)).scalars():
            schedule_source(src)
    finally:
        db.close()
    scheduler.add_job(run_enrichment, "interval", minutes=max(2, int(settings.get("enrichment_interval") or 10)),
                      id="enrichment", next_run_time=_now() + timedelta(minutes=2), replace_existing=True)
    scheduler.add_job(run_digest, "cron", hour=6, minute=0, id="digest", replace_existing=True)
    scheduler.add_job(run_housekeeping, "cron", hour=3, minute=30, id="housekeeping", replace_existing=True)
    scheduler.start()
    log.info("scheduler started with %d jobs", len(scheduler.get_jobs()))


def shutdown() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
