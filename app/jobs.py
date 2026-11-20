"""Background jobs (APScheduler): collectors, enrichment, CVE intel, digest, housekeeping.

Job status for the UI (``status()``):
- a manual "Collect now" queues one ``CollectorRun`` per source with status ``queued`` under one
  ``batch_id``; each run flips to running / ok / error, so the batch is one progress bar;
- enrichment and CVE-intel runs report fine-grained progress in memory (``_live``) instead of writing to
  SQLite mid-run, which would contend with the run's own write transaction;
- when the last run of a batch finishes, one summary notification is created (never one per source).
"""
from __future__ import annotations

import logging
import secrets
import threading
import traceback
from collections import deque
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import delete, func, select, update

from . import notify, settings
from .collectors import REGISTRY, SkipCollector
from .db import SessionLocal
from .models import CollectorRun, Entity, EntityLink, Insight, Item, ItemEntity, Source, utcnow
from .processing import topics

log = logging.getLogger(__name__)
scheduler = BackgroundScheduler(timezone="UTC", job_defaults={"coalesce": True, "max_instances": 1,
                                                             "misfire_grace_time": 600})

ACTIVE = ("queued", "running")
STALE_AFTER = timedelta(hours=3)  # a queued/running row older than this is treated as dead
_live: dict[int, dict] = {}  # run id -> {"done", "total", "phase"} while the run is in progress
_live_lock = threading.Lock()
_batch_lock = threading.Lock()


def _progress(run_id: int, done: int, total: int, phase: str = "") -> None:
    with _live_lock:
        _live[run_id] = {"done": int(done), "total": int(total), "phase": phase}


def _start_run(db, job: str, source_id: int | None = None, batch_id: str = "") -> CollectorRun:
    run = None
    if batch_id:
        run = db.execute(select(CollectorRun).where(CollectorRun.batch_id == batch_id, CollectorRun.job == job,
                                                    CollectorRun.status == "queued")).scalars().first()
    if run is None:
        run = CollectorRun(job=job, source_id=source_id, batch_id=batch_id or "")
        db.add(run)
    run.status, run.started_at = "running", utcnow()
    db.commit()
    return run


def _finish(db, run: CollectorRun, status: str, msg: str = "", new: int = 0) -> None:
    with _live_lock:
        live = _live.pop(run.id, None)
    if live:
        run.progress_done, run.progress_total, run.phase = live["done"], live["total"], live["phase"][:64]
    run.status, run.message, run.new_items, run.finished_at = status, msg[:4000], new, utcnow()
    db.commit()
    if run.batch_id:
        try:
            _maybe_finish_batch(db, run.batch_id)
        except Exception as e:  # a notification problem must never fail the job itself
            db.rollback()
            log.warning("batch summary failed: %s", e)


def _new_batch(kind: str) -> str:
    return f"{kind}-{secrets.token_hex(5)}"


# --------------------------------------------------------------------------- queueing (manual runs)
def active_batch(db, kind: str) -> str:
    """Batch id of a manual run of ``kind`` (collect | enrichment | cve_intel) that is still going, or ''."""
    row = db.execute(
        select(CollectorRun.batch_id).where(CollectorRun.batch_id.like(f"{kind}-%"), CollectorRun.status.in_(ACTIVE),
                                            CollectorRun.started_at >= utcnow() - STALE_AFTER)
        .order_by(CollectorRun.id.desc()).limit(1)
    ).first()
    return row[0] if row else ""


def job_running(db, job: str) -> bool:
    return bool(db.execute(
        select(CollectorRun.id).where(CollectorRun.job == job, CollectorRun.status.in_(ACTIVE),
                                      CollectorRun.started_at >= utcnow() - STALE_AFTER).limit(1)).first())


def create_collection_batch(db, source_ids: list[int]) -> str:
    batch = _new_batch("collect")
    for sid in source_ids:
        db.add(CollectorRun(job=f"source:{sid}", source_id=sid, status="queued", batch_id=batch))
    db.commit()
    return batch


def queue_collection(db, source_ids: list[int]) -> str:
    batch = create_collection_batch(db, source_ids)
    for sid in source_ids:
        run_now(run_source, sid, batch)
    return batch


def queue_backfill(db, source_ids: list[int], since: datetime, until: datetime) -> str:
    """One queued run per source under a ``backfill-`` batch; a single worker runs them one after another
    (backfills are long and SQLite has one writer, so they must not compete with each other)."""
    batch = _new_batch("backfill")
    for sid in source_ids:
        db.add(CollectorRun(job=f"backfill:{sid}", source_id=sid, status="queued", batch_id=batch))
    db.commit()
    run_now(run_backfill, batch, since.isoformat(), until.isoformat())
    return batch


_cancelled: set[str] = set()


def cancel_backfill(batch_id: str, db=None) -> int:
    """Stop a backfill: the source being crawled stops after its current page, the queued ones are aborted
    right away (so the page shows the batch as stopping instead of waiting for the worker to reach them)."""
    _cancelled.add(batch_id)
    if db is None:
        return 0
    queued = db.execute(select(CollectorRun).where(CollectorRun.batch_id == batch_id,
                                                   CollectorRun.status == "queued")).scalars().all()
    for run in queued:
        run.status, run.finished_at, run.message = "aborted", utcnow(), "backfill stopped by a user"
    return len(queued)


def run_backfill(batch_id: str, since_iso: str, until_iso: str) -> str:
    from . import backfill
    from .processing.pipeline import ingest_committed

    since, until = datetime.fromisoformat(since_iso), datetime.fromisoformat(until_iso)
    db = SessionLocal()
    total_new = 0
    try:
        runs = db.execute(select(CollectorRun).where(CollectorRun.batch_id == batch_id, CollectorRun.status == "queued")
                          .order_by(CollectorRun.id)).scalars().all()
        for run in runs:
            db.refresh(run)  # the Stop button aborts queued runs in the database
            if run.status != "queued":
                continue
            if batch_id in _cancelled:
                _finish(db, run, "aborted", "backfill stopped by a user")
                continue
            src = db.get(Source, run.source_id) if run.source_id else None
            run.status, run.started_at = "running", utcnow()
            db.commit()
            if src is None or src.kind not in REGISTRY:
                _finish(db, run, "error", "source not found")
                continue
            fetched = new = 0
            count = {"new": 0}  # read by the progress callback while pages arrive
            try:
                coll = REGISTRY[src.kind](src)
                cap = coll.backfill_capability()
                if not cap.supported:
                    _finish(db, run, "skipped", cap.note or "backfill not supported")
                    continue
                s_eff, clamp = backfill.effective_since(since, until, cap)

                def note(msg: str, _run=run, _src=src, _count=count) -> None:
                    _progress(_run.id, _count["new"], 0, f"{_src.name}: {msg}"[:64])

                for page in coll.backfill(s_eff, until, note):
                    if batch_id in _cancelled:
                        break
                    fetched += len(page)
                    new += len(ingest_committed(db, src, topics.keep(page, (src.config or {}).get("filter")),
                                                origin="backfill"))
                    src = db.get(Source, src.id)
                    count["new"] = new
                    _progress(run.id, new, 0, f"{src.name}: {fetched} fetched"[:64])
                msg = f"{new} new of {fetched} fetched, {s_eff:%Y-%m-%d} to {until:%Y-%m-%d}"
                if clamp:
                    msg += f" ({clamp})"
                if batch_id in _cancelled:
                    msg += "; stopped by a user"
                total_new += new
                _finish(db, run, "ok", msg, new)
            except SkipCollector as e:
                db.rollback()
                _finish(db, run, "skipped", str(e))
            except Exception as e:
                db.rollback()
                log.warning("backfill of source %s failed: %s", run.source_id, e)
                _finish(db, run, "error", f"{type(e).__name__}: {e}\n{traceback.format_exc()[-1500:]}", new)
        return f"backfilled {total_new} item(s)"
    finally:
        _cancelled.discard(batch_id)
        db.close()


def queue_job(db, job: str) -> str:
    """Queue a manual enrichment / CVE-intel run, visible as 'queued' immediately."""
    funcs = {"enrichment": run_enrichment, "cve_intel": run_cve_intel}
    batch = _new_batch(job)
    db.add(CollectorRun(job=job, status="queued", batch_id=batch))
    db.commit()
    run_now(funcs[job], batch)
    return batch


# --------------------------------------------------------------------------- batch summaries
def _maybe_finish_batch(db, batch_id: str) -> None:
    with _batch_lock:
        runs = db.execute(select(CollectorRun).where(CollectorRun.batch_id == batch_id)).scalars().all()
        if not runs or any(r.status in ACTIVE for r in runs):
            return
        key = f"batch:{batch_id}"
        if batch_id.startswith("collect-"):
            new = sum(r.new_items or 0 for r in runs)
            errs = [r for r in runs if r.status == "error"]
            skipped = [r for r in runs if r.status == "skipped"]
            names = dict(db.execute(select(Source.id, Source.name)
                                    .where(Source.id.in_([r.source_id for r in errs if r.source_id]))).all())
            title = f"Collected {new} new item{'s' if new != 1 else ''} from {len(runs)} source{'s' if len(runs) != 1 else ''}"
            if errs:
                title += f", {len(errs)} error{'s' if len(errs) != 1 else ''}"
            body = []
            if errs:
                failed = [names.get(r.source_id, f"#{r.source_id}") for r in errs]
                body.append("Failed: " + ", ".join(failed[:8]) + (f" and {len(failed) - 8} more" if len(failed) > 8 else ""))
            if skipped:
                body.append(f"{len(skipped)} skipped (missing API key or disabled provider)")
            notify.notify(db, "warning" if errs else "success", title, ". ".join(body),
                          "/settings?tab=sources" if errs else "/feed?days=1", key=key)
        elif batch_id.startswith("backfill-"):
            new = sum(r.new_items or 0 for r in runs)
            errs = [r for r in runs if r.status == "error"]
            done = [r for r in runs if r.status == "ok"]
            stopped = any(r.status == "aborted" for r in runs)
            title = (f"Backfill {'stopped' if stopped else 'finished'}: {new} historical item{'s' if new != 1 else ''} "
                     f"from {len(done)} source{'s' if len(done) != 1 else ''}")
            if errs:
                title += f", {len(errs)} error{'s' if len(errs) != 1 else ''}"
            notify.notify(db, "warning" if errs else "success", title,
                          "Backfilled items keep their original dates, so they do not count as trending now.",
                          "/backfill", key=key)
        else:
            run = runs[-1]
            label = {"enrichment": "Enrichment", "cve_intel": "CVE intel refresh"}.get(run.job, run.job)
            link = {"enrichment": "/iocs", "cve_intel": "/cves"}.get(run.job, "/")
            if run.status == "error":
                notify.notify(db, "error", f"{label} failed", run.message.splitlines()[0][:300] if run.message else "",
                              link, key=key)
            else:
                notify.notify(db, "success" if run.status == "ok" else "info", f"{label} finished", run.message[:300],
                              link, key=key)
        db.commit()


# --------------------------------------------------------------------------- collectors
def run_source(source_id: int, batch_id: str = "") -> str:
    db = SessionLocal()
    try:
        src = db.get(Source, source_id)
        if not src:
            if batch_id:  # don't leave a queued row behind
                run = _start_run(db, f"source:{source_id}", source_id, batch_id)
                _finish(db, run, "error", "source not found")
            return "source not found"
        cls = REGISTRY.get(src.kind)
        run = _start_run(db, f"source:{src.id}", src.id, batch_id)
        if not cls:
            _finish(db, run, "error", f"unknown collector kind {src.kind}")
            return f"unknown collector kind {src.kind}"
        prev_status = src.last_status
        try:
            _progress(run.id, 0, 0, "fetching")
            coll = cls(src)
            fetched = coll.fetch()
            raws = topics.keep(fetched, (src.config or {}).get("filter"))  # every source kind (0.13)
            if len(raws) < len(fetched):
                _progress(run.id, 0, 0, f"{len(fetched) - len(raws)} off topic")
            from .processing.pipeline import ingest_committed

            new_ids = ingest_committed(db, src, raws, progress=lambda d, t: _progress(run.id, d, t, "storing"))
            src = db.get(Source, source_id)
            src.last_status, src.last_error = "ok", ""
            src.last_run = utcnow()
            db.commit()
            _after_ingest(db, new_ids)
            _finish(db, run, "ok", f"fetched {len(fetched)}" + (f", {len(fetched) - len(raws)} off topic" if len(raws) < len(fetched) else "") + f", new {len(new_ids)}", len(new_ids))
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
            err = f"{type(e).__name__}: {e}"[:2000]
            src.last_status, src.last_error, src.last_run = "error", err, utcnow()
            # a scheduled run that starts failing gets its own notification (once, on the transition);
            # inside a manual batch the batch summary lists the failures instead
            if prev_status != "error" and not batch_id:
                notify.notify(db, "error", f"Source failing: {src.name}", err[:300], "/settings?tab=sources",
                              key=f"srcfail:{src.id}:{run.id}")
            db.commit()
            _finish(db, run, "error", traceback.format_exc()[-3000:])
            return f"{src.name}: error {e}"
    finally:
        db.close()


def _after_ingest(db, new_ids: list[int]) -> None:
    """Outbound side effects of new items: webhook events and MISP auto-push. Never fails the run."""
    if not new_ids:
        return
    try:
        from . import webhooks

        if webhooks.on_new_items(db, new_ids):
            db.commit()
    except Exception as e:
        db.rollback()
        log.warning("webhook events failed: %s", e)
    if int(settings.get("misp_autopush_min_severity") or 0) > 0:
        run_now(run_misp_autopush, list(new_ids))


# Auto-summaries run in their own single job, never inside a collector run: a slow model used to hold a collector
# worker for up to 10 × 600 s (audit 2026-11 E-4). New ids wait in a bounded queue; one drain job works them off.
_summary_queue: deque[int] = deque(maxlen=200)
_summary_lock = threading.Lock()
AUTO_SUMMARY_MAX_PER_RUN = 10
AUTO_SUMMARY_MIN_SEVERITY = 40
AUTO_SUMMARY_REQUEUE_HOURS = 24


def _maybe_auto_summarize(item_ids: list[int]) -> None:
    from .llm import client

    if not item_ids or not settings.get("llm_auto_summarize") or not client.is_configured():
        return
    with _summary_lock:
        _summary_queue.extend(item_ids)
    try:
        scheduler.add_job(run_auto_summaries, "date", run_date=_now() + timedelta(seconds=2), id="auto_summarize",
                          replace_existing=True, max_instances=1, coalesce=True)
    except Exception as e:  # scheduler not running (CLI): skip, the analyst can summarise by hand
        log.debug("auto-summarize not scheduled: %s", e)


def run_auto_summaries() -> str:
    from .llm.insights import summarize_item

    db = SessionLocal()
    done = 0
    try:
        while done < AUTO_SUMMARY_MAX_PER_RUN:
            with _summary_lock:
                if not _summary_queue:
                    break
                iid = _summary_queue.popleft()
            item = db.get(Item, iid)
            if not item or item.severity < AUTO_SUMMARY_MIN_SEVERITY or item.llm_summary or item.dup_of:
                continue
            try:
                summarize_item(db, item)
                db.commit()
                done += 1
            except Exception as e:
                db.rollback()
                log.warning("auto-summarize failed: %s", e)
                break  # the model is down or slow: do not try the whole queue against it
    finally:
        db.close()
    return f"summarised {done} item(s)"


def requeue_auto_summaries() -> int:
    """The queue lives in memory: after a restart, queue again what it would still hold (PM review 2026-11, item 15),
    i.e. live items of the last 24 hours that qualify and have no summary yet, the most severe first."""
    from .llm import client

    if not settings.get("llm_auto_summarize") or not client.is_configured():
        return 0
    db = SessionLocal()
    try:
        ids = [i for (i,) in db.execute(
            select(Item.id).where(Item.severity >= AUTO_SUMMARY_MIN_SEVERITY, Item.dup_of.is_(None),
                                  Item.origin == "live", func.coalesce(Item.llm_summary, "") == "",
                                  Item.collected_at >= utcnow() - timedelta(hours=AUTO_SUMMARY_REQUEUE_HOURS))
            .order_by(Item.severity.desc(), Item.id.desc()).limit(_summary_queue.maxlen))]
    finally:
        db.close()
    _maybe_auto_summarize(ids)
    return len(ids)


# --------------------------------------------------------------------------- enrichment
def _check_quota(db) -> None:
    """One warning per provider and day when its daily budget is used up (every provider with a budget, not only
    VirusTotal: PM review 2026-11, item 12)."""
    from .intel import quota

    day = date.today().isoformat()
    sent = False
    for q in quota.status():
        if not q["exhausted"]:
            continue
        what = "lookups" if q["group"] == "enrichment" else "context lookups"
        notify.notify(db, "warning", f"{q['label']} daily quota reached",
                      f"All {q['limit']} {what} for today are used; {q['label']} lookups resume tomorrow. "
                      "Other providers keep working. Budgets are under Settings → Enrichment.",
                      "/settings?tab=enrichment", key=f"quota:{q['provider']}:{day}")
        sent = True
    if sent:
        db.commit()


def run_enrichment(batch_id: str = "") -> str:
    db = SessionLocal()
    try:
        if not settings.get("enrichment_enabled"):
            if batch_id:
                _finish(db, _start_run(db, "enrichment", batch_id=batch_id), "skipped",
                        "automatic enrichment is disabled (Settings → Enrichment)")
            return "enrichment disabled"
        from .processing.enrichment import run_batch

        run = _start_run(db, "enrichment", batch_id=batch_id)
        try:
            msg = run_batch(db, progress=lambda d, t, p: _progress(run.id, d, t, p))
            db.commit()
            _finish(db, run, "ok", msg)
            _check_quota(db)
            return msg
        except Exception as e:
            db.rollback()
            _finish(db, run, "error", f"{e}\n{traceback.format_exc()[-2000:]}")
            if not batch_id:
                notify.notify(db, "error", "Enrichment run failed", str(e)[:300], "/iocs",
                              key=f"enrichfail:{date.today().isoformat()}")
                db.commit()
            return f"error: {e}"
    finally:
        db.close()


def run_cve_intel(batch_id: str = "", force: bool = False) -> str:
    """CISA KEV + FIRST EPSS + NVD CVSS for recently mentioned CVEs (see app/intel/cve.py).
    The setting only stops the scheduled run; a manual run (button / CLI) always goes ahead."""
    from .intel import cve

    db = SessionLocal()
    try:
        if not settings.get("cve_intel_enabled") and not (batch_id or force):
            return "CVE intel disabled"
        run = _start_run(db, "cve_intel", batch_id=batch_id)
        try:
            msg = cve.refresh(db, progress=lambda d, t, p: _progress(run.id, d, t, p))
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
        notify.notify(db, "info", "AI executive summary ready", ins.title, "/insights", key=f"digest:{ins.id}")
        db.commit()
        return ins.title
    except Exception as e:
        db.rollback()
        _finish(db, run, "error", str(e))
        notify.notify(db, "error", "AI executive summary failed", str(e)[:300], "/insights",
                      key=f"digestfail:{date.today().isoformat()}")
        db.commit()
        return f"error: {e}"
    finally:
        db.close()


def run_geotag(force: bool = False) -> str:
    """Geo attribution for every item (target countries / provinces, language, source country) and the
    offline GeoIP country of IP indicators. Runs once after an upgrade or a rules change (``GEO_VERSION``),
    or on demand (Settings -> General, ``manage.py geotag``)."""
    from . import geoip
    from .models import Entity
    from .processing.geo import GEO_VERSION, retag_all

    if not force and int(settings.get("geo_version") or 0) >= GEO_VERSION:
        return "geography is up to date"
    db = SessionLocal()
    run = _start_run(db, "geotag")
    try:
        def progress(done: int, total: int) -> None:
            run.progress_done, run.progress_total, run.phase = done, total, f"{done}/{total} items"
            db.commit()

        n = retag_all(db, progress)
        located = 0
        if geoip.database_path():
            for ent in db.execute(select(Entity).where(Entity.type == "ip")).scalars():
                cc = geoip.country(ent.value)
                if cc and cc != ent.country:
                    ent.country = cc
                    located += 1
            db.commit()
        settings.set("geo_version", GEO_VERSION)
        msg = f"geo-tagged {n} item(s)" + (f", located {located} IP(s)" if located else "")
        _finish(db, run, "ok", msg)
        if force:
            notify.notify(db, "success", "Geography updated", msg, "/geo", key=f"geotag:{run.id}")
            db.commit()
        return msg
    except Exception as e:
        db.rollback()
        _finish(db, run, "error", str(e))
        log.warning("geotag failed: %s", e)
        return f"error: {e}"
    finally:
        db.close()


def run_fraudtag(force: bool = False) -> str:
    """Scam & fraud analysis of every stored item. Runs once after an upgrade or a rules change
    (``fraud.RULES_VERSION``), or on demand (Settings -> Scam & fraud, ``manage.py fraudtag``)."""
    from .processing import fraud

    if not force and int(settings.get("fraud_version") or 0) >= fraud.RULES_VERSION:
        return "fraud analysis is up to date"
    db = SessionLocal()
    run = _start_run(db, "fraudtag")
    try:
        def progress(done: int, total: int) -> None:
            run.progress_done, run.progress_total, run.phase = done, total, f"{done}/{total} items"
            db.commit()

        n = fraud.retag_all(db, progress)
        found = db.scalar(select(func.count(Item.id)).where(Item.fraud_score > 0)) or 0
        settings.set("fraud_version", fraud.RULES_VERSION)
        msg = f"analysed {n} item(s), {found} about a scam"
        _finish(db, run, "ok", msg)
        if force:
            notify.notify(db, "success", "Scam & fraud analysis finished", msg, "/fraud", key=f"fraudtag:{run.id}")
            db.commit()
        return msg
    except Exception as e:
        db.rollback()
        _finish(db, run, "error", str(e))
        log.warning("fraudtag failed: %s", e)
        return f"error: {e}"
    finally:
        db.close()


DEDUP_VERSION = 1  # 1 (0.10.1): cross-source fingerprints (pipeline.fingerprint)


def _repair_self_copies() -> int:
    """Items marked as a copy of themselves (find_original before 0.13): they are originals. Cheap, every start."""
    db = SessionLocal()
    try:
        n = db.execute(update(Item).where(Item.dup_of == Item.id).values(dup_of=None)).rowcount or 0
        db.commit()
        if n:
            log.info("repaired %d item(s) marked as a copy of themselves", n)
        return n
    finally:
        db.close()


def run_dedup(force: bool = False) -> str:
    """Fingerprint the articles stored before cross-source dedup existed and mark syndicated copies, oldest first,
    so the first outlet to publish a story stays the original. Runs once after an upgrade."""
    from .processing.pipeline import find_original, fingerprint

    repaired = _repair_self_copies()
    if not force and int(settings.get("dedup_version") or 0) >= DEDUP_VERSION:
        return "dedup fingerprints are up to date" + (f"; {repaired} original(s) repaired" if repaired else "")
    db = SessionLocal()
    try:
        ids = [i for (i,) in db.execute(select(Item.id).where(Item.kind == "article")
                                        .order_by(Item.published_at, Item.id))]
        dups = 0
        for n in range(0, len(ids), 500):
            items = {i.id: i for i in db.execute(select(Item).where(Item.id.in_(ids[n:n + 500]))).unique().scalars()}
            for item_id in ids[n:n + 500]:  # keep the chronological order inside the chunk
                item = items.get(item_id)
                if item is None:
                    continue
                item.fingerprint = fingerprint(item.title, item.content)
                db.flush()
                item.dup_of = find_original(db, item)
                dups += bool(item.dup_of)
            db.commit()
            db.expunge_all()
        settings.set("dedup_version", DEDUP_VERSION)
        return f"fingerprinted {len(ids)} article(s), {dups} syndicated cop{'y' if dups == 1 else 'ies'}"
    except Exception as e:
        db.rollback()
        log.warning("dedup failed: %s", e)
        return f"error: {e}"
    finally:
        db.close()


CONTENT_VERSION = 1  # 1 (0.10): stylesheet text printed into WordPress posts (pipeline.strip_css)


def run_content_cleanup(force: bool = False) -> str:
    """Clean text that was stored before a cleaning rule existed (0.10: CSS rules some feeds print into the post
    body), then re-run the scam and sector analysis of the items that changed. Runs once after an upgrade."""
    from .processing import fraud, sectors
    from .processing.pipeline import _CSS_HINT, strip_css

    if not force and int(settings.get("content_version") or 0) >= CONTENT_VERSION:
        return "stored content is up to date"
    db = SessionLocal()
    try:
        changed = 0
        # only rows with a "{ ...: ...; }" in them can hold CSS; the regex check is done in Python
        ids = [i for (i,) in db.execute(select(Item.id).where(Item.content.like("%{%:%;%}%")))]
        for n in range(0, len(ids), 200):
            for item in db.execute(select(Item).where(Item.id.in_(ids[n:n + 200]))).unique().scalars():
                if not _CSS_HINT.search(item.content or ""):
                    continue
                clean = " ".join(strip_css(item.content).split())
                if clean == item.content:
                    continue
                item.content = clean
                fraud.retag_item(db, item)
                keep = set(sectors.detect(item.title, f"{clean}\n{' '.join(item.tags or [])}",
                                          sectors._feed_value(item.raw), scam=bool(item.fraud_score)))
                for link in list(item.entity_links):
                    if link.entity.type == "sector" and link.entity.value not in keep:
                        link.entity.mention_count = max(0, (link.entity.mention_count or 0) - 1)
                        db.delete(link)
                changed += 1
            db.commit()
        settings.set("content_version", CONTENT_VERSION)
        return f"cleaned {changed} item(s)"
    except Exception as e:
        db.rollback()
        log.warning("content cleanup failed: %s", e)
        return f"error: {e}"
    finally:
        db.close()


def run_sectortag(force: bool = False) -> str:
    """Critical infrastructure sectors of every stored item (0.10). Runs once after an upgrade or a rules change
    (``sectors.RULES_VERSION``), or on demand (``manage.py sectortag``)."""
    from .processing import sectors

    if not force and int(settings.get("sector_version") or 0) >= sectors.RULES_VERSION:
        return "sectors are up to date"
    db = SessionLocal()
    run = _start_run(db, "sectortag")
    try:
        def progress(done: int, total: int) -> None:
            run.progress_done, run.progress_total, run.phase = done, total, f"{done}/{total} items"
            db.commit()

        n = sectors.retag_all(db, progress)
        settings.set("sector_version", sectors.RULES_VERSION)
        msg = f"sector-tagged {n} item(s)"
        _finish(db, run, "ok", msg)
        return msg
    except Exception as e:
        db.rollback()
        _finish(db, run, "error", str(e))
        log.warning("sectortag failed: %s", e)
        return f"error: {e}"
    finally:
        db.close()


def run_digesttag(force: bool = False) -> str:
    """Flag the newsletters and round-ups among the stored items (``Item.is_digest``). Runs once after an upgrade or a
    rules change (``digest.RULES_VERSION``), or on demand (``manage.py digesttag``, also after a source's
    ``"digest"`` setting changed)."""
    from .processing import digest, trends

    if not force and int(settings.get("digest_version") or 0) >= digest.RULES_VERSION:
        return "digest flags are up to date"
    db = SessionLocal()
    run = _start_run(db, "digesttag")
    try:
        def progress(done: int, total: int) -> None:
            run.progress_done, run.progress_total, run.phase = done, total, f"{done}/{total} items"
            db.commit()

        n = digest.retag_all(db, progress)
        settings.set("digest_version", digest.RULES_VERSION)
        trends.invalidate_cache()
        msg = f"{n} item(s) flagged as newsletters / round-ups"
        _finish(db, run, "ok", msg)
        return msg
    except Exception as e:
        db.rollback()
        _finish(db, run, "error", str(e))
        log.warning("digesttag failed: %s", e)
        return f"error: {e}"
    finally:
        db.close()


def prune_identifiers(db) -> int:
    """UU PDP data minimisation: scammer phone numbers, bank accounts and e-wallets that no item has mentioned for
    ``fraud_identifier_days`` are deleted (crypto wallets are not personal data and stay)."""
    days = int(settings.get("fraud_identifier_days") or 0)
    if days <= 0:
        return 0
    res = db.execute(delete(Entity).where(Entity.type.in_(("phone", "bank_account", "ewallet")),
                                          Entity.last_seen < utcnow() - timedelta(days=days)))
    return res.rowcount or 0


def run_geoip_update() -> str:
    """Refresh the offline GeoIP database (monthly) and locate IP indicators again."""
    from . import geoip

    try:
        msg = geoip.update(str(settings.get("maxmind_license_key") or ""))
    except Exception as e:
        log.warning("GeoIP update failed: %s", e)
        return f"error: {e}"
    run_geotag(force=True)
    return msg


@dataclass(frozen=True)
class _Scored:
    """What score_item needs of a linked entity: its type and the origin of the link."""
    type: str
    origin: str


def run_rescore_if_outdated() -> str:
    """Re-score every stored item once after the severity rules changed (``severity.RULES_VERSION``)."""
    from .processing.severity import RULES_VERSION

    if int(settings.get("severity_version") or 0) >= RULES_VERSION:
        return "severity scores are up to date"
    db = SessionLocal()
    try:
        empty = db.execute(select(Item.id).limit(1)).first() is None
    finally:
        db.close()
    if empty:  # a fresh install: nothing to re-score, and no notification about it
        settings.set("severity_version", RULES_VERSION)
        return "no items yet"
    return run_rescore(reason="the severity rules changed")


def run_rescore(reason: str = "") -> str:
    """Recompute the severity of every item with the current scoring rules, using the
    entities already linked to it (no re-extraction, no network)."""
    from .processing.severity import RULES_VERSION, carry_over, reasons_to_json, score_item

    db = SessionLocal()
    run = _start_run(db, "rescore")
    n = 0
    try:
        # chunks of 500 (a big install does not fit in memory at once), and each entity scored with the origin of
        # its link, exactly as at ingest: a heuristic family must not score like a known one (audit 2026-11 D-12)
        ids = [i for (i,) in db.execute(select(Item.id).order_by(Item.id))]
        for c in range(0, len(ids), 500):
            for item in db.execute(select(Item).where(Item.id.in_(ids[c:c + 500]))).unique().scalars():
                ents = [link.entity for link in item.entity_links]
                scored = [_Scored(link.entity.type, link.origin or "") for link in item.entity_links]
                score, reasons = score_item(item.title, f"{item.content}\n{' '.join(item.tags or [])}", scored,
                                            item.kind)
                # keep what did not come from the text: the enrichment bonus and the last AI assessment
                item.severity, item.severity_detail = carry_over(score, reasons_to_json(reasons), item.severity_detail,
                                                                 [(e.type, e.verdict) for e in ents])
                n += 1
            db.commit()
            db.expunge_all()  # keep memory flat; the run row is loaded again below
        run = db.get(CollectorRun, run.id)
        _finish(db, run, "ok", f"re-scored {n} item(s)")
        notify.notify(db, "success", "Re-scoring finished",
                      f"{n} item(s) re-scored with the current rules" + (f" ({reason})" if reason else "")
                      + "; enrichment bonuses and AI assessments were kept", "/feed", key=f"rescore:{run.id}")
        db.commit()
        settings.set("severity_version", RULES_VERSION)  # every stored item now uses the current rules
        return f"re-scored {n} item(s)"
    except Exception as e:
        db.rollback()
        run = db.get(CollectorRun, run.id) or run  # may have been expunged with a chunk
        _finish(db, run, "error", str(e))
        return f"error: {e}"
    finally:
        db.close()


def run_context_lookup(entity_id: int) -> str:
    """Infrastructure context (Shodan, Censys, CrowdSec, ...) for one indicator."""
    from .intel import context
    from .processing.enrichment import enrich_entity

    db = SessionLocal()
    try:
        ent = db.get(Entity, entity_id)
        providers = context.available(ent.type) if ent else []
        if not providers:
            return "no context providers for this indicator"
        msgs = enrich_entity(db, ent, providers, auto_context=False)
        db.commit()
        _check_quota(db)
        return "; ".join(msgs)
    except Exception as e:
        db.rollback()
        log.warning("context lookup %s failed: %s", entity_id, e)
        return f"error: {e}"
    finally:
        db.close()


def run_source_health() -> str:
    """Hourly: notify about sources that went quiet or keep failing (app/sourcehealth.py)."""
    from . import sourcehealth

    db = SessionLocal()
    try:
        n = sourcehealth.check(db)
        db.commit()
        return f"{n} source health notification(s)"
    except Exception as e:
        db.rollback()
        log.warning("source health check failed: %s", e)
        return f"error: {e}"
    finally:
        db.close()


def run_webhooks() -> str:
    from . import webhooks

    db = SessionLocal()
    try:
        return webhooks.deliver_pending(db)
    finally:
        db.close()


def run_misp_autopush(item_ids: list[int]) -> str:
    from .intel import misp

    db = SessionLocal()
    try:
        return misp.autopush(db, item_ids)
    except Exception as e:
        db.rollback()
        log.warning("MISP auto-push failed: %s", e)
        notify.notify(db, "error", "MISP auto-push failed", str(e)[:300], "/settings?tab=misp",
                      key=f"mispfail:{date.today().isoformat()}")
        db.commit()
        return f"error: {e}"
    finally:
        db.close()


SNIPPET = 400


def slim_items(db, limit: int = 20_000) -> int:
    """Retention tier: past ``retention_full_days`` an item keeps its title, link, entities, severity and a
    short snippet; the full text and bulky raw provider data go (FTS follows through its triggers)."""
    days = int(settings.get("retention_full_days") or 0)
    if days <= 0:
        return 0
    cutoff = utcnow() - timedelta(days=days)
    n = 0
    rows = db.execute(select(Item).where(Item.published_at < cutoff, Item.slimmed_at.is_(None))
                      .order_by(Item.id).limit(limit)).unique().scalars()
    now = utcnow()
    for item in rows:
        text = item.content or ""
        if len(text) > SNIPPET:
            item.content = text[:SNIPPET].rsplit(" ", 1)[0] + " …"
        item.raw = {k: v for k, v in (item.raw or {}).items()
                    if isinstance(v, (str, int, float, bool)) and len(str(v)) <= 200}
        item.slimmed_at = now
        n += 1
        if n % 1000 == 0:
            db.commit()
    db.commit()
    return n


def run_housekeeping() -> str:
    days = int(settings.get("retention_days") or 0)
    db = SessionLocal()
    try:
        cutoff = utcnow() - timedelta(days=30)
        db.execute(delete(CollectorRun).where(CollectorRun.started_at < cutoff))
        notify.prune(db, 30)
        slimmed = slim_items(db)
        from .models import WebhookDelivery

        db.execute(delete(WebhookDelivery).where(WebhookDelivery.created_at < cutoff))
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
        pruned = prune_identifiers(db)
        db.commit()
        return f"removed {n} old item(s), slimmed {slimmed}, pruned {pruned} scammer identifier(s)"
    finally:
        db.close()


# --------------------------------------------------------------------------- status for the UI
def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt.isoformat(timespec="seconds") + "Z"


def _next_run(prefix: str, exact: bool = False) -> str | None:
    if not scheduler.running:
        return None
    times = [j.next_run_time for j in scheduler.get_jobs()
             if j.next_run_time and ((j.id == prefix) if exact else (j.id or "").startswith(prefix))]
    return _iso(min(times)) if times else None


def _last_finished(db, job_filter) -> CollectorRun | None:
    return db.execute(select(CollectorRun).where(job_filter, CollectorRun.status.not_in(ACTIVE))
                      .order_by(CollectorRun.finished_at.desc()).limit(1)).scalar()


def _single_job(db, job: str, noun: str) -> dict:
    run = db.execute(select(CollectorRun).where(CollectorRun.job == job, CollectorRun.status.in_(ACTIVE),
                                                CollectorRun.started_at >= utcnow() - STALE_AFTER)
                     .order_by(CollectorRun.id.desc()).limit(1)).scalar()
    out: dict = {"running": bool(run), "done": 0, "total": 0, "label": ""}
    if run:
        with _live_lock:
            live = dict(_live.get(run.id) or {})
        out["done"], out["total"] = live.get("done", 0), live.get("total", 0)
        if run.status == "queued":
            out["label"] = "Queued…"
        elif out["total"]:
            phase = f" ({live['phase']})" if live.get("phase") else ""
            out["label"] = f"Running… {out['done']}/{out['total']} {noun}{phase}"
        else:
            out["label"] = "Running…"
    last = _last_finished(db, CollectorRun.job == job)
    out["last"] = {"finished_at": _iso(last.finished_at), "status": last.status,
                   "summary": (last.message or "").splitlines()[0][:200] if last.message else "",
                   "message": (last.message or "")[:300] if last.status == "error" else ""} if last else None
    out["next"] = _next_run(job, exact=True)
    return out


def status(db) -> dict:
    """Last / next / running state of the jobs the dashboard buttons start."""
    collect: dict = {"running": False, "done": 0, "total": 0, "label": ""}
    batch = active_batch(db, "collect")
    if batch:
        runs = db.execute(select(CollectorRun.status, CollectorRun.new_items)
                          .where(CollectorRun.batch_id == batch)).all()
        done = sum(1 for s, _ in runs if s not in ACTIVE)
        new = sum(n or 0 for s, n in runs if s not in ACTIVE)
        errs = sum(1 for s, _ in runs if s == "error")
        collect.update(running=True, done=done, total=len(runs),
                       label=f"Collecting… {done}/{len(runs)} sources · {new} new"
                             + (f" · {errs} error{'s' if errs != 1 else ''}" if errs else ""))
    collect["active_sources"] = db.scalar(
        select(func.count(CollectorRun.id)).where(CollectorRun.job.like("source:%"), CollectorRun.status == "running",
                                                  CollectorRun.started_at >= utcnow() - STALE_AFTER)) or 0
    last = _last_finished(db, CollectorRun.job.like("source:%"))
    collect["last"] = {"finished_at": _iso(last.finished_at), "status": "ok", "summary": ""} if last else None
    collect["next"] = _next_run("source:")
    bf: dict = {"running": False, "done": 0, "total": 0, "label": "", "last": None, "next": None}
    bbatch = active_batch(db, "backfill")
    if bbatch:
        runs = db.execute(select(CollectorRun).where(CollectorRun.batch_id == bbatch)).scalars().all()
        done = sum(1 for r in runs if r.status not in ACTIVE)
        new = sum(r.new_items or 0 for r in runs if r.status not in ACTIVE)
        cur = next((r for r in runs if r.status == "running"), None)
        live = {}
        if cur:
            with _live_lock:
                live = dict(_live.get(cur.id) or {})
            new += live.get("done", 0)
        stopping = bbatch in _cancelled
        bf.update(running=True, done=done, total=len(runs), batch=bbatch, stopping=stopping,
                  label=(f"Stopping after the current page… {new} new" if stopping else
                         f"Backfilling… {done}/{len(runs)} sources · {new} new"
                         + (f" · {live['phase']}" if live.get("phase") else "")))
    lastb = _last_finished(db, CollectorRun.job.like("backfill:%"))
    if lastb:
        bf["last"] = {"finished_at": _iso(lastb.finished_at), "status": "ok", "summary": ""}
    return {
        "now": _iso(utcnow()),
        "jobs": {
            "backfill": bf,
            "collect": collect,
            "enrich": _single_job(db, "enrichment", "indicators"),
            "cve_intel": _single_job(db, "cve_intel", "CVEs"),
        },
    }


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


def _abort_stale_runs() -> None:
    """Runs that were queued or running when the process stopped will never finish."""
    db = SessionLocal()
    try:
        db.execute(update(CollectorRun).where(CollectorRun.status.in_(ACTIVE))
                   .values(status="aborted", finished_at=utcnow(), message="interrupted by a restart"))
        db.commit()
    finally:
        db.close()


def schedule_tz():
    """Time zone of the daily jobs (setting ``schedule_timezone``); UTC when the name is unknown."""
    from zoneinfo import ZoneInfo

    name = str(settings.get("schedule_timezone") or "UTC")
    if not settings.valid_timezone(name):
        log.warning("unknown time zone %r for the schedule, using UTC", name)
        name = "UTC"
    return ZoneInfo(name)


DAILY_JOBS = {"digest": ("digest_time", "06:00"), "housekeeping": ("housekeeping_time", "03:30")}


def schedule_daily_jobs() -> None:
    """(Re)schedule the executive summary and housekeeping at their configured local times (PM review, item 16).
    Called at start-up and when the General settings change."""
    tz = schedule_tz()
    funcs = {"digest": run_digest, "housekeeping": run_housekeeping}
    for job_id, (key, default) in DAILY_JOBS.items():
        h, m = settings.parse_hhmm(settings.get(key)) or settings.parse_hhmm(default)
        scheduler.add_job(funcs[job_id], "cron", hour=h, minute=m, timezone=tz, id=job_id, replace_existing=True)


def next_daily_runs() -> dict[str, datetime | None]:
    """Next run of each daily job, in the schedule's time zone (for Settings → General)."""
    out = {}
    for job_id in DAILY_JOBS:
        job = scheduler.get_job(job_id) if scheduler.running else None
        out[job_id] = job.next_run_time if job else None
    return out


def start() -> None:
    if scheduler.running:
        return
    _abort_stale_runs()
    db = SessionLocal()
    try:
        for src in db.execute(select(Source)).scalars():
            schedule_source(src)
    finally:
        db.close()
    scheduler.add_job(run_enrichment, "interval", minutes=max(2, int(settings.get("enrichment_interval") or 10)),
                      id="enrichment", next_run_time=_now() + timedelta(minutes=2), replace_existing=True)
    scheduler.add_job(run_cve_intel, "interval", hours=6, id="cve_intel",
                      next_run_time=_now() + timedelta(minutes=3), replace_existing=True)
    scheduler.add_job(run_webhooks, "interval", seconds=30, id="webhooks", replace_existing=True)
    scheduler.add_job(run_source_health, "interval", hours=1, id="source_health",
                      next_run_time=_now() + timedelta(minutes=15), replace_existing=True)
    schedule_daily_jobs()
    # one-off geo attribution of existing items after an upgrade (no-op when up to date)
    scheduler.add_job(run_geotag, "date", run_date=_now() + timedelta(seconds=20), id="geotag", replace_existing=True)
    # same for the scam & fraud analysis (0.9)
    scheduler.add_job(run_fraudtag, "date", run_date=_now() + timedelta(seconds=40), id="fraudtag",
                      replace_existing=True)
    # stored text that predates a cleaning rule (0.10: CSS printed into posts), before the re-analysis below
    scheduler.add_job(run_content_cleanup, "date", run_date=_now() + timedelta(seconds=15), id="content_cleanup",
                      replace_existing=True)
    # cross-source dedup fingerprints of stored articles (0.10.1)
    scheduler.add_job(run_dedup, "date", run_date=_now() + timedelta(seconds=30), id="dedup", replace_existing=True)
    # and for the critical infrastructure sectors (0.10)
    scheduler.add_job(run_sectortag, "date", run_date=_now() + timedelta(seconds=60), id="sectortag",
                      replace_existing=True)
    # newsletters / round-ups, so co-mentions and correlation can skip them (0.14.1)
    scheduler.add_job(run_digesttag, "date", run_date=_now() + timedelta(seconds=75), id="digesttag",
                      replace_existing=True)
    # and the severity scores, after the analyses above have settled the entities they read (0.12)
    scheduler.add_job(run_rescore_if_outdated, "date", run_date=_now() + timedelta(seconds=90), id="rescore_rules",
                      replace_existing=True)
    if settings.get("geoip_auto_update"):
        scheduler.add_job(run_geoip_update, "cron", day=5, hour=4, minute=0, id="geoip_update", replace_existing=True)
    scheduler.start()
    try:
        if n := requeue_auto_summaries():
            log.info("auto-summary queue rebuilt with %d item(s)", n)
    except Exception as e:  # never block the start-up on it
        log.warning("auto-summary queue not rebuilt: %s", e)
    log.info("scheduler started with %d jobs", len(scheduler.get_jobs()))


def shutdown() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
