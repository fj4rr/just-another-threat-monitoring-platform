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
from datetime import UTC, date, datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import delete, func, select, update

from . import notify, settings
from .collectors import REGISTRY, SkipCollector
from .db import SessionLocal
from .models import CollectorRun, Entity, EntityLink, Insight, Item, ItemEntity, Source, utcnow

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


def cancel_backfill(batch_id: str) -> None:
    _cancelled.add(batch_id)


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
                    new += len(ingest_committed(db, src, page, origin="backfill"))
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
            raws = cls(src).fetch()
            from .processing.pipeline import ingest_committed

            new_ids = ingest_committed(db, src, raws, progress=lambda d, t: _progress(run.id, d, t, "storing"))
            src = db.get(Source, source_id)
            src.last_status, src.last_error = "ok", ""
            src.last_run = utcnow()
            db.commit()
            _after_ingest(db, new_ids)
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


# --------------------------------------------------------------------------- enrichment
def _check_quota(db) -> None:
    """One warning per day when the VirusTotal budget is used up."""
    limit = int(settings.get("vt_daily_budget") or 0)
    if not limit or not settings.get("virustotal_api_key"):
        return
    state = settings.get("_budget_virustotal") or {}
    if isinstance(state, dict) and state.get("day") == date.today().isoformat() and state.get("count", 0) >= limit:
        notify.notify(db, "warning", "VirusTotal daily quota reached",
                      f"All {limit} lookups for today are used; VirusTotal lookups resume tomorrow. "
                      "Other providers keep working. The budget is under Settings → Enrichment.",
                      "/settings?tab=enrichment", key=f"quota:virustotal:{state['day']}")
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
        notify.notify(db, "info", "AI digest ready", ins.title, "/insights", key=f"digest:{ins.id}")
        db.commit()
        return ins.title
    except Exception as e:
        db.rollback()
        _finish(db, run, "error", str(e))
        notify.notify(db, "error", "AI digest failed", str(e)[:300], "/insights",
                      key=f"digestfail:{date.today().isoformat()}")
        db.commit()
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
        notify.notify(db, "success", "Re-scoring finished", f"{n} item(s) re-scored with the current rules", "/feed",
                      key=f"rescore:{run.id}")
        db.commit()
        return f"re-scored {n} item(s)"
    except Exception as e:
        db.rollback()
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
        return "; ".join(msgs)
    except Exception as e:
        db.rollback()
        log.warning("context lookup %s failed: %s", entity_id, e)
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
        db.commit()
        return f"removed {n} old item(s), slimmed {slimmed}"
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
        bf.update(running=True, done=done, total=len(runs), batch=bbatch,
                  label=f"Backfilling… {done}/{len(runs)} sources · {new} new"
                        + (f" · {live['phase']}" if live.get("phase") else ""))
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
    scheduler.add_job(run_digest, "cron", hour=6, minute=0, id="digest", replace_existing=True)
    scheduler.add_job(run_housekeeping, "cron", hour=3, minute=30, id="housekeeping", replace_existing=True)
    scheduler.start()
    log.info("scheduler started with %d jobs", len(scheduler.get_jobs()))


def shutdown() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
