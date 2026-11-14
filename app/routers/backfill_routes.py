"""Backfill page (admin): crawl further back, with per-source reach, estimates and live progress."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import backfill, jobs, settings
from ..auth import audit, require, verify_csrf
from ..db import get_db
from ..models import CollectorRun, Source, User
from ..web import render

router = APIRouter()


@router.get("/backfill")
def backfill_page(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    sources = db.execute(select(Source).order_by(Source.category, Source.kind, Source.name)).scalars().all()
    caps = {s.id: backfill.capability(s) for s in sources}
    runs = db.execute(select(CollectorRun).where(CollectorRun.job.like("backfill:%"))
                      .order_by(CollectorRun.id.desc()).limit(40)).scalars().all()
    names = {s.id: s.name for s in sources}
    return render(request, "backfill.html", {
        "user": user, "sources": sources, "caps": caps, "runs": runs, "names": names, "presets": backfill.PRESETS,
        "stats": backfill.storage_stats(db), "active": jobs.active_batch(db, "backfill"),
        "retention_days": int(settings.get("retention_days") or 0),
        "retention_full_days": int(settings.get("retention_full_days") or 0),
        "enrich_backfill": bool(settings.get("enrich_backfill")),
    })


def _parse(payload: dict, db: Session):
    try:
        since, until = backfill.window(int(payload.get("days") or 0), str(payload.get("since") or ""),
                                       str(payload.get("until") or ""))
    except ValueError as e:
        raise HTTPException(400, f"invalid range: {e}") from e
    ids = [int(i) for i in payload.get("source_ids") or [] if str(i).isdigit()]
    if not ids:
        raise HTTPException(400, "pick at least one source")
    sources = db.execute(select(Source).where(Source.id.in_(ids)).order_by(Source.name)).scalars().all()
    return since, until, sources


@router.post("/api/backfill/estimate", dependencies=[Depends(verify_csrf)])
def estimate(payload: dict = Body(...), _: User = Depends(require("admin")), db: Session = Depends(get_db)):
    since, until, sources = _parse(payload, db)
    rows = backfill.estimate(db, sources, since, until)
    total = sum(r["estimate"] or 0 for r in rows if r["supported"])
    return {"ok": True, "since": since.strftime("%Y-%m-%d"), "until": until.strftime("%Y-%m-%d"), "rows": rows,
            "message": f"about {total:,} item(s) reachable from {sum(1 for r in rows if r['supported'])} source(s)"}


@router.post("/api/backfill/start", dependencies=[Depends(verify_csrf)])
def start(request: Request, payload: dict = Body(...), user: User = Depends(require("admin")),
          db: Session = Depends(get_db)):
    if jobs.active_batch(db, "backfill"):
        return {"ok": True, "running": True, "message": "A backfill is already running"}
    since, until, sources = _parse(payload, db)
    usable = [s for s in sources if backfill.capability(s).supported]
    if not usable:
        raise HTTPException(400, "none of the selected sources supports backfill")
    batch = jobs.queue_backfill(db, [s.id for s in usable], since, until)
    audit(db, user, "backfill_started", f"{len(usable)} source(s) {since:%Y-%m-%d}..{until:%Y-%m-%d}", request)
    db.commit()
    return {"ok": True, "batch": batch,
            "message": f"Backfill queued for {len(usable)} source(s), {since:%Y-%m-%d} to {until:%Y-%m-%d}"}


@router.post("/api/backfill/stop", dependencies=[Depends(verify_csrf)])
def stop(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    batch = jobs.active_batch(db, "backfill")
    if not batch:
        return {"ok": True, "message": "No backfill is running"}
    jobs.cancel_backfill(batch)
    audit(db, user, "backfill_stopped", batch, request)
    db.commit()
    return {"ok": True, "message": "Stopping after the current page"}
