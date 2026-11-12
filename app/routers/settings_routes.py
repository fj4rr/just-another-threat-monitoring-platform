from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import jobs, settings
from ..auth import audit, require, verify_csrf
from ..collectors import REGISTRY
from ..db import get_db
from ..models import Source, User
from ..web import render

router = APIRouter(prefix="/settings")


@router.get("")
def settings_page(request: Request, tab: str = "sources", msg: str = "", user: User = Depends(require("admin")),
                  db: Session = Depends(get_db)):
    sources = db.execute(select(Source).order_by(Source.category, Source.name)).scalars().all()
    kinds = {k: {"label": c.label, "category": c.category, "fields": c.fields} for k, c in REGISTRY.items()}
    return render(request, "settings.html", {
        "user": user, "tab": tab, "msg": msg, "sources": sources, "kinds": kinds,
        "settings": settings.all_for_ui(),
    })


@router.post("/values", dependencies=[Depends(verify_csrf)])
async def save_values(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    form = await request.form()
    group = form.get("group", "")
    changed = []
    for key, spec in settings.SCHEMA.items():
        if spec[4] != group or settings.env_locked(key):
            continue
        kind = spec[3]
        if kind == "bool":
            val = form.get(key) == "on"
        else:
            raw = form.get(key)
            if raw is None:
                continue
            if kind == "secret":
                if raw == "":  # blank = keep existing
                    continue
                if raw == "__clear__":
                    raw = ""
            val = settings.coerce_form_value(key, raw)
        if settings.get(key) != val:
            settings.set(key, val)
            changed.append(key)
    audit(db, user, "settings_changed", ", ".join(changed), request)
    db.commit()
    if "enrichment_interval" in changed and jobs.scheduler.running:
        jobs.scheduler.reschedule_job("enrichment", trigger="interval",
                                      minutes=max(2, int(settings.get("enrichment_interval") or 10)))
    return RedirectResponse(f"/settings?tab={group}&msg=Saved", status_code=303)


def _source_config_from_form(kind: str, form) -> dict:
    cls = REGISTRY.get(kind)
    if not cls:
        raise HTTPException(400, "unknown kind")
    return {name: str(form.get(f"cfg_{name}", "")).strip() for name, _, _ in cls.fields if form.get(f"cfg_{name}")}


@router.post("/sources", dependencies=[Depends(verify_csrf)])
async def add_source(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    form = await request.form()
    kind = str(form.get("kind", ""))
    cls = REGISTRY.get(kind)
    if not cls:
        raise HTTPException(400, "unknown kind")
    src = Source(
        name=str(form.get("name", "")).strip()[:120] or cls.label, kind=kind,
        category=str(form.get("category") or cls.category), config=_source_config_from_form(kind, form),
        interval_minutes=max(5, int(form.get("interval_minutes") or 30)), enabled=True,
    )
    db.add(src)
    audit(db, user, "source_added", f"{src.kind}:{src.name}", request)
    db.commit()
    jobs.schedule_source(src)
    return RedirectResponse("/settings?tab=sources&msg=Source+added", status_code=303)


@router.post("/sources/{source_id}", dependencies=[Depends(verify_csrf)])
async def update_source(source_id: int, request: Request, user: User = Depends(require("admin")),
                        db: Session = Depends(get_db)):
    src = db.get(Source, source_id)
    if not src:
        raise HTTPException(404, "source not found")
    form = await request.form()
    action = form.get("action", "save")
    if action == "delete":
        jobs.unschedule_source(src.id)
        audit(db, user, "source_deleted", src.name, request)
        db.delete(src)
        db.commit()
        return RedirectResponse("/settings?tab=sources&msg=Source+deleted", status_code=303)
    if action == "toggle":
        src.enabled = not src.enabled
    else:
        src.name = str(form.get("name", src.name)).strip()[:120] or src.name
        src.interval_minutes = max(5, int(form.get("interval_minutes") or src.interval_minutes))
        src.category = str(form.get("category") or src.category)
        new_cfg = _source_config_from_form(src.kind, form)
        keep = {k: v for k, v in (src.config or {}).items() if k not in dict.fromkeys(n for n, _, _ in REGISTRY[src.kind].fields)}
        src.config = {**keep, **new_cfg}
    audit(db, user, "source_updated", f"{src.name} ({action})", request)
    db.commit()
    jobs.schedule_source(src)
    return RedirectResponse("/settings?tab=sources&msg=Saved", status_code=303)


@router.post("/sources-seed", dependencies=[Depends(verify_csrf)])
def seed_sources(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    from ..setup_service import seed_missing_sources

    added = seed_missing_sources(db)
    audit(db, user, "sources_seeded", f"{len(added)} added", request)
    db.commit()
    for src in added:
        jobs.schedule_source(src)
    return RedirectResponse(f"/settings?tab=sources&msg=Added+{len(added)}+built-in+source(s)", status_code=303)
