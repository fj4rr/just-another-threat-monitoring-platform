from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import jobs, settings
from ..auth import audit, require, verify_csrf
from ..collectors import REGISTRY
from ..db import get_db
from ..models import Source, User
from ..sharing import norm_tlp
from ..web import render

router = APIRouter(prefix="/settings")


def settings_ctx(db: Session, user: User, tab: str, msg: str = "") -> dict:
    sources = db.execute(select(Source).order_by(Source.category, Source.kind, Source.name)).scalars().all()
    kinds = {k: {"label": c.label, "category": c.category, "fields": c.fields} for k, c in REGISTRY.items()}
    ctx = {"user": user, "tab": tab, "msg": msg, "sources": sources, "kinds": kinds, "settings": settings.all_for_ui()}
    if tab == "intel":
        from ..processing.enrichment import PROVIDER_CLASSES, available_providers

        configured = {p.name for p in available_providers()}
        ctx["providers"] = [(c.name, c.name in configured) for c in PROVIDER_CLASSES]
    if tab == "webhooks":
        from .webhooks_routes import webhooks_ctx

        ctx.update(webhooks_ctx(db))
    return ctx


@router.get("")
def settings_page(request: Request, tab: str = "sources", msg: str = "", user: User = Depends(require("admin")),
                  db: Session = Depends(get_db)):
    ctx = settings_ctx(db, user, tab, msg)
    if tab == "llm":
        from ..llm import presets

        mode, vendor = settings.get("llm_mode") or "", settings.get("llm_vendor") or ""
        if mode not in presets.MODES or (mode != "none" and not presets.spec(mode, vendor)):
            mode, vendor = presets.infer(settings.get("llm_provider"), settings.get("llm_base_url"))
        if settings.env_locked("llm_provider"):  # env wins: show what is really in use
            mode, vendor = presets.infer(settings.get("llm_provider"), settings.get("llm_base_url"))
        ctx["ai"] = {
            "mode": mode, "vendor": vendor, "catalog": presets.ui_catalog(),
            "model": settings.get("llm_model") or "", "base_url": settings.get("llm_base_url") or "",
            "key_set": bool(settings.get("llm_api_key")), "locked": {k: settings.env_locked(k) for k in
                       ("llm_provider", "llm_base_url", "llm_model", "llm_api_key")},
            "vals": {k: settings.get(k) for k in ("llm_auto_summarize", "llm_auto_extract", "llm_daily_digest", "llm_language")},
        }
    return render(request, "settings.html", ctx)


@router.post("/values", dependencies=[Depends(verify_csrf)])
async def save_values(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    form = await request.form()
    group = form.get("group", "")
    changed = []
    if group == "llm":
        form = _normalise_llm_form(form)
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
                if form.get(f"{key}__clear") == "on":
                    raw = ""
                elif raw == "":  # blank = keep existing
                    continue
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


def _normalise_llm_form(form) -> dict:
    """The AI tab posts mode + vendor; derive provider / base URL / model from the presets so
    the rest of the app keeps reading the three classic settings."""
    from ..llm import presets

    data = {k: v for k, v in form.multi_items()}
    mode = data.get("llm_mode") or "none"
    vendor = data.get("vendor_local" if mode == "local" else "vendor_cloud") or ""
    if mode != "none" and not presets.spec(mode, vendor):
        mode = "none"
    data["llm_mode"], data["llm_vendor"] = mode, vendor
    data.update(presets.resolve(mode, vendor, data.get("llm_base_url", ""), data.get("llm_model", "")))
    if mode == "none":
        data.pop("llm_base_url", None)
        data.pop("llm_model", None)
    return data


def _source_config_from_form(kind: str, form) -> dict:
    cls = REGISTRY.get(kind)
    if not cls:
        raise HTTPException(400, "unknown kind")
    cfg = {name: str(form.get(f"cfg_{name}", "")).strip()[:2000] for name, _, _ in cls.fields if form.get(f"cfg_{name}")}
    for name, value in cfg.items():
        if name in ("url", "rss_bridge") and not value.lower().startswith(("http://", "https://")):
            raise HTTPException(400, f"{name} must start with http:// or https://")
    return cfg


def _interval(raw, fallback: int) -> int:
    try:
        return min(max(int(raw or fallback), 5), 10_080)
    except (TypeError, ValueError):
        return fallback


def _category(raw, fallback: str) -> str:
    return raw if raw in ("news", "social", "intel") else fallback


@router.post("/sources", dependencies=[Depends(verify_csrf)])
async def add_source(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    form = await request.form()
    kind = str(form.get("kind", ""))
    cls = REGISTRY.get(kind)
    if not cls:
        raise HTTPException(400, "unknown kind")
    src = Source(
        name=str(form.get("name", "")).strip()[:120] or cls.label, kind=kind,
        category=_category(form.get("category"), cls.category), config=_source_config_from_form(kind, form),
        interval_minutes=_interval(form.get("interval_minutes"), 30), enabled=True,
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
        src.interval_minutes = _interval(form.get("interval_minutes"), src.interval_minutes)
        src.category = _category(form.get("category"), src.category)
        new_cfg = _source_config_from_form(src.kind, form)
        keep = {k: v for k, v in (src.config or {}).items() if k not in dict.fromkeys(n for n, _, _ in REGISTRY[src.kind].fields)}
        src.config = {**keep, **new_cfg}
        if "tlp" in form:
            src.tlp = norm_tlp(form.get("tlp"))
        if "redistribute" in form:
            src.redistribute = {"1": True, "0": False}.get(str(form.get("redistribute")))
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
