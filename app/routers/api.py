from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import jobs
from ..auth import audit, current_user, require, verify_csrf
from ..db import get_db
from ..llm import client as llm
from ..llm.client import LLMError
from ..models import Entity, Item, Source, User, Watch
from ..processing import trends
from ..processing.enrichment import IOC_TYPES, enrich_entity, enrich_family
from ..web import md

router = APIRouter(prefix="/api")


def _days(n: int, lo: int = 1, hi: int = 365) -> int:
    return min(max(int(n), lo), hi)


# --------------------------------------------------------------------------- stats (read)
@router.get("/stats/overview")
def stats_overview(days: int = 7, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return trends.overview(db, _days(days))


@router.get("/stats/kpi_series")
def stats_kpi_series(days: int = 14, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return trends.kpi_series(db, min(max(days, 7), 60))


@router.get("/stats/timeline")
def stats_timeline(days: int = 30, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return trends.timeline(db, min(max(days, 7), 180))


@router.get("/stats/top")
def stats_top(type: str = "malware", days: int = 7, limit: int = 10, category: str = "",
              _: User = Depends(current_user), db: Session = Depends(get_db)):
    return trends.top_entities(db, type, _days(days), min(max(limit, 1), 50), category or None)


@router.get("/stats/trending")
def stats_trending(type: str = "malware", limit: int = 10, _: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    return trends.trending(db, type, min(max(limit, 1), 50))


@router.get("/stats/trending_timeline")
def stats_trending_timeline(limit: int = 5, days: int = 30, _: User = Depends(current_user),
                            db: Session = Depends(get_db)):
    top = trends.trending(db, "malware", limit=min(max(limit, 1), 8))
    tl = trends.family_timeline(db, [t["id"] for t in top], _days(days, 7, 180))
    return {"labels": tl["labels"], "series": [{"id": t["id"], "name": t["name"], "data": tl["series"][t["id"]]}
                                               for t in top]}


@router.get("/stats/categories")
def stats_categories(days: int = 30, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return trends.category_breakdown(db, _days(days))


@router.get("/stats/sources")
def stats_sources(days: int = 7, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return trends.source_breakdown(db, _days(days))


@router.get("/stats/iocs")
def stats_iocs(days: int = 30, _: User = Depends(current_user), db: Session = Depends(get_db)):
    return trends.ioc_breakdown(db, _days(days))


@router.get("/entities/{entity_id}/timeline")
def entity_timeline(entity_id: int, days: int = 60, _: User = Depends(current_user), db: Session = Depends(get_db)):
    tl = trends.family_timeline(db, [entity_id], _days(days, 7, 365))
    return {"labels": tl["labels"], "data": tl["series"][entity_id]}


# --------------------------------------------------------------------------- actions (write)
@router.post("/sources/{source_id}/run", dependencies=[Depends(verify_csrf)])
def source_run(source_id: int, request: Request, user: User = Depends(require("analyst")),
               db: Session = Depends(get_db)):
    src = db.get(Source, source_id)
    if not src:
        raise HTTPException(404, "source not found")
    jobs.run_now(jobs.run_source, source_id)
    audit(db, user, "source_run", src.name, request)
    db.commit()
    return {"ok": True, "message": f"{src.name} queued"}


@router.post("/sources/run_all", dependencies=[Depends(verify_csrf)])
def source_run_all(request: Request, user: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    srcs = db.execute(select(Source).where(Source.enabled)).scalars().all()
    for s in srcs:
        jobs.run_now(jobs.run_source, s.id)
    audit(db, user, "source_run_all", f"{len(srcs)} sources", request)
    db.commit()
    return {"ok": True, "message": f"{len(srcs)} sources queued"}


@router.post("/enrichment/run", dependencies=[Depends(verify_csrf)])
def enrichment_run(request: Request, user: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    jobs.run_now(jobs.run_enrichment)
    audit(db, user, "enrichment_run", "", request)
    db.commit()
    return {"ok": True, "message": "enrichment batch queued"}


@router.post("/items/rescore", dependencies=[Depends(verify_csrf)])
def items_rescore(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    jobs.run_now(jobs.run_rescore)
    audit(db, user, "items_rescore", "", request)
    db.commit()
    return {"ok": True, "message": "re-scoring queued; severities update in the background"}


@router.post("/entities/{entity_id}/enrich", dependencies=[Depends(verify_csrf)])
def entity_enrich(entity_id: int, request: Request, user: User = Depends(require("analyst")),
                  db: Session = Depends(get_db)):
    ent = db.get(Entity, entity_id)
    if not ent:
        raise HTTPException(404, "entity not found")
    if ent.type in IOC_TYPES:
        msgs = enrich_entity(db, ent)
    elif ent.type == "malware":
        msgs = enrich_family(db, ent)
    else:
        raise HTTPException(400, "enrichment supports IOCs and malware families")
    audit(db, user, "entity_enrich", f"{ent.type}:{ent.value}", request)
    db.commit()
    return {"ok": True, "message": "; ".join(msgs) or "no providers configured (Settings → API keys)"}


@router.post("/items/{item_id}/summarize", dependencies=[Depends(verify_csrf)])
def item_summarize(item_id: int, user: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    from ..llm.insights import summarize_item

    item = db.get(Item, item_id)
    if not item:
        raise HTTPException(404, "item not found")
    try:
        out = summarize_item(db, item)
    except LLMError as e:
        raise HTTPException(400, str(e)) from e
    db.commit()
    return {"ok": True, "html": str(md(out))}


@router.post("/entities/{entity_id}/brief", dependencies=[Depends(verify_csrf)])
def entity_brief(entity_id: int, user: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    from ..llm.insights import entity_brief as brief

    ent = db.get(Entity, entity_id)
    if not ent:
        raise HTTPException(404, "entity not found")
    try:
        out = brief(db, ent)
    except LLMError as e:
        raise HTTPException(400, str(e)) from e
    db.commit()
    return {"ok": True, "html": str(md(out))}


@router.post("/insights/digest", dependencies=[Depends(verify_csrf)])
def make_digest(user: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    from ..llm.insights import daily_digest

    try:
        ins = daily_digest(db, user.id)
    except LLMError as e:
        raise HTTPException(400, str(e)) from e
    db.commit()
    return {"ok": True, "id": ins.id, "html": str(md(ins.content))}


@router.post("/insights/ask", dependencies=[Depends(verify_csrf)])
def ask(payload: dict = Body(...), user: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    from ..llm.insights import ask as do_ask

    q = str(payload.get("question", "")).strip()[:1000]
    if not q:
        raise HTTPException(400, "question is empty")
    try:
        ins = do_ask(db, q, user.id)
    except LLMError as e:
        raise HTTPException(400, str(e)) from e
    db.commit()
    return {"ok": True, "id": ins.id, "html": str(md(ins.content))}


@router.post("/llm/test", dependencies=[Depends(verify_csrf)])
def llm_test(_: User = Depends(require("admin"))):
    try:
        return {"ok": True, "message": f"{llm.provider()}:{llm.model_name()} → {llm.test_connection()}"}
    except LLMError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(400, f"{type(e).__name__}: {e}") from e


@router.post("/llm/models", dependencies=[Depends(verify_csrf)])
def llm_models(payload: dict = Body(default={}), _: User = Depends(require("admin"))):
    """Live model list for the Settings page. Unsaved form values are passed in so the user
    can browse models before saving; a blank key uses the saved one."""
    from ..llm import presets

    mode = str(payload.get("mode") or "")
    vendor = str(payload.get("vendor") or "")
    sp = presets.spec(mode, vendor)
    if not sp:
        raise HTTPException(400, "choose local or cloud and a vendor first")
    base = str(payload.get("base_url") or "").strip()[:500] or sp["base_url"]
    if base and not base.lower().startswith(("http://", "https://")):
        raise HTTPException(400, "base URL must start with http:// or https://")
    key = str(payload.get("api_key") or "")[:500]
    try:
        models = llm.list_models(sp["provider"], base, key)
    except LLMError as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, "models": models, "message": f"{len(models)} model(s) found"}


@router.post("/watch/{entity_id}", dependencies=[Depends(verify_csrf)])
def watch_toggle(entity_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not db.get(Entity, entity_id):
        raise HTTPException(404, "entity not found")
    w = db.execute(select(Watch).where(Watch.user_id == user.id, Watch.entity_id == entity_id)).scalar_one_or_none()
    if w:
        db.delete(w)
        state = False
    else:
        db.add(Watch(user_id=user.id, entity_id=entity_id))
        state = True
    db.commit()
    return {"ok": True, "watching": state}
