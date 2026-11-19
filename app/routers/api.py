from __future__ import annotations

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import jobs, notify, throttle
from ..auth import audit, current_user, require, verify_csrf
from ..db import get_db
from ..llm import client as llm
from ..llm.client import LLMError
from ..models import Entity, Item, Source, User, Watch
from ..processing import trends
from ..processing.enrichment import IOC_TYPES, enrich_entity, enrich_family
from ..web import current_region, md

router = APIRouter(prefix="/api")


def _days(n: int, lo: int = 1, hi: int = 365) -> int:
    return min(max(int(n), lo), hi)


def _scope(scope: str):
    """``scope=fraud`` limits a statistic to scam reports (the scam & fraud dashboard); anything else = all items."""
    return Item.fraud_score > 0 if scope == "fraud" else None


# --------------------------------------------------------------------------- stats (read)
@router.get("/stats/overview")
def stats_overview(days: int = 7, _: User = Depends(current_user), db: Session = Depends(get_db),
                   region: str = Depends(current_region)):
    return trends.overview(db, _days(days), region)


@router.get("/stats/kpi_series")
def stats_kpi_series(days: int = 14, _: User = Depends(current_user), db: Session = Depends(get_db),
                     region: str = Depends(current_region)):
    return trends.kpi_series(db, _days(days, 7, 365), region)


@router.get("/stats/timeline")
def stats_timeline(days: int = 30, _: User = Depends(current_user), db: Session = Depends(get_db),
                   region: str = Depends(current_region)):
    return trends.timeline(db, _days(days, 7, 365), region)


@router.get("/stats/top")
def stats_top(type: str = "malware", days: int = 7, limit: int = 10, category: str = "",
              _: User = Depends(current_user), db: Session = Depends(get_db), region: str = Depends(current_region)):
    return trends.top_entities(db, type, _days(days), min(max(limit, 1), 50), category or None, region)


@router.get("/stats/trending")
def stats_trending(type: str = "malware", limit: int = 10, days: int = 7, scope: str = "",
                   _: User = Depends(current_user), db: Session = Depends(get_db),
                   region: str = Depends(current_region)):
    return trends.trending(db, type, min(max(limit, 1), 50), window=_days(days), region=region, extra=_scope(scope))


TREND_TYPES = ("malware", "cve", "actor", "scam_type", "brand")


@router.get("/stats/trending_timeline")
def stats_trending_timeline(limit: int = 5, days: int = 30, type: str = "malware", scope: str = "",
                            _: User = Depends(current_user), db: Session = Depends(get_db),
                            region: str = Depends(current_region)):
    """Mentions over time of the top trending entities of the period (``days``: the window and the chart)."""
    etype = type if type in TREND_TYPES else "malware"
    days, extra = _days(days, 7, 365), _scope(scope)
    top = trends.trending(db, etype, limit=min(max(limit, 1), 8), window=days, region=region, extra=extra)
    tl = trends.family_timeline(db, [t["id"] for t in top], days, region, extra)
    return {"labels": tl["labels"], "step": tl["step"],
            "series": [{"id": t["id"], "name": t["name"], "data": tl["series"][t["id"]]} for t in top]}


@router.get("/stats/categories")
def stats_categories(days: int = 30, type: str = "malware", scope: str = "", _: User = Depends(current_user),
                     db: Session = Depends(get_db), region: str = Depends(current_region)):
    """Malware by type, CVEs by exploitation risk, actor mentions by kind of actor, items per critical infrastructure sector,
    or (scam & fraud) scam reports per scam type and per kind of impersonated brand."""
    days = _days(days, 1, 3650)
    if type == "sector":
        return trends.sector_breakdown(db, days, region, _scope(scope))
    if type in ("scam_type", "brand_category"):
        from ..processing import fraudstats

        fn = fraudstats.scam_type_breakdown if type == "scam_type" else fraudstats.brand_category_breakdown
        return fn(db, days, region)
    fn = {"cve": trends.cve_breakdown, "actor": trends.actor_breakdown}.get(type, trends.category_breakdown)
    return fn(db, days, region)


@router.get("/stats/sources")
def stats_sources(days: int = 7, scope: str = "", _: User = Depends(current_user), db: Session = Depends(get_db),
                  region: str = Depends(current_region)):
    return trends.source_breakdown(db, _days(days), region, _scope(scope))


@router.get("/stats/fraud/overview")
def stats_fraud_overview(days: int = 7, _: User = Depends(current_user), db: Session = Depends(get_db),
                         region: str = Depends(current_region)):
    from ..processing import fraudstats

    return fraudstats.kpis(db, region, _days(days))


@router.get("/stats/fraud/kpi_series")
def stats_fraud_kpi_series(days: int = 14, _: User = Depends(current_user), db: Session = Depends(get_db),
                           region: str = Depends(current_region)):
    from ..processing import fraudstats

    return fraudstats.kpi_series(db, _days(days, 7, 365), region)


@router.get("/stats/fraud/timeline")
def stats_fraud_timeline(days: int = 30, _: User = Depends(current_user), db: Session = Depends(get_db),
                         region: str = Depends(current_region)):
    """Scam reports per day (week) split by the most reported scam types of the period."""
    from ..processing import fraudstats

    return fraudstats.timeline(db, _days(days, 7, 365), region)


@router.get("/stats/iocs")
def stats_iocs(days: int = 30, _: User = Depends(current_user), db: Session = Depends(get_db),
               region: str = Depends(current_region)):
    return trends.ioc_breakdown(db, _days(days), region)


@router.get("/stats/geo")
def stats_geo(days: int = 30, _: User = Depends(current_user), db: Session = Depends(get_db),
              region: str = Depends(current_region)):
    """Target countries, Indonesian provinces, source countries, languages and hosting countries."""
    return trends.geo_stats(db, _days(days, 0, 3650), region)


@router.get("/items/{item_id}/graph")
def item_graph(item_id: int, limit: int = 60, _: User = Depends(current_user), db: Session = Depends(get_db)):
    from ..processing import graph

    item = db.get(Item, item_id)
    if not item:
        raise HTTPException(404, "item not found")
    return graph.item_graph(db, item, min(max(limit, 20), 150))


@router.get("/entities/{entity_id}/graph")
def entity_graph(entity_id: int, limit: int = 60, _: User = Depends(current_user), db: Session = Depends(get_db)):
    from ..processing import graph

    ent = db.get(Entity, entity_id)
    if not ent:
        raise HTTPException(404, "entity not found")
    return graph.entity_graph(db, ent, min(max(limit, 20), 150))


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
    throttle.check(f"{user.id}:source_run", 20)
    # one run per source at a time: the queued row is created right away, so a second click finds it
    if jobs.job_running(db, f"source:{source_id}"):
        return {"ok": True, "running": True, "message": f"{src.name} is already running"}
    batch = jobs.queue_collection(db, [source_id])
    audit(db, user, "source_run", src.name, request)
    db.commit()
    return {"ok": True, "batch": batch, "message": f"{src.name} queued"}


@router.post("/sources/run_all", dependencies=[Depends(verify_csrf)])
def source_run_all(request: Request, user: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    if jobs.active_batch(db, "collect"):
        return {"ok": True, "running": True, "message": "Collection is already running"}
    srcs = db.execute(select(Source).where(Source.enabled)).scalars().all()
    if not srcs:
        return {"ok": True, "message": "No enabled sources (Settings → Sources)"}
    batch = jobs.queue_collection(db, [s.id for s in srcs])
    audit(db, user, "source_run_all", f"{len(srcs)} sources", request)
    db.commit()
    return {"ok": True, "batch": batch, "message": f"{len(srcs)} sources queued"}


@router.post("/enrichment/run", dependencies=[Depends(verify_csrf)])
def enrichment_run(request: Request, user: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    if jobs.job_running(db, "enrichment"):
        return {"ok": True, "running": True, "message": "Enrichment is already running"}
    batch = jobs.queue_job(db, "enrichment")
    audit(db, user, "enrichment_run", "", request)
    db.commit()
    return {"ok": True, "batch": batch, "message": "enrichment batch queued"}


@router.post("/cves/refresh", dependencies=[Depends(verify_csrf)])
def cve_refresh(request: Request, user: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    if jobs.job_running(db, "cve_intel"):
        return {"ok": True, "running": True, "message": "CVE intel refresh is already running"}
    batch = jobs.queue_job(db, "cve_intel")
    audit(db, user, "cve_refresh", "", request)
    db.commit()
    return {"ok": True, "batch": batch, "message": "CVE intel refresh queued (KEV, EPSS, CVSS)"}


# --------------------------------------------------------------------------- job status & notifications
@router.get("/jobs/status")
def jobs_status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = jobs.status(db)
    last = notify.latest(db, user)
    out["notifications"] = {"unread": notify.unread_count(db, user),
                            "latest": {"id": last.id, "title": last.title, "level": last.level} if last else None}
    return out


@router.get("/notifications")
def notifications(limit: int = 30, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from ..models import Notification

    rows = db.execute(select(Notification).where(notify.visible(user)).order_by(Notification.id.desc())
                      .limit(min(max(limit, 1), 100))).scalars().all()
    return {"items": [notify.as_dict(n, user) for n in rows], "unread": notify.unread_count(db, user)}


@router.post("/notifications/read", dependencies=[Depends(verify_csrf)])
def notifications_read(user: User = Depends(current_user), db: Session = Depends(get_db)):
    notify.mark_all_read(db, user)
    db.commit()
    return {"ok": True, "unread": 0}


@router.post("/items/geotag", dependencies=[Depends(verify_csrf)])
def items_geotag(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    jobs.run_now(jobs.run_geotag, True)
    audit(db, user, "items_geotag", "", request)
    db.commit()
    return {"ok": True, "message": "Geography is being recomputed in the background; a notification follows."}


@router.post("/items/fraudtag", dependencies=[Depends(verify_csrf)])
def items_fraudtag(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    jobs.run_now(jobs.run_fraudtag, True)
    audit(db, user, "items_fraudtag", "", request)
    db.commit()
    return {"ok": True, "message": "Scam & fraud analysis is running in the background; a notification follows."}


@router.post("/geoip/update", dependencies=[Depends(verify_csrf)])
def geoip_update(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    jobs.run_now(jobs.run_geoip_update)
    audit(db, user, "geoip_update", "", request)
    db.commit()
    return {"ok": True, "message": "Downloading the GeoIP database in the background."}


@router.post("/items/rescore", dependencies=[Depends(verify_csrf)])
def items_rescore(request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    jobs.run_now(jobs.run_rescore)
    audit(db, user, "items_rescore", "", request)
    db.commit()
    return {"ok": True, "message": "re-scoring queued; severities update in the background"}


# Manual lookups per user and minute: they call paid / rate-limited providers inside the request (audit 2026-11 S-7)
ENRICH_PER_MINUTE = 12
LOOKUPS_PER_MINUTE = 6


@router.post("/entities/{entity_id}/enrich", dependencies=[Depends(verify_csrf)])
def entity_enrich(entity_id: int, request: Request, user: User = Depends(require("analyst")),
                  db: Session = Depends(get_db)):
    ent = db.get(Entity, entity_id)
    if not ent:
        raise HTTPException(404, "entity not found")
    if ent.type not in IOC_TYPES and ent.type != "malware":
        raise HTTPException(400, "enrichment supports IOCs and malware families")
    throttle.check(f"{user.id}:enrich", ENRICH_PER_MINUTE)  # paid provider quota, synchronous (audit S-7)
    with throttle.exclusive(f"enrich:{ent.id}", "this entity is already being enriched"):
        msgs = enrich_entity(db, ent) if ent.type in IOC_TYPES else enrich_family(db, ent)
    audit(db, user, "entity_enrich", f"{ent.type}:{ent.value}", request)
    db.commit()
    return {"ok": True, "message": "; ".join(msgs) or "no providers configured (Settings → API keys)"}


@router.post("/items/{item_id}/summarize", dependencies=[Depends(verify_csrf)])
def item_summarize(item_id: int, user: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    from ..llm.insights import summarize_item

    item = db.get(Item, item_id)
    if not item:
        raise HTTPException(404, "item not found")
    throttle.check(f"{user.id}:summarize", LOOKUPS_PER_MINUTE)
    try:
        with throttle.exclusive(f"summarize:{item.id}", "a summary of this item is already being written"):
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
    from ..web import templates

    html = templates.get_template("_exec_summary.html").render(d=ins)
    return {"ok": True, "id": ins.id, "html": html}


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
    from ..web import templates

    html = templates.get_template("_exec_summary.html").render(d=ins)
    return {"ok": True, "id": ins.id, "html": html}


# --------------------------------------------------------------------------- analyst corrections (0.13)
CORRECTION_DONE = {
    "unlink": "Removed from this item; it will not be linked again",
    "false_positive": "Marked as not a threat: removed everywhere, it will not be linked again",
    "verdict": "Analyst verdict set; it wins over the providers",
    "not_scam": "Marked as not a scam report",
}


def _opt_int(v) -> int | None:
    try:
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        raise HTTPException(400, "ids must be numbers") from None


@router.post("/corrections", dependencies=[Depends(verify_csrf)])
def correction_create(request: Request, payload: dict = Body(...), user: User = Depends(require("analyst")),
                      db: Session = Depends(get_db)):
    from .. import corrections

    kind = str(payload.get("kind") or "")
    try:
        corr = corrections.create(db, user, kind, item_id=_opt_int(payload.get("item_id")),
                                  entity_id=_opt_int(payload.get("entity_id")), value=str(payload.get("value") or ""),
                                  reason=str(payload.get("reason") or ""))
    except corrections.CorrectionError as e:
        raise HTTPException(400, str(e)) from e
    audit(db, user, f"correction_{kind}", f"#{corr.id} item={corr.item_id or '-'} entity={corr.entity_id or '-'} "
                                          f"value={corr.value or '-'} reason={corr.reason[:200]}", request)
    db.commit()
    trends.invalidate_cache()
    return {"ok": True, "id": corr.id, "message": CORRECTION_DONE[kind]}


@router.post("/corrections/{correction_id}/undo", dependencies=[Depends(verify_csrf)])
def correction_undo(correction_id: int, request: Request, user: User = Depends(require("analyst")),
                    db: Session = Depends(get_db)):
    from .. import corrections
    from ..models import Correction

    corr = db.get(Correction, correction_id)
    if corr is None:
        raise HTTPException(404, "correction not found")
    try:
        corrections.undo(db, corr, user)
    except corrections.CorrectionError as e:
        raise HTTPException(400, str(e)) from e
    audit(db, user, "correction_undone", f"#{corr.id} {corr.kind}", request)
    db.commit()
    trends.invalidate_cache()
    return {"ok": True, "message": "Correction undone; what it changed is restored"}


@router.get("/corrections/export.jsonl")
def corrections_export(user: User = Depends(require("analyst")), db: Session = Depends(get_db)):
    """The active corrections as labelled cases for the quality report (``manage.py quality --corrections``)."""
    from fastapi.responses import PlainTextResponse

    from .. import quality

    lines = quality.cases_from_corrections(db)
    return PlainTextResponse("".join(lines), media_type="application/x-ndjson",
                             headers={"Content-Disposition": 'attachment; filename="jatmp-corrections.jsonl"'})


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


@router.post("/intel/test/{provider}", dependencies=[Depends(verify_csrf)])
def intel_test(provider: str, _: User = Depends(require("admin"))):
    from ..intel import NotConfigured
    from ..intel.context import CONTEXT_CLASSES
    from ..intel.darkweb import HudsonRock, RansomwareLive
    from ..processing.enrichment import PROVIDER_CLASSES

    cls = next((c for c in (*PROVIDER_CLASSES, *CONTEXT_CLASSES, RansomwareLive, HudsonRock) if c.name == provider), None)
    if cls is None:
        raise HTTPException(404, "unknown provider")
    try:
        return {"ok": True, "message": cls().test()}
    except NotConfigured as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(400, f"{provider}: {type(e).__name__}: {e}"[:300]) from e


@router.post("/entities/{entity_id}/context", dependencies=[Depends(verify_csrf)])
def entity_context(entity_id: int, request: Request, user: User = Depends(require("analyst")),
                   db: Session = Depends(get_db)):
    from ..intel import context

    ent = db.get(Entity, entity_id)
    if not ent:
        raise HTTPException(404, "entity not found")
    providers = context.available(ent.type)
    if not providers:
        raise HTTPException(400, f"no context provider configured for {ent.type} (Settings → Threat-intel APIs)")
    throttle.check(f"{user.id}:context", LOOKUPS_PER_MINUTE)
    with throttle.exclusive(f"context:{ent.id}", "a context lookup for this indicator is already running"):
        msgs = enrich_entity(db, ent, providers, auto_context=False)
    audit(db, user, "context_lookup", f"{ent.type}:{ent.value} via {', '.join(p.name for p in providers)}", request)
    db.commit()
    return {"ok": True, "message": "; ".join(msgs)}


# --------------------------------------------------------------------------- dark web tier 1 (deep dive)
@router.post("/entities/{entity_id}/deepdive", dependencies=[Depends(verify_csrf)])
def entity_deepdive(entity_id: int, request: Request, user: User = Depends(require("analyst")),
                    db: Session = Depends(get_db)):
    from ..intel import NotConfigured, darkweb
    from ..processing.enrichment import _link
    from ..processing.extractor import Extracted
    from ..processing.pipeline import get_or_create_entity

    ent = db.get(Entity, entity_id)
    if not ent:
        raise HTTPException(404, "entity not found")
    throttle.check(f"{user.id}:deepdive", LOOKUPS_PER_MINUTE)
    try:
        if ent.type in ("malware", "actor"):
            res = darkweb.ransomware_deep_dive(ent)
            for cve in res.data.get("cves", []):
                _link(db, ent, get_or_create_entity(db, Extracted("cve", cve, cve)), "exploits", "ransomware.live")
        elif ent.type == "domain":
            res = darkweb.infostealer_exposure(ent.value)
        else:
            raise HTTPException(400, "deep dive works on malware families, threat actors and domains")
    except NotConfigured as e:
        raise HTTPException(400, str(e)) from e
    except RuntimeError as e:
        raise HTTPException(400, str(e)) from e
    except httpx.HTTPError as e:
        raise HTTPException(502, f"{type(e).__name__}: {e}"[:300]) from e
    darkweb.save(db, ent, res)
    audit(db, user, "deep_dive", f"{ent.type}:{ent.value} via {res.provider}", request)
    db.commit()
    return {"ok": True, "message": f"{res.provider}: {res.summary}"}


# --------------------------------------------------------------------------- MISP
@router.post("/misp/test", dependencies=[Depends(verify_csrf)])
def misp_test(_: User = Depends(require("admin"))):
    from ..intel import NotConfigured
    from ..intel.misp import MISP

    try:
        return {"ok": True, "message": MISP().test()}
    except NotConfigured as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(400, f"{type(e).__name__}: {e}"[:300]) from e


@router.post("/misp/push/{kind}/{obj_id}", dependencies=[Depends(verify_csrf)])
def misp_push(kind: str, obj_id: int, request: Request, user: User = Depends(require("analyst")),
              db: Session = Depends(get_db)):
    from ..intel import NotConfigured
    from ..intel.misp import PushRefused, push_entity, push_item

    obj = db.get(Item, obj_id) if kind == "item" else db.get(Entity, obj_id) if kind == "entity" else None
    if obj is None:
        raise HTTPException(404, "not found")
    try:
        res = push_item(db, obj) if kind == "item" else push_entity(db, obj)
    except (NotConfigured, PushRefused) as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(502, f"MISP: {type(e).__name__}: {e}"[:300]) from e
    audit(db, user, "misp_push", f"{kind}:{obj_id} -> event {res.get('id')}", request)
    db.commit()
    verb = "Created" if res.get("created") else "Already in"
    return {"ok": True, "message": f"{verb} MISP event #{res.get('id')}", "url": res.get("url")}


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
