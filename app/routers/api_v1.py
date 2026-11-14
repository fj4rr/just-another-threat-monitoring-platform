"""Versioned, read-only REST API for other tools: SIEMs, firewalls, scripts, TIPs.

Authentication: ``Authorization: Bearer jatmp_<prefix>_<secret>`` (keys are created under Profile → API keys),
or the browser session. Everything returned goes through the sharing rules in app/sharing.py.
Incremental polling: list endpoints return ``next_cursor``; pass it back as ``cursor`` to get the next page,
or poll with ``since`` (ISO-8601, UTC) to fetch only what arrived after your last run.
"""
from __future__ import annotations

import base64
import csv
import io
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import __version__, apikeys, settings, sharing
from ..auth import LoginRequired, audit, current_user
from ..db import get_db
from ..models import Enrichment, Entity, EntityLink, Item, ItemEntity, Source, User, utcnow
from ..processing import trends
from ..search import item_text_clause
from ..web import render

router = APIRouter(prefix="/api/v1", tags=["v1"])
NAMED_TYPES = ("malware", "actor", "cve", "technique")
ENTITY_TYPES = NAMED_TYPES + trends.IOC_TYPES


# --------------------------------------------------------------------------- auth
def principal(scope: str):
    def dep(request: Request, db: Session = Depends(get_db)) -> User:
        auth = request.headers.get("authorization", "")
        token = ""
        if auth[:7].lower() == "bearer ":
            token = auth[7:].strip()
        elif auth[:6].lower() == "basic ":  # TAXII clients often only do Basic: the password is the API key
            try:
                user_part, _, pw = base64.b64decode(auth[6:].strip()).decode().partition(":")
            except (ValueError, UnicodeDecodeError):
                user_part, pw = "", ""
            token = pw or user_part
        if token:
            key = apikeys.verify(db, token)
            if key is None:
                raise HTTPException(401, "invalid, expired or revoked API key", headers={"WWW-Authenticate": "Bearer"})
            if scope not in (key.scopes or []):
                raise HTTPException(403, f"this API key lacks the '{scope}' scope")
            if not key.user or not key.user.is_active:
                raise HTTPException(401, "the key's user is disabled", headers={"WWW-Authenticate": "Bearer"})
            ok, retry = apikeys.rate_ok(key.id)
            if not ok:
                raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(retry)})
            now = utcnow()
            if key.last_used_at is None or now - key.last_used_at > timedelta(seconds=60):
                key.last_used_at = now
                key.last_used_ip = (request.client.host if request.client else "")[:64]
                db.commit()
            request.state.api_key = key
            return key.user
        try:
            return current_user(request, db)
        except LoginRequired:
            raise HTTPException(401, "authentication required: send 'Authorization: Bearer <API key>'",
                                headers={"WWW-Authenticate": "Bearer"}) from None

    return dep


# --------------------------------------------------------------------------- helpers
def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def _parse_since(since: str | None) -> datetime | None:
    if not since:
        return None
    try:
        dt = datetime.fromisoformat(since.strip().replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "since must be ISO-8601, e.g. 2026-11-14T08:00:00Z") from None
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def _link(path: str) -> str | None:
    base = str(settings.get("public_base_url") or "").rstrip("/")
    return f"{base}{path}" if base else None


def _entity_dict(e: Entity) -> dict:
    out = {"id": e.id, "type": e.type, "value": e.value, "display": e.display, "first_seen": _iso(e.first_seen),
           "last_seen": _iso(e.last_seen), "mentions": e.mention_count, "link": _link(f"/entities/{e.id}")}
    if e.category:
        out["category"] = e.category
    if e.type in trends.IOC_TYPES:
        out["verdict"] = (e.verdict or "unknown") if e.enriched_at else "pending"
    if e.type == "cve":
        m = e.meta or {}
        out["kev"] = bool(m.get("kev"))
        out["epss"] = (m.get("epss") or {}).get("score")
        out["cvss"] = (m.get("cvss") or {}).get("score")
    return out


def _item_dict(i: Item, full: bool = False) -> dict:
    out = {
        "id": i.id, "title": i.title, "url": i.url or None, "kind": i.kind,
        "source": {"name": i.source.name, "category": i.source.category, "kind": i.source.kind},
        "published_at": _iso(i.published_at), "collected_at": _iso(i.collected_at), "severity": i.severity,
        "tlp": sharing.item_tlp(i), "ai_summary": i.llm_summary or None, "link": _link(f"/items/{i.id}"),
        "origin": i.origin or "live",
        "entities": [{"id": link.entity.id, "type": link.entity.type, "value": link.entity.value}
                     for link in i.entity_links],
    }
    if full:
        out.update(content=i.content, tags=i.tags or [], severity_detail=i.severity_detail or [])
    return out


def _page(rows: list, limit: int) -> tuple[list, int | None]:
    more = len(rows) > limit
    rows = rows[:limit]
    return rows, (rows[-1].id if more and rows else None)


# --------------------------------------------------------------------------- items
@router.get("/items", summary="List items (articles, posts, pulses...)")
def list_items(since: str | None = Query(None, description="Only items collected after this time (ISO-8601 UTC)"),
               min_severity: int = Query(0, ge=0, le=100), source_type: str = Query("", description="news | social | intel"),
               q: str = Query("", max_length=200, description="Text search in title and content"),
               entity: int = Query(0, description="Only items mentioning this entity id"),
               order: str = Query("desc", pattern="^(asc|desc)$"),
               cursor: int = Query(0, ge=0, description="next_cursor from the previous page"),
               limit: int = Query(100, ge=1, le=500),
               _: User = Depends(principal("read")), db: Session = Depends(get_db)):
    stmt = select(Item).join(Source, Source.id == Item.source_id).where(sharing.shareable_item_clause())
    if (dt := _parse_since(since)) is not None:
        stmt = stmt.where(Item.collected_at > dt)
    if min_severity:
        stmt = stmt.where(Item.severity >= min_severity)
    if source_type:
        stmt = stmt.where(Source.category == source_type)
    if q.strip():
        stmt = stmt.where(item_text_clause(q.strip()))
    if entity:
        stmt = stmt.where(Item.id.in_(select(ItemEntity.item_id).where(ItemEntity.entity_id == entity)))
    if cursor:
        stmt = stmt.where(Item.id < cursor if order == "desc" else Item.id > cursor)
    stmt = stmt.order_by(Item.id.desc() if order == "desc" else Item.id.asc()).limit(limit + 1)
    rows, nxt = _page(db.execute(stmt).unique().scalars().all(), limit)
    return {"data": [_item_dict(i) for i in rows], "next_cursor": nxt}


@router.get("/items/{item_id}", summary="One item with content, tags and severity breakdown")
def get_item(item_id: int, _: User = Depends(principal("read")), db: Session = Depends(get_db)):
    item = db.get(Item, item_id)
    if not item or not sharing.item_shareable(item):
        raise HTTPException(404, "item not found")
    return _item_dict(item, full=True)


# --------------------------------------------------------------------------- entities
@router.get("/entities", summary="List malware families, actors, CVEs, techniques or indicators")
def list_entities(type: str = Query(..., description=" | ".join(ENTITY_TYPES)),
                  q: str = Query("", max_length=200), since: str | None = Query(None, description="last_seen after (ISO-8601)"),
                  cursor: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
                  _: User = Depends(principal("read")), db: Session = Depends(get_db)):
    if type not in ENTITY_TYPES:
        raise HTTPException(400, f"type must be one of {', '.join(ENTITY_TYPES)}")
    stmt = select(Entity).where(Entity.type == type)
    if type in trends.IOC_TYPES:
        stmt = stmt.where(sharing.shareable_entity_clause())
    if q.strip():
        stmt = stmt.where(Entity.display.ilike(f"%{q.strip()}%"))
    if (dt := _parse_since(since)) is not None:
        stmt = stmt.where(Entity.last_seen > dt)
    if cursor:
        stmt = stmt.where(Entity.id < cursor)
    rows, nxt = _page(db.execute(stmt.order_by(Entity.id.desc()).limit(limit + 1)).scalars().all(), limit)
    return {"data": [_entity_dict(e) for e in rows], "next_cursor": nxt}


@router.get("/entities/{entity_id}", summary="One entity with related entities, indicators and recent items")
def get_entity(entity_id: int, _: User = Depends(principal("read")), db: Session = Depends(get_db)):
    e = db.get(Entity, entity_id)
    if not e:
        raise HTTPException(404, "entity not found")
    if e.type in trends.IOC_TYPES and not db.execute(
            select(Entity.id).where(Entity.id == e.id, sharing.shareable_entity_clause())).first():
        raise HTTPException(404, "entity not found")
    out = _entity_dict(e)
    out["related"] = [{"id": c["id"], "type": c["type"], "name": c["name"], "co_mentions": c["count"]}
                      for c in trends.co_occurring(db, e.id, NAMED_TYPES, 20)]
    linked = db.execute(
        select(Entity, EntityLink.relation, EntityLink.provider).join(EntityLink, or_(
            (EntityLink.dst_id == Entity.id) & (EntityLink.src_id == e.id),
            (EntityLink.src_id == Entity.id) & (EntityLink.dst_id == e.id)))
        .where(sharing.shareable_entity_clause() if e.type not in trends.IOC_TYPES else Entity.type.in_(NAMED_TYPES))
        .limit(200)).all()
    out["linked"] = [{"id": x.id, "type": x.type, "value": x.value, "relation": rel,
                      **({"via": prov} if sharing.share_provider_details() else {})} for x, rel, prov in linked]
    items = db.execute(
        select(Item).join(Source, Source.id == Item.source_id).join(ItemEntity, ItemEntity.item_id == Item.id)
        .where(ItemEntity.entity_id == e.id, sharing.shareable_item_clause())
        .order_by(Item.published_at.desc()).limit(10)).unique().scalars().all()
    out["recent_items"] = [{"id": i.id, "title": i.title, "published_at": _iso(i.published_at), "severity": i.severity}
                           for i in items]
    if sharing.share_provider_details():
        out["providers"] = [{"provider": r.provider, "verdict": r.verdict, "summary": r.summary,
                             "permalink": r.permalink or None, "checked_at": _iso(r.fetched_at)}
                            for r in db.execute(select(Enrichment).where(Enrichment.entity_id == e.id)).scalars()]
    return out


@router.get("/trending", summary="Trending malware families, actors or CVEs (7 days vs 30-day baseline)")
def trending(type: str = Query("malware", pattern="^(malware|actor|cve)$"), limit: int = Query(20, ge=1, le=100),
             _: User = Depends(principal("read")), db: Session = Depends(get_db)):
    rows = trends.trending_cves(db, limit) if type == "cve" else trends.trending(db, type, limit)
    keep = ("id", "name", "category", "recent", "baseline", "sources", "growth", "score", "is_new",
            "kev", "epss", "cvss", "priority")
    return {"data": [{k: r[k] for k in keep if k in r} for r in rows]}


# --------------------------------------------------------------------------- IOCs + export feeds
def _confidence(verdict: str, enriched: bool, n_mal: int, n_sus: int) -> int:
    """0-100 from JATMP's consensus and how many providers back it."""
    if not enriched:
        return 20
    if verdict == "malicious":
        return min(100, 55 + 15 * max(n_mal, 1))
    if verdict == "suspicious":
        return min(60, 30 + 10 * max(n_sus, 1))
    return 0 if verdict == "clean" else 10


def _ioc_rows(db: Session, types: list[str], verdicts: list[str], family: str, since: datetime | None,
              min_confidence: int, cursor: int, limit: int) -> list[dict]:
    from .pages import _ioc_filter_for_entity

    mal = (select(Enrichment.entity_id, func.count().label("n")).where(Enrichment.verdict == "malicious")
           .group_by(Enrichment.entity_id).subquery())
    sus = (select(Enrichment.entity_id, func.count().label("n")).where(Enrichment.verdict == "suspicious")
           .group_by(Enrichment.entity_id).subquery())
    stmt = (select(Entity, func.coalesce(mal.c.n, 0), func.coalesce(sus.c.n, 0))
            .outerjoin(mal, mal.c.entity_id == Entity.id).outerjoin(sus, sus.c.entity_id == Entity.id)
            .where(Entity.type.in_(types), sharing.shareable_entity_clause()))
    if verdicts:
        conds = []
        if "pending" in verdicts:
            conds.append(Entity.enriched_at.is_(None))
        real = [v for v in verdicts if v != "pending"]
        if real:
            conds.append((Entity.verdict.in_(real)) & Entity.enriched_at.is_not(None))
        stmt = stmt.where(or_(*conds))
    if family:
        fam = db.get(Entity, int(family)) if family.isdigit() else db.execute(
            select(Entity).where(Entity.type.in_(("malware", "actor")), func.lower(Entity.display) == family.lower())
        ).scalars().first()
        if not fam:
            return []
        stmt = stmt.where(_ioc_filter_for_entity(fam.id))
    if since is not None:
        stmt = stmt.where(Entity.last_seen >= since)
    if cursor:
        stmt = stmt.where(Entity.id < cursor)
    out = []
    for e, n_mal, n_sus in db.execute(stmt.order_by(Entity.id.desc()).limit(limit * 3 if min_confidence else limit)):
        conf = _confidence(e.verdict or "", bool(e.enriched_at), n_mal, n_sus)
        if conf < min_confidence:
            continue
        out.append({"id": e.id, "type": e.type, "value": e.value,
                    "verdict": (e.verdict or "unknown") if e.enriched_at else "pending", "confidence": conf,
                    "first_seen": _iso(e.first_seen), "last_seen": _iso(e.last_seen), "mentions": e.mention_count})
        if len(out) >= limit:
            break
    if out:
        fams: dict[int, set[str]] = {}
        ids = [r["id"] for r in out]
        for a, b, name in db.execute(
                select(EntityLink.src_id, EntityLink.dst_id, Entity.display)
                .join(Entity, or_((Entity.id == EntityLink.dst_id) & EntityLink.src_id.in_(ids),
                                  (Entity.id == EntityLink.src_id) & EntityLink.dst_id.in_(ids)))
                .where(Entity.type == "malware")).all():
            for x in (a, b):
                if x in ids:
                    fams.setdefault(x, set()).add(name)
        for r in out:
            r["families"] = sorted(fams.get(r["id"], set()))
            r["link"] = _link(f"/entities/{r['id']}")
    return out


def _split(v: str, allowed) -> list[str]:
    vals = [x.strip().lower() for x in (v or "").split(",") if x.strip()]
    bad = [x for x in vals if x not in allowed]
    if bad:
        raise HTTPException(400, f"unknown value(s): {', '.join(bad)}; allowed: {', '.join(allowed)}")
    return vals


VERDICTS = ("malicious", "suspicious", "clean", "unknown", "pending")


@router.get("/iocs", summary="Indicators with JATMP verdict, confidence and attributed families")
def list_iocs(type: str = Query("", description="Comma list: " + ", ".join(trends.IOC_TYPES)),
              verdict: str = Query("", description="Comma list: " + ", ".join(VERDICTS)),
              family: str = Query("", description="Malware family / actor name or entity id"),
              since: str | None = Query(None, description="last_seen after (ISO-8601)"),
              min_confidence: int = Query(0, ge=0, le=100), cursor: int = Query(0, ge=0),
              limit: int = Query(100, ge=1, le=1000),
              _: User = Depends(principal("read")), db: Session = Depends(get_db)):
    types = _split(type, trends.IOC_TYPES) or list(trends.IOC_TYPES)
    rows = _ioc_rows(db, types, _split(verdict, VERDICTS), family.strip(), _parse_since(since), min_confidence,
                     cursor, limit + 1)
    more = len(rows) > limit
    rows = rows[:limit]
    return {"data": rows, "next_cursor": rows[-1]["id"] if more and rows else None}


@router.get("/feeds/iocs.{fmt}", summary="IOC export feed: csv, json or txt (one value per line, for blocklists)")
def ioc_feed(fmt: str, request: Request,
             type: str = Query("", description="Comma list of IOC types (default: all)"),
             verdict: str = Query("malicious", description="Comma list (default: malicious)"),
             family: str = Query(""), since_days: int = Query(30, ge=0, le=3650, description="0 = all time"),
             min_confidence: int = Query(0, ge=0, le=100), limit: int = Query(10_000, ge=1, le=50_000),
             user: User = Depends(principal("export")), db: Session = Depends(get_db)):
    if fmt not in ("csv", "json", "txt"):
        raise HTTPException(404, "feed format must be csv, json or txt")
    types = _split(type, trends.IOC_TYPES) or list(trends.IOC_TYPES)
    since = utcnow() - timedelta(days=since_days) if since_days else None
    rows = _ioc_rows(db, types, _split(verdict, VERDICTS), family.strip(), since, min_confidence, 0, limit)
    key = getattr(request.state, "api_key", None)
    if key is not None:
        audit(db, user, "api_export", f"iocs.{fmt} key={key.prefix} rows={len(rows)}", request)
        db.commit()
    name = f"jatmp-iocs-{utcnow():%Y%m%d}.{fmt}"
    disp = {"Content-Disposition": f'inline; filename="{name}"'}
    if fmt == "txt":
        return PlainTextResponse("".join(f"{r['value']}\n" for r in rows), headers=disp)
    if fmt == "json":
        return JSONResponse({"generated_at": _iso(utcnow()), "count": len(rows),
                             "filters": {"type": types, "verdict": verdict, "family": family, "since_days": since_days,
                                         "min_confidence": min_confidence}, "data": rows}, headers=disp)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "verdict", "confidence", "families", "first_seen", "last_seen", "mentions", "link"])
    for r in rows:
        w.writerow([r["type"], r["value"], r["verdict"], r["confidence"], ";".join(r["families"]), r["first_seen"],
                    r["last_seen"], r["mentions"], r["link"] or ""])
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8", headers=disp)


# --------------------------------------------------------------------------- STIX 2.1
def _stix(bundle: dict) -> JSONResponse:
    from ..stix import MEDIA_TYPE

    return JSONResponse(bundle, media_type=MEDIA_TYPE)


@router.get("/stix/bundle", summary="STIX 2.1 bundle of recent shareable items (reports) with their entities")
def stix_bundle(since_days: int = Query(7, ge=0, le=3650, description="0 = all time"),
                min_severity: int = Query(0, ge=0, le=100), limit: int = Query(200, ge=1, le=2000),
                _: User = Depends(principal("export")), db: Session = Depends(get_db)):
    from .. import stix

    return _stix(stix.items_bundle(db, since_days, min_severity, limit))


@router.get("/stix/items/{item_id}", summary="STIX 2.1 bundle for one item")
def stix_item(item_id: int, _: User = Depends(principal("export")), db: Session = Depends(get_db)):
    from .. import stix

    item = db.get(Item, item_id)
    if not item or not sharing.item_shareable(item):
        raise HTTPException(404, "item not found")
    return _stix(stix.item_bundle(db, item))


@router.get("/stix/entities/{entity_id}", summary="STIX 2.1 bundle for a family / actor / CVE / indicator")
def stix_entity(entity_id: int, _: User = Depends(principal("export")), db: Session = Depends(get_db)):
    from .. import stix

    e = db.get(Entity, entity_id)
    if not e or (e.type in trends.IOC_TYPES and not db.execute(
            select(Entity.id).where(Entity.id == e.id, sharing.shareable_entity_clause())).first()):
        raise HTTPException(404, "entity not found")
    return _stix(stix.entity_bundle(db, e))


# --------------------------------------------------------------------------- docs (served offline, no CDN)
def schema() -> dict:
    return get_openapi(title="JATMP REST API", version=f"v1 (JATMP {__version__})", routes=router.routes,
                       description=__doc__)


@router.get("/openapi.json", include_in_schema=False)
def openapi_json(_: User = Depends(principal("read"))):
    return schema()


@router.get("/docs", include_in_schema=False)
def docs(request: Request, db: Session = Depends(get_db)):
    try:
        user = current_user(request, db)
    except LoginRequired:  # a page, not an API call: send people to the login form
        return RedirectResponse("/login?next=/api/v1/docs", status_code=303)
    spec = schema()
    endpoints = []
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            endpoints.append({"method": method.upper(), "path": path, "summary": op.get("summary", ""),
                              "params": [{"name": p["name"], "in": p["in"], "required": p.get("required", False),
                                          "type": (p.get("schema") or {}).get("type", ""),
                                          "description": p.get("description", "")} for p in op.get("parameters", [])]})
    base = str(settings.get("public_base_url") or "").rstrip("/") or str(request.base_url).rstrip("/")
    return render(request, "api_docs.html", {"user": user, "endpoints": endpoints, "base": base})
