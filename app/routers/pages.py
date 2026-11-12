from __future__ import annotations

from datetime import timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import distinct, func, or_, select
from sqlalchemy.orm import Session

from ..auth import current_user
from ..db import get_db
from ..knowledge import CATEGORIES
from ..llm import client as llm
from ..models import (
    Enrichment,
    Entity,
    EntityLink,
    Insight,
    Item,
    ItemEntity,
    Source,
    User,
    Watch,
    utcnow,
)
from ..processing import trends
from ..web import render

router = APIRouter()
PAGE = 40
IOC_PAGE = 60


def _clamp(n: int, lo: int, hi: int) -> int:
    return min(max(int(n), lo), hi)


def _dir(d: str, default: str) -> str:
    return d if d in ("asc", "desc") else default


def _qs(**params) -> str:
    """Query string for links that must keep the current filters (sort/page added by the template)."""
    return urlencode({k: v for k, v in params.items() if v not in ("", 0, None, False)})


@router.get("/")
def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    digest = db.execute(select(Insight).where(Insight.kind == "digest").order_by(Insight.created_at.desc())
                        .limit(1)).scalar_one_or_none()
    recent = db.execute(select(Item).where(Item.severity >= 30).order_by(Item.published_at.desc())
                        .limit(12)).scalars().all()
    watch_ids = [w.entity_id for w in db.execute(select(Watch).where(Watch.user_id == user.id)).scalars()]
    return render(request, "dashboard.html", {
        "user": user, "ov": trends.overview(db, 7),
        "trending": trends.trending(db, "malware", limit=12),
        "actors": trends.trending(db, "actor", limit=8),
        "cves": trends.top_entities(db, "cve", days=7, limit=8),
        "recent": recent, "digest": digest, "llm_on": llm.is_configured(), "watch_ids": watch_ids,
    })


FEED_SORTS = {
    "time": (lambda: (Item.published_at,), "desc"),
    "severity": (lambda: (Item.severity, Item.published_at), "desc"),
    "title": (lambda: (func.lower(Item.title),), "asc"),
    "source": (lambda: (Source.category, Source.name, Item.published_at), "asc"),
}


@router.get("/feed")
def feed(request: Request, cat: str = "", kind: str = "", q: str = "", source: int = 0, entity: int = 0,
         min_sev: int = 0, days: int = 30, page: int = 1, sort: str = "time", dir: str = "",
         user: User = Depends(current_user), db: Session = Depends(get_db)):
    days, min_sev, page = _clamp(days, 0, 3650), _clamp(min_sev, 0, 100), _clamp(page, 1, 100_000)
    q = q.strip()[:200]
    sort = sort if sort in FEED_SORTS else "time"
    direction = _dir(dir, FEED_SORTS[sort][1])
    stmt = select(Item).join(Source, Source.id == Item.source_id)
    if cat:
        stmt = stmt.where(Source.category == cat)
    if kind:
        stmt = stmt.where(Item.kind == kind)
    if source:
        stmt = stmt.where(Item.source_id == source)
    if entity:
        stmt = stmt.where(Item.id.in_(select(ItemEntity.item_id).where(ItemEntity.entity_id == entity)))
    if min_sev:
        stmt = stmt.where(Item.severity >= min_sev)
    if days:
        stmt = stmt.where(Item.published_at >= utcnow() - timedelta(days=days))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Item.title.ilike(like), Item.content.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    cols = FEED_SORTS[sort][0]()
    order = [c.asc() if direction == "asc" else c.desc() for c in cols] + [Item.id.desc()]
    items = db.execute(stmt.order_by(*order).offset((page - 1) * PAGE).limit(PAGE)).unique().scalars().all()
    sources = db.execute(select(Source).order_by(Source.category, Source.name)).scalars().all()
    ent = db.get(Entity, entity) if entity else None
    f = {"cat": cat, "kind": kind, "q": q, "source": source, "entity": entity, "min_sev": min_sev, "days": days,
         "sort": sort, "dir": direction}
    f["qs"] = _qs(cat=cat, kind=kind, q=q, source=source, entity=entity, min_sev=min_sev, days=days)
    return render(request, "feed.html", {
        "user": user, "items": items, "total": total, "page": page, "pages": max(1, -(-total // PAGE)),
        "sources": sources, "f": f, "entity": ent,
    })


@router.get("/items/{item_id}")
def item_detail(item_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    item = db.get(Item, item_id)
    if not item:
        raise HTTPException(404, "Item not found")
    ents = sorted(item.entity_links, key=lambda link: (link.entity.type, link.entity.display))
    ent_ids = [link.entity_id for link in ents]
    related = trends.correlated_items(db, item, limit=15)
    enr = {}
    if ent_ids:
        for e in db.execute(select(Enrichment).where(Enrichment.entity_id.in_(ent_ids))).scalars():
            enr.setdefault(e.entity_id, []).append(e)
    return render(request, "item.html", {"user": user, "item": item, "ents": ents, "related": related,
                                         "enr": enr, "llm_on": llm.is_configured()})


# Sortable columns of the entity lists: key -> (python sort key, default direction)
ENTITY_SORTS = {
    "name": (lambda r, t: (r[0].display or "").lower(), "asc"),
    "category": (lambda r, t: (r[0].category or "zzz", -r[1]), "asc"),
    "mentions": (lambda r, t: (r[1], r[0].mention_count), "desc"),
    "total": (lambda r, t: r[0].mention_count, "desc"),
    "sources": (lambda r, t: (r[2], r[1]), "desc"),
    "trend": (lambda r, t: (t.get(r[0].id) or {}).get("score", 0), "desc"),
    "first_seen": (lambda r, t: r[0].first_seen, "desc"),
    "last_seen": (lambda r, t: r[0].last_seen, "desc"),
}


def _entity_list(request, user, db, etype: str, title: str, category: str = "", q: str = "", days: int = 30,
                 sort: str = "mentions", direction: str = ""):
    days = _clamp(days, 1, 3650)
    q = q.strip()[:100]
    sort = sort if sort in ENTITY_SORTS else "mentions"
    direction = _dir(direction, ENTITY_SORTS[sort][1])
    since = utcnow() - timedelta(days=days)
    recent = func.count(distinct(Item.id)).filter(Item.published_at >= since)
    stmt = (
        select(Entity, recent.label("recent"), func.count(distinct(Item.source_id)).label("srcs"))
        .outerjoin(ItemEntity, ItemEntity.entity_id == Entity.id)
        .outerjoin(Item, Item.id == ItemEntity.item_id)
        .where(Entity.type == etype).group_by(Entity.id)
    )
    if category:
        stmt = stmt.where(Entity.category == category)
    if q:
        stmt = stmt.where(Entity.display.ilike(f"%{q}%"))
    rows = list(db.execute(stmt.order_by(recent.desc(), Entity.mention_count.desc()).limit(300)).all())
    trend = {t["id"]: t for t in trends.trending(db, etype, limit=500)}
    keyfn = ENTITY_SORTS[sort][0]
    rows.sort(key=lambda r: keyfn(r, trend), reverse=(direction == "desc"))
    f = {"category": category, "q": q, "days": days, "sort": sort, "dir": direction,
         "qs": _qs(category=category, q=q, days=days)}
    return render(request, "entities.html", {
        "user": user, "rows": rows, "etype": etype, "title": title, "trend": trend,
        "categories": CATEGORIES if etype == "malware" else [], "f": f,
        "cat_breakdown": trends.category_breakdown(db, days) if etype == "malware" else [],
    })


@router.get("/malware")
def malware(request: Request, category: str = "", q: str = "", days: int = 30, sort: str = "mentions", dir: str = "",
            user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _entity_list(request, user, db, "malware", "Malware families", category, q, days, sort, dir)


@router.get("/actors")
def actors(request: Request, q: str = "", days: int = 30, sort: str = "mentions", dir: str = "",
           user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _entity_list(request, user, db, "actor", "Threat actors", "", q, days, sort, dir)


@router.get("/cves")
def cves(request: Request, q: str = "", days: int = 30, sort: str = "mentions", dir: str = "",
         user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _entity_list(request, user, db, "cve", "Vulnerabilities (CVE)", "", q, days, sort, dir)


IOC_SORTS = {
    "type": (Entity.type, "asc"),
    "value": (Entity.value, "asc"),
    "verdict": (Entity.verdict, "desc"),
    "mentions": (Entity.mention_count, "desc"),
    "first_seen": (Entity.first_seen, "desc"),
    "last_seen": (Entity.last_seen, "desc"),
}


def _ioc_filter_for_entity(entity_id: int):
    """IOCs that belong to a family/actor/CVE: seen in the same items, or linked by enrichment."""
    same_items = select(ItemEntity.entity_id).where(
        ItemEntity.item_id.in_(select(ItemEntity.item_id).where(ItemEntity.entity_id == entity_id)))
    linked = select(EntityLink.dst_id).where(EntityLink.src_id == entity_id).union(
        select(EntityLink.src_id).where(EntityLink.dst_id == entity_id))
    return or_(Entity.id.in_(same_items), Entity.id.in_(linked))


@router.get("/iocs")
def iocs(request: Request, type: str = "", verdict: str = "", q: str = "", page: int = 1, entity: int = 0,
         sort: str = "last_seen", dir: str = "", user: User = Depends(current_user), db: Session = Depends(get_db)):
    sort = sort if sort in IOC_SORTS else "last_seen"
    direction = _dir(dir, IOC_SORTS[sort][1])
    q = q.strip()[:200]
    stmt = select(Entity).where(Entity.type.in_(trends.IOC_TYPES))
    if type:
        stmt = stmt.where(Entity.type == type)
    if verdict == "pending":
        stmt = stmt.where(Entity.enriched_at.is_(None))
    elif verdict:
        stmt = stmt.where(Entity.verdict == verdict)
    if q:
        stmt = stmt.where(Entity.value.ilike(f"%{q.lower()}%"))
    ent = db.get(Entity, entity) if entity else None
    if ent:
        stmt = stmt.where(_ioc_filter_for_entity(ent.id))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    page = _clamp(page, 1, 100_000)
    col = IOC_SORTS[sort][0]
    order = (col.asc() if direction == "asc" else col.desc(), Entity.id.desc())
    rows = db.execute(stmt.order_by(*order).offset((page - 1) * IOC_PAGE).limit(IOC_PAGE)).scalars().all()
    ids = [r.id for r in rows]
    fam: dict[int, dict[int, str]] = {}
    srcs: dict[int, list[tuple[str, str]]] = {}
    if ids:
        links = db.execute(
            select(EntityLink.src_id, Entity.display, Entity.id)
            .join(Entity, Entity.id == EntityLink.dst_id)
            .where(EntityLink.src_id.in_(ids), Entity.type == "malware")
        ).all()
        for src, name, fid in links:
            fam.setdefault(src, {})[fid] = name
        back = db.execute(
            select(EntityLink.dst_id, Entity.display, Entity.id)
            .join(Entity, Entity.id == EntityLink.src_id)
            .where(EntityLink.dst_id.in_(ids), Entity.type == "malware")
        ).all()
        for dst, name, fid in back:
            fam.setdefault(dst, {})[fid] = name
        # where each indicator was seen (distinct sources, most recent first)
        seen = db.execute(
            select(ItemEntity.entity_id, Source.name, Source.category, func.max(Item.published_at).label("last"))
            .join(Item, Item.id == ItemEntity.item_id).join(Source, Source.id == Item.source_id)
            .where(ItemEntity.entity_id.in_(ids)).group_by(ItemEntity.entity_id, Source.id)
            .order_by(func.max(Item.published_at).desc())
        ).all()
        for eid, name, cat, _last in seen:
            srcs.setdefault(eid, []).append((name, cat))
        # indicators that only arrived through enrichment carry the provider as their source
        prov = db.execute(select(EntityLink.src_id, EntityLink.dst_id, EntityLink.provider)
                          .where(or_(EntityLink.src_id.in_(ids), EntityLink.dst_id.in_(ids)))).all()
        for a, b, provider in prov:
            for eid in (a, b):
                if eid in ids and eid not in srcs and provider:
                    srcs.setdefault(eid, [])
                    if (provider, "intel") not in srcs[eid]:
                        srcs[eid].append((provider, "intel"))
    f = {"type": type, "verdict": verdict, "q": q, "entity": entity, "sort": sort, "dir": direction,
         "qs": _qs(type=type, verdict=verdict, q=q, entity=entity)}
    return render(request, "iocs.html", {
        "user": user, "rows": rows, "fam": fam, "srcs": srcs, "total": total, "page": page,
        "pages": max(1, -(-total // IOC_PAGE)), "f": f, "types": trends.IOC_TYPES, "entity": ent,
    })


@router.get("/entities/{entity_id}")
def entity_detail(entity_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ent = db.get(Entity, entity_id)
    if not ent:
        raise HTTPException(404, "Entity not found")
    items = db.execute(
        select(Item).join(ItemEntity, ItemEntity.item_id == Item.id).where(ItemEntity.entity_id == ent.id)
        .order_by(Item.published_at.desc()).limit(60)
    ).unique().scalars().all()
    by_source = db.execute(
        select(Source.category, Source.name, Source.id, func.count(Item.id))
        .join(Item, Item.source_id == Source.id).join(ItemEntity, ItemEntity.item_id == Item.id)
        .where(ItemEntity.entity_id == ent.id).group_by(Source.id).order_by(func.count(Item.id).desc())
    ).all()
    enrichments = db.execute(select(Enrichment).where(Enrichment.entity_id == ent.id)
                             .order_by(Enrichment.provider)).scalars().all()
    out_links = db.execute(
        select(EntityLink, Entity).join(Entity, Entity.id == EntityLink.dst_id).where(EntityLink.src_id == ent.id)
        .order_by(Entity.type).limit(300)
    ).all()
    in_links = db.execute(
        select(EntityLink, Entity).join(Entity, Entity.id == EntityLink.src_id).where(EntityLink.dst_id == ent.id)
        .order_by(Entity.type).limit(300)
    ).all()
    linked: dict[int, dict] = {}
    for link, other in list(out_links) + list(in_links):
        d = linked.setdefault(other.id, {"entity": other, "relations": set(), "providers": set()})
        d["relations"].add(link.relation)
        d["providers"].add(link.provider)
    linked_list = sorted(linked.values(), key=lambda d: (d["entity"].type != "malware",
                                                          -{"malicious": 3, "suspicious": 2}.get(d["entity"].verdict, 0),
                                                          d["entity"].type))
    is_ioc = ent.type in trends.IOC_TYPES
    co = trends.co_occurring(db, ent.id, ("malware", "actor", "cve", "technique"), 20)
    # Indicators of a family / actor / CVE: IOCs from the same items plus IOCs linked by enrichment
    indicators: dict[int, dict] = {}
    if not is_ioc:
        for c in trends.co_occurring(db, ent.id, trends.IOC_TYPES, 60):
            indicators[c["id"]] = {"id": c["id"], "type": c["type"], "name": c["name"], "verdict": c["verdict"],
                                   "enriched": True, "via": {f"{c['count']} item(s)"}}
        for d in linked_list:
            e = d["entity"]
            if e.type in trends.IOC_TYPES:
                row = indicators.setdefault(e.id, {"id": e.id, "type": e.type, "name": e.display, "verdict": e.verdict,
                                                   "enriched": bool(e.enriched_at), "via": set()})
                row["via"] |= {p for p in d["providers"] if p}
        for row in indicators.values():
            row["via"] = ", ".join(sorted(row["via"]))
    rank = {"malicious": 0, "suspicious": 1, "": 3, "unknown": 3, "clean": 4}
    indicator_list = sorted(indicators.values(), key=lambda r: (rank.get(r["verdict"] or "", 3), r["type"], r["name"]))
    ioc_total = 0
    if not is_ioc:
        ioc_total = db.scalar(select(func.count(Entity.id)).where(Entity.type.in_(trends.IOC_TYPES),
                                                                   _ioc_filter_for_entity(ent.id))) or 0
    watching = db.execute(select(Watch).where(Watch.user_id == user.id, Watch.entity_id == ent.id)).scalar_one_or_none()
    return render(request, "entity.html", {
        "user": user, "ent": ent, "items": items, "by_source": by_source, "enrichments": enrichments,
        "linked": [d for d in linked_list if d["entity"].type not in trends.IOC_TYPES or is_ioc],
        "co": co, "indicators": indicator_list[:40], "ioc_total": ioc_total, "llm_on": llm.is_configured(),
        "watching": bool(watching), "is_ioc": is_ioc,
    })


@router.get("/insights")
def insights(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.execute(select(Insight).order_by(Insight.created_at.desc()).limit(50)).scalars().all()
    return render(request, "insights.html", {"user": user, "rows": rows, "llm_on": llm.is_configured(),
                                             "provider": llm.provider(), "model": llm.model_name()})


@router.get("/watchlist")
def watchlist(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.execute(select(Watch).where(Watch.user_id == user.id).order_by(Watch.created_at.desc())).scalars().all()
    ids = [w.entity_id for w in rows]
    latest: dict[int, list[Item]] = {eid: [] for eid in ids}
    if ids:
        # one query for every watched entity, newest first; keep the first 3 per entity
        rows_q = db.execute(
            select(ItemEntity.entity_id, Item).join(Item, Item.id == ItemEntity.item_id)
            .where(ItemEntity.entity_id.in_(ids)).order_by(Item.published_at.desc()).limit(60 * max(1, len(ids)))
        ).unique().all()
        for eid, item in rows_q:
            if len(latest[eid]) < 3:
                latest[eid].append(item)
    return render(request, "watchlist.html", {"user": user, "rows": rows, "latest": latest})
