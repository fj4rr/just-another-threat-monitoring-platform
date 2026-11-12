from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import distinct, func, or_, select
from sqlalchemy.orm import Session

from ..auth import current_user
from ..db import get_db
from ..knowledge import CATEGORIES
from ..llm import client as llm
from ..models import (
    Enrichment, Entity, EntityLink, Insight, Item, ItemEntity, Source, User, Watch, utcnow,
)
from ..processing import trends
from ..web import render

router = APIRouter()
PAGE = 40


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


@router.get("/feed")
def feed(request: Request, cat: str = "", kind: str = "", q: str = "", source: int = 0, entity: int = 0,
         min_sev: int = 0, days: int = 30, page: int = 1, user: User = Depends(current_user),
         db: Session = Depends(get_db)):
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
    page = max(1, page)
    items = db.execute(stmt.order_by(Item.published_at.desc()).offset((page - 1) * PAGE).limit(PAGE)).unique().scalars().all()
    sources = db.execute(select(Source).order_by(Source.category, Source.name)).scalars().all()
    ent = db.get(Entity, entity) if entity else None
    return render(request, "feed.html", {
        "user": user, "items": items, "total": total, "page": page, "pages": max(1, -(-total // PAGE)),
        "sources": sources, "f": {"cat": cat, "kind": kind, "q": q, "source": source, "entity": entity,
                                  "min_sev": min_sev, "days": days}, "entity": ent,
    })


@router.get("/items/{item_id}")
def item_detail(item_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    item = db.get(Item, item_id)
    if not item:
        raise HTTPException(404, "Item not found")
    ents = sorted((l for l in item.entity_links), key=lambda l: (l.entity.type, l.entity.display))
    ent_ids = [l.entity_id for l in ents]
    related = []
    if ent_ids:
        # items in OTHER sources sharing entities – the cross-source correlation view
        rows = db.execute(
            select(Item, func.count(distinct(ItemEntity.entity_id)).label("shared"))
            .join(ItemEntity, ItemEntity.item_id == Item.id)
            .where(ItemEntity.entity_id.in_(ent_ids), Item.id != item.id)
            .group_by(Item.id).order_by(func.count(distinct(ItemEntity.entity_id)).desc(), Item.published_at.desc())
            .limit(15)
        ).unique().all()
        related = [(r[0], r[1]) for r in rows]
    enr = {}
    if ent_ids:
        for e in db.execute(select(Enrichment).where(Enrichment.entity_id.in_(ent_ids))).scalars():
            enr.setdefault(e.entity_id, []).append(e)
    return render(request, "item.html", {"user": user, "item": item, "ents": ents, "related": related,
                                         "enr": enr, "llm_on": llm.is_configured()})


def _entity_list(request, user, db, etype: str, title: str, category: str = "", q: str = "", days: int = 30):
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
    rows = db.execute(stmt.order_by(recent.desc(), Entity.mention_count.desc()).limit(300)).all()
    trend = {t["id"]: t for t in trends.trending(db, etype, limit=500)}
    return render(request, "entities.html", {
        "user": user, "rows": rows, "etype": etype, "title": title, "trend": trend,
        "categories": CATEGORIES if etype == "malware" else [], "f": {"category": category, "q": q, "days": days},
        "cat_breakdown": trends.category_breakdown(db, days) if etype == "malware" else [],
    })


@router.get("/malware")
def malware(request: Request, category: str = "", q: str = "", days: int = 30,
            user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _entity_list(request, user, db, "malware", "Malware families", category, q, days)


@router.get("/actors")
def actors(request: Request, q: str = "", days: int = 30, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _entity_list(request, user, db, "actor", "Threat actors", "", q, days)


@router.get("/cves")
def cves(request: Request, q: str = "", days: int = 30, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _entity_list(request, user, db, "cve", "Vulnerabilities (CVE)", "", q, days)


@router.get("/iocs")
def iocs(request: Request, type: str = "", verdict: str = "", q: str = "", page: int = 1,
         user: User = Depends(current_user), db: Session = Depends(get_db)):
    stmt = select(Entity).where(Entity.type.in_(trends.IOC_TYPES))
    if type:
        stmt = stmt.where(Entity.type == type)
    if verdict == "pending":
        stmt = stmt.where(Entity.enriched_at.is_(None))
    elif verdict:
        stmt = stmt.where(Entity.verdict == verdict)
    if q:
        stmt = stmt.where(Entity.value.ilike(f"%{q.lower()}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    page = max(1, page)
    rows = db.execute(stmt.order_by(Entity.last_seen.desc()).offset((page - 1) * 60).limit(60)).scalars().all()
    # attributed families for display
    fam = {}
    if rows:
        links = db.execute(
            select(EntityLink.src_id, Entity.display, Entity.id)
            .join(Entity, Entity.id == EntityLink.dst_id)
            .where(EntityLink.src_id.in_([r.id for r in rows]), Entity.type == "malware")
        ).all()
        for src, name, fid in links:
            fam.setdefault(src, {})[fid] = name
        back = db.execute(
            select(EntityLink.dst_id, Entity.display, Entity.id)
            .join(Entity, Entity.id == EntityLink.src_id)
            .where(EntityLink.dst_id.in_([r.id for r in rows]), Entity.type == "malware")
        ).all()
        for dst, name, fid in back:
            fam.setdefault(dst, {})[fid] = name
    return render(request, "iocs.html", {
        "user": user, "rows": rows, "fam": fam, "total": total, "page": page, "pages": max(1, -(-total // 60)),
        "f": {"type": type, "verdict": verdict, "q": q}, "types": trends.IOC_TYPES,
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
        select(Source.category, Source.name, func.count(Item.id))
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
    co = trends.co_occurring(db, ent.id, ("malware", "actor", "cve", "technique"), 20)
    co_iocs = trends.co_occurring(db, ent.id, trends.IOC_TYPES, 40)
    watching = db.execute(select(Watch).where(Watch.user_id == user.id, Watch.entity_id == ent.id)).scalar_one_or_none()
    return render(request, "entity.html", {
        "user": user, "ent": ent, "items": items, "by_source": by_source, "enrichments": enrichments,
        "linked": linked_list, "co": co, "co_iocs": co_iocs, "llm_on": llm.is_configured(),
        "watching": bool(watching), "is_ioc": ent.type in trends.IOC_TYPES,
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
    latest = {}
    for eid in ids:
        latest[eid] = db.execute(
            select(Item).join(ItemEntity, ItemEntity.item_id == Item.id).where(ItemEntity.entity_id == eid)
            .order_by(Item.published_at.desc()).limit(3)).unique().scalars().all()
    return render(request, "watchlist.html", {"user": user, "rows": rows, "latest": latest})
