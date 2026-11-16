"""Scam & fraud section (0.9): overview, scam reports, scam types, impersonated brands, scammer identifiers.

Same items, entities and International / National switch as the rest of JATMP; only the lens differs.
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy import distinct, func, or_, select
from sqlalchemy.orm import Session

from .. import settings
from ..auth import current_user
from ..db import get_db
from ..models import Entity, Item, ItemEntity, Source, User, utcnow
from ..processing import fraud, geo, trends
from ..search import item_text_clause
from ..web import current_region, render
from .pages import _clamp, _dir, _entity_list, _keep, _qs, related_chips

router = APIRouter(prefix="/fraud")
PAGE = 40
IDENT_PAGE = 60
BRAND_CATEGORIES = sorted({c for _, c, _, _ in fraud.BRANDS})


def _since(days: int):
    return utcnow() - timedelta(days=days)


def _fraud_items(region: str):
    return geo.scoped(select(Item).where(Item.fraud_score > 0), region)


def _count(db: Session, stmt) -> int:
    return db.scalar(select(func.count()).select_from(stmt.subquery())) or 0


def _type_counts(db: Session, etype: str, region: str, lo, hi=None) -> dict[int, int]:
    q = (select(Entity.id, func.count(distinct(Item.id)))
         .join(ItemEntity, ItemEntity.entity_id == Entity.id).join(Item, Item.id == ItemEntity.item_id)
         .where(Entity.type == etype, Item.published_at > lo))
    if hi is not None:
        q = q.where(Item.published_at <= hi)
    return dict(db.execute(geo.scoped(q, region).group_by(Entity.id)).all())


def scam_type_table(db: Session, region: str) -> list[dict]:
    """Every scam type with reports this week, the week before and in 30 days, plus the spread velocity."""
    now = utcnow()
    week = _type_counts(db, "scam_type", region, now - timedelta(days=7))
    prev = _type_counts(db, "scam_type", region, now - timedelta(days=14), now - timedelta(days=7))
    month = _type_counts(db, "scam_type", region, now - timedelta(days=30))
    ents = {e.id: e for e in db.execute(select(Entity).where(Entity.type == "scam_type")).scalars()}
    rows = []
    for eid, n30 in month.items():
        e = ents.get(eid)
        if not e:
            continue
        w, p = week.get(eid, 0), prev.get(eid, 0)
        # same rule as the "spreading" part of the fraud score; "Other scam" is a catch-all, not one scam
        spreading = e.value != "other" and w >= fraud.VELOCITY_MIN and w >= 2 * max(1, p)
        rows.append({"entity": e, "week": w, "prev": p, "month": n30, "spreading": spreading})
    rows.sort(key=lambda r: (-r["week"], -r["month"]))
    related = related_chips(db, [r["entity"].id for r in rows], ("malware", "brand"), per=5)
    for r in rows:
        r["related"] = related.get(r["entity"].id, [])
    return rows


def top_entities(db: Session, etype: str, region: str, days: int = 30, limit: int = 12) -> list[dict]:
    counts = _type_counts(db, etype, region, _since(days))
    if not counts:
        return []
    ents = {e.id: e for e in db.execute(select(Entity).where(Entity.id.in_(list(counts)))).scalars()}
    out = [{"entity": ents[i], "count": n} for i, n in counts.items() if i in ents]
    out.sort(key=lambda r: -r["count"])
    return out[:limit]


def kpis(db: Session, region: str) -> dict:
    now = utcnow()
    base = _fraud_items(region)
    week = _count(db, base.where(Item.published_at >= now - timedelta(days=7)))
    prev = _count(db, base.where(Item.published_at >= now - timedelta(days=14), Item.published_at < now - timedelta(days=7)))
    month = base.where(Item.published_at >= now - timedelta(days=30)).subquery()
    loss = db.scalar(select(func.max(month.c.fraud_loss_idr))) or 0
    with_loss = db.scalar(select(func.count()).select_from(month).where(month.c.fraud_loss_idr > 0)) or 0
    victims = db.scalar(select(func.max(month.c.fraud_victims))) or 0

    def distinct_entities(types) -> int:
        q = (select(func.count(distinct(Entity.id))).select_from(Item)
             .join(ItemEntity, ItemEntity.item_id == Item.id).join(Entity, Entity.id == ItemEntity.entity_id)
             .where(Entity.type.in_(types), Item.published_at >= now - timedelta(days=30)))
        return db.scalar(geo.scoped(q, region)) or 0

    return {"week": week, "prev": prev, "loss": loss, "with_loss": with_loss, "victims": victims,
            "brands": distinct_entities(("brand",)), "identifiers": distinct_entities(fraud.IDENT_TYPES)}


@router.get("")
def overview(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db),
             region: str = Depends(current_region)):
    now = utcnow()
    recent = db.execute(_fraud_items(region).where(Item.published_at >= now - timedelta(days=30))
                        .order_by(Item.published_at.desc()).limit(12)).unique().scalars().all()
    top = db.execute(_fraud_items(region).where(Item.published_at >= now - timedelta(days=30))
                     .order_by(Item.fraud_score.desc(), Item.published_at.desc()).limit(8)).unique().scalars().all()
    idents = db.execute(
        geo.scoped(select(Entity, func.max(Item.published_at).label("last"))
                   .join(ItemEntity, ItemEntity.entity_id == Entity.id).join(Item, Item.id == ItemEntity.item_id)
                   .where(Entity.type.in_(fraud.IDENT_TYPES)), region)
        .group_by(Entity.id).order_by(func.max(Item.published_at).desc()).limit(10)).all()
    sources = db.execute(select(Source).where(Source.topic == "fraud").order_by(Source.name)).scalars().all()
    return render(request, "fraud.html", {
        "user": user, "section": "overview", "k": kpis(db, region), "types": scam_type_table(db, region),
        "brands": top_entities(db, "brand", region), "recent": recent, "top": top, "idents": idents,
        "sources": sources, "labels": fraud.IDENT_LABELS,
    })


ITEM_SORTS = {
    "score": (lambda: (Item.fraud_score, Item.published_at), "desc"),
    "time": (lambda: (Item.published_at,), "desc"),
    "loss": (lambda: (Item.fraud_loss_idr, Item.published_at), "desc"),
    "victims": (lambda: (Item.fraud_victims, Item.published_at), "desc"),
    "title": (lambda: (func.lower(Item.title),), "asc"),
}


@router.get("/items")
def items(request: Request, q: str = "", scam: int = 0, brand: int = 0, min_score: int = 0, days: int = 30,
          page: int = 1, sort: str = "time", dir: str = "", user: User = Depends(current_user),
          db: Session = Depends(get_db), region: str = Depends(current_region)):
    days, min_score, page = _clamp(days, 0, 3650), _clamp(min_score, 0, 100), _clamp(page, 1, 100_000)
    q = q.strip()[:200]
    sort = sort if sort in ITEM_SORTS else "time"
    direction = _dir(dir, ITEM_SORTS[sort][1])
    stmt = _fraud_items(region)
    for eid in (scam, brand):
        if eid:
            stmt = stmt.where(Item.id.in_(select(ItemEntity.item_id).where(ItemEntity.entity_id == eid)))
    if min_score:
        stmt = stmt.where(Item.fraud_score >= min_score)
    if days:
        stmt = stmt.where(Item.published_at >= _since(days))
    if q:
        stmt = stmt.where(item_text_clause(q))
    total = _count(db, stmt)
    cols = ITEM_SORTS[sort][0]()
    order = [c.asc() if direction == "asc" else c.desc() for c in cols] + [Item.id.desc()]
    rows = db.execute(stmt.order_by(*order).offset((page - 1) * PAGE).limit(PAGE)).unique().scalars().all()
    scam_types = db.execute(select(Entity).where(Entity.type == "scam_type").order_by(Entity.display)).scalars().all()
    brand_list = db.execute(select(Entity).where(Entity.type == "brand").order_by(Entity.display)).scalars().all()
    f = {"q": q, "scam": scam, "brand": brand, "min_score": min_score, "days": days, "sort": sort, "dir": direction,
         "qs": _qs(q=q, scam=scam, brand=brand, min_score=min_score, days=_keep(days))}
    return render(request, "fraud_items.html", {
        "user": user, "section": "items", "items": rows, "total": total, "page": page,
        "pages": max(1, -(-total // PAGE)), "f": f, "scam_types": scam_types, "brand_list": brand_list,
        "targets": geo.targets_for(db, [i.id for i in rows]),
    })


@router.get("/scams")
def scams(request: Request, q: str = "", days: int = 30, sort: str = "mentions", dir: str = "", page: int = 1,
          user: User = Depends(current_user), db: Session = Depends(get_db), region: str = Depends(current_region)):
    return _entity_list(request, user, db, "scam_type", "Scam types", "", q, days, sort, dir, page, region,
                        related_types=("malware", "brand"), categories=[], section="scams")


@router.get("/brands")
def brands(request: Request, category: str = "", q: str = "", days: int = 30, sort: str = "mentions", dir: str = "",
           page: int = 1, user: User = Depends(current_user), db: Session = Depends(get_db),
           region: str = Depends(current_region)):
    category = category if category in BRAND_CATEGORIES else ""
    return _entity_list(request, user, db, "brand", "Impersonated brands", category, q, days, sort, dir, page, region,
                        related_types=("scam_type", "malware"), categories=BRAND_CATEGORIES, section="brands")


IDENT_SORTS = {
    "type": (Entity.type, "asc"),
    "value": (Entity.value, "asc"),
    "mentions": (Entity.mention_count, "desc"),
    "first_seen": (Entity.first_seen, "desc"),
    "last_seen": (Entity.last_seen, "desc"),
}


@router.get("/identifiers")
def identifiers(request: Request, type: str = "", q: str = "", days: int = 0, page: int = 1, sort: str = "last_seen",
                dir: str = "", user: User = Depends(current_user), db: Session = Depends(get_db),
                region: str = Depends(current_region)):
    days, page = _clamp(days, 0, 3650), _clamp(page, 1, 100_000)
    type = type if type in fraud.IDENT_TYPES else ""
    q = q.strip()[:100]
    sort = sort if sort in IDENT_SORTS else "last_seen"
    direction = _dir(dir, IDENT_SORTS[sort][1])
    stmt = select(Entity).where(Entity.type.in_((type,) if type else fraud.IDENT_TYPES))
    if q:
        digits = "".join(ch for ch in q if ch.isdigit())
        stmt = stmt.where(or_(Entity.value.ilike(f"%{q.lower()}%"), Entity.display.ilike(f"%{q}%"),
                              *([Entity.value.ilike(f"%{digits[-8:]}%")] if len(digits) >= 6 else [])))
    if days:
        stmt = stmt.where(Entity.last_seen >= _since(days))
    in_region = trends._entities_in_region(region)
    if in_region is not None:
        stmt = stmt.where(in_region)
    total = _count(db, stmt)
    col = IDENT_SORTS[sort][0]
    rows = db.execute(stmt.order_by(col.asc() if direction == "asc" else col.desc(), Entity.id.desc())
                      .offset((page - 1) * IDENT_PAGE).limit(IDENT_PAGE)).scalars().all()
    ids = [e.id for e in rows]
    related = related_chips(db, ids, ("scam_type", "brand"), per=4)
    seen: dict[int, list[str]] = {}
    if ids:
        for eid, name in db.execute(
                select(ItemEntity.entity_id, Source.name).join(Item, Item.id == ItemEntity.item_id)
                .join(Source, Source.id == Item.source_id).where(ItemEntity.entity_id.in_(ids))
                .group_by(ItemEntity.entity_id, Source.id)).all():
            seen.setdefault(eid, []).append(name)
    f = {"type": type, "q": q, "days": days, "sort": sort, "dir": direction,
         "qs": _qs(type=type, q=q, days=days)}
    return render(request, "fraud_identifiers.html", {
        "user": user, "section": "identifiers", "rows": rows, "total": total, "page": page,
        "pages": max(1, -(-total // IDENT_PAGE)), "f": f, "related": related, "seen": seen,
        "labels": fraud.IDENT_LABELS, "links": {e.id: fraud.check_links(e) for e in rows},
        "retention": settings.get("fraud_identifier_days"),
    })
