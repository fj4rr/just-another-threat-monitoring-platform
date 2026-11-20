"""Aggregations behind the scam & fraud dashboard (0.10). Same item and entity tables as the threat dashboard,
limited to scam reports (``items.fraud_score > 0``) and to the period the dashboard shows."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from ..models import Entity, Item, ItemEntity, utcnow
from . import fraud
from .geo import scoped
from .trends import STORY, _series, buckets, n_stories

FRAUD = Item.fraud_score > 0


def _since(days: int):
    return utcnow() - timedelta(days=days)


def fraud_items(region: str):
    return scoped(select(Item).where(FRAUD), region)


def _count(db: Session, stmt) -> int:
    """Rows ``stmt`` selects (list pagination)."""
    return db.scalar(select(func.count()).select_from(stmt.subquery())) or 0


def _stories(db: Session, stmt) -> int:
    """Stories among the items ``stmt`` selects (syndicated copies once: the counting rule in trends)."""
    sub = stmt.subquery()
    return db.scalar(select(func.count(distinct(func.coalesce(sub.c.dup_of, sub.c.id))))) or 0


def type_counts(db: Session, etype: str, region: str, lo, hi=None) -> dict[int, int]:
    """Scam reports per entity of ``etype`` published in (lo, hi]."""
    q = (select(Entity.id, n_stories())
         .join(ItemEntity, ItemEntity.entity_id == Entity.id).join(Item, Item.id == ItemEntity.item_id)
         .where(Entity.type == etype, Item.published_at > lo))
    if hi is not None:
        q = q.where(Item.published_at <= hi)
    return dict(db.execute(scoped(q, region).group_by(Entity.id)).all())


def scam_type_table(db: Session, region: str, days: int = 7) -> list[dict]:
    """Every scam type reported in the period, with the period before it and the spread velocity (7-day rule)."""
    now = utcnow()
    cur = type_counts(db, "scam_type", region, now - timedelta(days=days))
    prev = type_counts(db, "scam_type", region, now - timedelta(days=2 * days), now - timedelta(days=days))
    week = cur if days == 7 else type_counts(db, "scam_type", region, now - timedelta(days=7))
    week_prev = prev if days == 7 else type_counts(db, "scam_type", region, now - timedelta(days=14),
                                                  now - timedelta(days=7))
    ents = {e.id: e for e in db.execute(select(Entity).where(Entity.type == "scam_type")).scalars()}
    rows = []
    for eid, n in cur.items():
        e = ents.get(eid)
        if not e:
            continue
        w, p = week.get(eid, 0), week_prev.get(eid, 0)
        # same rule as the "spreading" part of the fraud score; "Other scam" is a catch-all, not one scam
        spreading = e.value != "other" and w >= fraud.VELOCITY_MIN and w >= 2 * max(1, p)
        rows.append({"entity": e, "count": n, "prev": prev.get(eid, 0), "week": w, "week_prev": p,
                     "spreading": spreading})
    rows.sort(key=lambda r: (-r["count"], -r["week"]))
    return rows


def top_entities(db: Session, etype: str, region: str, days: int = 30, limit: int = 12) -> list[dict]:
    counts = type_counts(db, etype, region, _since(days))
    if not counts:
        return []
    ents = {e.id: e for e in db.execute(select(Entity).where(Entity.id.in_(list(counts)))).scalars()}
    out = [{"entity": ents[i], "count": n} for i, n in counts.items() if i in ents]
    out.sort(key=lambda r: -r["count"])
    return out[:limit]


def _distinct_entities(db: Session, types, region: str, lo, hi=None) -> int:
    q = (select(func.count(distinct(Entity.id))).select_from(Item)
         .join(ItemEntity, ItemEntity.item_id == Item.id).join(Entity, Entity.id == ItemEntity.entity_id)
         .where(Entity.type.in_(types), Item.published_at >= lo))
    if hi is not None:
        q = q.where(Item.published_at < hi)
    return db.scalar(scoped(q, region)) or 0


def kpis(db: Session, region: str, days: int = 7) -> dict:
    now = utcnow()
    since, prev_since = now - timedelta(days=days), now - timedelta(days=2 * days)
    base = fraud_items(region)
    reports = _stories(db, base.where(Item.published_at >= since))
    prev = _stories(db, base.where(Item.published_at >= prev_since, Item.published_at < since))
    period = base.where(Item.published_at >= since).subquery()
    loss = db.scalar(select(func.max(period.c.fraud_loss_idr))) or 0
    with_loss = db.scalar(select(func.count(distinct(func.coalesce(period.c.dup_of, period.c.id))))
                          .where(period.c.fraud_loss_idr > 0)) or 0
    victims = db.scalar(select(func.max(period.c.fraud_victims))) or 0
    types = scam_type_table(db, region, days)
    return {
        "days": days, "reports": reports, "prev": prev, "loss": loss, "with_loss": with_loss, "victims": victims,
        "scam_types": len(types), "spreading": sum(1 for t in types if t["spreading"]),
        "brands": _distinct_entities(db, ("brand",), region, since),
        "brands_prev": _distinct_entities(db, ("brand",), region, prev_since, since),
        "identifiers": _distinct_entities(db, fraud.IDENT_TYPES, region, since),
        "identifiers_prev": _distinct_entities(db, fraud.IDENT_TYPES, region, prev_since, since),
    }


def kpi_series(db: Session, days: int, region: str) -> dict:
    """Daily (weekly) values behind the scam dashboard tiles."""
    since = _since(days)
    labels, step, key = buckets(days)
    day = func.date(Item.published_at)

    def per_day(q) -> list[int]:
        return _series(db.execute(scoped(q, region)).all(), labels, key)

    ents = (select(day, func.count(distinct(Entity.id))).select_from(Item)
            .join(ItemEntity, ItemEntity.item_id == Item.id).join(Entity, Entity.id == ItemEntity.entity_id)
            .where(FRAUD, Item.published_at >= since))
    return {
        "labels": labels, "step": step,
        "reports": per_day(select(day, n_stories()).where(FRAUD, Item.published_at >= since).group_by(day)),
        "losses": per_day(select(day, n_stories()).where(FRAUD, Item.fraud_loss_idr > 0,
                                                                  Item.published_at >= since).group_by(day)),
        "scam_types": per_day(ents.where(Entity.type == "scam_type").group_by(day)),
        "brands": per_day(ents.where(Entity.type == "brand").group_by(day)),
        "identifiers": per_day(ents.where(Entity.type.in_(fraud.IDENT_TYPES)).group_by(day)),
    }


def timeline(db: Session, days: int, region: str, top: int = 5) -> dict:
    """Scam reports per day (week) for the ``top`` scam types of the period, the rest as "Other scam types".
    An item with two scam types counts for its strongest one (the first in its fraud reasons)."""
    since = _since(days)
    labels, step, key = buckets(days)
    day = func.date(Item.published_at)
    rows = db.execute(scoped(
        select(STORY, day, Entity.value, Entity.display)
        .join(ItemEntity, ItemEntity.item_id == Item.id).join(Entity, Entity.id == ItemEntity.entity_id)
        .where(FRAUD, Entity.type == "scam_type", Item.published_at >= since), region)).all()
    names = {v: d for _, _, v, d in rows}
    per_item: dict[int, tuple] = {}
    for iid, d, value, _ in rows:  # strongest scam type of the item: the heaviest in the taxonomy
        w = next((wt for k, _, wt, *_ in fraud.SCAM_TYPES if k == value), fraud.OTHER[2])
        if iid not in per_item or w > per_item[iid][2]:
            per_item[iid] = (d, value, w)
    totals: dict[str, int] = defaultdict(int)
    for _, value, _ in per_item.values():
        totals[value] += 1
    keep = [v for v, _ in sorted(totals.items(), key=lambda kv: -kv[1]) if v != "other"][:top]
    series: dict[str, list] = defaultdict(list)
    for d, value, _ in per_item.values():
        series[value if value in keep else "_rest"].append((d, 1))
    out = [{"key": v, "name": names.get(v, v), "data": _series(series[v], labels, key)} for v in keep]
    if series.get("_rest"):
        out.append({"key": "_rest", "name": "Other scam types", "data": _series(series["_rest"], labels, key)})
    return {"labels": labels, "step": step, "series": out}


def scam_type_breakdown(db: Session, days: int, region: str) -> list[dict]:
    counts = type_counts(db, "scam_type", region, _since(days))
    ents = {e.id: e for e in db.execute(select(Entity).where(Entity.id.in_(list(counts) or [0]))).scalars()}
    out = [{"id": i, "category": ents[i].value, "label": ents[i].display, "count": n}
           for i, n in counts.items() if i in ents]
    return sorted(out, key=lambda r: (r["category"] == "other", -r["count"]))


BRAND_CATEGORY_LABELS = {"bank": "Banks", "ewallet": "E-wallets", "payment": "Payments", "marketplace": "Marketplaces",
                         "app": "Super apps", "courier": "Couriers", "telco": "Telecoms", "utility": "Utilities",
                         "government": "Government", "platform": "Platforms", "crypto": "Crypto exchanges",
                         "person": "People"}


def brand_category_breakdown(db: Session, days: int, region: str) -> list[dict]:
    """Scam reports per kind of impersonated brand (bank, e-wallet, courier, government…)."""
    rows = db.execute(scoped(
        select(Entity.category, n_stories())
        .join(ItemEntity, ItemEntity.entity_id == Entity.id).join(Item, Item.id == ItemEntity.item_id)
        .where(Entity.type == "brand", Item.published_at >= _since(days)), region)
        .group_by(Entity.category)).all()
    out = [{"category": c or "other", "label": BRAND_CATEGORY_LABELS.get(c or "", (c or "other").title()), "count": n}
           for c, n in rows]
    return sorted(out, key=lambda r: -r["count"])
