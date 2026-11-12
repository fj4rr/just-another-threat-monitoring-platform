"""Aggregations used by the dashboard and the LLM digest."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import and_, distinct, func, select
from sqlalchemy.orm import Session

from ..models import Entity, Item, ItemEntity, Source, utcnow

IOC_TYPES = ("md5", "sha1", "sha256", "ip", "domain", "url")


def _since(days: int) -> datetime:
    return utcnow() - timedelta(days=days)


def overview(db: Session, days: int = 7) -> dict:
    since = _since(days)
    prev = _since(days * 2)
    items_now = db.scalar(select(func.count(Item.id)).where(Item.published_at >= since)) or 0
    items_prev = db.scalar(
        select(func.count(Item.id)).where(Item.published_at >= prev, Item.published_at < since)) or 0
    new_fams = db.scalar(
        select(func.count(Entity.id)).where(Entity.type == "malware", Entity.first_seen >= since)) or 0
    active_fams = db.scalar(
        select(func.count(distinct(Entity.id)))
        .join(ItemEntity, ItemEntity.entity_id == Entity.id)
        .join(Item, Item.id == ItemEntity.item_id)
        .where(Entity.type == "malware", Item.published_at >= since)) or 0
    iocs = db.scalar(
        select(func.count(Entity.id)).where(Entity.type.in_(IOC_TYPES), Entity.last_seen >= since)) or 0
    malicious = db.scalar(
        select(func.count(Entity.id)).where(Entity.type.in_(IOC_TYPES), Entity.verdict == "malicious",
                                            Entity.last_seen >= since)) or 0
    cves = db.scalar(
        select(func.count(distinct(Entity.id)))
        .join(ItemEntity, ItemEntity.entity_id == Entity.id)
        .join(Item, Item.id == ItemEntity.item_id)
        .where(Entity.type == "cve", Item.published_at >= since)) or 0
    sources_ok = db.scalar(select(func.count(Source.id)).where(Source.enabled, Source.last_status == "ok")) or 0
    sources_total = db.scalar(select(func.count(Source.id)).where(Source.enabled)) or 0
    return {
        "items": items_now, "items_prev": items_prev, "active_families": active_fams,
        "new_families": new_fams, "iocs": iocs, "malicious_iocs": malicious, "cves": cves,
        "sources_ok": sources_ok, "sources_total": sources_total, "days": days,
    }


def timeline(db: Session, days: int = 30) -> dict:
    """Daily item counts split by source category."""
    since = _since(days)
    day = func.date(Item.published_at)
    rows = db.execute(
        select(day, Source.category, func.count(Item.id))
        .join(Source, Source.id == Item.source_id)
        .where(Item.published_at >= since)
        .group_by(day, Source.category)
    ).all()
    labels = [(since + timedelta(days=i + 1)).strftime("%Y-%m-%d") for i in range(days)]
    series: dict[str, dict[str, int]] = defaultdict(dict)
    for d, cat, n in rows:
        series[cat][str(d)] = n
    return {"labels": labels,
            "series": {cat: [series[cat].get(lbl, 0) for lbl in labels] for cat in ("news", "social", "intel")}}


def family_timeline(db: Session, entity_ids: list[int], days: int = 30) -> dict:
    since = _since(days)
    day = func.date(Item.published_at)
    rows = db.execute(
        select(ItemEntity.entity_id, day, func.count(Item.id))
        .join(Item, Item.id == ItemEntity.item_id)
        .where(ItemEntity.entity_id.in_(entity_ids), Item.published_at >= since)
        .group_by(ItemEntity.entity_id, day)
    ).all()
    labels = [(since + timedelta(days=i + 1)).strftime("%Y-%m-%d") for i in range(days)]
    m: dict[int, dict[str, int]] = defaultdict(dict)
    for eid, d, n in rows:
        m[eid][str(d)] = n
    return {"labels": labels, "series": {eid: [m[eid].get(lbl, 0) for lbl in labels] for eid in entity_ids}}


def top_entities(db: Session, etype: str, days: int = 7, limit: int = 10, category: str | None = None) -> list[dict]:
    since = _since(days)
    q = (
        select(Entity.id, Entity.display, Entity.category, func.count(distinct(Item.id)).label("n"),
               func.count(distinct(Item.source_id)).label("srcs"))
        .join(ItemEntity, ItemEntity.entity_id == Entity.id)
        .join(Item, Item.id == ItemEntity.item_id)
        .where(Entity.type == etype, Item.published_at >= since)
        .group_by(Entity.id).order_by(func.count(distinct(Item.id)).desc()).limit(limit)
    )
    if category:
        q = q.where(Entity.category == category)
    return [{"id": i, "name": d, "category": c, "count": n, "sources": s} for i, d, c, n, s in db.execute(q)]


def category_breakdown(db: Session, days: int = 30) -> list[dict]:
    since = _since(days)
    rows = db.execute(
        select(Entity.category, func.count(distinct(Item.id)))
        .join(ItemEntity, ItemEntity.entity_id == Entity.id)
        .join(Item, Item.id == ItemEntity.item_id)
        .where(Entity.type == "malware", Item.published_at >= since)
        .group_by(Entity.category).order_by(func.count(distinct(Item.id)).desc())
    ).all()
    return [{"category": c or "other", "count": n} for c, n in rows]


def source_breakdown(db: Session, days: int = 7) -> list[dict]:
    since = _since(days)
    rows = db.execute(
        select(Source.name, Source.category, func.count(Item.id))
        .join(Item, Item.source_id == Source.id)
        .where(Item.published_at >= since)
        .group_by(Source.id).order_by(func.count(Item.id).desc())
    ).all()
    return [{"name": n, "category": c, "count": k} for n, c, k in rows]


def ioc_breakdown(db: Session, days: int = 30) -> list[dict]:
    since = _since(days)
    rows = db.execute(
        select(Entity.type, Entity.verdict, func.count(Entity.id))
        .where(Entity.type.in_(IOC_TYPES), Entity.last_seen >= since)
        .group_by(Entity.type, Entity.verdict)
    ).all()
    out: dict[str, dict] = {}
    for t, v, n in rows:
        d = out.setdefault(t, {"type": t, "malicious": 0, "suspicious": 0, "other": 0})
        key = v if v in ("malicious", "suspicious") else "other"
        d[key] += n
    return sorted(out.values(), key=lambda d: -(d["malicious"] + d["suspicious"] + d["other"]))


def trending(db: Session, etype: str = "malware", limit: int = 10, window: int = 7, baseline: int = 30) -> list[dict]:
    """Trend score = recent mention rate vs. baseline rate, weighted by cross-source spread.
    New entities (first seen inside the window) get flagged."""
    now = utcnow()
    w_start, b_start = now - timedelta(days=window), now - timedelta(days=window + baseline)
    recent = func.count(distinct(Item.id)).filter(Item.published_at >= w_start)
    base = func.count(distinct(Item.id)).filter(and_(Item.published_at >= b_start, Item.published_at < w_start))
    srcs = func.count(distinct(Item.source_id)).filter(Item.published_at >= w_start)
    cats = func.count(distinct(Source.category)).filter(Item.published_at >= w_start)
    rows = db.execute(
        select(Entity.id, Entity.display, Entity.category, Entity.first_seen, recent, base, srcs, cats)
        .join(ItemEntity, ItemEntity.entity_id == Entity.id)
        .join(Item, Item.id == ItemEntity.item_id)
        .join(Source, Source.id == Item.source_id)
        .where(Entity.type == etype, Item.published_at >= b_start)
        .group_by(Entity.id)
    ).all()
    out = []
    for eid, name, cat, first_seen, r, b, s, c in rows:
        if not r:
            continue
        rate_recent = r / window
        rate_base = (b / baseline) if b else 0.0
        growth = (rate_recent + 0.1) / (rate_base + 0.1)
        score = round(r * min(growth, 10) ** 0.5 * (1 + 0.25 * (s - 1)) * (1 + 0.2 * (c - 1)), 2)
        out.append({
            "id": eid, "name": name, "category": cat, "recent": r, "baseline": b,
            "sources": s, "source_types": c, "growth": round(growth, 2), "score": score,
            "is_new": bool(first_seen and first_seen >= w_start),
        })
    out.sort(key=lambda d: -d["score"])
    return out[:limit]


def co_occurring(db: Session, entity_id: int, etypes: tuple[str, ...], limit: int = 15) -> list[dict]:
    sub = select(ItemEntity.item_id).where(ItemEntity.entity_id == entity_id)
    rows = db.execute(
        select(Entity.id, Entity.type, Entity.display, Entity.category, Entity.verdict, func.count(ItemEntity.item_id))
        .join(ItemEntity, ItemEntity.entity_id == Entity.id)
        .where(ItemEntity.item_id.in_(sub), Entity.id != entity_id, Entity.type.in_(etypes))
        .group_by(Entity.id).order_by(func.count(ItemEntity.item_id).desc()).limit(limit)
    ).all()
    return [{"id": i, "type": t, "name": d, "category": c, "verdict": v, "count": n} for i, t, d, c, v, n in rows]


def kpi_series(db: Session, days: int = 14) -> dict:
    """Daily values behind the KPI tiles (for sparklines)."""
    since = _since(days)
    labels = [(since + timedelta(days=i + 1)).strftime("%Y-%m-%d") for i in range(days)]
    day = func.date(Item.published_at)

    def per_day(q) -> list[int]:
        m = {str(d): n for d, n in db.execute(q).all()}
        return [m.get(lbl, 0) for lbl in labels]

    base = (select(day, func.count(distinct(Entity.id)))
            .select_from(Item).join(ItemEntity, ItemEntity.item_id == Item.id)
            .join(Entity, Entity.id == ItemEntity.entity_id).where(Item.published_at >= since))
    return {
        "labels": labels,
        "items": per_day(select(day, func.count(Item.id)).where(Item.published_at >= since).group_by(day)),
        "families": per_day(base.where(Entity.type == "malware").group_by(day)),
        "iocs": per_day(base.where(Entity.type.in_(IOC_TYPES)).group_by(day)),
        "cves": per_day(base.where(Entity.type == "cve").group_by(day)),
    }


# --------------------------------------------------------------------------- correlation
# How strongly a shared entity ties two items together. A shared file hash is near-proof
# that two reports describe the same activity; a shared CVE or technique is weak evidence.
CORRELATION_WEIGHT = {
    "sha256": 6.0, "sha1": 6.0, "md5": 6.0, "url": 5.0, "domain": 4.0, "ip": 3.0,
    "malware": 2.5, "actor": 2.5, "cve": 1.5, "technique": 0.5,
}
# Entities mentioned in more items than this are too generic to generate candidates
# (they still weigh in for candidates found through rarer entities).
CORRELATION_MAX_MENTIONS = 400


def correlated_items(db: Session, item: Item, limit: int = 15) -> list[dict]:
    """Items that share entities with ``item``, ranked by evidence strength rather than by a
    plain count: weight(type) / log2(2 + mentions) per shared entity, with a bonus for items
    from another source (×1.15) or another source *type* (×1.3) — the cross-source view."""
    import math

    links = [(link.entity_id, link.entity) for link in item.entity_links]
    if not links:
        return []
    weights = {eid: CORRELATION_WEIGHT.get(e.type, 1.0) / math.log2(2 + (e.mention_count or 0)) for eid, e in links}
    names = {eid: (e.type, e.display) for eid, e in links}
    seeds = [eid for eid, e in links if (e.mention_count or 0) <= CORRELATION_MAX_MENTIONS] or [eid for eid, _ in links]
    rows = db.execute(
        select(ItemEntity.item_id, ItemEntity.entity_id)
        .join(Item, Item.id == ItemEntity.item_id)
        .where(ItemEntity.entity_id.in_(seeds), ItemEntity.item_id != item.id)
        .order_by(Item.published_at.desc()).limit(4000)
    ).all()
    shared: dict[int, set[int]] = defaultdict(set)
    for iid, eid in rows:
        shared[iid].add(eid)
    if not shared:
        return []
    # all shared entities for the candidates (including the generic ones skipped as seeds)
    cand_ids = list(shared)
    if len(seeds) != len(weights):
        extra = db.execute(select(ItemEntity.item_id, ItemEntity.entity_id)
                           .where(ItemEntity.item_id.in_(cand_ids[:500]), ItemEntity.entity_id.in_(list(weights)))).all()
        for iid, eid in extra:
            shared[iid].add(eid)
    scored = sorted(((sum(weights[e] for e in ents), iid) for iid, ents in shared.items()), reverse=True)[:limit * 4]
    items = {i.id: i for i in db.execute(select(Item).where(Item.id.in_([iid for _, iid in scored]))).unique().scalars()}
    out = []
    for base, iid in scored:
        other = items.get(iid)
        if not other:
            continue
        score = base
        if other.source_id != item.source_id:
            score *= 1.3 if other.source.category != item.source.category else 1.15
        ents = sorted(shared[iid], key=lambda e: -weights[e])
        out.append({"item": other, "score": round(score, 2), "shared": len(ents),
                    "entities": [names[e] for e in ents[:6]],
                    "strong": any(names[e][0] in ("sha256", "sha1", "md5", "url", "domain", "ip") for e in ents)})
    out.sort(key=lambda d: (-d["score"], -d["item"].published_at.timestamp()))
    return out[:limit]
