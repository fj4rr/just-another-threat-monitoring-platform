"""Ingest raw collected items: dedupe, store, extract & link entities."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Entity, Item, ItemEntity, Source, utcnow
from .extractor import Extracted, extract_all, severity_score

log = logging.getLogger(__name__)


@dataclass
class RawItem:
    external_id: str
    title: str
    url: str = ""
    author: str = ""
    content: str = ""
    published_at: datetime | None = None
    kind: str = "article"
    tags: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    # Indicators delivered structurally by the feed (OTX pulse indicators, urlscan page...)
    indicators: list[Extracted] = field(default_factory=list)


def strip_html(html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html or "")
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&#8217;|&rsquo;", "'", text)
    text = re.sub(r"&#\d+;", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def get_or_create_entity(db: Session, ex: Extracted, seen_at: datetime | None = None) -> Entity:
    seen_at = seen_at or utcnow()
    ent = db.execute(
        select(Entity).where(Entity.type == ex.type, Entity.value == ex.value)
    ).scalar_one_or_none()
    if ent is None:
        ent = Entity(
            type=ex.type, value=ex.value, display=ex.display or ex.value, category=ex.category,
            first_seen=seen_at, last_seen=seen_at, mention_count=0, meta={},
        )
        db.add(ent)
        db.flush()
    else:
        if seen_at > ent.last_seen:
            ent.last_seen = seen_at
        if seen_at < ent.first_seen:
            ent.first_seen = seen_at
        if ex.category and not ent.category:
            ent.category = ex.category
    return ent


def link_entities(db: Session, item: Item, extracted: list[Extracted]) -> int:
    existing = {
        eid for (eid,) in db.execute(select(ItemEntity.entity_id).where(ItemEntity.item_id == item.id))
    }
    added = 0
    for ex in extracted:
        ent = get_or_create_entity(db, ex, item.published_at)
        if ent.id in existing:
            continue
        existing.add(ent.id)
        db.add(ItemEntity(item_id=item.id, entity_id=ent.id, origin=ex.origin))
        ent.mention_count = (ent.mention_count or 0) + 1
        added += 1
    return added


def ingest(db: Session, source: Source, raws: list[RawItem]) -> list[int]:
    """Store new items. Returns IDs of newly created items."""
    new_ids: list[int] = []
    strict = source.category != "intel"
    for r in raws:
        ext = (r.external_id or r.url or r.title)[:500]
        if not ext:
            continue
        exists = db.execute(
            select(Item.id).where(Item.source_id == source.id, Item.external_id == ext)
        ).scalar_one_or_none()
        if exists:
            continue
        content = r.content if r.kind != "article" else strip_html(r.content)
        item = Item(
            source_id=source.id, kind=r.kind, external_id=ext, title=(r.title or "")[:1000],
            url=(r.url or "")[:2000], author=(r.author or "")[:250], content=content[:50000],
            tags=r.tags[:50], published_at=r.published_at or utcnow(), raw=r.raw or {},
        )
        db.add(item)
        db.flush()
        text = f"{item.title}\n{content}\n{' '.join(r.tags)}"
        extracted = extract_all(text, strict=strict)
        for ind in r.indicators:
            extracted.append(Extracted(ind.type, ind.value, ind.display, ind.category, "feed"))
        # tags on intel feeds (e.g. OTX malware_families) often name families directly
        from ..knowledge import canonical_malware

        for tag in r.tags:
            hit = canonical_malware(tag)
            if hit:
                extracted.append(Extracted("malware", hit[0].lower(), hit[0], hit[1], "feed"))
        # dedupe by (type,value)
        uniq = {(e.type, e.value): e for e in extracted}
        item.severity = severity_score(text, list(uniq.values()))
        link_entities(db, item, list(uniq.values()))
        new_ids.append(item.id)
    source.items_count = (source.items_count or 0) + len(new_ids)
    return new_ids
