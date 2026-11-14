"""Ingest raw collected items: dedupe, store, extract & link entities."""
from __future__ import annotations

import html
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Entity, Item, ItemEntity, Source, utcnow
from ..sharing import norm_tlp
from .extractor import Extracted, extract_all
from .severity import reasons_to_json, score_item

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


_TAG_RE = re.compile(r"(?s)<[^>]+>")
_SCRIPT_RE = re.compile(r"(?is)<(script|style).*?</\1>")
_WS_RE = re.compile(r"\s+")


def strip_html(text: str) -> str:
    text = _SCRIPT_RE.sub(" ", text or "")
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text)
    return _WS_RE.sub(" ", text).strip()


def safe_url(url: str | None) -> str:
    """Feeds are untrusted: keep only http(s) links so a crafted `javascript:` URL from an
    RSS entry can never end up in an <a href>."""
    u = (url or "").strip()
    if not u.lower().startswith(("http://", "https://")):
        return ""
    if any(c in u for c in "\n\r\t"):
        return ""
    return u[:2000]


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


def _external_id(r: RawItem) -> str:
    return (r.external_id or r.url or r.title or "").strip()[:500]


def ingest(db: Session, source: Source, raws: list[RawItem], progress=None) -> list[int]:
    """Store new items. Returns IDs of newly created items.
    ``progress(done, total)`` is called as entries are processed (in-memory job progress, no DB writes)."""
    from ..knowledge import canonical_malware

    new_ids: list[int] = []
    strict = source.category != "intel"
    wanted = {ext for ext in (_external_id(r) for r in raws) if ext}
    if not wanted:
        return new_ids
    # one query for the whole batch instead of one per entry
    known = {
        ext for (ext,) in db.execute(
            select(Item.external_id).where(Item.source_id == source.id, Item.external_id.in_(wanted))
        )
    }
    for n, r in enumerate(raws, 1):
        if progress and (n % 5 == 0 or n == len(raws)):
            progress(n, len(raws))
        ext = _external_id(r)
        if not ext or ext in known:
            continue
        known.add(ext)  # a feed may repeat an entry inside the same batch
        content = r.content if r.kind != "article" else strip_html(r.content)
        now = utcnow()
        published = r.published_at or now
        if published > now:  # clocks drift and some feeds post-date entries; never show "in 3h"
            published = now
        item = Item(
            source_id=source.id, kind=r.kind, external_id=ext, title=(r.title or "")[:1000],
            url=safe_url(r.url), author=(r.author or "")[:250], content=content[:50000],
            tags=[str(t)[:80] for t in r.tags[:50]], published_at=published, raw=r.raw or {},
            tlp=norm_tlp((r.raw or {}).get("tlp")),
        )
        db.add(item)
        db.flush()
        text = f"{item.title}\n{content}\n{' '.join(item.tags)}"
        extracted = extract_all(text, strict=strict)
        for ind in r.indicators:
            extracted.append(Extracted(ind.type, ind.value, ind.display, ind.category, "feed"))
        # tags on intel feeds (e.g. OTX malware_families) often name families directly
        for tag in item.tags:
            hit = canonical_malware(tag)
            if hit:
                extracted.append(Extracted("malware", hit[0].lower(), hit[0], hit[1], "feed"))
        # dedupe by (type,value)
        uniq = {(e.type, e.value): e for e in extracted}
        item.severity, reasons = score_item(item.title, f"{content}\n{' '.join(item.tags)}", list(uniq.values()), item.kind)
        item.severity_detail = reasons_to_json(reasons)
        link_entities(db, item, list(uniq.values()))
        new_ids.append(item.id)
    source.items_count = (source.items_count or 0) + len(new_ids)
    return new_ids
