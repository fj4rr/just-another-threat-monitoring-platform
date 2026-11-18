"""Ingest raw collected items: dedupe, store, extract & link entities."""
from __future__ import annotations

import hashlib
import html
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import geoip
from ..models import Enrichment, Entity, Item, ItemEntity, Source, utcnow
from ..sharing import norm_tlp
from . import fraud, sectors
from .extractor import Extracted, extract_all
from .geo import tag_item
from .severity import IOC_TYPES, carry_over, reasons_to_json, score_item

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
    # Set for entries that grow after they were first stored (ThreatFox: one item per family and day): when the id
    # is already stored, new indicators are added to that item instead of being dropped, and its title becomes this
    # text with {n} replaced by the item's indicator count
    merge_title: str = ""


_TAG_RE = re.compile(r"(?s)<[^>]+>")
_SCRIPT_RE = re.compile(r"(?is)<(script|style).*?</\1>")
_WS_RE = re.compile(r"\s+")
# Stylesheet text some WordPress plugins print into the post body outside a <style> tag (Kadence blocks in the
# Malwarebytes feed): ".kb-btns97520 .kt-button{font-weight:normal;}" and "@media (...){...{...}}". A rule only
# counts when its body is nothing but "property: value;" declarations, so code and JSON in articles stay.
# A selector is made of real compound selectors (".kt-button", "ul.menu", "a:hover", "[data-x]"), never plain words.
#
# The patterns must stay linear on hostile input (audit 2026-11 S-2): every article goes through here, and a
# regex that backtracks for minutes holds a scheduler thread that cannot be killed. So
# * two compound selectors are always separated by a real combinator (whitespace or > + ~), never by nothing:
#   ".a.a" has exactly one parse, where "(?:x)+(?:\s*[>+~]?\s*(?:x)+)*" had exponentially many;
# * a plain rule is found from its declaration block backwards, in a bounded window, instead of trying a
#   selector match at every position of a 50 KB text.
_CSS_COMPOUND = r"(?:[a-z][a-z0-9]*)?(?:[.#][\w-]+|::?[\w-]+(?:\([^(){}]{0,40}\))?|\[[^\]{}]{0,60}\])+"
_CSS_COMPLEX = rf"{_CSS_COMPOUND}(?:(?:\s*[>+~]\s*|\s+){_CSS_COMPOUND})*"
_CSS_SEL = rf"{_CSS_COMPLEX}(?:\s*,\s*{_CSS_COMPLEX})*"
_CSS_DECLS = r"\{(?:\s*-{0,2}[a-z][a-z-]*\s*:\s*[^;{}<>]{1,300};)+\s*\}"
_CSS_MEDIA = re.compile(rf"@media[^{{}}]{{0,200}}\{{\s*(?:{_CSS_SEL}\s*{_CSS_DECLS}\s*)+\}}", re.I)
_CSS_BLOCK = re.compile(_CSS_DECLS, re.I)
_CSS_SEL_TAIL = re.compile(rf"(?:{_CSS_SEL})\s*\Z", re.I)
_CSS_SEL_WINDOW = 200  # longest selector looked for in front of a declaration block
_CSS_HINT = re.compile(r"\{[^{}:;]{0,300}:[^{};]{0,300};")


def strip_css(text: str) -> str:
    """Drop stylesheet rules that ended up in the text (see _CSS_COMPOUND)."""
    if not text or not _CSS_HINT.search(text):
        return text or ""
    if "@media" in text.lower():
        text = _CSS_MEDIA.sub(" ", text)
    out: list[str] = []
    pos = 0
    for m in _CSS_BLOCK.finditer(text):
        lo = max(pos, m.start() - _CSS_SEL_WINDOW)
        sel = _CSS_SEL_TAIL.search(text[lo:m.start()])
        if sel is None:
            continue  # "{key: value;}" without a selector in front: JSON, code, prose
        out.append(text[pos:lo + sel.start()])
        out.append(" ")
        pos = m.end()
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


def strip_html(text: str) -> str:
    text = _SCRIPT_RE.sub(" ", text or "")
    text = _TAG_RE.sub(" ", text)
    text = strip_css(html.unescape(text))
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


def _apply_seen(ent: Entity, ex: Extracted, seen_at: datetime) -> None:
    if seen_at > ent.last_seen:
        ent.last_seen = seen_at
    if seen_at < ent.first_seen:
        ent.first_seen = seen_at
    if ex.category and not ent.category:
        ent.category = ex.category


def _new_entity(db: Session, ex: Extracted, seen_at: datetime) -> Entity:
    ent = Entity(
        type=ex.type, value=ex.value, display=ex.display or ex.value, category=ex.category,
        first_seen=seen_at, last_seen=seen_at, mention_count=0, meta={},
        country=geoip.country(ex.value) if ex.type == "ip" else "",
    )
    db.add(ent)
    return ent


def get_or_create_entity(db: Session, ex: Extracted, seen_at: datetime | None = None) -> Entity:
    seen_at = seen_at or utcnow()
    ent = db.execute(
        select(Entity).where(Entity.type == ex.type, Entity.value == ex.value)
    ).scalar_one_or_none()
    if ent is None:
        ent = _new_entity(db, ex, seen_at)
        db.flush()
    else:
        _apply_seen(ent, ex, seen_at)
    return ent


def _entities_for(db: Session, extracted: list[Extracted], seen_at: datetime) -> dict[tuple[str, str], Entity]:
    """Entities for a batch of extractions: one lookup query per entity type and one flush for the new ones,
    instead of a query (and a flush) per indicator. A blocklist item with 500 domains costs two queries."""
    by_type: dict[str, set[str]] = {}
    for ex in extracted:
        by_type.setdefault(ex.type, set()).add(ex.value)
    found: dict[tuple[str, str], Entity] = {}
    for etype, values in by_type.items():
        vals = list(values)
        for n in range(0, len(vals), 500):
            for ent in db.execute(select(Entity).where(Entity.type == etype, Entity.value.in_(vals[n:n + 500]))).scalars():
                found[(ent.type, ent.value)] = ent
    created = False
    for ex in extracted:
        key = (ex.type, ex.value)
        ent = found.get(key)
        if ent is None:
            found[key] = _new_entity(db, ex, seen_at)
            created = True
        else:
            _apply_seen(ent, ex, seen_at)
    if created:
        db.flush()
    return found


def link_entities(db: Session, item: Item, extracted: list[Extracted]) -> int:
    if not extracted:
        return 0
    existing = {
        eid for (eid,) in db.execute(select(ItemEntity.entity_id).where(ItemEntity.item_id == item.id))
    } if item.id else set()
    ents = _entities_for(db, extracted, item.published_at or utcnow())
    added = 0
    for ex in extracted:
        ent = ents[(ex.type, ex.value)]
        if ent.id in existing:
            continue
        existing.add(ent.id)
        db.add(ItemEntity(item_id=item.id, entity_id=ent.id, origin=ex.origin))
        ent.mention_count = (ent.mention_count or 0) + 1
        added += 1
    return added


def mark_listed(db: Session, indicators: list[Extracted], provider: str, summary: str, permalink: str = "") -> int:
    """Indicators from a curated blocklist (ScamSniffer…) are confirmed malicious by the list itself: record that as
    an enrichment result so they do not wait in the enrichment queue and spend provider quota."""
    if not indicators:
        return 0
    now = utcnow()
    ents: list[Entity] = []
    by_type: dict[str, set[str]] = {}
    for ind in indicators:
        by_type.setdefault(ind.type, set()).add(ind.value)
    for etype, values in by_type.items():
        vals = list(values)
        for n in range(0, len(vals), 500):
            ents += db.execute(select(Entity).where(Entity.type == etype, Entity.value.in_(vals[n:n + 500]))).scalars()
    if not ents:
        return 0
    ids = [e.id for e in ents]
    done = {eid for (eid,) in db.execute(select(Enrichment.entity_id).where(Enrichment.entity_id.in_(ids),
                                                                            Enrichment.provider == provider))}
    if done:  # listed again: the list confirms the verdict today
        db.execute(update(Enrichment).where(Enrichment.entity_id.in_(done), Enrichment.provider == provider)
                   .values(fetched_at=now))
    for ent in ents:
        if ent.id not in done:
            db.add(Enrichment(entity_id=ent.id, provider=provider, verdict="malicious", score=1.0,
                              summary=summary[:500], permalink=permalink, data={}, fetched_at=now))
        if not ent.enriched_at:
            ent.verdict, ent.enriched_at = "malicious", now
        if ent.verdict == "malicious":
            ent.verdict_at = now  # a blocklist that still lists the indicator keeps its verdict fresh
    return len(ents)


EXT_MAX = 500  # the external_id column keeps 512; longer ids are shortened with a hash so they stay unique


def _external_id(r: RawItem) -> str:
    """Dedup key of an entry within its source. Ids longer than EXT_MAX (URLs with tracking parameters) keep
    a readable prefix plus a hash of the whole id: cutting them at 500 characters made different entries
    collide (audit 2026-11 D-13)."""
    ext = (r.external_id or r.url or r.title or "").strip()
    if len(ext) <= EXT_MAX:
        return ext
    return f"{ext[:EXT_MAX - 66]}#sha256:{hashlib.sha256(ext.encode('utf-8', 'replace')).hexdigest()}"


# --------------------------------------------------------------------------- cross-source dedup (audit D-10)
_FP_SUFFIX = re.compile(r"\s+[|\-–—:]\s+[^|\-–—:]{1,40}$")  # " - ANTARA News", " | Republika Online"
_FP_WORD = re.compile(r"[^\W_]+")
DUP_WINDOW = timedelta(days=4)  # a syndicated copy appears within days of the original


def fingerprint(title: str, content: str = "") -> str:
    """Same story, other outlet: the normalised title (without the outlet's suffix). Short titles ("Weekly
    update") also take the start of the text so unrelated items do not collide. "" when there is too little."""
    t = _FP_SUFFIX.sub("", (title or "").strip())
    words = _FP_WORD.findall(t.lower())
    if len(words) < 5:
        words += _FP_WORD.findall((content or "")[:400].lower())[:30]
    if len(words) < 6:
        return ""
    return hashlib.blake2b(" ".join(words).encode(), digest_size=20).hexdigest()


def find_original(db: Session, item: Item, batch: dict[str, tuple[int, int, datetime]] | None = None) -> int | None:
    """Id of the earlier item from another source with the same fingerprint, if ``item`` is a copy."""
    if not item.fingerprint:
        return None
    at = item.published_at or utcnow()
    if batch is not None and item.fingerprint in batch:
        oid, osrc, oat = batch[item.fingerprint]
        if osrc != item.source_id and abs(oat - at) <= DUP_WINDOW:
            return oid
    row = db.execute(
        select(Item.id, Item.dup_of).where(
            Item.fingerprint == item.fingerprint, Item.source_id != item.source_id, Item.id != item.id,
            Item.published_at >= at - DUP_WINDOW, Item.published_at <= at + DUP_WINDOW)
        .order_by(Item.published_at, Item.id).limit(1)).first()
    if row is None:
        return None
    return row.dup_of or row.id


def tag_families(tags: list[str], source: Source | None) -> list[Extracted]:
    """Families named by an intel feed's tags (OTX ``malware_families``). Only intel feeds: news and social tags
    are free-form, and a tag is never an everyday word ("Play", "Hook", "Chaos", "Snake"; audit 2026-11 D-7)."""
    from ..knowledge import COMMON_WORDS, canonical_malware

    if source is None or source.category != "intel":
        return []
    out = []
    for tag in tags or []:
        low = str(tag).strip().lower()
        if not low or low in COMMON_WORDS or len(low) <= 3:
            continue
        hit = canonical_malware(low)
        if hit:
            out.append(Extracted("malware", hit[0].lower(), hit[0], hit[1], "feed"))
    return out


def _slim_raw(raw: dict | None, content: str) -> dict:
    """Keep provider metadata, drop bulky copies of the content (some feeds repeat the full text in raw)."""
    out = {}
    for k, v in (raw or {}).items():
        if isinstance(v, str) and (len(v) > 2000 or (content and v.strip() == content.strip())):
            continue
        out[k] = v
    return out


def ingest_committed(db: Session, source: Source, raws: list[RawItem], progress=None, origin: str = "live",
                     attempts: int = 3) -> list[int]:
    """``ingest`` + commit, safe against a concurrent run of the same source (scheduled collector vs backfill,
    or two manual runs): if the other run stored an entry between our duplicate check and our insert, the
    unique constraint fires; roll back and try again, and the second pass skips what is now stored."""
    from sqlalchemy.exc import IntegrityError

    for attempt in range(attempts):
        try:
            ids = ingest(db, source, raws, progress, origin)
            db.commit()
            if ids:
                from .trends import invalidate_cache

                invalidate_cache()  # the trending lists include the new items from now on
            return ids
        except IntegrityError:
            db.rollback()
            if attempt == attempts - 1:
                raise
            source = db.get(Source, source.id)
    return []


def merge_indicators(db: Session, source: Source, ext: str, r: RawItem) -> int:
    """Add the indicators of ``r`` that its stored item does not have yet (PM review 2026-11, item 7: ThreatFox kept
    one item per family and day and dropped every IOC reported after the first run of the day). The item is scored
    again with the new indicator count, keeping its enrichment bonus and AI assessment. Returns how many were added."""
    db.flush()  # the session does not autoflush: links added earlier in this batch must be visible to link_entities
    item = db.execute(select(Item).where(Item.source_id == source.id, Item.external_id == ext)).scalar_one_or_none()
    if item is None:
        return 0
    added = link_entities(db, item, [Extracted(i.type, i.value, i.display, i.category, "feed") for i in r.indicators])
    if not added:
        return 0
    db.flush()
    rows = db.execute(select(Entity.type, Entity.verdict, ItemEntity.origin).join(
        ItemEntity, ItemEntity.entity_id == Entity.id).where(ItemEntity.item_id == item.id)).all()
    n_ioc = sum(1 for t, _, origin in rows if origin == "feed" and t in IOC_TYPES)
    item.title = r.merge_title.replace("{n}", str(n_ioc))[:1000]
    item.tags = sorted(set(item.tags or []) | {str(t)[:80] for t in r.tags[:50]})[:50]
    scored = [Extracted(t, "", "", "", origin or "") for t, _, origin in rows]
    score, reasons = score_item(item.title, f"{item.content}\n{' '.join(item.tags)}", scored, item.kind)
    item.severity, item.severity_detail = carry_over(score, reasons_to_json(reasons), item.severity_detail,
                                                     [(t, v) for t, v, _ in rows])
    return added


def ingest(db: Session, source: Source, raws: list[RawItem], progress=None, origin: str = "live") -> list[int]:
    """Store new items. Returns IDs of newly created items.
    ``progress(done, total)`` is called as entries are processed (in-memory job progress, no DB writes)."""
    new_ids: list[int] = []
    strict = source.category != "intel"
    wanted = {ext for ext in (_external_id(r) for r in raws) if ext}
    if not wanted:
        return new_ids
    # ids stored by 0.10 and older were cut at 500 characters: look those up too, so an upgrade re-ingests nothing
    legacy = {(r.external_id or r.url or r.title or "").strip()[:EXT_MAX]: ext
              for r, ext in ((r, _external_id(r)) for r in raws) if "#sha256:" in ext}
    lookup = list(wanted | set(legacy))
    # one query (per 500 keys) for the whole batch instead of one per entry
    known: set[str] = set()
    for n in range(0, len(lookup), 500):
        for (ext,) in db.execute(select(Item.external_id).where(Item.source_id == source.id,
                                                                Item.external_id.in_(lookup[n:n + 500]))):
            known.add(legacy.get(ext, ext))
    fp_batch: dict[str, tuple[int, int, datetime]] = {}
    velocity_cache: dict = {}  # scam-type spread counts, once per type and day for the whole batch
    for n, r in enumerate(raws, 1):
        if progress and (n % 5 == 0 or n == len(raws)):
            progress(n, len(raws))
        ext = _external_id(r)
        if ext and ext in known and r.merge_title and r.indicators:
            merge_indicators(db, source, ext, r)
            continue
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
            tags=[str(t)[:80] for t in r.tags[:50]], published_at=published, raw=_slim_raw(r.raw, content),
            tlp=norm_tlp((r.raw or {}).get("tlp")), origin=origin,
        )
        if r.kind == "article":
            item.fingerprint = fingerprint(item.title, content)
        db.add(item)
        db.flush()
        if item.fingerprint:
            item.dup_of = find_original(db, item, fp_batch)
            fp_batch.setdefault(item.fingerprint, (item.dup_of or item.id, item.source_id, item.published_at))
        text = f"{item.title}\n{content}\n{' '.join(item.tags)}"
        extracted = extract_all(text, strict=strict)
        for ind in r.indicators:
            extracted.append(Extracted(ind.type, ind.value, ind.display, ind.category, "feed"))
        # tags on intel feeds (e.g. OTX malware_families) often name families directly
        extracted += tag_families(item.tags, source)
        # dedupe by (type,value)
        uniq = {(e.type, e.value): e for e in extracted}
        item.severity, reasons = score_item(item.title, f"{content}\n{' '.join(item.tags)}", list(uniq.values()), item.kind)
        item.severity_detail = reasons_to_json(reasons)
        for fx in fraud.apply(db, item, source.topic or "", cache=velocity_cache):  # scam types, brands, identifiers
            uniq.setdefault((fx.type, fx.value), fx)
        for sx in sectors.apply(item):  # critical infrastructure sectors (0.10)
            uniq.setdefault((sx.type, sx.value), sx)
        link_entities(db, item, list(uniq.values()))
        if (r.raw or {}).get("listed_by") and r.indicators:
            mark_listed(db, r.indicators, str(r.raw["listed_by"]), str(r.raw.get("listed_summary") or ""), item.url)
        tag_item(db, item, source, replace=False)
        new_ids.append(item.id)
    source.items_count = (source.items_count or 0) + len(new_ids)
    return new_ids
