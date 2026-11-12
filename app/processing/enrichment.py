"""Cross-source enrichment.

* IOCs seen in news / social / feeds  -> looked up on VirusTotal, OTX, urlscan, ANY.RUN.
  Families the providers attribute are linked back (hash -> "Lumma Stealer"), so a hash
  posted on Bluesky gets connected to the news articles about that family.
* Trending malware families -> OTX pulse search + ANY.RUN TI Lookup pull fresh IOCs,
  which are linked to the family and enriched in later runs.
"""
from __future__ import annotations

import logging
import re
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import settings
from ..intel import LookupResult, NotConfigured
from ..intel.clients import OTX, AnyRun, URLScan, VirusTotal
from ..knowledge import canonical_malware
from ..models import Enrichment, Entity, EntityLink, Item, ItemEntity, utcnow
from .extractor import Extracted
from .pipeline import get_or_create_entity

log = logging.getLogger(__name__)

IOC_TYPES = ("md5", "sha1", "sha256", "ip", "domain", "url")
VERDICT_RANK = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0, "": 0}


def available_providers() -> list:
    out = []
    for cls in (VirusTotal, OTX, URLScan, AnyRun):
        try:
            out.append(cls())
        except NotConfigured:
            continue
    return out


def resolve_family(label: str) -> tuple[str, str] | None:
    """Map provider labels like 'trojan.lumma/lummastealer' to a known family."""
    hit = canonical_malware(label)
    if hit:
        return hit
    for tok in re.split(r"[./,:\s_\-]+", label.lower()):
        if len(tok) < 4 or tok in {"trojan", "generic", "malware", "win32", "win64", "msil", "agent",
                                   "stealer", "ransom", "backdoor", "downloader", "dropper", "heur"}:
            continue
        hit = canonical_malware(tok)
        if hit:
            return hit
    return None


def _upsert(db: Session, entity: Entity, res: LookupResult) -> Enrichment:
    row = db.execute(
        select(Enrichment).where(Enrichment.entity_id == entity.id, Enrichment.provider == res.provider)
    ).scalar_one_or_none()
    if row is None:
        row = Enrichment(entity_id=entity.id, provider=res.provider)
        db.add(row)
    row.verdict, row.score, row.summary = res.verdict, res.score, res.summary[:2000]
    row.permalink, row.fetched_at = res.permalink, utcnow()
    row.data = {**res.data, "tags": res.tags, "malware": res.malware}
    return row


def _link(db: Session, src: Entity, dst: Entity, relation: str, provider: str) -> None:
    if src.id == dst.id:
        return
    exists = db.execute(
        select(EntityLink.id).where(EntityLink.src_id == src.id, EntityLink.dst_id == dst.id,
                                    EntityLink.provider == provider)
    ).scalar_one_or_none()
    if not exists:
        db.add(EntityLink(src_id=src.id, dst_id=dst.id, relation=relation, provider=provider))


def enrich_entity(db: Session, entity: Entity, providers: list | None = None) -> list[str]:
    """Look an IOC up on every configured provider. Returns list of messages."""
    msgs = []
    providers = providers if providers is not None else available_providers()
    best = entity.verdict or ""
    for p in providers:
        try:
            res = p.lookup(entity.type, entity.value)
        except Exception as e:  # provider errors must not stop the batch
            msgs.append(f"{p.name}: {e}")
            log.warning("enrich %s %s via %s failed: %s", entity.type, entity.value, p.name, e)
            continue
        if res is None:
            continue
        _upsert(db, entity, res)
        if VERDICT_RANK[res.verdict] > VERDICT_RANK.get(best, 0):
            best = res.verdict
        for label in res.malware[:5]:
            fam = resolve_family(label)
            if fam:
                fam_ent = get_or_create_entity(db, Extracted("malware", fam[0].lower(), fam[0], fam[1]))
                _link(db, entity, fam_ent, "attributed-to", p.name)
        for rel in res.related[:15]:
            rel_ent = get_or_create_entity(db, rel)
            _link(db, entity, rel_ent, "related", p.name)
        msgs.append(f"{p.name}: {res.verdict}")
    entity.verdict = best or "unknown"
    entity.enriched_at = utcnow()
    return msgs


def enrich_family(db: Session, entity: Entity) -> list[str]:
    """Pull fresh IOCs & context for a malware family from OTX and ANY.RUN."""
    msgs = []
    name = entity.display or entity.value
    try:
        otx = OTX()
        pulses = otx.search_pulses(name, limit=10)
        linked = 0
        for pulse in pulses[:5]:
            for ex in otx.pulse_indicators(pulse, limit=40):
                ioc = get_or_create_entity(db, ex)
                _link(db, entity, ioc, "indicator", "otx")
                linked += 1
        res = LookupResult("otx", "malicious" if pulses else "unknown", min(100, len(pulses) * 10),
                           f"{len(pulses)} recent OTX pulse(s), {linked} indicator(s) linked",
                           f"https://otx.alienvault.com/browse/global/pulses?q={name}")
        res.data = {"pulses": [{"id": p.get("id"), "name": p.get("name"), "modified": p.get("modified"),
                                "author": p.get("author_name")} for p in pulses[:10]]}
        _upsert(db, entity, res)
        msgs.append(f"otx: {len(pulses)} pulses")
    except NotConfigured:
        pass
    except Exception as e:
        msgs.append(f"otx: {e}")
    try:
        ar = AnyRun()
        data = ar.ti_search(f'threatName:"{entity.value}"', 14)
        iocs = ar._related_iocs(data, 40)
        for ex in iocs:
            _link(db, entity, get_or_create_entity(db, ex), "indicator", "anyrun")
        tasks = data.get("sourceTasks") or []
        res = LookupResult("anyrun", "malicious" if tasks else "unknown", 90 if tasks else 0,
                           f"{len(tasks)} sandbox task(s) in 14 days, {len(iocs)} IOC(s) linked",
                           "https://intelligence.any.run/analysis/lookup")
        res.data = {"tasks": [{"uuid": t.get("uuid"), "url": t.get("related"), "date": t.get("date")}
                              for t in tasks[:10]]}
        _upsert(db, entity, res)
        msgs.append(f"anyrun: {len(tasks)} tasks")
    except NotConfigured:
        pass
    except Exception as e:
        msgs.append(f"anyrun: {e}")
    entity.enriched_at = utcnow()
    return msgs


def run_batch(db: Session) -> str:
    providers = available_providers()
    if not providers:
        return "no intel providers configured"
    batch = int(settings.get("enrichment_batch") or 8)
    since = utcnow() - timedelta(days=14)
    # 1) IOCs mentioned in collected items that were never enriched; prefer IOCs from
    #    news/social (they gain the most from cross-source context) and most-mentioned.
    q = (
        select(Entity)
        .join(ItemEntity, ItemEntity.entity_id == Entity.id)
        .join(Item, Item.id == ItemEntity.item_id)
        .where(Entity.type.in_(IOC_TYPES), Entity.enriched_at.is_(None), Item.published_at >= since)
        .group_by(Entity.id)
        .order_by(func.max(Item.severity).desc(), Entity.mention_count.desc(), Entity.last_seen.desc())
        .limit(batch)
    )
    iocs = list(db.execute(q).scalars())
    # top-up with IOCs discovered via enrichment links (family indicators)
    if len(iocs) < batch:
        extra = db.execute(
            select(Entity).where(Entity.type.in_(IOC_TYPES), Entity.enriched_at.is_(None))
            .order_by(Entity.first_seen.desc()).limit(batch - len(iocs))
        ).scalars()
        iocs += [e for e in extra if e not in iocs]
    done = 0
    for ent in iocs:
        enrich_entity(db, ent, providers)
        db.commit()
        done += 1
    fam_done = 0
    if settings.get("enrich_families"):
        from .trends import trending

        stale = utcnow() - timedelta(hours=24)
        for row in trending(db, "malware", limit=5):
            ent = db.get(Entity, row["id"])
            if ent and (ent.enriched_at is None or ent.enriched_at < stale):
                enrich_family(db, ent)
                db.commit()
                fam_done += 1
                if fam_done >= 2:
                    break
    return f"enriched {done} IOC(s), {fam_done} family(ies)"
