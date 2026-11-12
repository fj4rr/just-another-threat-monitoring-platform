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

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from .. import settings
from ..intel import LookupResult, NotConfigured
from ..intel.clients import OTX, AnyRun, URLScan, VirusTotal
from ..knowledge import AMBIGUOUS, canonical_malware
from ..models import Enrichment, Entity, EntityLink, Item, ItemEntity, utcnow
from .extractor import Extracted
from .pipeline import get_or_create_entity

log = logging.getLogger(__name__)

IOC_TYPES = ("md5", "sha1", "sha256", "ip", "domain", "url")
VERDICT_RANK = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0, "": 0}
# How much an item's severity rises when one of its indicators is confirmed by enrichment.
VERDICT_BONUS = {"malicious": 12, "suspicious": 5}
# Re-check cadence: providers learn about an indicator days after it is first posted.
RECHECK_UNKNOWN_AFTER = timedelta(days=3)
RECHECK_ERROR_AFTER = timedelta(hours=6)
RECHECK_MAX_AGE = timedelta(days=21)


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
        # short / ambiguous tokens ("play", "hook", "fog") only count when they ARE the label
        if len(tok) < 4 or tok in AMBIGUOUS or tok in {
                "trojan", "generic", "malware", "win32", "win64", "msil", "agent", "stealer", "ransom",
                "backdoor", "downloader", "dropper", "heur", "variant", "family", "riskware", "adware",
                "pua", "pup", "hacktool", "packed", "suspicious", "malicious", "virus", "worm", "script",
                "android", "linux", "macos", "osx", "unix", "python", "powershell", "java", "html", "phishing"}:
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


def _consensus(entity: Entity, results: list[LookupResult]) -> str:
    """Combine provider verdicts. Any provider saying *malicious* wins; otherwise the strongest
    verdict, except that a lone OTX pulse mention is only *suspicious* unless pulses attribute
    a family (OTX pulses include plenty of benign infrastructure)."""
    best = entity.verdict or ""
    for res in results:
        v = res.verdict
        if res.provider == "otx" and v == "malicious" and not res.malware and (res.data.get("pulse_count") or 0) < 5:
            v = "suspicious"
        if VERDICT_RANK.get(v, 0) > VERDICT_RANK.get(best, 0):
            best = v
    return best


def _bump_items(db: Session, entity: Entity, old: str, new: str) -> int:
    """Feed a confirmed verdict back into the severity of the items that mention the IOC."""
    gain = VERDICT_BONUS.get(new, 0) - VERDICT_BONUS.get(old, 0)
    if gain <= 0:
        return 0
    items = db.execute(select(Item).join(ItemEntity, ItemEntity.item_id == Item.id)
                       .where(ItemEntity.entity_id == entity.id)).unique().scalars().all()
    label = f"indicator confirmed {new} ({entity.type})"
    for item in items:
        detail = [d for d in (item.severity_detail or []) if not str(d.get("label", "")).startswith("indicator confirmed")]
        detail.append({"label": label, "points": gain})
        item.severity_detail = detail
        item.severity = min(100, (item.severity or 0) + gain)
    return len(items)


def enrich_entity(db: Session, entity: Entity, providers: list | None = None) -> list[str]:
    """Look an IOC up on every configured provider. Returns list of messages."""
    msgs = []
    providers = providers if providers is not None else available_providers()
    results: list[LookupResult] = []
    attempted = failed = 0
    for p in providers:
        if entity.type not in getattr(p, "supports", {entity.type}) and entity.type not in getattr(p, "FIELD", {entity.type}):
            continue
        attempted += 1
        try:
            res = p.lookup(entity.type, entity.value)
        except Exception as e:  # provider errors must not stop the batch
            failed += 1
            msgs.append(f"{p.name}: {e}")
            log.warning("enrich %s %s via %s failed: %s", entity.type, entity.value, p.name, e)
            continue
        if res is None:
            continue
        results.append(res)
        _upsert(db, entity, res)
        for label in res.malware[:5]:
            fam = resolve_family(label)
            if fam:
                fam_ent = get_or_create_entity(db, Extracted("malware", fam[0].lower(), fam[0], fam[1]))
                _link(db, entity, fam_ent, "attributed-to", p.name)
        for rel in res.related[:8]:
            rel_ent = get_or_create_entity(db, rel)
            _link(db, entity, rel_ent, "related", p.name)
        msgs.append(f"{p.name}: {res.verdict}")
    old = entity.verdict or ""
    if results:
        new = _consensus(entity, results) or "unknown"
        entity.verdict = new
        n = _bump_items(db, entity, old, new)
        if n:
            msgs.append(f"severity raised on {n} item(s)")
    elif attempted and failed == attempted:
        # every provider errored (quota, network): keep "" so the re-check pass retries soon
        entity.verdict = entity.verdict or ""
    else:
        entity.verdict = entity.verdict or "unknown"
    entity.enriched_at = utcnow()
    return msgs


def _pulse_mentions(pulse: dict, name_l: str) -> bool:
    """Only trust pulses that actually name the family (OTX full-text search is fuzzy)."""
    fams = " ".join(str(f.get("display_name") if isinstance(f, dict) else f) for f in pulse.get("malware_families") or [])
    hay = " ".join([pulse.get("name") or "", " ".join(pulse.get("tags") or []), fams]).lower()
    squashed = name_l.replace(" ", "")
    return name_l in hay or squashed in hay.replace(" ", "")


def enrich_family(db: Session, entity: Entity) -> list[str]:
    """Pull fresh IOCs & context for a malware family from OTX and ANY.RUN."""
    msgs = []
    name = entity.display or entity.value
    low = name.lower()
    try:
        otx = OTX()
        # short / ambiguous names ("Play", "Fog") need a qualifier or the search returns noise
        query = name if len(low) > 5 and low not in AMBIGUOUS else f'"{name}" {entity.category or "malware"}'
        pulses = [p for p in otx.search_pulses(query, limit=20) if _pulse_mentions(p, low)][:10]
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
    # 3) re-check: "unknown" results age (providers learn about an IOC days later) and
    #    errored lookups (quota / network) deserve a retry. Uses up to a quarter of the batch.
    recheck_slots = max(1, batch // 4) if len(iocs) < batch else max(0, batch // 4)
    rechecked: list[Entity] = []
    if recheck_slots:
        now = utcnow()
        rq = (
            select(Entity)
            .where(Entity.type.in_(IOC_TYPES), Entity.enriched_at.is_not(None), Entity.last_seen >= now - RECHECK_MAX_AGE,
                   or_(and_(Entity.verdict == "", Entity.enriched_at < now - RECHECK_ERROR_AFTER),
                       and_(Entity.verdict == "unknown", Entity.enriched_at < now - RECHECK_UNKNOWN_AFTER)))
            .order_by(Entity.mention_count.desc(), Entity.enriched_at.asc())
            .limit(recheck_slots)
        )
        rechecked = [e for e in db.execute(rq).scalars() if e not in iocs]
    done = 0
    for ent in iocs + rechecked:
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
    return f"enriched {done} IOC(s) ({len(rechecked)} re-checked), {fam_done} family(ies)"
