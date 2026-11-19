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
import threading
from datetime import timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from .. import settings
from ..intel import LookupResult, NotConfigured
from ..intel.clients import OTX, AbuseIPDB, AnyRun, GreyNoise, MalwareBazaar, URLhaus, URLScan, VirusTotal
from ..knowledge import AMBIGUOUS, canonical_malware
from ..models import Enrichment, Entity, EntityLink, Item, ItemEntity, utcnow
from .extractor import Extracted
from .pipeline import get_or_create_entity
from .severity import VERDICT_BONUS  # how much a confirmed indicator adds to an item's severity

log = logging.getLogger(__name__)

IOC_TYPES = ("md5", "sha1", "sha256", "ip", "domain", "url")
VERDICT_RANK = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0, "": 0}
# Re-check cadence: providers learn about an indicator days after it is first posted.
RECHECK_UNKNOWN_AFTER = timedelta(days=3)
RECHECK_ERROR_AFTER = timedelta(hours=6)
RECHECK_MAX_AGE = timedelta(days=21)
# Tier 1 of a batch: indicators never looked up that an item of the last 14 days mentions
FRESH_WINDOW = timedelta(days=14)
# Verdicts that age (PM review 2026-11, item 5): IPs, domains and URLs change owners, file hashes do not.
INFRA_TYPES = ("ip", "domain", "url")
# a stale verdict is only looked up again while the indicator is still mentioned somewhat recently
STALE_RECHECK_SEEN = timedelta(days=90)
# when the verdict was given: verdict_at, or enriched_at for rows from before 0.12
verdict_given_at = func.coalesce(Entity.verdict_at, Entity.enriched_at)


def verdict_is_stale(entity: Entity, days: int | None = None) -> bool:
    """A malicious / suspicious IP, domain or URL whose verdict is older than ``days`` (default: the feed limit)."""
    days = int(settings.get("verdict_feed_days") or 0) if days is None else days
    at = entity.verdict_at or entity.enriched_at
    return bool(days and at and entity.type in INFRA_TYPES and entity.verdict in ("malicious", "suspicious")
                and at < utcnow() - timedelta(days=days))


def fresh_verdict_clause():
    """Condition for the export feeds and TAXII: hashes always, other indicators unless a malicious / suspicious
    verdict is older than ``verdict_feed_days`` and was not confirmed again. None when aging is off."""
    days = int(settings.get("verdict_feed_days") or 0)
    if not days:
        return None
    return or_(Entity.type.not_in(INFRA_TYPES), Entity.verdict.not_in(("malicious", "suspicious")),
               verdict_given_at >= utcnow() - timedelta(days=days))


PROVIDER_CLASSES = (VirusTotal, OTX, URLScan, AnyRun, MalwareBazaar, URLhaus, GreyNoise, AbuseIPDB)
# Providers whose verdicts alone are weak evidence: a GreyNoise "benign service" / "benign scanner"
# answer overrides them (OTX pulses and AbuseIPDB reports often include scanners and CDNs).
NOISY_PROVIDERS = {"otx", "abuseipdb", "urlscan"}


def available_providers() -> list:
    out = []
    for cls in PROVIDER_CLASSES:
        try:
            out.append(cls())
        except NotConfigured:
            continue
    return out


def _supports(p, etype: str) -> bool:
    return etype in getattr(p, "supports", {etype}) or etype in getattr(p, "FIELD", {etype})


def prefetch(todo: list[tuple[int, str, str]], providers: list, progress=None) -> dict[int, dict[str, object]]:
    """Look a batch up with every provider at its own pace (PM review 2026-11, item 11): one thread per provider
    works through the indicators it supports, so a run takes as long as the slowest provider instead of the sum
    of all of them. ``todo`` holds plain (entity id, type, value) tuples: no database access in the threads.
    Returns {entity id: {provider name: LookupResult | None | Exception}} for enrich_entity(prefetched=...)."""
    from concurrent.futures import ThreadPoolExecutor

    out: dict[int, dict[str, object]] = {eid: {} for eid, _, _ in todo}
    work = [(p, [(eid, t, v) for eid, t, v in todo if _supports(p, t)]) for p in providers]
    total = sum(len(w) for _, w in work) or 1
    done = [0]
    lock = threading.Lock()

    def run(p, rows):
        for eid, etype, value in rows:
            try:
                res: object = p.lookup(etype, value)
            except Exception as e:  # recorded; enrich_entity reports it like a failed call
                res = e
            with lock:
                out[eid][p.name] = res
                done[0] += 1
                if progress:
                    progress(done[0], total)

    with ThreadPoolExecutor(max_workers=max(1, len(work)), thread_name_prefix="enrich") as pool:
        for f in [pool.submit(run, p, rows) for p, rows in work if rows]:
            f.result()
    return out


def resolve_family(label: str) -> tuple[str, str] | None:
    """Map provider labels like 'trojan.lumma/lummastealer' to a known family."""
    hit = canonical_malware(label)
    if hit:
        return hit
    from .extractor import GENERIC_WORDS, LEGIT_TOOLS

    for tok in re.split(r"[./,:\s_\-]+", label.lower()):
        # short / ambiguous tokens ("play", "hook", "fog") only count when they ARE the label; generic words,
        # legitimate tools, platforms and demonyms never (the extractor's filters, audit 2026-11 D-14)
        if len(tok) < 4 or tok in AMBIGUOUS or tok in GENERIC_WORDS or tok in LEGIT_TOOLS or tok in {
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


def _consensus(entity: Entity, results: list[LookupResult], base: str | None = None) -> str:
    """Combine provider verdicts. Any provider saying *malicious* wins; otherwise the strongest
    verdict, except that a lone OTX pulse mention is only *suspicious* unless pulses attribute
    a family (OTX pulses include plenty of benign infrastructure)."""
    # a verdict normally only rises; a re-check of a stale verdict starts from scratch (base="") so it may fall
    best = (entity.verdict or "") if base is None else base
    gn = next((r for r in results if r.provider == "greynoise"), None)
    benign = bool(gn and gn.verdict == "clean")
    for res in results:
        v = res.verdict
        if res.provider == "otx" and v == "malicious" and not res.malware and (res.data.get("pulse_count") or 0) < 5:
            v = "suspicious"
        # GreyNoise says this IP is a known benign service / scanner: weak signals don't count
        if benign and res.provider in NOISY_PROVIDERS and v in ("malicious", "suspicious"):
            continue
        if VERDICT_RANK.get(v, 0) > VERDICT_RANK.get(best, 0):
            best = v
    if benign and best in ("", "unknown", "suspicious") and not any(
            r.verdict in ("malicious", "suspicious") and r.provider not in NOISY_PROVIDERS | {"greynoise"}
            for r in results):
        best = "clean"
    return best


def _bump_items(db: Session, entity: Entity, old: str, new: str) -> int:
    """Feed a confirmed verdict back into the severity of the items that mention the IOC."""
    full = VERDICT_BONUS.get(new, 0)
    if full <= VERDICT_BONUS.get(old, 0):
        return 0
    items = db.execute(select(Item).join(ItemEntity, ItemEntity.item_id == Item.id)
                       .where(ItemEntity.entity_id == entity.id)).unique().scalars().all()
    label = f"indicator confirmed {new} ({entity.type})"
    n = 0
    for item in items:
        # one entry per item, for its strongest confirmed indicator: it replaces a weaker one (suspicious ->
        # malicious) and the score rises by the difference, so the breakdown keeps adding up to the score
        mine = [d for d in (item.severity_detail or []) if str(d.get("label", "")).startswith("indicator confirmed")]
        had = max((int(d.get("points") or 0) for d in mine), default=0)
        if had >= full:
            continue
        item.severity_detail = [d for d in (item.severity_detail or []) if d not in mine] + [
            {"label": label, "points": full}]
        item.severity = min(100, (item.severity or 0) + full - had)
        n += 1
    return n


def _sync_bonus(db: Session, entity: Entity) -> int:
    """After a verdict fell: give each item that mentions ``entity`` the bonus of its strongest remaining indicator."""
    db.flush()  # the session does not autoflush: the queries below must see the new verdict
    items = db.execute(select(Item).join(ItemEntity, ItemEntity.item_id == Item.id)
                       .where(ItemEntity.entity_id == entity.id)).unique().scalars().all()
    n = 0
    for item in items:
        rows = db.execute(select(Entity.type, Entity.verdict).join(ItemEntity, ItemEntity.entity_id == Entity.id)
                          .where(ItemEntity.item_id == item.id, Entity.type.in_(IOC_TYPES))).all()
        best = max(rows, key=lambda tv: VERDICT_BONUS.get(tv[1] or "", 0), default=None)
        full = VERDICT_BONUS.get(best[1] or "", 0) if best else 0
        mine = [d for d in (item.severity_detail or []) if str(d.get("label", "")).startswith("indicator confirmed")]
        had = max((int(d.get("points") or 0) for d in mine), default=0)
        if had == full:
            continue
        item.severity_detail = [d for d in (item.severity_detail or []) if d not in mine] + (
            [{"label": f"indicator confirmed {best[1]} ({best[0]})", "points": full}] if full else [])
        item.severity = max(0, min(100, (item.severity or 0) + full - had))
        n += 1
    return n


def enrich_entity(db: Session, entity: Entity, providers: list | None = None, auto_context: bool = True,
                  recheck: bool = False, prefetched: dict | None = None) -> list[str]:
    """Look an IOC up on every configured provider. Returns list of messages. ``recheck``: the verdict is stale
    and the providers' answer today replaces it, even when it is lower. ``prefetched``: answers already fetched by
    prefetch() for this entity (provider name -> result or exception); no call is made for those."""
    msgs = []
    providers = providers if providers is not None else available_providers()
    results: list[LookupResult] = []
    attempted = failed = 0
    for p in providers:
        if not _supports(p, entity.type):
            continue
        attempted += 1
        try:
            if prefetched is not None:
                res = prefetched.get(p.name)
                if isinstance(res, Exception):
                    raise res
            else:
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
        if res.provider == "greynoise":  # badges on IOC pages / previews ("mass scanner", "benign service")
            entity.meta = {**(entity.meta or {}), "greynoise": {k: res.data.get(k) for k in
                                                               ("noise", "riot", "classification", "name")}}
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
        new = _consensus(entity, results, base="" if recheck else None) or "unknown"
        if (entity.meta or {}).get("analyst"):  # an analyst's verdict wins over the providers (0.13)
            new = old or new
            msgs.append(f"analyst verdict {new} kept")
        entity.verdict = new
        entity.verdict_at = utcnow()
        if VERDICT_RANK.get(new, 0) < VERDICT_RANK.get(old, 0):
            msgs.append(f"verdict lowered from {old} to {new}")
            n = _sync_bonus(db, entity)
            if n:
                msgs.append(f"severity lowered on {n} item(s)")
        if new == "malicious" and old != "malicious":
            from .. import webhooks

            db.flush()
            webhooks.on_ioc_malicious(db, entity)
            if auto_context and settings.get("context_on_malicious"):
                from .. import jobs

                jobs.run_now(jobs.run_context_lookup, entity.id)
        if entity.type == "ip":
            from ..intel.context import geo_from

            geo = geo_from(results)
            if geo:
                entity.meta = {**(entity.meta or {}), "geo": geo}
            entity.country = infra_country(entity, results) or entity.country or ""
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


# Providers that report where an IP is hosted, best first, and the key holding the country.
COUNTRY_KEYS = (("ipinfo", "country"), ("censys", "country"), ("shodan", "country"), ("virustotal", "country"),
                ("abuseipdb", "countryCode"), ("crowdsec", "country"), ("otx", "country"))


def infra_country(entity: Entity, results: list[LookupResult]) -> str:
    """Hosting country of an IP: offline GeoIP first (consistent), then the providers. ISO2 or ''."""
    from .. import geoip
    from ..gazetteer import normalise_country

    cc = geoip.country(entity.value)
    if cc:
        return cc
    by = {r.provider: r for r in results}
    for provider, key in COUNTRY_KEYS:
        r = by.get(provider)
        if r is not None:
            cc = normalise_country((r.data or {}).get(key))
            if cc:
                return cc
    return ""


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


def run_batch(db: Session, progress=None) -> str:
    """One enrichment pass. ``progress(done, total, phase)`` reports in-memory job progress."""
    progress = progress or (lambda *_: None)
    providers = available_providers()
    if not providers:
        return "no intel providers configured"
    batch = int(settings.get("enrichment_batch") or 8)
    since = utcnow() - FRESH_WINDOW
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
        extra_q = select(Entity).where(Entity.type.in_(IOC_TYPES), Entity.enriched_at.is_(None))
        if not settings.get("enrich_backfill"):
            # indicators only seen in backfilled history would burn the free quotas on old data
            live = select(ItemEntity.entity_id).join(Item, Item.id == ItemEntity.item_id).where(
                or_(Item.origin.is_(None), Item.origin != "backfill"))
            linked = select(EntityLink.dst_id).union(select(EntityLink.src_id))
            extra_q = extra_q.where(or_(Entity.id.in_(live), Entity.id.in_(linked)))
        extra = db.execute(extra_q.order_by(Entity.first_seen.desc()).limit(batch - len(iocs))).scalars()
        iocs += [e for e in extra if e not in iocs]
    # 4) stale verdicts: malicious / suspicious infrastructure whose verdict is older than verdict_recheck_days
    #    and that is still mentioned; the answer today replaces the old verdict (PM review 2026-11, item 5)
    stale: list[Entity] = []
    stale_days = int(settings.get("verdict_recheck_days") or 0)
    if stale_days:
        now = utcnow()
        sq = (select(Entity).where(Entity.type.in_(INFRA_TYPES), Entity.verdict.in_(("malicious", "suspicious")),
                                   verdict_given_at < now - timedelta(days=stale_days),
                                   Entity.last_seen >= now - STALE_RECHECK_SEEN)
              .order_by(verdict_given_at.asc()).limit(max(1, batch // 4)))
        stale = [e for e in db.execute(sq).scalars() if e not in iocs]
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
        rechecked = [e for e in db.execute(rq).scalars() if e not in iocs and e not in stale]
    done = 0
    fam_slots = 2 if settings.get("enrich_families") else 0
    todo = iocs + rechecked + stale
    total = len(todo) + fam_slots
    # every provider at its own pace, in parallel; then the verdicts are applied one indicator at a time
    answers = prefetch([(e.id, e.type, e.value) for e in todo], providers,
                       lambda d, t: progress(round(d / t * len(todo)), total, "lookups"))
    for ent in todo:
        enrich_entity(db, ent, providers, recheck=ent in stale, prefetched=answers.get(ent.id, {}))
        db.commit()
        done += 1
        progress(done, total, "indicators")
    fam_done = 0
    if fam_slots:
        progress(done, total, "families")
        from .trends import trending

        stale = utcnow() - timedelta(hours=24)
        for row in trending(db, "malware", limit=5):
            ent = db.get(Entity, row["id"])
            if ent and (ent.enriched_at is None or ent.enriched_at < stale):
                enrich_family(db, ent)
                db.commit()
                fam_done += 1
                progress(done + fam_done, total, "families")
                if fam_done >= 2:
                    break
    return (f"enriched {done} IOC(s) ({len(rechecked)} re-checked, {len(stale)} stale verdict(s)), "
            f"{fam_done} family(ies)")


def queue_status(db: Session) -> dict:
    """What the enrichment job has in front of it (PM review 2026-11, item 11), for the IOC page and Settings."""
    now = utcnow()
    live = select(ItemEntity.entity_id).join(Item, Item.id == ItemEntity.item_id).where(
        Item.published_at >= now - FRESH_WINDOW, func.coalesce(Item.origin, "live") != "backfill")
    pending = select(func.count(Entity.id), func.min(Entity.first_seen)).where(
        Entity.type.in_(IOC_TYPES), Entity.enriched_at.is_(None))
    waiting, oldest = db.execute(pending.where(Entity.id.in_(live))).one()
    never, _ = db.execute(pending).one()
    recheck = db.scalar(select(func.count(Entity.id)).where(
        Entity.type.in_(IOC_TYPES), Entity.enriched_at.is_not(None), Entity.last_seen >= now - RECHECK_MAX_AGE,
        or_(and_(Entity.verdict == "", Entity.enriched_at < now - RECHECK_ERROR_AFTER),
            and_(Entity.verdict == "unknown", Entity.enriched_at < now - RECHECK_UNKNOWN_AFTER)))) or 0
    stale_days = int(settings.get("verdict_recheck_days") or 0)
    stale = db.scalar(select(func.count(Entity.id)).where(
        Entity.type.in_(INFRA_TYPES), Entity.verdict.in_(("malicious", "suspicious")),
        verdict_given_at < now - timedelta(days=stale_days), Entity.last_seen >= now - STALE_RECHECK_SEEN)) or 0 \
        if stale_days else 0
    arrivals = round((db.scalar(select(func.count(Entity.id)).where(
        Entity.type.in_(IOC_TYPES), Entity.first_seen >= now - timedelta(days=7))) or 0) / 7)
    interval = max(2, int(settings.get("enrichment_interval") or 10))
    batch = int(settings.get("enrichment_batch") or 8)
    capacity = batch * (1440 // interval)
    return {
        "waiting": waiting or 0, "oldest": oldest, "oldest_days": (now - oldest).days if oldest else 0,
        "never": never or 0, "recheck": recheck, "stale": stale, "arrivals_per_day": arrivals,
        "capacity_per_day": capacity, "batch": batch, "interval": interval,
        "enabled": bool(settings.get("enrichment_enabled")), "behind": bool(waiting and arrivals > capacity),
    }
