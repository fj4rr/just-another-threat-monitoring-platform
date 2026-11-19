"""Analyst corrections (PM review 2026-11, item 6): the platform's rules make mistakes, analysts fix them, and the
fix sticks.

Four kinds, each with a reason, an audit trail (this table, plus the audit log) and an undo:

=================  ======================  =====================================================================
kind               target                  effect
=================  ======================  =====================================================================
``unlink``         item + entity           "Wrong entity here": the link is removed and the item re-scored
``false_positive`` entity                  "Not a threat / wrong entity everywhere": every link is removed, no new
                                           link is made, an indicator becomes *clean*
``verdict``        indicator (+ value)     The analyst's verdict (malicious / suspicious / clean) wins over the
                                           provider consensus; the items' enrichment bonus follows it
``not_scam``       item                    "Not a scam report": fraud score 0, scam types / brands / identifiers off
=================  ======================  =====================================================================

The corrections stay in force: ``pipeline.link_entities`` skips blocked links (re-extraction, AI extraction, the
ThreatFox merge), ``fraud.apply`` honours ``not_scam`` (re-analysis after an upgrade), and enrichment keeps an
analyst verdict. They are also the labelled data of the quality report (``app/quality.py``, item 18).
"""
from __future__ import annotations

import threading
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Correction, Entity, Item, ItemEntity, User, utcnow

KINDS = ("unlink", "false_positive", "verdict", "not_scam")
VERDICTS = ("malicious", "suspicious", "clean")
IOC_TYPES = ("md5", "sha1", "sha256", "ip", "domain", "url")
MAX_STORED_LINKS = 20_000  # links a false positive removed, kept for its undo

# Every ingest asks "is this link blocked?": the active corrections are few, so they are held in memory and
# reloaded after a change in this process or at most every CACHE_TTL seconds.
CACHE_TTL = 30.0
_cache: dict = {"at": 0.0}
_lock = threading.Lock()


class CorrectionError(ValueError):
    pass


def invalidate() -> None:
    with _lock:
        _cache["at"] = 0.0


def _state(db: Session) -> dict:
    with _lock:
        if time.monotonic() - _cache["at"] < CACHE_TTL:
            return _cache
    fp: set[int] = set()
    unlinked: dict[int, set[int]] = {}
    not_scam: set[int] = set()
    for kind, item_id, entity_id in db.execute(
            select(Correction.kind, Correction.item_id, Correction.entity_id).where(Correction.active)):
        if kind == "false_positive" and entity_id:
            fp.add(entity_id)
        elif kind == "unlink" and item_id and entity_id:
            unlinked.setdefault(item_id, set()).add(entity_id)
        elif kind == "not_scam" and item_id:
            not_scam.add(item_id)
    with _lock:
        _cache.update(at=time.monotonic(), fp=fp, unlinked=unlinked, not_scam=not_scam)
        return _cache


def blocked_entities(db: Session, item_id: int | None) -> set[int]:
    """Entity ids that must not be linked to ``item_id``: false positives everywhere, unlinks on this item."""
    st = _state(db)
    if not st["fp"] and not st["unlinked"]:
        return set()
    return st["fp"] | st["unlinked"].get(item_id or 0, set())


def is_not_scam(db: Session, item_id: int | None) -> bool:
    return bool(item_id) and item_id in _state(db)["not_scam"]


# --------------------------------------------------------------------------- effects
def rescore_item(db: Session, item: Item) -> None:
    """Severity of one item from its text and the entities still linked, keeping bonus and AI points."""
    from .processing.extractor import Extracted
    from .processing.severity import carry_over, reasons_to_json, score_item

    db.flush()
    rows = db.execute(select(Entity.type, Entity.verdict, ItemEntity.origin)
                      .join(ItemEntity, ItemEntity.entity_id == Entity.id).where(ItemEntity.item_id == item.id)).all()
    score, reasons = score_item(item.title, f"{item.content}\n{' '.join(item.tags or [])}",
                                [Extracted(t, "", "", "", o or "") for t, _, o in rows], item.kind)
    item.severity, item.severity_detail = carry_over(score, reasons_to_json(reasons), item.severity_detail,
                                                     [(t, v) for t, v, _ in rows])


def _set_verdict(db: Session, ent: Entity, new: str, analyst: dict | None) -> None:
    """Give ``ent`` a verdict and keep the items' enrichment bonus in line with it."""
    from .processing.enrichment import VERDICT_RANK, _bump_items, _sync_bonus

    old = ent.verdict or ""
    ent.verdict, ent.verdict_at = new, (utcnow() if new else None)
    if new:
        ent.enriched_at = ent.enriched_at or utcnow()
    meta = {k: v for k, v in (ent.meta or {}).items() if k != "analyst"}
    ent.meta = {**meta, "analyst": analyst} if analyst else meta
    if VERDICT_RANK.get(new, 0) > VERDICT_RANK.get(old, 0):
        _bump_items(db, ent, old, new)
        if new == "malicious" and old != "malicious":
            from . import webhooks

            db.flush()
            webhooks.on_ioc_malicious(db, ent)
    elif VERDICT_RANK.get(new, 0) < VERDICT_RANK.get(old, 0):
        _sync_bonus(db, ent)


def _remove_links(db: Session, ent: Entity, item_ids: list[int] | None = None) -> list[list]:
    """Delete links of ``ent`` (all, or on ``item_ids``); returns [[item id, origin], ...] for the undo."""
    q = select(ItemEntity).where(ItemEntity.entity_id == ent.id)
    if item_ids is not None:
        q = q.where(ItemEntity.item_id.in_(item_ids))
    removed = []
    for link in db.execute(q).scalars().all():
        removed.append([link.item_id, link.origin or ""])
        db.delete(link)
    ent.mention_count = max(0, (ent.mention_count or 0) - len(removed))
    db.flush()
    for (iid, _) in removed:
        item = db.get(Item, iid)
        if item is not None:
            rescore_item(db, item)
    return removed


def _restore_links(db: Session, ent: Entity, links: list[list]) -> int:
    have = {iid for (iid,) in db.execute(select(ItemEntity.item_id).where(ItemEntity.entity_id == ent.id))}
    n = 0
    for iid, origin in links:
        if iid in have or db.get(Item, iid) is None:
            continue
        db.add(ItemEntity(item_id=iid, entity_id=ent.id, origin=origin or "regex"))
        n += 1
    ent.mention_count = (ent.mention_count or 0) + n
    db.flush()
    for iid, _ in links:
        item = db.get(Item, iid)
        if item is not None:
            rescore_item(db, item)
    return n


# --------------------------------------------------------------------------- create / undo
def create(db: Session, user: User | None, kind: str, *, item_id: int | None = None, entity_id: int | None = None,
           value: str = "", reason: str = "") -> Correction:
    """Record a correction and apply it. Raises CorrectionError for an impossible request. Caller commits."""
    if kind not in KINDS:
        raise CorrectionError(f"unknown kind {kind!r}")
    reason = (reason or "").strip()[:1000]
    item = db.get(Item, item_id) if item_id else None
    ent = db.get(Entity, entity_id) if entity_id else None
    if kind in ("unlink", "not_scam") and item is None:
        raise CorrectionError("item not found")
    if kind in ("unlink", "false_positive", "verdict") and ent is None:
        raise CorrectionError("entity not found")
    active = select(Correction).where(Correction.active, Correction.kind == kind)
    corr = Correction(kind=kind, item_id=item.id if item else None, entity_id=ent.id if ent else None,
                      value=value, reason=reason, user_id=user.id if user else None,
                      username=user.username if user else "", data={})

    if kind == "unlink":
        if not db.execute(select(ItemEntity.id).where(ItemEntity.item_id == item.id,
                                                      ItemEntity.entity_id == ent.id)).first():
            raise CorrectionError(f"{ent.display} is not linked to this item")
        corr.data = {"links": _remove_links(db, ent, [item.id]), "entity": ent.display, "type": ent.type,
                     "value": ent.value,
                     "item": (item.title or "")[:200]}
    elif kind == "false_positive":
        if db.execute(active.where(Correction.entity_id == ent.id)).first():
            raise CorrectionError(f"{ent.display} is already marked as not a threat")
        links = _remove_links(db, ent)
        corr.data = {"links": links[:MAX_STORED_LINKS], "entity": ent.display, "type": ent.type, "value": ent.value,
                     "prev_verdict": ent.verdict or "", "prev_verdict_at": _iso(ent.verdict_at)}
        if ent.type in IOC_TYPES:
            _set_verdict(db, ent, "clean", {"verdict": "clean", "by": corr.username, "reason": reason,
                                            "at": _iso(utcnow())})
        ent.meta = {**(ent.meta or {}), "false_positive": {"by": corr.username, "at": _iso(utcnow()),
                                                           "reason": reason}}
    elif kind == "verdict":
        if ent.type not in IOC_TYPES:
            raise CorrectionError("verdicts are for indicators (IPs, domains, URLs, hashes)")
        if value not in VERDICTS:
            raise CorrectionError(f"verdict must be one of {', '.join(VERDICTS)}")
        for prev in db.execute(active.where(Correction.entity_id == ent.id)).scalars():  # the newest one counts
            prev.active, prev.undone_at, prev.undone_by = False, utcnow(), f"replaced by {corr.username}"
        corr.data = {"entity": ent.display, "type": ent.type, "prev_verdict": ent.verdict or "",
                     "prev_verdict_at": _iso(ent.verdict_at), "prev_analyst": (ent.meta or {}).get("analyst")}
        _set_verdict(db, ent, value, {"verdict": value, "by": corr.username, "reason": reason, "at": _iso(utcnow())})
    elif kind == "not_scam":
        if db.execute(active.where(Correction.item_id == item.id)).first():
            raise CorrectionError("this item is already marked as not a scam report")
        corr.data = {"item": (item.title or "")[:200], "prev_score": item.fraud_score or 0}
    db.add(corr)
    db.flush()
    invalidate()
    if kind == "not_scam":
        from .processing import fraud

        fraud.retag_item(db, item)  # fraud.apply sees the correction: score 0, the scam entities go
        rescore_item(db, item)
    return corr


def undo(db: Session, corr: Correction, user: User | None) -> None:
    """Withdraw a correction and restore what it changed. Caller commits."""
    if not corr.active:
        raise CorrectionError("this correction is no longer active")
    corr.active, corr.undone_at, corr.undone_by = False, utcnow(), user.username if user else ""
    db.flush()
    invalidate()
    ent = db.get(Entity, corr.entity_id) if corr.entity_id else None
    data = corr.data or {}
    if corr.kind in ("unlink", "false_positive") and ent is not None:
        _restore_links(db, ent, data.get("links") or [])
    if corr.kind == "false_positive" and ent is not None:
        ent.meta = {k: v for k, v in (ent.meta or {}).items() if k != "false_positive"}
        if ent.type in IOC_TYPES:
            _set_verdict(db, ent, data.get("prev_verdict") or "", None)
    if corr.kind == "verdict" and ent is not None:
        _set_verdict(db, ent, data.get("prev_verdict") or "", data.get("prev_analyst"))
    if corr.kind == "not_scam":
        item = db.get(Item, corr.item_id)
        if item is not None:
            from .processing import fraud

            fraud.retag_item(db, item)
            rescore_item(db, item)


def _iso(dt) -> str | None:
    return dt.isoformat(timespec="seconds") if dt else None


# --------------------------------------------------------------------------- what the corrections say
def stats(db: Session, days: int = 30) -> dict:
    """Corrections per kind, the most corrected entities (rules to tune) and the error rates analysts reported."""
    from datetime import timedelta

    from sqlalchemy import func

    since = utcnow() - timedelta(days=days)
    rows = db.execute(select(Correction).where(Correction.created_at >= since)).scalars().all()
    per_kind = {k: sum(1 for c in rows if c.kind == k and c.active) for k in KINDS}
    hot: dict[tuple[str, str], int] = {}
    for c in rows:
        if c.active and c.kind in ("unlink", "false_positive"):
            key = ((c.data or {}).get("type", ""), (c.data or {}).get("entity", ""))
            hot[key] = hot.get(key, 0) + (len((c.data or {}).get("links") or []) if c.kind == "false_positive" else 1)
    linked = dict(db.execute(
        select(Entity.type, func.count(ItemEntity.id)).join(ItemEntity, ItemEntity.entity_id == Entity.id)
        .join(Item, Item.id == ItemEntity.item_id).where(Item.collected_at >= since).group_by(Entity.type)).all())
    removed: dict[str, int] = {}
    for c in rows:
        if c.active and c.kind in ("unlink", "false_positive"):
            t = (c.data or {}).get("type", "")
            removed[t] = removed.get(t, 0) + len((c.data or {}).get("links") or [])
    scam_reports = db.scalar(select(func.count(Item.id)).where(Item.collected_at >= since, Item.fraud_score > 0)) or 0
    rates = []
    for label, types in (("Malware families", ("malware",)), ("Threat actors", ("actor",)), ("CVEs", ("cve",)),
                         ("Indicators", IOC_TYPES), ("Scam types and brands", ("scam_type", "brand")),
                         ("Sectors", ("sector",))):
        bad = sum(removed.get(t, 0) for t in types)
        total = sum(linked.get(t, 0) for t in types) + bad
        if total:
            rates.append({"label": label, "removed": bad, "total": total, "pct": round(100 * bad / total, 1)})
    not_scam = per_kind["not_scam"]
    if scam_reports or not_scam:
        rates.append({"label": "Scam reports", "removed": not_scam, "total": scam_reports + not_scam,
                      "pct": round(100 * not_scam / (scam_reports + not_scam), 1)})
    return {"days": days, "per_kind": per_kind, "rates": rates,
            "hot": sorted(({"type": t, "name": n, "count": k} for (t, n), k in hot.items()),
                          key=lambda r: -r["count"])[:15]}


def describe(c: Correction) -> str:
    """One sentence for the log and the item / entity pages."""
    d = c.data or {}
    who = c.username or "an analyst"
    name = d.get("entity") or "the entity"
    if c.kind == "unlink":
        text = f"{name} ({d.get('type', '')}) removed from this item by {who}"
    elif c.kind == "false_positive":
        what = "not a threat" if d.get("type") in IOC_TYPES else "a wrong entity"
        text = f"{name} marked {what} by {who}; {len(d.get('links') or [])} link(s) removed"
    elif c.kind == "verdict":
        text = f"{name}: analyst verdict {c.value} by {who} (was {d.get('prev_verdict') or 'not looked up'})"
    else:
        text = f"marked not a scam report by {who} (fraud score was {d.get('prev_score', 0)})"
    return text + (f": “{c.reason}”" if c.reason else "")
