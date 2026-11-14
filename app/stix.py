"""STIX 2.1 export (used by /api/v1/stix/... and the TAXII 2.1 server in routers/taxii.py).

Mapping
    item       -> report (published, description = AI summary or the start of the text, external reference,
                  TLP marking, object_refs = its entities)
    malware    -> malware (is_family, malware_types from the JATMP category)
    actor      -> intrusion-set
    cve        -> vulnerability (external reference cve)
    technique  -> attack-pattern (external reference mitre-attack)
    IOC        -> indicator (STIX pattern, valid_from = first seen, confidence, labels = verdict)
                  + relationship indicator --indicates--> malware for families linked by enrichment

IDs are UUIDv5 under a namespace derived from this install's secret, so the same object keeps its id across
exports (consumers update instead of duplicating) and two JATMP installs never collide. Only data allowed by
app/sharing.py is exported. Hand-built JSON (no ``stix2`` dependency); tests check the required properties.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import sharing
from .config import load_config
from .models import Entity, EntityLink, Item, ItemEntity, Source, utcnow

SPEC = "2.1"
MEDIA_TYPE = "application/stix+json;version=2.1"
# TLP marking definitions from the STIX 2.1 specification (section 7.2.1.4)
TLP = {
    "CLEAR": ("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", "white"),
    "GREEN": ("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da", "green"),
    "AMBER": ("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "amber"),
    "RED": ("marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", "red"),
}
MALWARE_TYPES = {
    "ransomware": "ransomware", "stealer": "spyware", "spyware": "spyware", "rat": "remote-access-trojan",
    "c2-framework": "remote-access-trojan", "loader": "downloader", "botnet": "bot", "banking": "trojan",
    "backdoor": "backdoor", "miner": "resource-exploitation", "rootkit": "rootkit", "worm": "worm",
    "exploit-kit": "exploit-kit", "wiper": "unknown",
}
IOC_TYPES = ("md5", "sha1", "sha256", "ip", "domain", "url")


def _namespace() -> uuid.UUID:
    seed = hashlib.sha256(("jatmp-stix:" + str(load_config().get("secret_key") or "")).encode()).hexdigest()
    return uuid.uuid5(uuid.NAMESPACE_URL, f"urn:jatmp:{seed[:32]}")


def ts(dt: datetime | None) -> str:
    return (dt or utcnow()).strftime("%Y-%m-%dT%H:%M:%S.") + f"{(dt or utcnow()).microsecond // 1000:03d}Z"


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def pattern(e: Entity) -> str | None:
    v = _esc(e.value)
    if e.type == "ip":
        return f"[{'ipv6-addr' if ':' in e.value else 'ipv4-addr'}:value = '{v}']"
    return {"domain": f"[domain-name:value = '{v}']", "url": f"[url:value = '{v}']",
            "md5": f"[file:hashes.MD5 = '{v}']", "sha1": f"[file:hashes.'SHA-1' = '{v}']",
            "sha256": f"[file:hashes.'SHA-256' = '{v}']"}.get(e.type)


def marking_object(level: str) -> dict:
    mid, name = TLP[level]
    return {"type": "marking-definition", "spec_version": SPEC, "id": mid, "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp", "name": f"TLP:{name.upper()}", "definition": {"tlp": name}}


class Bundle:
    def __init__(self):
        self.ns = _namespace()
        self.objects: dict[str, dict] = {}
        self.identity = self.sid("identity", "self")
        app = str(load_config().get("app_name") or "JATMP")
        self.objects[self.identity] = {
            "type": "identity", "spec_version": SPEC, "id": self.identity, "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z", "name": f"{app} (JATMP threat monitoring)",
            "identity_class": "system"}
        self._fam_cache: dict[int, list[Entity]] = {}

    def sid(self, stype: str, key: str) -> str:
        return f"{stype}--{uuid.uuid5(self.ns, f'{stype}:{key}')}"

    def _base(self, stype: str, key: str, created: datetime | None, modified: datetime | None) -> dict:
        c = created or utcnow()
        m = max(modified or c, c)
        return {"type": stype, "spec_version": SPEC, "id": self.sid(stype, key), "created": ts(c), "modified": ts(m),
                "created_by_ref": self.identity}

    def _mark(self, obj: dict, level: str) -> None:
        level = sharing.norm_tlp(level) or "CLEAR"
        self.objects.setdefault(TLP[level][0], marking_object(level))
        obj["object_marking_refs"] = [TLP[level][0]]

    def entity(self, e: Entity) -> str | None:
        key = f"entity:{e.type}:{e.value}"
        if e.type == "malware":
            o = self._base("malware", key, e.first_seen, e.last_seen)
            o.update(name=e.display or e.value, is_family=True,
                     malware_types=[MALWARE_TYPES.get(e.category or "", "unknown")])
        elif e.type == "actor":
            o = self._base("intrusion-set", key, e.first_seen, e.last_seen)
            o["name"] = e.display or e.value
        elif e.type == "cve":
            o = self._base("vulnerability", key, e.first_seen, e.last_seen)
            o.update(name=e.value.upper(), external_references=[{"source_name": "cve", "external_id": e.value.upper()}])
            desc = ((e.meta or {}).get("cvss") or {}).get("description")
            if desc:
                o["description"] = desc
        elif e.type == "technique":
            o = self._base("attack-pattern", key, e.first_seen, e.last_seen)
            o.update(name=e.display or e.value,
                     external_references=[{"source_name": "mitre-attack", "external_id": e.value.upper()}])
        elif e.type in IOC_TYPES:
            pat = pattern(e)
            if not pat:
                return None
            from .routers.api_v1 import _confidence

            verdict = (e.verdict or "unknown") if e.enriched_at else "pending"
            o = self._base("indicator", key, e.first_seen, e.enriched_at or e.last_seen)
            o.update(name=e.display or e.value, pattern=pat, pattern_type="stix", valid_from=ts(e.first_seen),
                     confidence=_confidence(e.verdict or "", bool(e.enriched_at), 1, 1), labels=[verdict])
            if verdict in ("malicious", "suspicious"):
                o["indicator_types"] = ["malicious-activity"]
            self._mark(o, "CLEAR")
        else:
            return None
        self.objects.setdefault(o["id"], o)
        return o["id"]

    def relationship(self, src: str, rel: str, dst: str, when: datetime | None = None) -> None:
        o = self._base("relationship", f"{src}|{rel}|{dst}", when, when)
        o.update(relationship_type=rel, source_ref=src, target_ref=dst)
        self.objects.setdefault(o["id"], o)

    def indicator_with_families(self, db: Session, e: Entity) -> str | None:
        iid = self.entity(e)
        if not iid:
            return None
        fams = db.execute(
            select(Entity).join(EntityLink, ((EntityLink.dst_id == Entity.id) & (EntityLink.src_id == e.id))
                                | ((EntityLink.src_id == Entity.id) & (EntityLink.dst_id == e.id)))
            .where(Entity.type == "malware")).scalars().all()
        for f in fams:
            fid = self.entity(f)
            self.relationship(iid, "indicates", fid, e.enriched_at or e.first_seen)
        return iid

    def item(self, db: Session, item: Item, shareable_iocs: set[int] | None = None) -> str:
        refs = []
        for link in item.entity_links:
            e = link.entity
            if e.type in IOC_TYPES:
                refs.append(self.indicator_with_families(db, e))
            else:
                refs.append(self.entity(e))
        refs = [r for r in dict.fromkeys(refs) if r] or [self.identity]
        o = self._base("report", f"item:{item.id}", item.collected_at, item.collected_at)
        o.update(name=item.title or "(untitled)", published=ts(item.published_at), report_types=["threat-report"],
                 description=(item.llm_summary or item.content or "")[:4000], object_refs=refs,
                 labels=[f"severity:{item.severity}", f"source-type:{item.source.category}"])
        if item.url:
            o["external_references"] = [{"source_name": item.source.name, "url": item.url}]
        self._mark(o, sharing.item_tlp(item))
        self.objects[o["id"]] = o
        return o["id"]

    def as_bundle(self) -> dict:
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(self.objects.values())}


# --------------------------------------------------------------------------- exports
def items_bundle(db: Session, since_days: int = 7, min_severity: int = 0, limit: int = 200) -> dict:
    from datetime import timedelta

    b = Bundle()
    stmt = (select(Item).join(Source, Source.id == Item.source_id).where(sharing.shareable_item_clause())
            .order_by(Item.collected_at.desc()).limit(limit))
    if since_days:
        stmt = stmt.where(Item.collected_at >= utcnow() - timedelta(days=since_days))
    if min_severity:
        stmt = stmt.where(Item.severity >= min_severity)
    for item in db.execute(stmt).unique().scalars():
        b.item(db, item)
    return b.as_bundle()


def item_bundle(db: Session, item: Item) -> dict:
    b = Bundle()
    b.item(db, item)
    return b.as_bundle()


def entity_bundle(db: Session, ent: Entity, max_iocs: int = 500) -> dict:
    from .routers.pages import _ioc_filter_for_entity

    b = Bundle()
    if ent.type in IOC_TYPES:
        b.indicator_with_families(db, ent)
    else:
        root = b.entity(ent)
        iocs = db.execute(select(Entity).where(Entity.type.in_(IOC_TYPES), _ioc_filter_for_entity(ent.id),
                                               sharing.shareable_entity_clause())
                          .order_by(Entity.last_seen.desc()).limit(max_iocs)).scalars().all()
        for e in iocs:
            iid = b.indicator_with_families(db, e)
            # enrichment attribution became "indicates" above; IOCs only seen in the same reports are weaker
            if iid and root and b.sid("relationship", f"{iid}|indicates|{root}") not in b.objects:
                b.relationship(iid, "related-to", root, e.first_seen)
    items = db.execute(select(Item).join(Source, Source.id == Item.source_id)
                       .join(ItemEntity, ItemEntity.item_id == Item.id)
                       .where(ItemEntity.entity_id == ent.id, sharing.shareable_item_clause())
                       .order_by(Item.published_at.desc()).limit(20)).unique().scalars().all()
    for item in items:
        b.item(db, item)
    return b.as_bundle()
