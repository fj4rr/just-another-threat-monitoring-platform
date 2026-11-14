"""What may leave JATMP: the REST API, IOC export feeds, webhooks and MISP pushes all go through here.

Two independent rules:

* **TLP.** Every item has an effective TLP: its own (OTX pulses and MISP events carry one), else the
  source's, else CLEAR. Only items at or below the ``api_max_tlp`` setting (default GREEN) are shared.
* **Redistribution.** Some providers' terms forbid passing their data on (ANY.RUN, VirusTotal, commercial
  dark-web feeds). Items from a source with ``redistribute = False`` are never shared (by default every
  ANY.RUN collector), and provider *details* (verdict summaries, raw data) only leave when an admin turns
  on ``api_share_provider_details``. JATMP's own consensus verdict is always shareable.

An indicator is shareable when at least one shareable item mentions it, or when it was linked by a
provider whose data may be redistributed (OTX, abuse.ch, MISP).
"""
from __future__ import annotations

from sqlalchemy import and_, case, func, or_, select

from . import settings
from .models import Entity, EntityLink, Item, ItemEntity, Source

TLP_LEVELS = ("CLEAR", "GREEN", "AMBER", "RED")
_ALIASES = {"WHITE": "CLEAR", "AMBER+STRICT": "AMBER"}
NO_REDISTRIBUTE_KINDS = {"anyrun", "ransomwarelive"}  # provider terms; victim names stay in-house
# enrichment providers whose indicator relationships may be passed on
REDISTRIBUTABLE_PROVIDERS = ("otx", "threatfox", "malwarebazaar", "urlhaus", "misp")


def norm_tlp(value) -> str:
    """'tlp:amber', 'white', 'Amber+Strict' -> CLEAR | GREEN | AMBER | RED, or '' when unknown."""
    v = str(value or "").strip().upper()
    if v.startswith("TLP:"):
        v = v[4:]
    v = _ALIASES.get(v, v)
    return v if v in TLP_LEVELS else ""


def rank(tlp: str) -> int:
    return TLP_LEVELS.index(norm_tlp(tlp) or "CLEAR")


def max_rank() -> int:
    return rank(settings.get("api_max_tlp") or "GREEN")


def source_redistributable(src: Source) -> bool:
    if src.redistribute is not None:
        return bool(src.redistribute)
    return src.kind not in NO_REDISTRIBUTE_KINDS


def item_tlp(item: Item) -> str:
    return norm_tlp(item.tlp) or norm_tlp(item.source.tlp if item.source else "") or "CLEAR"


def item_shareable(item: Item) -> bool:
    return source_redistributable(item.source) and rank(item_tlp(item)) <= max_rank()


def share_provider_details() -> bool:
    return bool(settings.get("api_share_provider_details"))


# ---------------------------------------------------------------- SQL versions (for list endpoints / feeds)
def _tlp_rank_expr():
    eff = func.upper(func.coalesce(func.nullif(Item.tlp, ""), func.nullif(Source.tlp, ""), "CLEAR"))
    return case((eff.in_(("RED",)), 3), (eff.in_(("AMBER", "AMBER+STRICT")), 2), (eff.in_(("GREEN",)), 1), else_=0)


def _redistributable_source():
    return or_(Source.redistribute.is_(True),
               and_(Source.redistribute.is_(None), Source.kind.not_in(NO_REDISTRIBUTE_KINDS)))


def shareable_item_clause():
    """WHERE clause for a query that already joins Item to Source."""
    return and_(_redistributable_source(), _tlp_rank_expr() <= max_rank())


def shareable_item_ids():
    return select(Item.id).join(Source, Source.id == Item.source_id).where(shareable_item_clause())


def shareable_entity_clause():
    """Indicators backed by at least one shareable item or a redistributable provider link."""
    linked = select(EntityLink.dst_id).where(EntityLink.provider.in_(REDISTRIBUTABLE_PROVIDERS)).union(
        select(EntityLink.src_id).where(EntityLink.provider.in_(REDISTRIBUTABLE_PROVIDERS)))
    return or_(Entity.id.in_(select(ItemEntity.entity_id).where(ItemEntity.item_id.in_(shareable_item_ids()))),
               Entity.id.in_(linked))
