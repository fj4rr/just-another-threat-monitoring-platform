"""Targeted clean-up of false IP and SHA-1 indicators already stored (``manage.py ioc-clean``).

``manage.py reextract`` rebuilds everything from the stored text, which loses entities of items whose text was
slimmed by retention and is far more than a rule fix needs. This looks only at ``regex`` links of ``ip`` and
``sha1`` entities (four-part version numbers, git commits) and removes a link when

* the value still appears in the item's text (so the text is there to judge), and
* the current extractor no longer produces it.

Links whose value is not in the stored text (slimmed items) are kept. Feed, LLM, knowledge-base and analyst-added
links are never touched. An entity that loses its last link and has no enrichment link is deleted.
"""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..models import Entity, EntityLink, Item, ItemEntity
from .extractor import extract_iocs, refang

TYPES = ("ip", "sha1")


def clean_false_iocs(db: Session, apply: bool = False, batch: int = 500, item_ids: list[int] | None = None) -> dict:
    q = (select(ItemEntity.id, ItemEntity.item_id, ItemEntity.entity_id, Entity.type, Entity.value)
         .join(Entity, Entity.id == ItemEntity.entity_id)
         .where(ItemEntity.origin == "regex", Entity.type.in_(TYPES)))
    if item_ids is not None:
        q = q.where(ItemEntity.item_id.in_(item_ids))
    rows = db.execute(q).all()
    by_item: dict[int, list] = defaultdict(list)
    for r in rows:
        by_item[r.item_id].append(r)
    drop: list[tuple[int, int]] = []  # (link id, entity id)
    kept_unjudged = 0
    ids = list(by_item)
    for c in range(0, len(ids), batch):
        for item in db.execute(select(Item).where(Item.id.in_(ids[c:c + batch]))).unique().scalars():
            text = f"{item.title}\n{item.content}\n{' '.join(item.tags or [])}"
            low = refang(text).lower()
            now = {(e.type, e.value) for e in extract_iocs(text, strict=item.source.category != "intel")}
            for r in by_item[item.id]:
                if (r.type, r.value) in now:
                    continue
                if r.value.lower() not in low:
                    kept_unjudged += 1  # text was trimmed: cannot tell
                    continue
                drop.append((r.id, r.entity_id))
        db.expunge_all()
    entities = {eid for _, eid in drop}
    out = {"links": len(drop), "entities_touched": len(entities), "kept_unjudged": kept_unjudged, "entities_deleted": 0}
    if not apply or not drop:
        return out
    link_ids = [lid for lid, _ in drop]
    for c in range(0, len(link_ids), 500):
        db.execute(delete(ItemEntity).where(ItemEntity.id.in_(link_ids[c:c + 500])))
    db.flush()
    ent_list = list(entities)
    for c in range(0, len(ent_list), 500):
        chunk = ent_list[c:c + 500]
        counts = dict(db.execute(select(ItemEntity.entity_id, func.count()).where(ItemEntity.entity_id.in_(chunk))
                                 .group_by(ItemEntity.entity_id)).all())
        linked = set(db.execute(select(EntityLink.src_id).where(EntityLink.src_id.in_(chunk))).scalars()) | \
            set(db.execute(select(EntityLink.dst_id).where(EntityLink.dst_id.in_(chunk))).scalars())
        for ent in db.execute(select(Entity).where(Entity.id.in_(chunk))).scalars():
            ent.mention_count = counts.get(ent.id, 0)
            if ent.mention_count == 0 and ent.id not in linked:
                db.delete(ent)
                out["entities_deleted"] += 1
    db.commit()
    return out
