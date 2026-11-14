"""Relationship graphs for the item and entity pages (rendered by static/js/graph.js).

Item graph:   item -> its entities (mentions) -> entities linked by enrichment (hash -> family, IOC from OTX)
              and other items that share those entities (ranked by trends.correlated_items).
Entity graph: entity -> enrichment links + co-mentioned families / actors / CVEs + recent items, with the
              edges between those items and the entities already on the canvas.
Both are capped (``limit`` nodes) so a heavily mentioned entity never produces an unreadable hairball;
``truncated`` tells the UI to offer "show more".
"""
from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..models import Entity, EntityLink, Item, ItemEntity
from . import trends

NAMED = ("malware", "actor", "cve", "technique")
_RANK = {"malicious": 0, "suspicious": 1}


def _ent_node(e: Entity, center: bool = False) -> dict:
    n = {"id": f"e{e.id}", "kind": e.type, "label": (e.display or e.value)[:64], "ref": f"/entities/{e.id}",
         "preview": f"/entities/{e.id}/preview", "center": center}
    if e.type in trends.IOC_TYPES:
        n["verdict"] = (e.verdict or "unknown") if e.enriched_at else "pending"
    return n


def _item_node(i: Item, center: bool = False) -> dict:
    return {"id": f"i{i.id}", "kind": "item", "label": (i.title or "(untitled)")[:80], "ref": f"/items/{i.id}",
            "preview": f"/items/{i.id}/preview", "severity": i.severity, "source": i.source.name, "center": center}


def _ent_sort(e: Entity):
    return (e.type not in NAMED, _RANK.get(e.verdict or "", 2), -(e.mention_count or 0))


class _Graph:
    def __init__(self, limit: int):
        self.limit = limit
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple[str, str], dict] = {}
        self.truncated = False

    def node(self, n: dict) -> bool:
        if n["id"] in self.nodes:
            return True
        if len(self.nodes) >= self.limit:
            self.truncated = True
            return False
        self.nodes[n["id"]] = n
        return True

    def edge(self, a: str, b: str, label: str, kind: str) -> None:
        if a in self.nodes and b in self.nodes and a != b and (a, b) not in self.edges and (b, a) not in self.edges:
            self.edges[(a, b)] = {"source": a, "target": b, "label": label, "kind": kind}

    def out(self) -> dict:
        return {"nodes": list(self.nodes.values()), "edges": list(self.edges.values()), "truncated": self.truncated,
                "limit": self.limit}


def _enrichment_links(db: Session, g: _Graph, ids: list[int], cap: int) -> None:
    if not ids:
        return
    links = db.execute(select(EntityLink).where(or_(EntityLink.src_id.in_(ids), EntityLink.dst_id.in_(ids)))
                       .limit(400)).scalars().all()
    other_ids = {lk.dst_id if lk.src_id in ids else lk.src_id for lk in links} - set(ids)
    others = {e.id: e for e in db.execute(select(Entity).where(Entity.id.in_(other_ids))).scalars()} if other_ids else {}
    added = 0
    for lk in sorted(links, key=lambda lk: _ent_sort(others.get(lk.dst_id if lk.src_id in ids else lk.src_id)
                                                     or Entity(type="zz", verdict=""))):
        here, there = (lk.src_id, lk.dst_id) if lk.src_id in ids else (lk.dst_id, lk.src_id)
        e = others.get(there)
        if e is None and f"e{there}" not in g.nodes:
            continue
        if f"e{there}" not in g.nodes:
            if added >= cap or not g.node(_ent_node(e)):
                g.truncated = True
                continue
            added += 1
        g.edge(f"e{here}", f"e{there}", f"{lk.relation} · {lk.provider}" if lk.provider else lk.relation, "enrichment")


def item_graph(db: Session, item: Item, limit: int = 60) -> dict:
    g = _Graph(limit)
    g.node(_item_node(item, center=True))
    links = sorted(item.entity_links, key=lambda lk: _ent_sort(lk.entity))
    ent_cap = max(8, int(limit * 0.45))
    ids = []
    for lk in links:
        if len(ids) >= ent_cap or not g.node(_ent_node(lk.entity)):
            g.truncated = True
            break
        ids.append(lk.entity_id)
        g.edge(f"i{item.id}", f"e{lk.entity_id}", "mentions" if lk.origin != "feed" else "listed by feed", "mention")
    _enrichment_links(db, g, ids, cap=max(4, int(limit * 0.25)))
    related = trends.correlated_items(db, item, limit=12)
    if related and ids:
        rel_ids = [r["item"].id for r in related]
        shared: dict[int, list[int]] = {}
        for iid, eid in db.execute(select(ItemEntity.item_id, ItemEntity.entity_id)
                                   .where(ItemEntity.item_id.in_(rel_ids), ItemEntity.entity_id.in_(ids))).all():
            shared.setdefault(iid, []).append(eid)
        for r in related:
            other = r["item"]
            if not g.node(_item_node(other)):
                break
            for eid in shared.get(other.id, []):
                g.edge(f"i{other.id}", f"e{eid}", "also mentions", "shared")
    return g.out()


def entity_graph(db: Session, ent: Entity, limit: int = 60) -> dict:
    g = _Graph(limit)
    g.node(_ent_node(ent, center=True))
    _enrichment_links(db, g, [ent.id], cap=max(6, int(limit * 0.4)))
    for c in trends.co_occurring(db, ent.id, ("malware", "actor", "cve"), max(4, int(limit * 0.2))):
        other = db.get(Entity, c["id"])
        if other is None or not g.node(_ent_node(other)):
            break
        g.edge(f"e{ent.id}", f"e{other.id}", f"co-mentioned ×{c['count']}", "comention")
    items = db.execute(select(Item).join(ItemEntity, ItemEntity.item_id == Item.id).where(ItemEntity.entity_id == ent.id)
                       .order_by(Item.severity.desc(), Item.published_at.desc()).limit(10)).unique().scalars().all()
    on_canvas = [int(k[1:]) for k in g.nodes if k.startswith("e")]
    for i in items:
        if not g.node(_item_node(i)):
            break
        g.edge(f"i{i.id}", f"e{ent.id}", "mentions", "mention")
    item_ids = [i.id for i in items if f"i{i.id}" in g.nodes]
    if item_ids:
        for iid, eid in db.execute(select(ItemEntity.item_id, ItemEntity.entity_id)
                                   .where(ItemEntity.item_id.in_(item_ids), ItemEntity.entity_id.in_(on_canvas))).all():
            g.edge(f"i{iid}", f"e{eid}", "mentions", "mention")
    return g.out()
