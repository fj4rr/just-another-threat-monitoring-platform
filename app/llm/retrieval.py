"""Which items answer an analyst's question (PM review 2026-11, item 13, first steps).

Q&A used to match the question word by word (``LIKE``) against titles and text: "ransomware attacks on hospitals"
found nothing when the articles said "LockBit hit a healthcare provider". ``find_items`` now combines:

* **entities named in the question**: families, actors, CVEs and indicators (the extractor, aliases included),
  scam types and impersonated brands (the fraud rules);
* **concepts**: a malware category ("ransomware", "stealer", "pencuri data"), a critical infrastructure sector
  ("hospital", "rumah sakit", "bank"), or a question about scams in general;
* **words**: the full-text index (FTS5 / PostgreSQL), each word on its own, so an item does not have to contain
  every word of the question;
* **the period** the question names ("today", "minggu ini", "this month"), else 30 days.

Each item gets a score (entities weigh most, then concepts, then words, title words a little more), copies of a
syndicated story are left out (the counting rule), and the best items go to the model numbered [1]…[n], which it
cites. Semantic search with embeddings is a later step.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Entity, Item, ItemEntity, utcnow
from ..search import item_text_clause

DEFAULT_DAYS = 30
MAX_ITEMS = 25
CANDIDATES_PER_SIGNAL = 300
W_ENTITY, W_CONCEPT, W_WORD, W_TITLE = 4.0, 2.0, 1.0, 0.5

_STOP = """
what which who whom whose when where why how the and or but about are is was were be been being this that these
those there their they them it its any some all have has had with from for into onto over under our ours we us me
my you your tell show list give does did do can could would should may might will shall new recent latest last
week weeks today yesterday month months year years day days now currently current please explain describe summary
summarise summarize anything something happened happening seen see mentioned report reports reported item items
apa yang dan atau ini itu ada saja siapa kapan mana bagaimana berapa minggu hari bulan tahun terbaru terkini terkait
tentang dengan untuk dari pada di ke oleh sudah belum apakah adakah tolong jelaskan sebutkan ringkas ringkasan
berita laporan kami kita saya anda mereka sebuah suatu banyak beberapa sedang telah akan bisa dapat terhadap mengenai
against regarding concerning involving related
"""
STOPWORDS = frozenset(re.split(r"\s+", _STOP.strip()))

# malware category words, English and Indonesian -> knowledge.CATEGORIES
CATEGORY_WORDS = [
    (r"ransomware|pemerasan data", "ransomware"),
    (r"(?:info)?stealers?|pencuri (?:data|kredensial|password)|password stealer", "stealer"),
    (r"\brats?\b|remote access trojans?", "rat"),
    (r"\bloaders?\b|droppers?", "loader"),
    (r"botnets?", "botnet"),
    (r"banking (?:trojans?|malware)|trojan perbankan|malware perbankan", "banking"),
    (r"backdoors?|pintu belakang", "backdoor"),
    (r"wipers?|penghapus data", "wiper"),
    (r"(?:crypto)?miners?|cryptojacking|penambang", "miner"),
    (r"spyware|stalkerware|mata-mata", "spyware"),
    (r"rootkits?", "rootkit"),
    (r"\bworms?\b", "worm"),
]
_CATEGORY_RX = [(re.compile(rx, re.I), cat) for rx, cat in CATEGORY_WORDS]
_SCAM_RX = re.compile(r"\bscams?\b|\bfraud\w*|penipuan|penipu|\bmodus\b|phishing|phising|investasi bodong|pinjol", re.I)
# the period a question names: (pattern, days)
_PERIODS = [
    (re.compile(r"\btoday\b|\bhari ini\b|last 24 hours|24 jam", re.I), 1),
    (re.compile(r"\bthis week\b|\bpast week\b|\blast week\b|\bminggu ini\b|\bseminggu\b|7 days|7 hari", re.I), 7),
    (re.compile(r"\bthis month\b|\bbulan ini\b|30 days|30 hari", re.I), 30),
    (re.compile(r"\b(?:last|past) (?:three|3) months\b|\b3 bulan\b|90 days|90 hari|this quarter", re.I), 90),
    (re.compile(r"\bthis year\b|\btahun ini\b|\blast year\b|\b12 months\b|365 days", re.I), 365),
]
_WORD = re.compile(r"[\w][\w.\-]{2,}", re.UNICODE)


@dataclass
class Retrieval:
    items: list[Item]
    days: int
    entities: list[str] = field(default_factory=list)  # names matched in the question
    concepts: list[str] = field(default_factory=list)  # "ransomware (category)", "Health (sector)", "scams"
    words: list[str] = field(default_factory=list)

    def matched(self) -> dict:
        return {"entities": self.entities, "concepts": self.concepts, "words": self.words, "days": self.days}


def period_days(question: str) -> int:
    for rx, days in _PERIODS:
        if rx.search(question):
            return days
    return DEFAULT_DAYS


def keywords(question: str) -> list[str]:
    out: list[str] = []
    for w in _WORD.findall(question.lower()):
        w = w.strip(".-")
        if len(w) >= 3 and w not in STOPWORDS and not w.isdigit() and w not in out:
            out.append(w)
    return out[:8]


def _question_entities(db: Session, question: str) -> tuple[list[int], list[str]]:
    """Entity ids (and names) the question names: extractor entities, scam types, brands."""
    from ..processing import fraud
    from ..processing.extractor import extract_all

    wanted = {(e.type, e.value): e.display for e in extract_all(question, strict=False)
              if e.type not in ("sector",)}
    for key, name, *_ in fraud.scam_types(question, ""):
        wanted.setdefault(("scam_type", key), name)
    for name, _cat in fraud.brands(question, ""):
        wanted.setdefault(("brand", name.lower()), name)
    ids, names = [], []
    for (etype, value), display in wanted.items():
        ent = db.execute(select(Entity.id, Entity.display).where(Entity.type == etype, Entity.value == value)).first()
        if ent:
            ids.append(ent[0])
            names.append(ent[1] or display)
    return ids, names


def _concepts(question: str) -> tuple[list[str], list[str], bool]:
    """Malware categories and sectors the question is about, and whether it asks about scams."""
    from ..processing import sectors

    cats = [cat for rx, cat in _CATEGORY_RX if rx.search(question)]
    secs = [k for k, rx, cs in sectors._RX if sectors._hits(rx, cs, question)]
    return list(dict.fromkeys(cats)), secs, bool(_SCAM_RX.search(question))


def find_items(db: Session, question: str, limit: int = MAX_ITEMS) -> Retrieval:
    from ..processing.sectors import SECTOR_NAMES

    days = period_days(question)
    since = utcnow() - timedelta(days=days)
    base = select(Item.id).where(Item.published_at >= since, Item.dup_of.is_(None))
    score: dict[int, float] = defaultdict(float)

    ent_ids, ent_names = _question_entities(db, question)
    if ent_ids:
        for iid, _ent in db.execute(
                select(ItemEntity.item_id, ItemEntity.entity_id).join(Item, Item.id == ItemEntity.item_id)
                .where(ItemEntity.entity_id.in_(ent_ids), Item.published_at >= since, Item.dup_of.is_(None))
                .limit(CANDIDATES_PER_SIGNAL * len(ent_ids))).all():
            score[iid] += W_ENTITY

    cats, secs, scam = _concepts(question)
    concepts = [f"{c} (malware type)" for c in cats] + [f"{SECTOR_NAMES[s]} (sector)" for s in secs]
    if scam:
        concepts.append("scam reports")
    concept_q = []
    if cats:
        concept_q.append(select(ItemEntity.item_id).join(Entity, Entity.id == ItemEntity.entity_id)
                         .where(Entity.type == "malware", Entity.category.in_(cats)))
    if secs:
        concept_q.append(select(ItemEntity.item_id).join(Entity, Entity.id == ItemEntity.entity_id)
                         .where(Entity.type == "sector", Entity.value.in_(secs)))
    for sub in concept_q:
        for (iid,) in db.execute(base.where(Item.id.in_(sub)).order_by(Item.published_at.desc())
                                 .limit(CANDIDATES_PER_SIGNAL)):
            score[iid] += W_CONCEPT
    if scam:
        for (iid,) in db.execute(base.where(Item.fraud_score > 0).order_by(Item.fraud_score.desc())
                                 .limit(CANDIDATES_PER_SIGNAL)):
            score[iid] += W_CONCEPT

    words = keywords(question)
    for w in words:
        for (iid,) in db.execute(base.where(item_text_clause(w)).order_by(Item.published_at.desc())
                                 .limit(CANDIDATES_PER_SIGNAL)):
            score[iid] += W_WORD

    if not score:  # nothing matched: the most severe recent items, so the model can say what is there
        rows = db.execute(base.order_by(Item.severity.desc(), Item.published_at.desc()).limit(limit)).all()
        score = {iid: 0.0 for (iid,) in rows}
    top = sorted(score, key=lambda i: -score[i])[:limit * 3]
    items = db.execute(select(Item).where(Item.id.in_(top))).unique().scalars().all()
    for it in items:  # words in the title say more than words somewhere in the text
        title = (it.title or "").lower()
        score[it.id] += W_TITLE * sum(1 for w in words if w in title)
    items.sort(key=lambda it: (-score[it.id], -(it.severity or 0), -it.published_at.timestamp()))
    return Retrieval(items=items[:limit], days=days, entities=ent_names, concepts=concepts, words=words)
