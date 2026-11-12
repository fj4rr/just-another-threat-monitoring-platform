"""LLM-powered analyst features: item summaries, family briefs, daily digest, Q&A."""
from __future__ import annotations

import json
import re
from datetime import timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import settings
from ..knowledge import CATEGORIES, canonical_malware
from ..models import Enrichment, Entity, EntityLink, Insight, Item, ItemEntity, utcnow
from ..processing.extractor import Extracted
from ..processing.pipeline import link_entities
from ..processing import trends
from . import client

SYSTEM = (
    "You are a senior cyber threat intelligence analyst supporting a SOC. You write concise, "
    "factual, defender-oriented analysis for monitoring malware campaigns. Base every claim on "
    "the supplied source material; say so when information is missing instead of guessing. "
    "Never invent IOCs. Focus on detection and mitigation value."
)


def _lang() -> str:
    return settings.get("llm_language") or "English"


def _clip(s: str, n: int) -> str:
    s = re.sub(r"\s+", " ", s or "").strip()
    return s if len(s) <= n else s[:n] + "…"


def _json_from(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return {}


def summarize_item(db: Session, item: Item) -> str:
    ents = ", ".join(sorted({f"{l.entity.type}:{l.entity.display}" for l in item.entity_links})[:40])
    prompt = f"""Analyse this {item.kind} from "{item.source.name}" ({item.source.category}).

TITLE: {item.title}
PUBLISHED: {item.published_at:%Y-%m-%d}
AUTHOR: {item.author}
ENTITIES ALREADY EXTRACTED: {ents or 'none'}
CONTENT:
{_clip(item.content, 12000)}

Return two parts.
PART 1 – a JSON object on one line, keys:
  "malware": [{{"name": str, "category": one of {CATEGORIES}}}],  // families explicitly named in the text
  "actors": [str], "severity": 0-100 int, "tags": [str]  // e.g. phishing, clickfix, supply-chain
PART 2 – after a line containing only ---, a markdown brief in {_lang()} with:
  **TL;DR** (2 sentences), **Key points** (bullets), **Who/what is targeted**, **Delivery & TTPs**
  (map to MITRE ATT&CK IDs only when clear), **Detection & mitigation ideas** (bullets).
Keep it under 350 words."""
    out = client.complete(SYSTEM, prompt, max_tokens=2500)
    head, _, brief = out.partition("\n---")
    data = _json_from(head)
    brief = brief.strip() or out
    item.llm_summary = brief
    item.llm_at = utcnow()
    if data and settings.get("llm_auto_extract"):
        extra: list[Extracted] = []
        for m in data.get("malware") or []:
            name = (m.get("name") if isinstance(m, dict) else str(m)).strip()
            if not name or len(name) > 60 or name.lower() not in (item.title + item.content).lower():
                continue  # only accept names that actually appear in the text
            hit = canonical_malware(name)
            if hit:
                extra.append(Extracted("malware", hit[0].lower(), hit[0], hit[1], "llm"))
            else:
                cat = m.get("category", "other") if isinstance(m, dict) else "other"
                extra.append(Extracted("malware", name.lower(), name, cat if cat in CATEGORIES else "other", "llm"))
        for a in data.get("actors") or []:
            a = str(a).strip()
            if a and len(a) < 60 and a.lower() in (item.title + item.content).lower():
                extra.append(Extracted("actor", a.lower(), a, "", "llm"))
        if extra:
            link_entities(db, item, extra)
        if isinstance(data.get("severity"), int):
            item.severity = max(item.severity, min(100, data["severity"]))
        if data.get("tags"):
            item.tags = sorted(set((item.tags or []) + [str(t)[:40] for t in data["tags"][:10]]))
    return brief


def entity_brief(db: Session, entity: Entity) -> str:
    since = utcnow() - timedelta(days=60)
    items = db.execute(
        select(Item).join(ItemEntity, ItemEntity.item_id == Item.id)
        .where(ItemEntity.entity_id == entity.id, Item.published_at >= since)
        .order_by(Item.published_at.desc()).limit(25)
    ).unique().scalars().all()
    corpus = "\n".join(
        f"- [{i.published_at:%Y-%m-%d}] ({i.source.category}/{i.source.name}) {i.title} :: "
        f"{_clip(i.llm_summary or i.content, 600)}" for i in items
    )
    enr = db.execute(select(Enrichment).where(Enrichment.entity_id == entity.id)).scalars().all()
    enr_txt = "\n".join(f"- {e.provider}: {e.verdict} – {e.summary}" for e in enr) or "none"
    related = trends.co_occurring(db, entity.id, ("malware", "actor", "cve", "technique"), 15)
    rel_txt = ", ".join(f"{r['type']}:{r['name']}({r['count']})" for r in related) or "none"
    ioc_links = db.execute(
        select(Entity).join(EntityLink, or_(EntityLink.dst_id == Entity.id, EntityLink.src_id == Entity.id))
        .where(or_(EntityLink.src_id == entity.id, EntityLink.dst_id == entity.id), Entity.id != entity.id)
        .limit(30)
    ).scalars().all()
    ioc_txt = ", ".join(f"{e.type}:{e.display}[{e.verdict or '?'}]" for e in ioc_links) or "none"
    prompt = f"""Write a threat brief in {_lang()} about the {entity.type} "{entity.display}"
(category: {entity.category or 'n/a'}; first seen in our data {entity.first_seen:%Y-%m-%d},
{entity.mention_count} mentions).

RECENT COVERAGE ACROSS SOURCES (newest first):
{corpus or 'no recent items'}

THREAT-INTEL ENRICHMENT:
{enr_txt}

CO-OCCURRING ENTITIES: {rel_txt}
LINKED INDICATORS (sample): {ioc_txt}

Markdown sections: **Overview**, **Recent activity & campaigns** (what changed lately – cite dates
and sources), **Infection chain / TTPs**, **Targeting**, **Notable indicators** (only from the data
above), **Detection & hunting ideas**, **Assessment** (is activity rising? confidence level).
Max ~450 words."""
    out = client.complete(SYSTEM, prompt, max_tokens=3000)
    entity.llm_brief = out
    entity.llm_at = utcnow()
    return out


def daily_digest(db: Session, user_id: int | None = None) -> Insight:
    since = utcnow() - timedelta(hours=24)
    trend = trends.trending(db, "malware", limit=10)
    actors = trends.trending(db, "actor", limit=5)
    cves = trends.top_entities(db, "cve", days=2, limit=8)
    items = db.execute(
        select(Item).where(Item.published_at >= since).order_by(Item.severity.desc()).limit(30)
    ).scalars().all()
    lines = "\n".join(
        f"- ({i.source.category}/{i.source.name}, sev {i.severity}) {i.title} :: {_clip(i.llm_summary or i.content, 300)}"
        for i in items
    )
    prompt = f"""Produce today's threat-landscape digest in {_lang()} for a SOC team.

TRENDING MALWARE (score, recent mentions vs baseline, #sources, new?):
{json.dumps(trend, default=str)}
TRENDING ACTORS: {json.dumps(actors, default=str)}
MOST-DISCUSSED CVEs (48h): {json.dumps(cves, default=str)}
TOP ITEMS LAST 24H:
{lines or 'none'}

Markdown: **Headline** (1 sentence), **Top 5 things to know** (each: what, why it matters, source),
**Rising / new malware** (explain the trend), **Vulnerabilities to patch**, **Recommended actions today**.
Max ~500 words."""
    out = client.complete(SYSTEM, prompt, max_tokens=3500)
    ins = Insight(kind="digest", title=f"Daily digest {utcnow():%Y-%m-%d}", content=out,
                  model=f"{client.provider()}:{client.model_name()}", user_id=user_id)
    db.add(ins)
    return ins


def ask(db: Session, question: str, user_id: int | None = None) -> Insight:
    words = [w for w in re.findall(r"[\w\-\.]{3,}", question.lower()) if w not in
             {"what", "which", "the", "and", "about", "how", "are", "is", "this", "week", "today", "latest", "there"}]
    since = utcnow() - timedelta(days=30)
    q = select(Item).where(Item.published_at >= since)
    if words:
        q = q.where(or_(*[Item.title.ilike(f"%{w}%") for w in words[:8]],
                        *[Item.content.ilike(f"%{w}%") for w in words[:8]]))
    items = db.execute(q.order_by(Item.published_at.desc()).limit(25)).scalars().all()
    ctx = "\n".join(f"- [{i.published_at:%Y-%m-%d}] ({i.source.name}) {i.title} :: {_clip(i.llm_summary or i.content, 500)}"
                    for i in items)
    trend = trends.trending(db, "malware", limit=10)
    prompt = f"""Question from an analyst: {question}

Answer in {_lang()} using ONLY the context below (our collected data from the last 30 days).
If the context is insufficient, say what is missing.

TRENDING MALWARE: {json.dumps(trend, default=str)}
RELEVANT ITEMS:
{ctx or 'no matching items'}"""
    out = client.complete(SYSTEM, prompt, max_tokens=2500)
    ins = Insight(kind="answer", title=question[:500], content=out,
                  model=f"{client.provider()}:{client.model_name()}", user_id=user_id)
    db.add(ins)
    return ins
