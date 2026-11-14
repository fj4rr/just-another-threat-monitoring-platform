"""Report builder: a "Threat Intel Findings" document for a date range, exported as PDF,
Word (.docx), Markdown or CSV.

Structure (PDF / Word / Markdown):
  1. Summary paragraph for the period
  2. Top findings – the highest-severity items, each written up with published time, severity,
     description, related malware / actors / CVEs and the link to the original
  3. Top malware families – type, mentions, sources that covered them, an example hash
  4. Top indicators of compromise – verdict, attributed family, where they were seen
  Appendix (optional) – collection statistics, threat actors, CVEs, newly seen families, AI digest

``gather()`` collects everything once into plain dicts; the exporters only format.
Word and PDF need the optional ``python-docx`` / ``reportlab`` packages (in requirements.txt).
"""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timedelta

from sqlalchemy import and_, distinct, func, or_, select, true
from sqlalchemy.orm import Session

from . import __version__
from .models import Entity, EntityLink, Insight, Item, ItemEntity, Source, utcnow
from .processing import trends

IOC_TYPES = trends.IOC_TYPES
HASH_TYPES = ("sha256", "sha1", "md5")
SECTIONS = {
    "findings": "Top findings (highest-severity items, written up)",
    "families": "Top malware families (type, sources, example hash)",
    "iocs": "Top indicators of compromise",
    "overview": "Appendix: collection statistics",
    "actors": "Appendix: threat actors",
    "cves": "Appendix: vulnerabilities (CVE)",
    "new": "Appendix: newly seen families",
    "digest": "Appendix: latest AI digest",
}
DEFAULT_COUNTS = {"findings": 3, "families": 10, "iocs": 20}
FORMATS = {"pdf": "PDF", "docx": "Word (.docx)", "md": "Markdown", "csv": "CSV"}
MIME = {
    "csv": "text/csv; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pdf": "application/pdf",
}
VERDICT_RANK = {"malicious": 0, "suspicious": 1, "unknown": 2, "pending": 2, "": 2, "clean": 3}


def _fmt(dt: datetime | None, with_time: bool = True) -> str:
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M UTC" if with_time else "%Y-%m-%d")


def period_label(since: datetime, until: datetime) -> str:
    """'5–12 Nov 2026', '28 Oct – 12 Nov 2026' or '12 Nov 2026' (until is exclusive)."""
    last = until - timedelta(seconds=1)
    if since.date() == last.date():
        return f"{since.day} {since:%b %Y}"
    if since.year == last.year and since.month == last.month:
        return f"{since.day}–{last.day} {last:%b %Y}"
    if since.year == last.year:
        return f"{since.day} {since:%b} – {last.day} {last:%b %Y}"
    return f"{since.day} {since:%b %Y} – {last.day} {last:%b %Y}"


def _plain(text: str, limit: int) -> str:
    """Markdown / whitespace-free excerpt, cut at a sentence boundary when possible."""
    t = re.sub(r"[*_#`>]+", "", text or "")
    t = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"\s+", " ", t).strip()
    if len(t) <= limit:
        return t
    cut = t[:limit]
    dot = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    return (cut[: dot + 1] if dot > limit * 0.5 else cut.rstrip() + "…")


def gather(db: Session, since: datetime, until: datetime, sections: set[str], *, counts: dict | None = None,
           ioc_verdicts: set[str] | None = None, title: str = "", min_sev: int = 0, region: str = "") -> dict:
    """Collect the report data. ``until`` is exclusive. ``region`` "id" limits it to the National (Indonesia) view."""
    from .processing.geo import region_clause

    counts = {**DEFAULT_COUNTS, **(counts or {})}
    days = max(1, round((until - since).total_seconds() / 86400))
    in_range = and_(Item.published_at >= since, Item.published_at < until)
    scope = region_clause(region)
    if scope is not None:
        in_range = and_(in_range, scope)
    ent_scope = trends._entities_in_region(region, since)
    ent_scope = ent_scope if ent_scope is not None else true()
    label = period_label(since, until)
    rep: dict = {
        "title": title or f"Threat Intel Findings {label}" + (" · Indonesia" if scope is not None else ""),
        "period": label, "region": "id" if scope is not None else "intl",
        "since": since, "until": until, "days": days, "generated": utcnow(), "version": __version__,
        "sections": [s for s in SECTIONS if s in sections], "counts": counts,
    }

    # ---- numbers used by the summary paragraph (always computed, cheap)
    total = db.scalar(select(func.count(Item.id)).where(in_range)) or 0
    by_cat = dict(db.execute(select(Source.category, func.count(Item.id)).join(Item, Item.source_id == Source.id)
                             .where(in_range).group_by(Source.category)).all())
    fam_count = db.scalar(select(func.count(distinct(ItemEntity.entity_id))).join(Item, Item.id == ItemEntity.item_id)
                          .join(Entity, Entity.id == ItemEntity.entity_id).where(in_range, Entity.type == "malware")) or 0
    new_fams = db.scalar(select(func.count(Entity.id)).where(Entity.type == "malware", Entity.first_seen >= since,
                                                             Entity.first_seen < until, ent_scope)) or 0
    ioc_count = db.scalar(select(func.count(Entity.id)).where(Entity.type.in_(IOC_TYPES), Entity.last_seen >= since,
                                                              Entity.last_seen < until, ent_scope)) or 0
    malicious = db.scalar(select(func.count(Entity.id)).where(Entity.type.in_(IOC_TYPES), Entity.verdict == "malicious",
                                                              Entity.last_seen >= since, Entity.last_seen < until,
                                                              ent_scope)) or 0
    high = db.scalar(select(func.count(Item.id)).where(in_range, Item.severity >= 60)) or 0
    cve_count = db.scalar(select(func.count(distinct(ItemEntity.entity_id))).join(Item, Item.id == ItemEntity.item_id)
                          .join(Entity, Entity.id == ItemEntity.entity_id).where(in_range, Entity.type == "cve")) or 0
    rep["stats"] = {"items": total, "by_category": {c: by_cat.get(c, 0) for c in ("news", "social", "intel")},
                    "families": fam_count, "new_families": new_fams, "iocs": ioc_count, "malicious": malicious,
                    "high_sev": high, "cves": cve_count}

    # ---- 1. top findings
    if "findings" in sections:
        items = db.execute(select(Item).where(in_range, Item.severity >= min_sev)
                           .order_by(Item.severity.desc(), Item.published_at.desc()).limit(counts["findings"] * 3)
                           ).unique().scalars().all()
        # avoid three near-identical headlines (syndicated stories): keep one per normalised title
        seen_titles: set[str] = set()
        findings = []
        for i in items:
            key = re.sub(r"\W+", " ", (i.title or "").lower()).strip()[:60]
            if key in seen_titles:
                continue
            seen_titles.add(key)
            ents = {"malware": [], "actor": [], "cve": []}
            for link in i.entity_links:
                if link.entity.type in ents and link.entity.display not in ents[link.entity.type]:
                    ents[link.entity.type].append(link.entity.display)
            findings.append({
                "id": i.id, "title": i.title or "(untitled)", "source": i.source.name, "category": i.source.category,
                "kind": i.kind, "published": i.published_at, "severity": i.severity, "url": i.url,
                "description": _plain(i.llm_summary or i.content or "", 650) or "No description available.",
                "malware": ents["malware"][:8], "actors": ents["actor"][:5], "cves": ents["cve"][:8],
                "reasons": [d for d in (i.severity_detail or []) if isinstance(d, dict) and d.get("label")][:6],
            })
            if len(findings) >= counts["findings"]:
                break
        rep["findings"] = findings

    # ---- 2. top malware families
    if "families" in sections:
        n = func.count(distinct(Item.id))
        rows = db.execute(
            select(Entity.id, Entity.display, Entity.category, Entity.first_seen, n, func.max(Item.severity))
            .join(ItemEntity, ItemEntity.entity_id == Entity.id).join(Item, Item.id == ItemEntity.item_id)
            .where(Entity.type == "malware", in_range).group_by(Entity.id).order_by(n.desc(), Entity.display)
            .limit(counts["families"])).all()
        ids = [r[0] for r in rows] or [0]
        srcs: dict[int, list[str]] = {}
        for eid, name in db.execute(
                select(ItemEntity.entity_id, Source.name).join(Item, Item.id == ItemEntity.item_id)
                .join(Source, Source.id == Item.source_id).where(ItemEntity.entity_id.in_(ids), in_range)
                .group_by(ItemEntity.entity_id, Source.name).order_by(func.count(Item.id).desc())).all():
            srcs.setdefault(eid, []).append(name)
        # example hash: a hash extracted from the same items (prefer sha256, then confirmed ones),
        # else one a provider attributed to the family
        other = ItemEntity.__table__.alias("other")
        hashes: dict[int, list[tuple[str, str, str]]] = {}
        for fid, h, typ, verdict in db.execute(
                select(ItemEntity.entity_id, Entity.value, Entity.type, Entity.verdict)
                .join(other, other.c.item_id == ItemEntity.item_id)
                .join(Entity, Entity.id == other.c.entity_id)
                .where(ItemEntity.entity_id.in_(ids), Entity.type.in_(HASH_TYPES))).all():
            hashes.setdefault(fid, []).append((h, typ, verdict or ""))
        for fid, h, typ, verdict in db.execute(
                select(EntityLink.dst_id, Entity.value, Entity.type, Entity.verdict)
                .join(Entity, Entity.id == EntityLink.src_id)
                .where(EntityLink.dst_id.in_(ids), Entity.type.in_(HASH_TYPES))).all():
            hashes.setdefault(fid, []).append((h, typ, verdict or ""))
        type_rank = {"sha256": 0, "sha1": 1, "md5": 2}
        families = []
        for eid, name, cat, first, mentions, maxsev in rows:
            cands = sorted(set(hashes.get(eid, [])), key=lambda t: (VERDICT_RANK.get(t[2], 2), type_rank[t[1]]))
            ex = cands[0] if cands else None
            families.append({"id": eid, "name": name, "category": cat or "other", "mentions": mentions,
                             "sources": srcs.get(eid, []), "max_severity": maxsev or 0,
                             "example_hash": ex[0] if ex else "", "example_hash_type": ex[1] if ex else "",
                             "example_hash_verdict": ex[2] if ex else "",
                             "is_new": bool(first and since <= first < until)})
        rep["families"] = families

    # ---- 3. top indicators
    if "iocs" in sections:
        q = select(Entity).where(Entity.type.in_(IOC_TYPES), Entity.last_seen >= since, Entity.last_seen < until)
        if ioc_verdicts:
            conds = [Entity.verdict.in_([v for v in ioc_verdicts if v != "pending"])]
            if "pending" in ioc_verdicts:
                conds.append(Entity.enriched_at.is_(None))
            q = q.where(or_(*conds))
        pool = db.execute(q.order_by(Entity.mention_count.desc(), Entity.last_seen.desc()).limit(max(200, counts["iocs"] * 10))
                          ).scalars().all()
        pool.sort(key=lambda e: (VERDICT_RANK.get((e.verdict or "") if e.enriched_at else "pending", 2),
                                 -(e.mention_count or 0), -(e.last_seen.timestamp() if e.last_seen else 0)))
        iocs = pool[:counts["iocs"]]
        ids = [e.id for e in iocs] or [0]
        fam: dict[int, set[str]] = {}
        for ioc_id, name in db.execute(select(EntityLink.src_id, Entity.display).join(Entity, Entity.id == EntityLink.dst_id)
                                       .where(EntityLink.src_id.in_(ids), Entity.type == "malware")).all():
            fam.setdefault(ioc_id, set()).add(name)
        for ioc_id, name in db.execute(select(EntityLink.dst_id, Entity.display).join(Entity, Entity.id == EntityLink.src_id)
                                       .where(EntityLink.dst_id.in_(ids), Entity.type == "malware")).all():
            fam.setdefault(ioc_id, set()).add(name)
        other = ItemEntity.__table__.alias("other")
        for ioc_id, name in db.execute(
                select(ItemEntity.entity_id, Entity.display).join(other, other.c.item_id == ItemEntity.item_id)
                .join(Entity, Entity.id == other.c.entity_id)
                .where(ItemEntity.entity_id.in_(ids), Entity.type == "malware")).all():
            fam.setdefault(ioc_id, set()).add(name)
        seen: dict[int, list[str]] = {}
        for ioc_id, name in db.execute(
                select(ItemEntity.entity_id, Source.name).join(Item, Item.id == ItemEntity.item_id)
                .join(Source, Source.id == Item.source_id).where(ItemEntity.entity_id.in_(ids))
                .group_by(ItemEntity.entity_id, Source.name)).all():
            seen.setdefault(ioc_id, []).append(name)
        for a, b, provider in db.execute(select(EntityLink.src_id, EntityLink.dst_id, EntityLink.provider)
                                         .where(or_(EntityLink.src_id.in_(ids), EntityLink.dst_id.in_(ids)))).all():
            for eid in (a, b):
                if eid in ids and provider and not seen.get(eid):
                    seen.setdefault(eid, []).append(provider)
        rep["iocs"] = [{
            "type": e.type, "value": e.value, "verdict": (e.verdict or "unknown") if e.enriched_at else "pending",
            "families": sorted(fam.get(e.id, ()))[:3], "seen_in": seen.get(e.id, [])[:3], "mentions": e.mention_count or 0,
            "first_seen": e.first_seen, "last_seen": e.last_seen,
        } for e in iocs]

    # ---- appendix
    if "overview" in sections:
        by_src = db.execute(select(Source.name, Source.category, func.count(Item.id)).join(Item, Item.source_id == Source.id)
                            .where(in_range).group_by(Source.id).order_by(func.count(Item.id).desc()).limit(15)).all()
        prev = and_(Item.published_at >= since - (until - since), Item.published_at < since)
        day = func.date(Item.published_at)
        rep["overview"] = {
            **rep["stats"],
            "items_prev": db.scalar(select(func.count(Item.id)).where(prev)) or 0,
            "actors": db.scalar(select(func.count(distinct(ItemEntity.entity_id))).join(Item, Item.id == ItemEntity.item_id)
                                .join(Entity, Entity.id == ItemEntity.entity_id).where(in_range, Entity.type == "actor")) or 0,
            "top_sources": [{"name": n_, "category": c, "count": k} for n_, c, k in by_src],
            "daily": [(str(d), k) for d, k in db.execute(select(day, func.count(Item.id)).where(in_range).group_by(day)
                                                         .order_by(day)).all()],
        }

    def _entity_table(etype: str, limit: int = 25) -> list[dict]:
        n = func.count(distinct(Item.id))
        rows = db.execute(
            select(Entity.id, Entity.display, Entity.first_seen, n, func.count(distinct(Item.source_id)), func.max(Item.severity))
            .join(ItemEntity, ItemEntity.entity_id == Entity.id).join(Item, Item.id == ItemEntity.item_id)
            .where(Entity.type == etype, in_range).group_by(Entity.id).order_by(n.desc()).limit(limit)).all()
        return [{"name": name, "mentions": k, "sources": s, "max_severity": m or 0,
                 "is_new": bool(first and since <= first < until)} for _eid, name, first, k, s, m in rows]

    if "actors" in sections:
        rep["actors"] = _entity_table("actor")
    if "cves" in sections:
        rep["cves"] = _entity_table("cve")
    if "new" in sections:
        rows = db.execute(select(Entity).where(Entity.type == "malware", Entity.first_seen >= since, Entity.first_seen < until)
                          .order_by(Entity.mention_count.desc()).limit(25)).scalars().all()
        rep["new"] = [{"name": e.display, "category": e.category or "other", "first_seen": e.first_seen,
                       "mentions": e.mention_count or 0} for e in rows]
    if "digest" in sections:
        d = db.execute(select(Insight).where(Insight.kind == "digest", Insight.created_at < until)
                       .order_by(Insight.created_at.desc()).limit(1)).scalar_one_or_none()
        rep["digest"] = {"title": d.title, "created": d.created_at, "model": d.model, "content": d.content} if d else None
    return rep


# --------------------------------------------------------------------------- shared text pieces
def summary_text(rep: dict) -> str:
    s = rep["stats"]
    bc = s["by_category"]
    parts = [f"Between {rep['period']} JATMP collected {s['items']} item(s) "
             f"({bc['news']} news, {bc['social']} social, {bc['intel']} threat-intel)."]
    if s["high_sev"]:
        parts.append(f"{s['high_sev']} item(s) scored 60 or higher on the severity scale.")
    if s["families"]:
        parts.append(f"{s['families']} malware famil{'y was' if s['families'] == 1 else 'ies were'} discussed"
                     + (f", {s['new_families']} of them seen for the first time." if s["new_families"] else "."))
    if s["cves"]:
        parts.append(f"{s['cves']} CVE(s) came up in the coverage.")
    if s["iocs"]:
        parts.append(f"{s['iocs']} indicator(s) were extracted or pulled in by enrichment"
                     + (f"; {s['malicious']} are confirmed malicious by at least one provider." if s["malicious"] else
                        "; none has been confirmed malicious yet."))
    return " ".join(parts)


def finding_meta(f: dict) -> str:
    return f"{_fmt(f['published'])} · {f['source']} ({f['category']}, {f['kind']}) · severity {f['severity']}/100"


def finding_related(f: dict) -> list[tuple[str, str]]:
    out = []
    if f["malware"]:
        out.append(("Related malware", ", ".join(f["malware"])))
    if f["actors"]:
        out.append(("Threat actors", ", ".join(f["actors"])))
    if f["cves"]:
        out.append(("Vulnerabilities", ", ".join(f["cves"])))
    if f["reasons"]:
        out.append(("Why it scored", ", ".join(f"{d['label']} ({d.get('points', 0):+d})" for d in f["reasons"]
                                                 if isinstance(d.get("points"), int))))
    return out


def family_rows(rep: dict) -> tuple[list[str], list[list]]:
    hdr = ["#", "Family", "Type", "Mentions", "Covered by", "Example hash"]
    rows = []
    for i, f in enumerate(rep.get("families", []), 1):
        src = ", ".join(f["sources"][:4]) + (f" +{len(f['sources']) - 4} more" if len(f["sources"]) > 4 else "")
        h = f["example_hash"]
        if h:
            h = f"{f['example_hash_type']}: {h}" + (f" [{f['example_hash_verdict']}]" if f["example_hash_verdict"] in ("malicious", "suspicious") else "")
        rows.append([i, f["name"] + (" (new)" if f["is_new"] else ""), f["category"], f["mentions"], src or "–", h or "–"])
    return hdr, rows


def ioc_rows(rep: dict) -> tuple[list[str], list[list]]:
    hdr = ["#", "Type", "Indicator", "Verdict", "Attributed family", "Seen in", "Last seen"]
    rows = [[i, r["type"], r["value"], r["verdict"], ", ".join(r["families"]) or "–", ", ".join(r["seen_in"]) or "–",
             _fmt(r["last_seen"], False)] for i, r in enumerate(rep.get("iocs", []), 1)]
    return hdr, rows


def appendix_tables(rep: dict) -> list[tuple[str, list[str], list[list]]]:
    out: list[tuple[str, list[str], list[list]]] = []
    if "overview" in rep:
        o = rep["overview"]
        out.append(("Collection statistics", ["Metric", "Value"], [
            ["Items collected", o["items"]], ["Items in the previous period", o["items_prev"]],
            ["news / social / intel", f"{o['by_category']['news']} / {o['by_category']['social']} / {o['by_category']['intel']}"],
            ["Items with severity ≥ 60", o["high_sev"]], ["Malware families mentioned", o["families"]],
            ["Families first seen in period", o["new_families"]], ["Threat actors mentioned", o["actors"]],
            ["CVEs discussed", o["cves"]], ["Indicators seen", o["iocs"]], ["Indicators confirmed malicious", o["malicious"]]]))
        out.append(("Most active sources", ["Source", "Type", "Items"], [[s["name"], s["category"], s["count"]] for s in o["top_sources"]]))
        out.append(("Daily volume", ["Day", "Items"], [list(r) for r in o["daily"]]))
    for key, label in (("actors", "Threat actors"), ("cves", "Vulnerabilities (CVE)")):
        if key in rep:
            out.append((label, ["Name", "Mentions", "Sources", "Max severity", "New"],
                        [[r["name"], r["mentions"], r["sources"], r["max_severity"], "yes" if r["is_new"] else ""] for r in rep[key]]))
    if "new" in rep:
        out.append(("Newly seen families", ["Family", "Type", "First seen", "Mentions"],
                    [[r["name"], r["category"], _fmt(r["first_seen"]), r["mentions"]] for r in rep["new"]]))
    return out


def _subtitle(rep: dict) -> str:
    return (f"Period {rep['period']} (UTC) · generated {rep['generated']:%Y-%m-%d %H:%M} UTC · "
            f"JATMP {rep['version']} · {rep['stats']['items']} items reviewed")


# --------------------------------------------------------------------------- Markdown
def to_markdown(rep: dict) -> bytes:
    def cell(v) -> str:
        return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")

    def table(hdr, rows):
        if not rows:
            return ["_nothing in this period_", ""]
        return ["| " + " | ".join(hdr) + " |", "|" + "|".join("---" for _ in hdr) + "|",
                *["| " + " | ".join(cell(c) for c in r) + " |" for r in rows], ""]

    lines = [f"# {rep['title']}", "", f"_{_subtitle(rep)}_", "", "## Summary", "", summary_text(rep), ""]
    if "findings" in rep:
        lines += ["## Top findings", ""]
        if not rep["findings"]:
            lines += ["_No items in this period._", ""]
        for i, f in enumerate(rep["findings"], 1):
            lines += [f"### {i}. {f['title']}", "", f"_{finding_meta(f)}_", "", f["description"], ""]
            lines += [f"- **{k}:** {v}" for k, v in finding_related(f)]
            if f["url"]:
                lines.append(f"- **Source:** <{f['url']}>")
            lines.append("")
    if "families" in rep:
        lines += [f"## Top {len(rep['families'])} malware families", ""] + table(*family_rows(rep))
    if "iocs" in rep:
        lines += [f"## Top {len(rep['iocs'])} indicators of compromise", ""] + table(*ioc_rows(rep))
    app = appendix_tables(rep)
    if app or "digest" in rep:
        lines += ["## Appendix", ""]
        for title, hdr, rows in app:
            lines += [f"### {title}", ""] + table(hdr, rows)
        if rep.get("digest"):
            d = rep["digest"]
            lines += [f"### Latest AI digest — {d['title']}", "", f"_{_fmt(d['created'])} · {d['model']}_", "", d["content"], ""]
        elif "digest" in rep:
            lines += ["### Latest AI digest", "", "_no digest available for this period_", ""]
    return "\n".join(lines).encode("utf-8")


# --------------------------------------------------------------------------- CSV
def to_csv(rep: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow([rep["title"]])
    w.writerow([_subtitle(rep)])
    w.writerow([summary_text(rep)])
    if "findings" in rep:
        w.writerow([])
        w.writerow(["## Top findings"])
        w.writerow(["#", "Published (UTC)", "Severity", "Title", "Source", "Type", "Description", "Related malware",
                    "Threat actors", "Vulnerabilities", "URL"])
        for i, f in enumerate(rep["findings"], 1):
            w.writerow([i, _fmt(f["published"]), f["severity"], f["title"], f["source"], f["category"], f["description"],
                        ", ".join(f["malware"]), ", ".join(f["actors"]), ", ".join(f["cves"]), f["url"]])
    for key, fn in (("families", family_rows), ("iocs", ioc_rows)):
        if key in rep:
            hdr, rows = fn(rep)
            w.writerow([])
            w.writerow([f"## Top {len(rows)} {'malware families' if key == 'families' else 'indicators of compromise'}"])
            w.writerow(hdr)
            w.writerows(rows)
    for title, hdr, rows in appendix_tables(rep):
        w.writerow([])
        w.writerow([f"## {title}"])
        w.writerow(hdr)
        w.writerows(rows)
    if rep.get("digest"):
        w.writerow([])
        w.writerow(["## Latest AI digest", rep["digest"]["title"], _fmt(rep["digest"]["created"]), rep["digest"]["model"]])
        for line in rep["digest"]["content"].splitlines():
            w.writerow([line])
    return ("\ufeff" + buf.getvalue()).encode("utf-8")


# --------------------------------------------------------------------------- Word
def to_docx(rep: dict) -> bytes:
    try:
        from docx import Document
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.shared import Pt, RGBColor
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("Word export needs the python-docx package: pip install python-docx") from e
    doc = Document()
    doc.styles["Normal"].font.size = Pt(10)
    muted = RGBColor(0x77, 0x76, 0x6F)

    def small(text: str, italic: bool = False):
        p = doc.add_paragraph()
        r = p.add_run(text)
        r.font.size, r.font.color.rgb, r.italic = Pt(8.5), muted, italic
        return p

    def table(hdr, rows, widths: list[float] | None = None):
        if not rows:
            small("Nothing in this period.")
            return
        t = doc.add_table(rows=1, cols=len(hdr))
        t.style = "Light Grid Accent 1"
        for i, h in enumerate(hdr):
            cell = t.rows[0].cells[i]
            cell.text = str(h)
            for p in cell.paragraphs:
                for r in p.runs:
                    r.font.bold, r.font.size = True, Pt(8.5)
        for row in rows[:400]:
            cells = t.add_row().cells
            for i, v in enumerate(row):
                cells[i].text = str(v if v is not None else "")
                for p in cells[i].paragraphs:
                    for r in p.runs:
                        r.font.size = Pt(8)
        doc.add_paragraph()

    doc.add_heading(rep["title"], 0)
    small(_subtitle(rep))
    doc.add_heading("Summary", 1)
    doc.add_paragraph(summary_text(rep))

    if "findings" in rep:
        doc.add_heading("Top findings", 1)
        if not rep["findings"]:
            doc.add_paragraph("No items were collected in this period.")
        for i, f in enumerate(rep["findings"], 1):
            doc.add_heading(f"{i}. {f['title']}", 2)
            small(finding_meta(f), italic=True)
            doc.add_paragraph(f["description"])
            for k, v in finding_related(f):
                p = doc.add_paragraph(style="List Bullet")
                p.add_run(f"{k}: ").bold = True
                p.add_run(v)
            if f["url"]:
                p = doc.add_paragraph(style="List Bullet")
                p.add_run("Original: ").bold = True
                _add_hyperlink(p, f["url"], f["url"])
    if "families" in rep:
        doc.add_heading(f"Top {len(rep['families'])} malware families", 1)
        doc.add_paragraph("Families ranked by the number of items that mentioned them in the period. "
                          "The example hash is a sample extracted from the same coverage or attributed by a provider.")
        table(*family_rows(rep))
    if "iocs" in rep:
        doc.add_heading(f"Top {len(rep['iocs'])} indicators of compromise", 1)
        doc.add_paragraph("Confirmed-malicious indicators first, then suspicious, then unverified ones; within a verdict "
                          "the most-mentioned indicators lead. Verdicts come from VirusTotal, OTX, urlscan and ANY.RUN enrichment.")
        table(*ioc_rows(rep))
    app = appendix_tables(rep)
    if app or "digest" in rep:
        doc.add_page_break()
        doc.add_heading("Appendix", 1)
        for title, hdr, rows in app:
            doc.add_heading(title, 2)
            table(hdr, rows)
        if rep.get("digest"):
            d = rep["digest"]
            doc.add_heading(f"Latest AI digest — {d['title']}", 2)
            small(f"{_fmt(d['created'])} · {d['model']}")
            for para in re.split(r"\n{2,}", d["content"]):
                doc.add_paragraph(re.sub(r"[*_#`]+", "", para).strip())
    p = small(f"Generated by JATMP {rep['version']} · severity and verdicts are heuristics for triage, not a vulnerability rating.")
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _add_hyperlink(paragraph, url: str, text: str) -> None:
    """python-docx has no public hyperlink API; build the w:hyperlink element by hand."""
    from docx.opc.constants import RELATIONSHIP_TYPE
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    part = paragraph.part
    r_id = part.relate_to(url, RELATIONSHIP_TYPE.HYPERLINK, is_external=True)
    link = OxmlElement("w:hyperlink")
    link.set(qn("r:id"), r_id)
    run = OxmlElement("w:r")
    rpr = OxmlElement("w:rPr")
    color = OxmlElement("w:color")
    color.set(qn("w:val"), "2A78D6")
    u = OxmlElement("w:u")
    u.set(qn("w:val"), "single")
    rpr.append(color)
    rpr.append(u)
    run.append(rpr)
    t = OxmlElement("w:t")
    t.text = text
    run.append(t)
    link.append(run)
    paragraph._p.append(link)


# --------------------------------------------------------------------------- PDF
def to_pdf(rep: dict) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("PDF export needs the reportlab package: pip install reportlab") from e
    from xml.sax.saxutils import escape

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=rep["title"], author=f"JATMP {rep['version']}")
    width = A4[0] - 32 * mm
    ss = getSampleStyleSheet()
    for h in ("Heading1", "Heading2"):
        ss[h].keepWithNext = True
    ink, muted_c, accent = colors.HexColor("#0b0b0b"), colors.HexColor("#77766f"), colors.HexColor("#2a78d6")
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9.5, leading=13, textColor=ink)
    meta = ParagraphStyle("meta", parent=body, fontSize=8, leading=10, textColor=muted_c)
    bullet = ParagraphStyle("bullet", parent=body, leftIndent=10, bulletIndent=0, spaceBefore=1)
    cellp = ParagraphStyle("cell", parent=body, fontSize=7.4, leading=9)
    cellh = ParagraphStyle("cellh", parent=cellp, fontName="Helvetica-Bold")
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=14, spaceBefore=10, spaceAfter=4, textColor=ink)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=11, spaceBefore=8, spaceAfter=2, textColor=ink)

    def table(hdr, rows, weights):
        if not rows:
            return [Paragraph("Nothing in this period.", meta)]
        total = sum(weights)
        data = [[Paragraph(escape(str(h)), cellh) for h in hdr]]
        for r in rows[:400]:
            data.append([Paragraph(escape(str(v if v is not None else "")), cellp) for v in r])
        t = Table(data, colWidths=[width * w_ / total for w_ in weights], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6e5e0")),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor("#8f8e86")),
            ("LINEBELOW", (0, 1), (-1, -1), 0.25, colors.HexColor("#d9d8d2")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f4")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        return [t]

    story = [Paragraph(escape(rep["title"]), ss["Title"]), Paragraph(escape(_subtitle(rep)), meta), Spacer(1, 6),
             Paragraph("Summary", h1), Paragraph(escape(summary_text(rep)), body)]
    if "findings" in rep:
        story.append(Paragraph("Top findings", h1))
        if not rep["findings"]:
            story.append(Paragraph("No items were collected in this period.", body))
        for i, f in enumerate(rep["findings"], 1):
            block = [Paragraph(escape(f"{i}. {f['title']}"), h2), Paragraph(escape(finding_meta(f)), meta), Spacer(1, 2),
                     Paragraph(escape(f["description"]), body)]
            for k, v in finding_related(f):
                block.append(Paragraph(f"<b>{escape(k)}:</b> {escape(v)}", bullet, bulletText="•"))
            if f["url"]:
                u = escape(f["url"])
                block.append(Paragraph(f'<b>Original:</b> <link href="{u}" color="#2a78d6">{u}</link>', bullet, bulletText="•"))
            block.append(Spacer(1, 6))
            story.append(KeepTogether(block))
    if "families" in rep:
        story += [Paragraph(f"Top {len(rep['families'])} malware families", h1),
                  Paragraph("Families ranked by the number of items that mentioned them in the period. The example hash is a "
                            "sample extracted from the same coverage or attributed by a provider.", meta), Spacer(1, 4)]
        story += table(*family_rows(rep), [0.3, 1.6, 1.1, 0.8, 2.4, 3.6])
    if "iocs" in rep:
        story += [Paragraph(f"Top {len(rep['iocs'])} indicators of compromise", h1),
                  Paragraph("Confirmed-malicious indicators first, then suspicious, then unverified ones; within a verdict the "
                            "most-mentioned lead. Verdicts come from VirusTotal, OTX, urlscan and ANY.RUN enrichment.", meta), Spacer(1, 4)]
        story += table(*ioc_rows(rep), [0.3, 0.7, 3.6, 0.9, 1.5, 1.7, 1.0])
    app = appendix_tables(rep)
    if app or "digest" in rep:
        story += [PageBreak(), Paragraph("Appendix", h1)]
        for title, hdr, rows in app:
            story.append(Paragraph(escape(title), h2))
            weights = [3 if h.lower() in ("metric", "source", "name", "family") else 1 for h in hdr]
            story += table(hdr, rows, weights)
            story.append(Spacer(1, 6))
        if rep.get("digest"):
            d = rep["digest"]
            story += [Paragraph(escape(f"Latest AI digest — {d['title']}"), h2), Paragraph(escape(f"{_fmt(d['created'])} · {d['model']}"), meta)]
            for para in re.split(r"\n{2,}", d["content"]):
                story.append(Paragraph(escape(re.sub(r"[*_#`]+", "", para).strip()).replace("\n", "<br/>"), body))
                story.append(Spacer(1, 3))
    story += [Spacer(1, 10), Paragraph(escape(f"Generated by JATMP {rep['version']} · severity and verdicts are heuristics for "
                                              "triage, not a vulnerability rating."), meta)]

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(muted_c)
        canvas.drawString(16 * mm, 9 * mm, rep["title"])
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {doc_.page}")
        canvas.setStrokeColor(accent)
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


EXPORTERS = {"csv": to_csv, "md": to_markdown, "docx": to_docx, "pdf": to_pdf}


def build(rep: dict, fmt: str) -> tuple[bytes, str, str]:
    """(bytes, filename, mime)"""
    fmt = fmt if fmt in EXPORTERS else "pdf"
    data = EXPORTERS[fmt](rep)
    name = f"threat-intel-findings-{rep['since']:%Y%m%d}-{(rep['until'] - timedelta(seconds=1)):%Y%m%d}.{fmt}"
    return data, name, MIME[fmt]
