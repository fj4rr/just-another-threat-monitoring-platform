"""Report builder: curated threat-landscape report for a date range, exported as CSV,
Markdown, Word (.docx) or PDF.

``gather()`` collects everything once into plain dicts/lists; the exporters only format.
Word and PDF need the optional ``python-docx`` / ``reportlab`` packages (in requirements.txt).
"""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timedelta

from sqlalchemy import and_, distinct, func, or_, select
from sqlalchemy.orm import Session

from . import __version__
from .models import Entity, EntityLink, Insight, Item, ItemEntity, Source, utcnow
from .processing import trends

IOC_TYPES = trends.IOC_TYPES
SECTIONS = {
    "overview": "Overview & collection volume",
    "malware": "Trending malware families",
    "actors": "Threat actors",
    "cves": "Vulnerabilities (CVE)",
    "iocs": "Indicators of compromise",
    "items": "Notable items",
    "new": "Newly seen families",
    "digest": "Latest AI digest",
}
FORMATS = {"csv": "CSV", "md": "Markdown", "docx": "Word (.docx)", "pdf": "PDF"}
MIME = {
    "csv": "text/csv; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pdf": "application/pdf",
}


def _fmt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M") if dt else ""


def gather(db: Session, since: datetime, until: datetime, sections: set[str], *, min_sev: int = 40,
           ioc_verdicts: set[str] | None = None, limit: int = 50, title: str = "") -> dict:
    """Collect the report data. ``until`` is exclusive."""
    days = max(1, round((until - since).total_seconds() / 86400))
    in_range = and_(Item.published_at >= since, Item.published_at < until)
    rep: dict = {
        "title": title or "Threat landscape report",
        "since": since, "until": until, "days": days, "generated": utcnow(), "version": __version__,
        "sections": [s for s in SECTIONS if s in sections],
    }

    if "overview" in sections:
        total = db.scalar(select(func.count(Item.id)).where(in_range)) or 0
        by_cat = dict(db.execute(select(Source.category, func.count(Item.id)).join(Item, Item.source_id == Source.id)
                                 .where(in_range).group_by(Source.category)).all())
        by_src = db.execute(select(Source.name, Source.category, func.count(Item.id)).join(Item, Item.source_id == Source.id)
                            .where(in_range).group_by(Source.id).order_by(func.count(Item.id).desc()).limit(15)).all()
        prev = and_(Item.published_at >= since - (until - since), Item.published_at < since)
        rep["overview"] = {
            "items": total,
            "items_prev": db.scalar(select(func.count(Item.id)).where(prev)) or 0,
            "by_category": {c: by_cat.get(c, 0) for c in ("news", "social", "intel")},
            "families": db.scalar(select(func.count(distinct(ItemEntity.entity_id))).join(Item, Item.id == ItemEntity.item_id)
                                  .join(Entity, Entity.id == ItemEntity.entity_id)
                                  .where(in_range, Entity.type == "malware")) or 0,
            "new_families": db.scalar(select(func.count(Entity.id)).where(Entity.type == "malware", Entity.first_seen >= since,
                                                                           Entity.first_seen < until)) or 0,
            "actors": db.scalar(select(func.count(distinct(ItemEntity.entity_id))).join(Item, Item.id == ItemEntity.item_id)
                                .join(Entity, Entity.id == ItemEntity.entity_id).where(in_range, Entity.type == "actor")) or 0,
            "cves": db.scalar(select(func.count(distinct(ItemEntity.entity_id))).join(Item, Item.id == ItemEntity.item_id)
                              .join(Entity, Entity.id == ItemEntity.entity_id).where(in_range, Entity.type == "cve")) or 0,
            "iocs": db.scalar(select(func.count(Entity.id)).where(Entity.type.in_(IOC_TYPES), Entity.last_seen >= since,
                                                                 Entity.last_seen < until)) or 0,
            "malicious": db.scalar(select(func.count(Entity.id)).where(Entity.type.in_(IOC_TYPES), Entity.verdict == "malicious",
                                                                      Entity.last_seen >= since, Entity.last_seen < until)) or 0,
            "high_sev": db.scalar(select(func.count(Item.id)).where(in_range, Item.severity >= 60)) or 0,
            "top_sources": [{"name": n, "category": c, "count": k} for n, c, k in by_src],
            "daily": _daily(db, since, until),
        }

    def _entity_table(etype: str) -> list[dict]:
        recent = func.count(distinct(Item.id))
        rows = db.execute(
            select(Entity.id, Entity.display, Entity.category, Entity.first_seen, recent,
                   func.count(distinct(Item.source_id)), func.max(Item.severity))
            .join(ItemEntity, ItemEntity.entity_id == Entity.id).join(Item, Item.id == ItemEntity.item_id)
            .where(Entity.type == etype, in_range).group_by(Entity.id).order_by(recent.desc()).limit(limit)
        ).all()
        baseline_start = since - timedelta(days=30)
        base = dict(db.execute(
            select(ItemEntity.entity_id, func.count(distinct(Item.id))).join(Item, Item.id == ItemEntity.item_id)
            .where(ItemEntity.entity_id.in_([r[0] for r in rows] or [0]), Item.published_at >= baseline_start,
                   Item.published_at < since).group_by(ItemEntity.entity_id)).all())
        out = []
        for eid, name, cat, first, n, srcs, maxsev in rows:
            b = base.get(eid, 0)
            rate_now, rate_base = n / days, b / 30
            growth = round((rate_now + 0.1) / (rate_base + 0.1), 1)
            out.append({"id": eid, "name": name, "category": cat or "", "mentions": n, "sources": srcs,
                        "baseline": b, "growth": growth, "max_severity": maxsev or 0,
                        "is_new": bool(first and since <= first < until), "first_seen": first})
        out.sort(key=lambda d: (-d["mentions"], -d["growth"]))
        return out

    if "malware" in sections:
        rep["malware"] = _entity_table("malware")
    if "actors" in sections:
        rep["actors"] = _entity_table("actor")
    if "cves" in sections:
        rep["cves"] = _entity_table("cve")

    if "iocs" in sections:
        q = select(Entity).where(Entity.type.in_(IOC_TYPES), Entity.last_seen >= since, Entity.last_seen < until)
        if ioc_verdicts:
            if "pending" in ioc_verdicts:
                q = q.where(or_(Entity.verdict.in_([v for v in ioc_verdicts if v != "pending"]), Entity.enriched_at.is_(None)))
            else:
                q = q.where(Entity.verdict.in_(list(ioc_verdicts)))
        rank = {"malicious": 0, "suspicious": 1}
        iocs = db.execute(q.order_by(Entity.mention_count.desc(), Entity.last_seen.desc()).limit(limit * 10)).scalars().all()
        iocs.sort(key=lambda e: (rank.get(e.verdict or "", 2), -(e.mention_count or 0)))
        iocs = iocs[:limit * 4]
        ids = [e.id for e in iocs]
        fam: dict[int, set[str]] = {}
        if ids:
            for ioc_id, name in db.execute(
                    select(EntityLink.src_id, Entity.display).join(Entity, Entity.id == EntityLink.dst_id)
                    .where(EntityLink.src_id.in_(ids), Entity.type == "malware")).all():
                fam.setdefault(ioc_id, set()).add(name)
            for ioc_id, name in db.execute(
                    select(EntityLink.dst_id, Entity.display).join(Entity, Entity.id == EntityLink.src_id)
                    .where(EntityLink.dst_id.in_(ids), Entity.type == "malware")).all():
                fam.setdefault(ioc_id, set()).add(name)
        rep["iocs"] = [{
            "type": e.type, "value": e.value, "verdict": (e.verdict or "pending") if e.enriched_at else "pending",
            "families": ", ".join(sorted(fam.get(e.id, ()))), "mentions": e.mention_count or 0,
            "first_seen": e.first_seen, "last_seen": e.last_seen,
        } for e in iocs]

    if "items" in sections:
        items = db.execute(select(Item).where(in_range, Item.severity >= min_sev)
                           .order_by(Item.severity.desc(), Item.published_at.desc()).limit(limit)).unique().scalars().all()
        rep["items"] = [{
            "id": i.id, "title": i.title, "source": i.source.name, "category": i.source.category, "kind": i.kind,
            "published": i.published_at, "severity": i.severity, "url": i.url,
            "entities": ", ".join(sorted({link.entity.display for link in i.entity_links
                                          if link.entity.type in ("malware", "actor", "cve")}))[:300],
            "reasons": ", ".join(f"{d.get('label')} {d.get('points'):+d}" for d in (i.severity_detail or [])
                                 if isinstance(d, dict) and isinstance(d.get("points"), int)),
            "summary": re.sub(r"\s+", " ", i.llm_summary or i.content or "")[:400],
        } for i in items]
        rep["min_sev"] = min_sev

    if "new" in sections:
        rows = db.execute(select(Entity).where(Entity.type == "malware", Entity.first_seen >= since, Entity.first_seen < until)
                          .order_by(Entity.mention_count.desc()).limit(limit)).scalars().all()
        rep["new"] = [{"name": e.display, "category": e.category or "", "first_seen": e.first_seen,
                       "mentions": e.mention_count or 0} for e in rows]

    if "digest" in sections:
        d = db.execute(select(Insight).where(Insight.kind == "digest", Insight.created_at < until)
                       .order_by(Insight.created_at.desc()).limit(1)).scalar_one_or_none()
        rep["digest"] = {"title": d.title, "created": d.created_at, "model": d.model, "content": d.content} if d else None
    return rep


def _daily(db: Session, since: datetime, until: datetime) -> list[tuple[str, int]]:
    day = func.date(Item.published_at)
    rows = db.execute(select(day, func.count(Item.id)).where(Item.published_at >= since, Item.published_at < until)
                      .group_by(day).order_by(day)).all()
    return [(str(d), n) for d, n in rows]


# --------------------------------------------------------------------------- tabular view shared by exporters
def tables(rep: dict) -> list[tuple[str, list[str], list[list]]]:
    """[(section title, header, rows)] – the common shape for CSV, Word and PDF."""
    out: list[tuple[str, list[str], list[list]]] = []
    if "overview" in rep:
        o = rep["overview"]
        out.append(("Overview", ["Metric", "Value"], [
            ["Items collected", o["items"]], ["Items in previous period", o["items_prev"]],
            ["  news / social / intel", f"{o['by_category']['news']} / {o['by_category']['social']} / {o['by_category']['intel']}"],
            ["Items with severity ≥ 60", o["high_sev"]], ["Malware families mentioned", o["families"]],
            ["Families first seen in period", o["new_families"]], ["Threat actors mentioned", o["actors"]],
            ["CVEs discussed", o["cves"]], ["Indicators seen", o["iocs"]], ["Indicators confirmed malicious", o["malicious"]],
        ]))
        out.append(("Top sources", ["Source", "Type", "Items"], [[s["name"], s["category"], s["count"]] for s in o["top_sources"]]))
        out.append(("Daily volume", ["Day", "Items"], [list(r) for r in o["daily"]]))
    for key, label in (("malware", "Trending malware families"), ("actors", "Threat actors"), ("cves", "Vulnerabilities (CVE)")):
        if key in rep:
            hdr = ["Name", "Category", "Mentions", "Sources", "Baseline (30d)", "Growth ×", "Max severity", "New"]
            rows = [[r["name"], r["category"], r["mentions"], r["sources"], r["baseline"], r["growth"], r["max_severity"],
                     "yes" if r["is_new"] else ""] for r in rep[key]]
            if key != "malware":
                hdr.pop(1)
                rows = [row[:1] + row[2:] for row in rows]
            out.append((label, hdr, rows))
    if "new" in rep:
        out.append(("Newly seen families", ["Family", "Category", "First seen", "Mentions"],
                    [[r["name"], r["category"], _fmt(r["first_seen"]), r["mentions"]] for r in rep["new"]]))
    if "iocs" in rep:
        out.append(("Indicators of compromise", ["Type", "Indicator", "Verdict", "Attributed family", "Mentions", "First seen", "Last seen"],
                    [[r["type"], r["value"], r["verdict"], r["families"], r["mentions"], _fmt(r["first_seen"]), _fmt(r["last_seen"])]
                     for r in rep["iocs"]]))
    if "items" in rep:
        out.append((f"Notable items (severity ≥ {rep.get('min_sev', 0)})",
                    ["Published", "Severity", "Title", "Source", "Type", "Entities", "Why", "URL"],
                    [[_fmt(r["published"]), r["severity"], r["title"], r["source"], r["category"], r["entities"], r["reasons"], r["url"]]
                     for r in rep["items"]]))
    return out


# --------------------------------------------------------------------------- CSV
def to_csv(rep: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow([rep["title"]])
    w.writerow([f"Period {rep['since']:%Y-%m-%d} to {rep['until'] - timedelta(seconds=1):%Y-%m-%d} (UTC)",
                f"generated {rep['generated']:%Y-%m-%d %H:%M} UTC", f"JATMP {rep['version']}"])
    for title, hdr, rows in tables(rep):
        w.writerow([])
        w.writerow([f"## {title}"])
        w.writerow(hdr)
        for r in rows:
            w.writerow(r)
    if rep.get("digest"):
        w.writerow([])
        w.writerow(["## Latest AI digest", rep["digest"]["title"], _fmt(rep["digest"]["created"]), rep["digest"]["model"]])
        for line in rep["digest"]["content"].splitlines():
            w.writerow([line])
    return ("\ufeff" + buf.getvalue()).encode("utf-8")


# --------------------------------------------------------------------------- Markdown
def to_markdown(rep: dict) -> bytes:
    def cell(v) -> str:
        return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")

    lines = [f"# {rep['title']}", "",
             f"Period **{rep['since']:%Y-%m-%d}** to **{rep['until'] - timedelta(seconds=1):%Y-%m-%d}** (UTC) · "
             f"generated {rep['generated']:%Y-%m-%d %H:%M} UTC · JATMP {rep['version']}", ""]
    for title, hdr, rows in tables(rep):
        lines += [f"## {title}", ""]
        if not rows:
            lines += ["_nothing in this period_", ""]
            continue
        lines.append("| " + " | ".join(hdr) + " |")
        lines.append("|" + "|".join("---" for _ in hdr) + "|")
        lines += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
        lines.append("")
    if rep.get("digest"):
        d = rep["digest"]
        lines += [f"## Latest AI digest — {d['title']}", "", f"_{_fmt(d['created'])} UTC · {d['model']}_", "", d["content"], ""]
    elif "digest" in rep:
        lines += ["## Latest AI digest", "", "_no digest available for this period_", ""]
    return "\n".join(lines).encode("utf-8")


# --------------------------------------------------------------------------- Word
def to_docx(rep: dict) -> bytes:
    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
        from docx.shared import Pt
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("Word export needs the python-docx package: pip install python-docx") from e
    doc = Document()
    sec = doc.sections[0]
    sec.orientation = WD_ORIENT.LANDSCAPE
    sec.page_width, sec.page_height = sec.page_height, sec.page_width
    style = doc.styles["Normal"]
    style.font.size = Pt(9)
    doc.add_heading(rep["title"], 0)
    doc.add_paragraph(f"Period {rep['since']:%Y-%m-%d} to {rep['until'] - timedelta(seconds=1):%Y-%m-%d} (UTC) · "
                      f"generated {rep['generated']:%Y-%m-%d %H:%M} UTC · JATMP {rep['version']}")
    for title, hdr, rows in tables(rep):
        doc.add_heading(title, 1)
        if not rows:
            doc.add_paragraph("Nothing in this period.")
            continue
        t = doc.add_table(rows=1, cols=len(hdr))
        t.style = "Light Grid Accent 1"
        for i, h in enumerate(hdr):
            t.rows[0].cells[i].text = str(h)
        for r in rows[:400]:
            cells = t.add_row().cells
            for i, v in enumerate(r):
                cells[i].text = str(v if v is not None else "")
    if rep.get("digest"):
        d = rep["digest"]
        doc.add_heading(f"Latest AI digest — {d['title']}", 1)
        doc.add_paragraph(f"{_fmt(d['created'])} UTC · {d['model']}")
        for para in re.split(r"\n{2,}", d["content"]):
            doc.add_paragraph(re.sub(r"[*_#`]+", "", para).strip())
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# --------------------------------------------------------------------------- PDF
def to_pdf(rep: dict) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("PDF export needs the reportlab package: pip install reportlab") from e
    from xml.sax.saxutils import escape

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=14 * mm, rightMargin=14 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm, title=rep["title"], author=f"JATMP {rep['version']}")
    ss = getSampleStyleSheet()
    ss["Heading2"].keepWithNext = True  # never leave a section title alone at the bottom of a page
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=8, leading=10, alignment=TA_LEFT)
    cellp = ParagraphStyle("cell", parent=body, fontSize=7.2, leading=8.6)
    story = [Paragraph(escape(rep["title"]), ss["Title"]),
             Paragraph(escape(f"Period {rep['since']:%Y-%m-%d} to {rep['until'] - timedelta(seconds=1):%Y-%m-%d} (UTC) · "
                              f"generated {rep['generated']:%Y-%m-%d %H:%M} UTC · JATMP {rep['version']}"), body),
             Spacer(1, 6)]
    width = landscape(A4)[0] - 28 * mm
    for title, hdr, rows in tables(rep):
        story.append(Paragraph(escape(title), ss["Heading2"]))
        if not rows:
            story.append(Paragraph("Nothing in this period.", body))
            continue
        # column widths: long text columns get more room
        weights = [3 if h.lower() in ("title", "indicator", "entities", "why", "url", "metric", "source", "name", "family", "attributed family")
                   else 1 for h in hdr]
        total = sum(weights)
        widths = [width * w_ / total for w_ in weights]
        data = [[Paragraph(f"<b>{escape(str(h))}</b>", cellp) for h in hdr]]
        for r in rows[:400]:
            data.append([Paragraph(escape(str(v if v is not None else "")), cellp) for v in r])
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6e5e0")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#b5b4ad")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f4f1")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(KeepTogether([t]) if len(rows) < 8 else t)
        story.append(Spacer(1, 8))
    if rep.get("digest"):
        d = rep["digest"]
        story += [PageBreak(), Paragraph(escape(f"Latest AI digest — {d['title']}"), ss["Heading2"]),
                  Paragraph(escape(f"{_fmt(d['created'])} UTC · {d['model']}"), body), Spacer(1, 4)]
        for para in re.split(r"\n{2,}", d["content"]):
            story.append(Paragraph(escape(re.sub(r"[*_#`]+", "", para).strip()).replace("\n", "<br/>"), body))
            story.append(Spacer(1, 3))
    doc.build(story)
    return buf.getvalue()


EXPORTERS = {"csv": to_csv, "md": to_markdown, "docx": to_docx, "pdf": to_pdf}


def build(rep: dict, fmt: str) -> tuple[bytes, str, str]:
    """(bytes, filename, mime)"""
    fmt = fmt if fmt in EXPORTERS else "csv"
    data = EXPORTERS[fmt](rep)
    name = f"jatmp-report-{rep['since']:%Y%m%d}-{(rep['until'] - timedelta(seconds=1)):%Y%m%d}.{fmt}"
    return data, name, MIME[fmt]
