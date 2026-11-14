"""Report builder page and download endpoint."""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from .. import reports
from ..auth import audit, current_user, verify_csrf
from ..db import get_db
from ..models import User, utcnow
from ..web import current_region, render

router = APIRouter(prefix="/reports")
PRESETS = [(1, "Last 24 hours"), (7, "Last 7 days"), (14, "Last 14 days"), (30, "Last 30 days"), (90, "Last 90 days")]


def _parse_range(preset: str, start: str, end: str) -> tuple[datetime, datetime]:
    """Either a preset (days back from now) or an explicit start / end date (inclusive, UTC)."""
    now = utcnow()
    if start or end:
        try:
            since = datetime.strptime(start, "%Y-%m-%d") if start else now - timedelta(days=30)
            until = (datetime.strptime(end, "%Y-%m-%d") + timedelta(days=1)) if end else now
        except ValueError as e:
            raise HTTPException(400, "dates must be YYYY-MM-DD") from e
    else:
        try:
            days = min(max(int(preset or 7), 1), 3650)
        except ValueError:
            days = 7
        since, until = now - timedelta(days=days), now
    if until <= since:
        raise HTTPException(400, "the end date must be after the start date")
    if until - since > timedelta(days=3650):
        raise HTTPException(400, "range too large")
    return since, min(until, now + timedelta(days=1))


@router.get("")
def report_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return render(request, "reports.html", {
        "user": user, "sections": reports.SECTIONS, "formats": reports.FORMATS, "presets": PRESETS,
        "counts": reports.DEFAULT_COUNTS,
        "today": utcnow().strftime("%Y-%m-%d"), "month_ago": (utcnow() - timedelta(days=30)).strftime("%Y-%m-%d"),
    })


@router.post("/build", dependencies=[Depends(verify_csrf)])
async def report_build(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    form = await request.form()
    since, until = _parse_range(str(form.get("preset", "7")), str(form.get("start", "")).strip(), str(form.get("end", "")).strip())
    chosen = {s for s in form.getlist("sections") if s in reports.SECTIONS} or set(reports.SECTIONS)
    fmt = str(form.get("format", "csv"))
    if fmt not in reports.FORMATS:
        raise HTTPException(400, "unknown format")
    try:
        counts = {k: min(max(int(form.get(f"n_{k}") or v), 1), 200) for k, v in reports.DEFAULT_COUNTS.items()}
        min_sev = min(max(int(form.get("min_sev") or 0), 0), 100)
    except ValueError as e:
        raise HTTPException(400, "numbers expected") from e
    verdicts = {v for v in form.getlist("verdicts") if v in ("malicious", "suspicious", "clean", "unknown", "pending")}
    title = str(form.get("title", "")).strip()[:120]
    region = str(form.get("region") or current_region(request))
    rep = reports.gather(db, since, until, chosen, counts=counts, ioc_verdicts=verdicts or None, title=title,
                         min_sev=min_sev, region=region)
    try:
        data, name, mime = reports.build(rep, fmt)
    except RuntimeError as e:  # optional dependency missing
        raise HTTPException(400, str(e)) from e
    audit(db, user, "report_built", f"{fmt} {since:%Y-%m-%d}..{until:%Y-%m-%d} {','.join(sorted(chosen))}", request)
    db.commit()
    return Response(content=data, media_type=mime,
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})
