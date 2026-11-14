"""Read-only TAXII 2.1 server for SIEMs / TIPs (OpenCTI, MISP, Sentinel, Splunk, ...).

    GET /taxii2/                                        discovery
    GET /taxii2/api/                                    API root
    GET /taxii2/api/collections/                        collections
    GET /taxii2/api/collections/{id}/                   one collection
    GET /taxii2/api/collections/{id}/objects/           STIX objects (added_after, limit, next, match[type], match[id])
    GET /taxii2/api/collections/{id}/manifest/          manifest of the same page

Collections: ``indicators`` (shareable malicious / suspicious indicators with the families they indicate;
date added = when JATMP's verdict was set) and ``reports`` (shareable items as reports; date added = when
collected). Authentication is the REST API key, as ``Authorization: Bearer <key>`` or HTTP Basic with the
key as password. Objects pass through app/sharing.py like every other export.
"""
from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from .. import __version__, settings, sharing, stix
from ..db import get_db
from ..models import Entity, Item, Source, User
from .api_v1 import principal

router = APIRouter(prefix="/taxii2", tags=["taxii"], include_in_schema=False)
TAXII = "application/taxii+json;version=2.1"
COLLECTIONS = {
    "indicators": ("JATMP indicators", "Shareable malicious and suspicious indicators, with the malware families "
                                       "they indicate (STIX indicator, malware, relationship)."),
    "reports": ("JATMP reports", "Shareable collected items (news, social, intel) as STIX reports with their "
                                 "families, actors, CVEs, techniques and indicators."),
}
MAX_LIMIT = 1000


def _coll_id(key: str) -> str:
    return str(uuid.uuid5(stix._namespace(), f"taxii-collection:{key}"))


def _by_id(cid: str) -> str:
    for key in COLLECTIONS:
        if _coll_id(key) == cid:
            return key
    raise HTTPException(404, "collection not found")


def _resp(body: dict, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(body, media_type=TAXII, headers=headers)


def accept(request: Request) -> None:
    acc = request.headers.get("accept", "*/*").lower()
    if not any(x in acc for x in ("taxii+json", "*/*", "application/json", "application/*")):
        raise HTTPException(406, f"only {TAXII} is served")


def _base(request: Request) -> str:
    return (str(settings.get("public_base_url") or "").rstrip("/") or str(request.base_url).rstrip("/")) + "/taxii2"


def _collection(key: str) -> dict:
    title, desc = COLLECTIONS[key]
    return {"id": _coll_id(key), "title": title, "description": desc, "can_read": True, "can_write": False,
            "media_types": [stix.MEDIA_TYPE]}


@router.get("/", dependencies=[Depends(accept)])
def discovery(request: Request, _: User = Depends(principal("read"))):
    base = _base(request)
    return _resp({"title": "JATMP TAXII 2.1", "description": f"Read-only threat intel from JATMP {__version__}",
                  "default": f"{base}/api/", "api_roots": [f"{base}/api/"]})


@router.get("/api/", dependencies=[Depends(accept)])
def api_root(_: User = Depends(principal("read"))):
    return _resp({"title": "JATMP", "description": "Indicators and reports shared by this JATMP install",
                  "versions": [TAXII], "max_content_length": 10_485_760})


@router.get("/api/collections/", dependencies=[Depends(accept)])
def collections(_: User = Depends(principal("read"))):
    return _resp({"collections": [_collection(k) for k in COLLECTIONS]})


@router.get("/api/collections/{cid}/", dependencies=[Depends(accept)])
def collection(cid: str, _: User = Depends(principal("read"))):
    return _resp(_collection(_by_id(cid)))


# --------------------------------------------------------------------------- paging
def _parse_ts(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "added_after must be a timestamp like 2026-11-14T08:00:00.000Z") from None
    return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt


def _encode(dt: datetime, oid: int) -> str:
    return base64.urlsafe_b64encode(f"{dt.isoformat()}|{oid}".encode()).decode().rstrip("=")


def _decode(token: str) -> tuple[datetime, int]:
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode()
        when, _, oid = raw.partition("|")
        return datetime.fromisoformat(when), int(oid)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(400, "invalid next token") from None


def _page(db: Session, key: str, added_after: datetime | None, nxt: str | None, limit: int):
    """Rows of the collection in date-added order: [(date_added, row)], more."""
    if key == "indicators":
        col, idc = Entity.enriched_at, Entity.id
        stmt = select(Entity).where(Entity.type.in_(stix.IOC_TYPES), Entity.enriched_at.is_not(None),
                                    Entity.verdict.in_(("malicious", "suspicious")), sharing.shareable_entity_clause())
    else:
        col, idc = Item.collected_at, Item.id
        stmt = select(Item).join(Source, Source.id == Item.source_id).where(sharing.shareable_item_clause())
    if added_after is not None:
        stmt = stmt.where(col > added_after)
    if nxt:
        when, oid = _decode(nxt)
        stmt = stmt.where(or_(col > when, and_(col == when, idc > oid)))
    rows = db.execute(stmt.order_by(col.asc(), idc.asc()).limit(limit + 1)).unique().scalars().all()
    more = len(rows) > limit
    rows = rows[:limit]
    return [((r.enriched_at if key == "indicators" else r.collected_at), r) for r in rows], more


def _build(db: Session, key: str, rows) -> tuple[stix.Bundle, list[tuple[datetime, str]]]:
    b = stix.Bundle()
    primary = []
    for when, row in rows:
        oid = b.indicator_with_families(db, row) if key == "indicators" else b.item(db, row)
        if oid:
            primary.append((when, oid))
    return b, primary


def _filters(request: Request) -> tuple[set[str], set[str]]:
    q = request.query_params
    types = {t.strip() for v in q.getlist("match[type]") for t in v.split(",") if t.strip()}
    ids = {t.strip() for v in q.getlist("match[id]") for t in v.split(",") if t.strip()}
    return types, ids


def _headers(primary) -> dict:
    if not primary:
        return {}
    return {"X-TAXII-Date-Added-First": stix.ts(primary[0][0]), "X-TAXII-Date-Added-Last": stix.ts(primary[-1][0])}


@router.get("/api/collections/{cid}/objects/", dependencies=[Depends(accept)])
def objects(cid: str, request: Request, added_after: str | None = None, next: str | None = None,
            limit: int = Query(100, ge=1, le=MAX_LIMIT), _: User = Depends(principal("read")),
            db: Session = Depends(get_db)):
    key = _by_id(cid)
    rows, more = _page(db, key, _parse_ts(added_after), next, limit)
    b, primary = _build(db, key, rows)
    types, ids = _filters(request)
    objs = [o for o in b.objects.values() if (not types or o["type"] in types) and (not ids or o["id"] in ids)]         if primary else []
    body = {"more": more, "objects": objs}
    if more and rows:
        body["next"] = _encode(rows[-1][0], rows[-1][1].id)
    return _resp(body, _headers(primary))


@router.get("/api/collections/{cid}/manifest/", dependencies=[Depends(accept)])
def manifest(cid: str, added_after: str | None = None, next: str | None = None,
             limit: int = Query(100, ge=1, le=MAX_LIMIT), _: User = Depends(principal("read")),
             db: Session = Depends(get_db)):
    key = _by_id(cid)
    rows, more = _page(db, key, _parse_ts(added_after), next, limit)
    b, primary = _build(db, key, rows)
    entries = [{"id": oid, "date_added": stix.ts(when), "version": b.objects[oid]["modified"],
                "media_type": stix.MEDIA_TYPE} for when, oid in primary]
    body = {"more": more, "objects": entries}
    if more and rows:
        body["next"] = _encode(rows[-1][0], rows[-1][1].id)
    return _resp(body, _headers(primary))
