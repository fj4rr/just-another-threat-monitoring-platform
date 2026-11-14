"""CVE context from free public sources, stored in ``Entity.meta`` of CVE entities.

- CISA Known Exploited Vulnerabilities catalog (one JSON file, cached on disk for 12 h)
  -> ``meta["kev"]``: date_added, due_date, ransomware ("Known" / "Unknown"), vendor, product, name
- FIRST EPSS (batch API, no key)        -> ``meta["epss"]``: score (0-1), percentile (0-1), date
- NVD CVE API 2.0 (key optional; without one NVD allows ~5 requests / 30 s, so lookups are throttled and
  capped per run)                        -> ``meta["cvss"]``: score, severity, version, vector, description

Only CVEs mentioned in the last 30 days are refreshed; EPSS / KEV daily, CVSS weekly.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import settings
from ..config import DATA_DIR
from ..models import Entity, utcnow
from .clients import USER_AGENT, throttle

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_CACHE = DATA_DIR / "cache" / "cisa_kev.json"
KEV_MAX_AGE = timedelta(hours=12)
RECHECK = timedelta(hours=24)
CVSS_RECHECK = timedelta(days=7)
WINDOW = timedelta(days=30)
MAX_PER_RUN = 60


def _client() -> httpx.Client:
    return httpx.Client(timeout=40, headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                        follow_redirects=True)


def _parse_dt(s: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(s) if s else None
    except ValueError:
        return None


# --------------------------------------------------------------------------- CISA KEV
def parse_kev(data: dict) -> dict[str, dict]:
    out = {}
    for v in data.get("vulnerabilities") or []:
        cid = str(v.get("cveID") or "").upper().strip()
        if not cid.startswith("CVE-"):
            continue
        out[cid] = {
            "date_added": v.get("dateAdded") or "", "due_date": v.get("dueDate") or "",
            "ransomware": v.get("knownRansomwareCampaignUse") or "", "vendor": v.get("vendorProject") or "",
            "product": v.get("product") or "", "name": v.get("vulnerabilityName") or "",
        }
    return out


def load_kev(http: httpx.Client) -> dict[str, dict]:
    """KEV catalog, from the disk cache when it is fresh; a stale cache beats no data when CISA is down."""
    cached = None
    if KEV_CACHE.exists():
        try:
            cached = json.loads(KEV_CACHE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cached = None
        if cached is not None and time.time() - KEV_CACHE.stat().st_mtime < KEV_MAX_AGE.total_seconds():
            return parse_kev(cached)
    try:
        r = http.get(KEV_URL)
        r.raise_for_status()
        data = r.json()
        KEV_CACHE.parent.mkdir(parents=True, exist_ok=True)
        KEV_CACHE.write_text(json.dumps(data), encoding="utf-8")
        return parse_kev(data)
    except (httpx.HTTPError, ValueError, OSError) as e:
        log.warning("CISA KEV download failed: %s", e)
        return parse_kev(cached) if cached else {}


# --------------------------------------------------------------------------- FIRST EPSS
def fetch_epss(http: httpx.Client, cves: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for i in range(0, len(cves), 80):  # keep the query string short
        chunk = cves[i:i + 80]
        r = http.get(EPSS_URL, params={"cve": ",".join(chunk)})
        r.raise_for_status()
        for row in r.json().get("data") or []:
            try:
                out[str(row["cve"]).upper()] = {"score": round(float(row["epss"]), 5),
                                                "percentile": round(float(row["percentile"]), 5),
                                                "date": row.get("date") or ""}
            except (KeyError, TypeError, ValueError):
                continue
    return out


# --------------------------------------------------------------------------- NVD CVSS
_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def parse_nvd(data: dict) -> dict | None:
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve") or {}
    desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    out = {"description": desc[:2000], "published": (cve.get("published") or "")[:10], "score": None,
           "severity": "", "version": "", "vector": ""}
    metrics = cve.get("metrics") or {}
    for key in _METRIC_KEYS:
        rows = metrics.get(key) or []
        if not rows:
            continue
        row = next((r for r in rows if r.get("type") == "Primary"), rows[0])
        cd = row.get("cvssData") or {}
        score = cd.get("baseScore")
        if score is None:
            continue
        out.update(score=float(score), severity=cd.get("baseSeverity") or row.get("baseSeverity") or "",
                   version=str(cd.get("version") or key[-2:].replace("V", "")), vector=cd.get("vectorString") or "")
        break
    return out


def fetch_nvd(http: httpx.Client, cve_id: str, api_key: str = "") -> dict | None:
    r = http.get(NVD_URL, params={"cveId": cve_id}, headers={"apiKey": api_key} if api_key else None)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return parse_nvd(r.json())


# --------------------------------------------------------------------------- refresh job
def candidates(db: Session, limit: int = MAX_PER_RUN) -> list[Entity]:
    now = utcnow()
    rows = db.execute(select(Entity).where(Entity.type == "cve", Entity.last_seen >= now - WINDOW)
                      .order_by(Entity.last_seen.desc()).limit(1000)).scalars().all()
    due = []
    for e in rows:
        checked = _parse_dt((e.meta or {}).get("intel_checked_at"))
        if checked is None or checked < now - RECHECK:
            due.append(e)
    # never-checked first, then the most recently mentioned
    due.sort(key=lambda e: ((e.meta or {}).get("intel_checked_at") is not None, -e.last_seen.timestamp()))
    return due[:limit]


def refresh(db: Session, progress=None, limit: int = MAX_PER_RUN, http: httpx.Client | None = None) -> str:
    progress = progress or (lambda *_: None)
    ents = candidates(db, limit)
    if not ents:
        return "all recently mentioned CVEs are up to date"
    progress(0, len(ents), "KEV / EPSS")
    api_key = str(settings.get("nvd_api_key") or "")
    nvd_budget, interval = (50, 0.8) if api_key else (10, 6.5)
    notes: list[str] = []
    own = http is None
    http = http or _client()
    try:
        kev = load_kev(http)
        if not kev:
            notes.append("KEV unavailable")
        try:
            epss = fetch_epss(http, [e.value.upper() for e in ents])
        except (httpx.HTTPError, ValueError) as ex:
            log.warning("EPSS lookup failed: %s", ex)
            epss = {}
            notes.append("EPSS unavailable")
        n_kev = n_epss = n_nvd = nvd_fails = 0
        now = utcnow()
        for i, ent in enumerate(ents, 1):
            cid = ent.value.upper()
            meta = dict(ent.meta or {})
            if kev:  # only overwrite when the catalog was actually loaded
                meta["kev"] = kev.get(cid)
                n_kev += bool(meta["kev"])
            if cid in epss:
                meta["epss"] = epss[cid]
                n_epss += 1
            cvss_at = _parse_dt(meta.get("cvss_checked_at"))
            if nvd_budget > 0 and (cvss_at is None or cvss_at < now - CVSS_RECHECK):
                throttle.wait("nvd", interval)
                nvd_budget -= 1
                try:
                    res = fetch_nvd(http, cid, api_key)
                    if res is not None:
                        meta["cvss"] = res
                        n_nvd += 1
                    meta["cvss_checked_at"] = now.isoformat(timespec="seconds")
                    nvd_fails = 0
                except (httpx.HTTPError, ValueError) as ex:
                    log.info("NVD lookup %s failed: %s", cid, ex)
                    nvd_fails += 1
                    if nvd_fails >= 2:  # NVD is down or throttling us: don't burn the run on timeouts
                        nvd_budget = 0
                        notes.append("NVD unavailable, CVSS retried next run")
            meta["intel_checked_at"] = now.isoformat(timespec="seconds")
            ent.meta = meta
            progress(i, len(ents), "KEV / EPSS / NVD")
            if i % 10 == 0:
                db.commit()
    finally:
        if own:
            http.close()
    msg = f"checked {len(ents)} CVE(s): {n_kev} in CISA KEV, {n_epss} with EPSS, {n_nvd} CVSS from NVD"
    return msg + (f" ({', '.join(notes)})" if notes else "")


def priority(trend_score: float, meta: dict | None) -> tuple[float, dict]:
    """Rank trending CVEs by exploitation risk, not just chatter:
    trend × 2 if in CISA KEV × (1 + EPSS) × (0.5 + CVSS/10) (unknown CVSS = ×1)."""
    m = meta or {}
    kev = bool(m.get("kev"))
    epss = (m.get("epss") or {}).get("score")
    cvss = (m.get("cvss") or {}).get("score")
    factor = (2.0 if kev else 1.0) * (1 + (epss or 0)) * ((0.5 + cvss / 10) if isinstance(cvss, (int, float)) else 1.0)
    return round(trend_score * factor, 2), {"kev": kev, "epss": epss, "cvss": cvss}
