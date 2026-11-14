"""Dark web, tier 1: clearnet aggregators only. JATMP never visits leak sites or forums itself.

* ransomware.live: leak-site victims per group / country, group profiles. With a (free) PRO key the
  PRO API is used (``X-API-KEY``, allowed for organisations); without one the keyless v2 API, which
  ransomware.live offers for personal use only and limits to one request per minute per endpoint.
* Hudson Rock Cavalier: infostealer exposure *statistics* for a domain (how many employees / users were
  infected, when, which sensitive apps). Never credentials or personal data. Needs a free API key.

Hard rules (README): no forum logins, no CAPTCHA solving, no downloading leaked data, no purchases.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter

import httpx
from sqlalchemy.orm import Session

from .. import settings
from ..models import Entity, utcnow
from . import LookupResult, NotConfigured
from .clients import USER_AGENT, throttle

log = logging.getLogger(__name__)

RL_PRO = "https://api-pro.ransomware.live"
RL_FREE = "https://api.ransomware.live/v2"
HR_BASE = "https://api.hudsonrock.com/json/v3"
# JATMP family name -> ransomware.live group names to try (their names are lower-case, no spaces)
GROUP_ALIASES = {
    "lockbit": ["lockbit5", "lockbit3", "lockbit"], "blackcat": ["alphv"], "alphv": ["alphv"],
    "cl0p": ["clop"], "clop": ["clop"], "black basta": ["blackbasta"], "8base": ["8base"],
    "ransomhub": ["ransomhub"], "medusa": ["medusa"], "play": ["play"], "inc ransom": ["incransom"],
}


def _client(headers: dict | None = None, timeout: int = 40) -> httpx.Client:
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    h.update(headers or {})
    return httpx.Client(timeout=timeout, headers=h, follow_redirects=True)


def _as_list(data) -> list[dict]:
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for k in ("victims", "data", "results", "items"):
            if isinstance(data.get(k), list):
                return [d for d in data[k] if isinstance(d, dict)]
    return []


def normalise_victim(v: dict) -> dict:
    """Old and new field names (post_title/victim, group_name/group, published/attackdate)."""
    country = str(v.get("country") or "").strip().upper()[:2]
    sector = str(v.get("activity") or v.get("sector") or "").strip()
    return {
        "victim": str(v.get("victim") or v.get("post_title") or "").strip(),
        "group": str(v.get("group") or v.get("group_name") or "").strip(),
        "country": country if len(country) == 2 and country.isalpha() else "",
        "sector": "" if sector.lower() in ("not found", "unknown", "n/a") else sector,
        "website": str(v.get("website") or v.get("domain") or "").strip(),
        "discovered": str(v.get("discovered") or "")[:19],
        "attackdate": str(v.get("attackdate") or v.get("published") or "")[:19],
        "permalink": str(v.get("permalink") or v.get("url") or ""),
        "id": str(v.get("id") or ""),
    }


_free_calls: dict[str, float] = {}
_free_lock = threading.Lock()
_groups_cache: dict[str, tuple[float, list[str]]] = {}


class RansomwareLive:
    name = "ransomware.live"

    def __init__(self):
        self.key = str(settings.get("ransomwarelive_api_key") or "")
        self.pro = bool(self.key)

    def _get(self, path: str, params: dict | None = None):
        base = RL_PRO if self.pro else RL_FREE
        if self.pro:
            throttle.wait(self.name, 0.5)
        else:  # the free API allows one request per minute per endpoint: fail fast instead of sleeping
            endpoint = path.strip("/").split("/")[0]
            with _free_lock:
                wait = 61 - (time.monotonic() - _free_calls.get(endpoint, -1e9))
                if wait > 0:
                    raise RuntimeError(f"ransomware.live free API: one request per minute per endpoint, try again "
                                       f"in {int(wait) + 1} s (a free PRO key removes the limit)")
                _free_calls[endpoint] = time.monotonic()
        with _client({"X-API-KEY": self.key} if self.pro else None) as c:
            r = c.get(base + path, params=params)
        if r.status_code in (401, 403):
            raise RuntimeError(f"ransomware.live rejected the API key ({r.status_code})")
        if r.status_code == 429:
            raise RuntimeError("ransomware.live rate limit (429); a free PRO key removes it")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def recent_victims(self) -> list[dict]:
        return [normalise_victim(v) for v in _as_list(self._get("/victims/recent" if self.pro else "/recentvictims"))]

    def group_victims(self, group: str) -> list[dict]:
        data = self._get("/victims/", {"group": group}) if self.pro else self._get(f"/groupvictims/{group}")
        return [normalise_victim(v) for v in _as_list(data)]

    def country_victims(self, cc: str) -> list[dict]:
        cc = cc.strip().upper()[:2]
        data = self._get("/victims/", {"country": cc}) if self.pro else self._get(f"/countryvictims/{cc}")
        return [normalise_victim(v) for v in _as_list(data)]

    def groups(self) -> list[str]:
        """Group names known to ransomware.live (cached for 6 h)."""
        hit = _groups_cache.get("pro" if self.pro else "free")
        if hit and time.monotonic() - hit[0] < 6 * 3600:
            return hit[1]
        data = self._get("/groups")
        names = sorted({str(g.get("name") or g.get("group") or "").lower() if isinstance(g, dict) else str(g).lower()
                        for g in (data if isinstance(data, list) else _as_list(data))} - {""})
        _groups_cache["pro" if self.pro else "free"] = (time.monotonic(), names)
        return names

    def group_info(self, group: str) -> dict | None:
        data = self._get(f"/groups/{group}") if self.pro else self._get(f"/group/{group}")
        if isinstance(data, list):
            data = data[0] if data else None
        if isinstance(data, dict) and isinstance(data.get("group"), dict):
            data = data["group"]
        return data if isinstance(data, dict) and data else None

    def test(self) -> str:
        if self.pro:
            self._get("/validate")
            return "ransomware.live PRO API reachable, key accepted"
        self._get("/info")
        return "ransomware.live free API reachable (personal use only; add a free PRO key for organisations)"


def group_candidates(ent: Entity) -> list[str]:
    name = (ent.display or ent.value).lower().replace("ransomware", "").strip()
    out = list(GROUP_ALIASES.get(name, []))
    for c in (name.replace(" ", ""), name.replace(" ", "-"), ent.value.lower().replace(" ", "")):
        if c and c not in out:
            out.append(c)
    return out[:4]


def ransomware_deep_dive(ent: Entity, rl: RansomwareLive | None = None) -> LookupResult:
    rl = rl or RansomwareLive()
    known = set(rl.groups())
    group = next((c for c in group_candidates(ent) if c in known), "")
    info = rl.group_info(group) if group else None
    if not group or not info:
        return LookupResult("ransomware.live", "unknown", 0, "No leak-site group by this name on ransomware.live",
                            "https://www.ransomware.live/groups")
    victims = rl.group_victims(group)
    victims.sort(key=lambda v: v["discovered"] or v["attackdate"], reverse=True)
    countries = Counter(v["country"] for v in victims if v["country"])
    sectors = Counter(v["sector"] for v in victims if v["sector"])
    cves = []
    for vul in info.get("vulnerabilities") or []:
        cid = (vul.get("CVE") or vul.get("cve")) if isinstance(vul, dict) else vul
        if isinstance(cid, str) and cid.upper().startswith("CVE-"):
            cves.append(cid.upper())
    tools = []
    for t in info.get("tools") or []:
        if isinstance(t, str):
            tools.append(t)
        elif isinstance(t, dict):
            tools += [str(x) for x in (t.get("tools") or t.get("names") or [])]
    last = (victims[0]["discovered"] or victims[0]["attackdate"]) if victims else ""
    res = LookupResult(
        "ransomware.live", "malicious" if victims else "unknown", min(100, len(victims)),
        f"{len(victims)} leak-site victim(s) for group '{group}'" + (f", latest {last[:10]}" if last else ""),
        f"https://www.ransomware.live/group/{group}")
    res.data = {
        "group": group, "victims_total": len(victims), "api": "pro" if rl.pro else "free",
        "description": str(info.get("description") or "")[:1500],
        "first_seen": str(info.get("firstseen") or "")[:10], "last_seen": str(info.get("lastseen") or last)[:10],
        "countries": countries.most_common(15), "sectors": sectors.most_common(10),
        "recent": [{k: v[k] for k in ("victim", "country", "sector", "discovered", "permalink")} for v in victims[:15]],
        "cves": sorted(set(cves))[:30], "tools": sorted(set(tools))[:30],
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }
    return res


class HudsonRock:
    name = "hudsonrock"

    def __init__(self):
        self.key = str(settings.get("hudsonrock_api_key") or "")
        if not self.key:
            raise NotConfigured("Hudson Rock API key not set (free key: hudsonrock.com/free-api-key)")

    def overview(self, domains: list[str]) -> list[dict]:
        throttle.wait(self.name, 0.5)
        with _client({"api-key": self.key, "Content-Type": "application/json"}, timeout=95) as c:
            r = c.post(f"{HR_BASE}/search-by-domain/overview", json={"domains": domains[:500]})
        if r.status_code in (401, 403):
            raise RuntimeError(f"Hudson Rock rejected the key ({r.status_code})")
        if r.status_code == 429:
            raise RuntimeError("Hudson Rock rate limit (429)")
        r.raise_for_status()
        rows = r.json().get("data") or []
        keep = ("domain", "compromised_employees", "compromised_users", "last_employee_compromised",
                "last_user_compromised", "sensitive_applications")
        return [{k: row.get(k) for k in keep} for row in rows if isinstance(row, dict)]

    def test(self) -> str:
        self.overview(["example.com"])
        return "Hudson Rock reachable, key accepted"


def infostealer_exposure(domain: str, hr: HudsonRock | None = None) -> LookupResult:
    hr = hr or HudsonRock()
    domain = domain.strip().lower().removeprefix("www.")
    rows = hr.overview([domain])
    row = next((r for r in rows if (r.get("domain") or "").lower() == domain), rows[0] if rows else None)
    link = "https://www.hudsonrock.com/free-tools"
    if not row:
        return LookupResult("hudsonrock", "unknown", 0, f"No infostealer infections recorded for {domain}", link,
                            data={"domain": domain})
    emp, usr = int(row.get("compromised_employees") or 0), int(row.get("compromised_users") or 0)
    res = LookupResult("hudsonrock", "unknown", 0,
                       f"{emp} employee(s) and {usr} user(s) of {domain} infected by infostealers", link)
    res.data = {**row, "domain": domain, "checked_at": utcnow().isoformat(timespec="seconds")}
    return res


def save(db: Session, ent: Entity, res: LookupResult) -> None:
    """Store a deep-dive result as an Enrichment row (it does not change the entity's verdict)."""
    from ..processing.enrichment import _upsert

    _upsert(db, ent, res)
