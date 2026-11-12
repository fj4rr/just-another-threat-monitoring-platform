"""Provider API clients: VirusTotal, AlienVault OTX, urlscan.io, ANY.RUN, ThreatFox."""
from __future__ import annotations

import base64
import threading
import time
from datetime import date

import httpx

from .. import __version__, settings
from . import LookupResult, NotConfigured, make_ioc

USER_AGENT = f"JATMP/{__version__} (+threat-monitoring; self-hosted)"


def _client(headers: dict | None = None) -> httpx.Client:
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    h.update(headers or {})
    return httpx.Client(timeout=30, headers=h, follow_redirects=True)


# --------------------------------------------------------------------------- rate limiting
class _Throttle:
    def __init__(self):
        self.lock = threading.Lock()
        self.last: dict[str, float] = {}

    def wait(self, provider: str, min_interval: float) -> None:
        with self.lock:
            now = time.monotonic()
            delta = now - self.last.get(provider, 0)
            if delta < min_interval:
                time.sleep(min_interval - delta)
            self.last[provider] = time.monotonic()


throttle = _Throttle()


_budget_lock = threading.Lock()


def _budget_ok(provider: str, limit: int) -> bool:
    """Per-day call counter persisted in settings (survives restarts). Read-modify-write is
    serialised because the scheduler and manual "Enrich now" clicks can overlap."""
    key = f"_budget_{provider}"
    today = date.today().isoformat()
    with _budget_lock:
        state = settings.get(key) or {}
        if not isinstance(state, dict) or state.get("day") != today:
            state = {"day": today, "count": 0}
        if limit and state["count"] >= limit:
            return False
        state["count"] += 1
        settings.set(key, state)
    return True


# --------------------------------------------------------------------------- VirusTotal
class VirusTotal:
    name = "virustotal"
    BASE = "https://www.virustotal.com/api/v3"
    supports = {"md5", "sha1", "sha256", "ip", "domain", "url"}

    def __init__(self):
        self.key = settings.get("virustotal_api_key")
        if not self.key:
            raise NotConfigured("VirusTotal API key not set")

    def lookup(self, etype: str, value: str) -> LookupResult | None:
        if etype not in self.supports:
            return None
        if not _budget_ok(self.name, int(settings.get("vt_daily_budget") or 0)):
            raise RuntimeError("VirusTotal daily budget exhausted")
        throttle.wait(self.name, float(settings.get("vt_min_interval") or 16))
        if etype in ("md5", "sha1", "sha256"):
            path, gui = f"files/{value}", f"https://www.virustotal.com/gui/file/{value}"
        elif etype == "ip":
            path, gui = f"ip_addresses/{value}", f"https://www.virustotal.com/gui/ip-address/{value}"
        elif etype == "domain":
            path, gui = f"domains/{value}", f"https://www.virustotal.com/gui/domain/{value}"
        else:
            uid = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            path, gui = f"urls/{uid}", f"https://www.virustotal.com/gui/url/{uid}"
        with _client({"x-apikey": self.key}) as c:
            r = c.get(f"{self.BASE}/{path}")
        if r.status_code == 404:
            return LookupResult(self.name, "unknown", 0, "Not found on VirusTotal", gui)
        if r.status_code == 429:
            raise RuntimeError("VirusTotal quota exceeded (429)")
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int)) or 1
        verdict = "malicious" if mal >= 3 else "suspicious" if (mal or sus) else "clean" if total > 1 else "unknown"
        res = LookupResult(self.name, verdict, round(100 * (mal + sus) / total, 1),
                           f"{mal}/{total} engines flag as malicious", gui)
        ptc = attrs.get("popular_threat_classification") or {}
        for entry in ptc.get("popular_threat_name", []) or []:
            if entry.get("value"):
                res.malware.append(entry["value"])
        if ptc.get("suggested_threat_label"):
            res.tags.append(ptc["suggested_threat_label"])
        res.tags += (attrs.get("tags") or [])[:15]
        res.data = {
            "stats": stats,
            "reputation": attrs.get("reputation"),
            "type": attrs.get("type_description") or attrs.get("as_owner"),
            "names": (attrs.get("names") or [])[:5],
            "country": attrs.get("country"),
            "categories": attrs.get("categories"),
            "first_submission": attrs.get("first_submission_date"),
            "threat_label": ptc.get("suggested_threat_label"),
        }
        if res.malware:
            res.summary += f" · family: {', '.join(res.malware[:3])}"
        return res


# --------------------------------------------------------------------------- AlienVault OTX
class OTX:
    name = "otx"
    BASE = "https://otx.alienvault.com/api/v1"
    TYPES = {"ip": "IPv4", "domain": "domain", "url": "url", "md5": "file", "sha1": "file",
             "sha256": "file", "cve": "cve"}
    IND_MAP = {"IPv4": "ip", "domain": "domain", "hostname": "domain", "URL": "url",
               "FileHash-MD5": "md5", "FileHash-SHA1": "sha1", "FileHash-SHA256": "sha256", "CVE": "cve"}

    def __init__(self, require_key: bool = True):
        self.key = settings.get("otx_api_key")
        if require_key and not self.key:
            raise NotConfigured("OTX API key not set")

    def _get(self, path: str, params: dict | None = None) -> dict:
        headers = {"X-OTX-API-KEY": self.key} if self.key else {}
        with _client(headers) as c:
            r = c.get(f"{self.BASE}/{path}", params=params)
        r.raise_for_status()
        return r.json()

    def subscribed(self, since_iso: str | None = None, limit: int = 50) -> list[dict]:
        params = {"limit": limit}
        if since_iso:
            params["modified_since"] = since_iso
        return self._get("pulses/subscribed", params).get("results", [])

    def search_pulses(self, query: str, limit: int = 20) -> list[dict]:
        return self._get("search/pulses", {"q": query, "limit": limit, "sort": "-modified"}).get("results", [])

    def pulse_indicators(self, pulse: dict, limit: int = 200):
        out = []
        for ind in (pulse.get("indicators") or [])[:limit]:
            kind = self.IND_MAP.get(ind.get("type", ""))
            if kind and kind != "cve":
                ex = make_ioc(ind.get("indicator", ""), kind)
                if ex:
                    out.append(ex)
        return out

    def lookup(self, etype: str, value: str) -> LookupResult | None:
        t = self.TYPES.get(etype)
        if not t:
            return None
        if etype == "domain":
            t = "domain"
        data = self._get(f"indicators/{t}/{value}/general")
        pinfo = data.get("pulse_info", {}) or {}
        count = pinfo.get("count", 0)
        pulses = pinfo.get("pulses", []) or []
        families = []
        for p in pulses:
            for f in p.get("malware_families", []) or []:
                name = f.get("display_name") if isinstance(f, dict) else f
                if name and name not in families:
                    families.append(name)
        for f in (pinfo.get("related", {}) or {}).get("alienvault", {}).get("malware_families", []) or []:
            if f not in families:
                families.append(f)
        # OTX marks well-known benign infrastructure (CDNs, big-tech domains) in `validation`
        validation = [v for v in (data.get("validation") or []) if isinstance(v, dict)]
        whitelisted = any("whitelist" in str(v.get("source", "")).lower() or "false positive" in str(v.get("message", "")).lower()
                          for v in validation)
        if whitelisted:
            verdict = "clean"
            summary = f"Whitelisted by OTX ({validation[0].get('message') or validation[0].get('source')}); {count} pulse(s)"
        else:
            verdict = "malicious" if (count >= 3 or (count and families)) else "suspicious" if count else "unknown"
            summary = f"Referenced in {count} OTX pulse(s)"
        gui_t = {"ip": "ip", "domain": "domain", "url": "url"}.get(etype, "file")
        if etype == "cve":
            gui_t = "cve"
        res = LookupResult(
            self.name, verdict, 0 if whitelisted else min(100, count * 10), summary,
            f"https://otx.alienvault.com/indicator/{gui_t}/{value}",
        )
        res.malware = families[:10]
        res.tags = sorted({t for p in pulses[:20] for t in (p.get("tags") or [])})[:20]
        res.data = {
            "pulse_count": count,
            "pulses": [{"id": p.get("id"), "name": p.get("name"), "created": p.get("created")} for p in pulses[:10]],
            "country": data.get("country_name"),
            "asn": data.get("asn"),
            "validation": validation[:5],
        }
        if families and not whitelisted:
            res.summary += f" · families: {', '.join(families[:3])}"
        return res


# --------------------------------------------------------------------------- urlscan.io
class URLScan:
    name = "urlscan"
    BASE = "https://urlscan.io/api/v1"

    def __init__(self, require_key: bool = True):
        self.key = settings.get("urlscan_api_key")
        if require_key and not self.key:
            raise NotConfigured("urlscan API key not set")

    def search(self, query: str, size: int = 100) -> list[dict]:
        headers = {"API-Key": self.key} if self.key else {}
        throttle.wait(self.name, 2)
        with _client(headers) as c:
            r = c.get(f"{self.BASE}/search/", params={"q": query, "size": size})
        if r.status_code == 429:
            raise RuntimeError("urlscan rate limit (429)")
        r.raise_for_status()
        return r.json().get("results", [])

    def lookup(self, etype: str, value: str) -> LookupResult | None:
        q = {"domain": f"page.domain:{value}", "ip": f"page.ip:\"{value}\"",
             "url": f"page.url:\"{value}\"", "sha256": f"hash:{value}"}.get(etype)
        if not q:
            return None
        results = self.search(q, size=20)
        if not results:
            return LookupResult(self.name, "unknown", 0, "No urlscan.io scans", f"https://urlscan.io/search/#{q}")
        mal = [r for r in results if (r.get("verdicts") or {}).get("malicious") or
               "malicious" in ((r.get("task") or {}).get("tags") or [])]
        tags = sorted({t for r in results for t in ((r.get("task") or {}).get("tags") or [])})
        brands = sorted({b.get("name", b) if isinstance(b, dict) else b
                         for r in results for b in ((r.get("verdicts") or {}).get("brands") or [])})
        verdict = "malicious" if mal else "unknown"
        res = LookupResult(
            self.name, verdict, round(100 * len(mal) / len(results), 1),
            f"{len(results)} scan(s), {len(mal)} flagged malicious",
            f"https://urlscan.io/search/#{q}",
        )
        res.tags = tags[:20]
        res.data = {
            "scans": [{"uuid": r.get("_id"), "url": (r.get("page") or {}).get("url"),
                       "time": (r.get("task") or {}).get("time"),
                       "screenshot": r.get("screenshot"),
                       "country": (r.get("page") or {}).get("country"),
                       "ip": (r.get("page") or {}).get("ip")} for r in results[:10]],
            "brands": brands[:10],
        }
        seen_ips: set[str] = set()
        for r in (mal or results)[:20]:
            page = r.get("page") or {}
            ip = page.get("ip")
            if ip and etype != "ip" and ip not in seen_ips and len(seen_ips) < 5:
                ex = make_ioc(ip, "ip")
                if ex:
                    seen_ips.add(ip)
                    res.related.append(ex)
        return res


# --------------------------------------------------------------------------- ANY.RUN
class AnyRun:
    """ANY.RUN Threat Intelligence Lookup. Requires a TI Lookup-enabled API key."""

    name = "anyrun"
    FIELD = {"ip": "destinationIP", "domain": "domainName", "url": "url",
             "md5": "md5", "sha1": "sha1", "sha256": "sha256"}

    def __init__(self):
        self.key = settings.get("anyrun_api_key")
        self.base = (settings.get("anyrun_api_base") or "https://api.any.run/v1").rstrip("/")
        if not self.key:
            raise NotConfigured("ANY.RUN API key not set")

    def ti_search(self, query: str, depth_days: int = 30) -> dict:
        throttle.wait(self.name, 3)
        with _client({"Authorization": f"API-Key {self.key}", "Content-Type": "application/json"}) as c:
            r = c.post(f"{self.base}/intelligence/api/search",
                       json={"query": query, "lookupDepth": depth_days})
        if r.status_code in (401, 403):
            raise RuntimeError(f"ANY.RUN rejected the key ({r.status_code}); TI Lookup plan required")
        r.raise_for_status()
        return r.json()

    @staticmethod
    def _related_iocs(data: dict, limit: int = 100):
        out = []
        for key, kind in (("relatedIPs", "ip"), ("relatedDNS", "domain"), ("relatedURLs", "url"),
                          ("destinationIP", "ip"), ("domainName", "domain")):
            for entry in (data.get(key) or [])[:limit]:
                val = entry.get(kind if kind != "domain" else "domainName") if isinstance(entry, dict) else entry
                if isinstance(entry, dict):
                    val = entry.get("destinationIP") or entry.get("domainName") or entry.get("url") or entry.get("value") or val
                if val:
                    ex = make_ioc(str(val), kind)
                    if ex:
                        out.append(ex)
        for f in (data.get("relatedFiles") or [])[:limit]:
            h = (f.get("hashes") or {}).get("sha256") if isinstance(f, dict) else None
            h = h or (f.get("sha256") if isinstance(f, dict) else None)
            if h:
                ex = make_ioc(h, "sha256")
                if ex:
                    out.append(ex)
        return out

    @staticmethod
    def _threats(data: dict) -> list[str]:
        names: list[str] = []
        summary = data.get("summary") or {}
        for t in (summary.get("tags") or []) + (summary.get("threatNames") or []):
            if isinstance(t, dict):
                t = t.get("tag") or t.get("name")
            if t and t not in names:
                names.append(t)
        for task in (data.get("sourceTasks") or [])[:20]:
            for t in task.get("tags") or []:
                if t not in names:
                    names.append(t)
        return names

    def lookup(self, etype: str, value: str) -> LookupResult | None:
        field = self.FIELD.get(etype)
        if not field:
            return None
        data = self.ti_search(f'{field}:"{value}"')
        summary = data.get("summary") or {}
        level = str(summary.get("threatLevel", "")).lower()
        verdict = {"malicious": "malicious", "2": "malicious", "suspicious": "suspicious",
                   "1": "suspicious", "no threats detected": "clean", "0": "clean"}.get(level, "unknown")
        tasks = data.get("sourceTasks") or []
        res = LookupResult(
            self.name, verdict, {"malicious": 90, "suspicious": 50}.get(verdict, 0),
            f"{len(tasks)} sandbox task(s), threat level: {level or 'n/a'}",
            "https://intelligence.any.run/analysis/lookup",
        )
        res.malware = self._threats(data)[:10]
        res.related = self._related_iocs(data, 30)
        res.data = {
            "summary": summary,
            "tasks": [{"uuid": t.get("uuid") or t.get("taskUuid"), "url": t.get("related"),
                       "date": t.get("date"), "verdict": t.get("threatLevel")} for t in tasks[:10]],
        }
        return res


# --------------------------------------------------------------------------- ThreatFox (abuse.ch)
class ThreatFox:
    name = "threatfox"
    BASE = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self):
        self.key = settings.get("threatfox_auth_key")
        if not self.key:
            raise NotConfigured("abuse.ch Auth-Key not set")

    def recent(self, days: int = 1) -> list[dict]:
        with _client({"Auth-Key": self.key}) as c:
            r = c.post(self.BASE, json={"query": "get_iocs", "days": days})
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") != "ok":
            return []
        return data.get("data") or []
