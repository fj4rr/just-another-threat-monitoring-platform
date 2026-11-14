"""Infrastructure context providers, run on demand (an analyst presses "Context lookup") or, if enabled,
when an indicator turns malicious. Free tiers are small, so these never run in the background batch.

    Shodan        IP -> open ports, hostnames, CPEs, known CVEs, tags (InternetDB without a key, host API with one)
    Censys        IP -> services, software, ASN, location (Platform API v3, personal access token)
    CrowdSec CTI  IP -> reputation, behaviours, attack classifications
    Pulsedive     IP / domain / URL -> risk level, threats, feeds
    Hybrid Analysis  hash -> sandbox verdict, threat score, family
    IPinfo        IP -> ASN, organisation, country (also stored in Entity.meta["geo"] for geography features)

Providers that work without a key (Shodan InternetDB, IPinfo) still send the indicator to a third party,
so they only run when ``context_keyless`` is switched on.
"""
from __future__ import annotations

from .. import settings
from . import LookupResult, NotConfigured, make_ioc
from .clients import _budget_ok, _client, throttle


def _budget(name: str) -> None:
    if not _budget_ok(name, int(settings.get("context_daily_budget") or 0)):
        raise RuntimeError(f"{name}: daily budget for context lookups exhausted")


def _get(name: str, url: str, headers: dict | None = None, params: dict | None = None, wait: float = 1.0):
    throttle.wait(name, wait)
    with _client(headers) as c:
        r = c.get(url, params=params)
    if r.status_code in (401, 403):
        raise RuntimeError(f"{name} rejected the key ({r.status_code})")
    if r.status_code == 429:
        raise RuntimeError(f"{name} rate limit / quota reached (429)")
    return r


class Shodan:
    name = "shodan"
    supports = {"ip"}

    def __init__(self):
        self.key = str(settings.get("shodan_api_key") or "")
        if not self.key and not settings.get("context_keyless"):
            raise NotConfigured("Shodan API key not set (or allow keyless context lookups for InternetDB)")

    def lookup(self, etype: str, value: str) -> LookupResult | None:
        if etype != "ip":
            return None
        _budget(self.name)
        link = f"https://www.shodan.io/host/{value}"
        if self.key:
            r = _get(self.name, f"https://api.shodan.io/shodan/host/{value}", params={"key": self.key, "minify": "true"})
        else:
            r = _get(self.name, f"https://internetdb.shodan.io/{value}")
        if r.status_code == 404:
            return LookupResult(self.name, "unknown", 0, "No open services recorded by Shodan", link)
        r.raise_for_status()
        d = r.json()
        vulns = d.get("vulns") or []
        vulns = sorted(vulns if isinstance(vulns, list) else list(vulns))
        ports = sorted(int(p) for p in d.get("ports") or [])
        tags = [str(t) for t in d.get("tags") or []]
        verdict = "suspicious" if {"c2", "malware", "compromised"} & {t.lower() for t in tags} else "unknown"
        parts = [f"open ports: {', '.join(map(str, ports[:12])) or 'none'}"]
        if vulns:
            parts.append(f"{len(vulns)} known CVE(s)")
        if tags:
            parts.append("tags: " + ", ".join(tags[:6]))
        res = LookupResult(self.name, verdict, 40 if verdict == "suspicious" else 0, " · ".join(parts), link)
        res.tags = tags[:20]
        res.data = {"ports": ports[:50], "hostnames": (d.get("hostnames") or [])[:20], "cpes": (d.get("cpes") or [])[:20],
                    "vulns": vulns[:50], "org": d.get("org") or d.get("isp"), "asn": d.get("asn"),
                    "country": d.get("country_code"), "api": "host" if self.key else "internetdb"}
        for h in (d.get("hostnames") or [])[:3]:
            ex = make_ioc(h, "domain")
            if ex:
                res.related.append(ex)
        return res

    def test(self) -> str:
        if self.key:
            r = _get(self.name, "https://api.shodan.io/api-info", params={"key": self.key})
            r.raise_for_status()
            return f"Shodan reachable, key accepted ({r.json().get('plan', 'plan n/a')})"
        r = _get(self.name, "https://internetdb.shodan.io/8.8.8.8")
        r.raise_for_status()
        return "Shodan InternetDB reachable (no key)"


class Censys:
    name = "censys"
    supports = {"ip"}
    BASE = "https://api.platform.censys.io/v3/global/asset/host/"

    def __init__(self):
        self.token = str(settings.get("censys_api_token") or "")
        if not self.token:
            raise NotConfigured("Censys personal access token not set")
        self.org = str(settings.get("censys_org_id") or "")

    def _host(self, ip: str):
        params = {"organization_id": self.org} if self.org else None
        return _get(self.name, self.BASE + ip, {"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
                    params, wait=1.5)

    def lookup(self, etype: str, value: str) -> LookupResult | None:
        if etype != "ip":
            return None
        _budget(self.name)
        r = self._host(value)
        link = f"https://platform.censys.io/hosts/{value}"
        if r.status_code == 404:
            return LookupResult(self.name, "unknown", 0, "Host not found on Censys", link)
        r.raise_for_status()
        body = r.json()
        host = (body.get("result") or {}).get("resource") or body.get("result") or body
        services = host.get("services") or []
        ports = sorted({int(s.get("port")) for s in services if str(s.get("port", "")).isdigit()})
        protos = sorted({str(s.get("protocol") or "") for s in services} - {""})
        threats = sorted({str(t.get("name") or t.get("id") or t) if isinstance(t, dict) else str(t)
                          for s in services for t in (s.get("threats") or [])})
        asys = host.get("autonomous_system") or {}
        loc = host.get("location") or {}
        verdict = "suspicious" if threats else "unknown"
        summary = f"{len(services)} service(s) on {', '.join(map(str, ports[:10])) or 'no ports'}"
        if asys.get("name"):
            summary += f" · AS{asys.get('asn')} {asys['name']}"
        if threats:
            summary += f" · threats: {', '.join(threats[:4])}"
        res = LookupResult(self.name, verdict, 50 if threats else 0, summary, link)
        res.tags = threats[:10] + [str(lbl.get("value") if isinstance(lbl, dict) else lbl)
                                   for lbl in (host.get("labels") or [])][:10]
        res.data = {"ports": ports[:50], "protocols": protos[:20], "threats": threats[:20], "asn": asys.get("asn"),
                    "as_name": asys.get("name"), "country": loc.get("country_code") or loc.get("country")}
        return res

    def test(self) -> str:
        r = self._host("8.8.8.8")
        if r.status_code not in (200, 404):
            r.raise_for_status()
        return "Censys reachable, token accepted"


class CrowdSec:
    name = "crowdsec"
    supports = {"ip"}

    def __init__(self):
        self.key = str(settings.get("crowdsec_api_key") or "")
        if not self.key:
            raise NotConfigured("CrowdSec CTI API key not set")

    def _smoke(self, ip: str):
        return _get(self.name, f"https://cti.api.crowdsec.net/v2/smoke/{ip}", {"x-api-key": self.key})

    def lookup(self, etype: str, value: str) -> LookupResult | None:
        if etype != "ip":
            return None
        _budget(self.name)
        r = self._smoke(value)
        link = f"https://app.crowdsec.net/cti/{value}"
        if r.status_code == 404:
            return LookupResult(self.name, "unknown", 0, "Not seen by the CrowdSec network", link)
        r.raise_for_status()
        d = r.json()
        rep = str(d.get("reputation") or "unknown").lower()
        verdict = {"malicious": "malicious", "suspicious": "suspicious", "safe": "clean"}.get(rep, "unknown")
        behaviors = [b.get("label") or b.get("name") for b in d.get("behaviors") or [] if isinstance(b, dict)]
        classes = [c.get("label") or c.get("name") for c in (d.get("classifications") or {}).get("classifications") or []]
        total = ((d.get("scores") or {}).get("overall") or {}).get("total")
        summary = f"Reputation: {rep}"
        if behaviors:
            summary += " · " + ", ".join(behaviors[:4])
        res = LookupResult(self.name, verdict, float(total or 0) * 20, summary, link)
        res.tags = [t for t in behaviors + classes if t][:20]
        res.data = {"reputation": rep, "behaviors": behaviors[:20], "classifications": classes[:20],
                    "background_noise": d.get("background_noise_score"), "as_name": d.get("as_name"),
                    "asn": d.get("as_num"), "country": (d.get("location") or {}).get("country"),
                    "first_seen": (d.get("history") or {}).get("first_seen"),
                    "last_seen": (d.get("history") or {}).get("last_seen")}
        return res

    def test(self) -> str:
        r = self._smoke("8.8.8.8")
        if r.status_code not in (200, 404):
            r.raise_for_status()
        return "CrowdSec CTI reachable, key accepted"


class Pulsedive:
    name = "pulsedive"
    supports = {"ip", "domain", "url"}

    def __init__(self):
        self.key = str(settings.get("pulsedive_api_key") or "")
        if not self.key:
            raise NotConfigured("Pulsedive API key not set")

    def lookup(self, etype: str, value: str) -> LookupResult | None:
        if etype not in self.supports:
            return None
        _budget(self.name)
        r = _get(self.name, "https://pulsedive.com/api/info.php", params={"indicator": value, "key": self.key})
        link = f"https://pulsedive.com/indicator/?ioc={value}"
        if r.status_code == 404:
            return LookupResult(self.name, "unknown", 0, "Not in Pulsedive", link)
        r.raise_for_status()
        d = r.json()
        if d.get("error"):
            return LookupResult(self.name, "unknown", 0, f"Pulsedive: {d['error']}"[:200], link)
        risk = str(d.get("risk") or "unknown").lower()
        verdict = {"critical": "malicious", "high": "malicious", "medium": "suspicious"}.get(risk, "unknown")
        threats = [t.get("name") for t in d.get("threats") or [] if isinstance(t, dict) and t.get("name")]
        feeds = [f.get("name") for f in d.get("feeds") or [] if isinstance(f, dict) and f.get("name")]
        summary = f"Risk: {risk}"
        if threats:
            summary += f" · threats: {', '.join(threats[:3])}"
        if feeds:
            summary += f" · {len(feeds)} feed(s)"
        res = LookupResult(self.name, verdict, {"critical": 95, "high": 80, "medium": 50, "low": 20}.get(risk, 0),
                           summary, link)
        res.malware = threats[:5]
        res.data = {"risk": risk, "threats": threats[:20], "feeds": feeds[:20],
                    "risk_factors": [f.get("description") for f in d.get("riskfactors") or [] if isinstance(f, dict)][:10]}
        return res

    def test(self) -> str:
        r = _get(self.name, "https://pulsedive.com/api/info.php", params={"indicator": "pulsedive.com", "key": self.key})
        if r.status_code not in (200, 404):
            r.raise_for_status()
        return "Pulsedive reachable, key accepted"


class HybridAnalysis:
    name = "hybrid-analysis"
    supports = {"md5", "sha1", "sha256"}
    BASE = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self):
        self.key = str(settings.get("hybrid_analysis_api_key") or "")
        if not self.key:
            raise NotConfigured("Hybrid Analysis API key not set")
        self.headers = {"api-key": self.key, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}

    def _sha256(self, value: str) -> str | None:
        r = _get(self.name, f"{self.BASE}/search/hash", self.headers, {"hash": value})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        d = r.json()
        rows = d if isinstance(d, list) else (d.get("reports") or d.get("result") or [])
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get("sha256"):
                return row["sha256"]
        shas = d.get("sha256s") if isinstance(d, dict) else None
        return shas[0] if shas else None

    def lookup(self, etype: str, value: str) -> LookupResult | None:
        if etype not in self.supports:
            return None
        _budget(self.name)
        sha = value if etype == "sha256" else self._sha256(value)
        link = f"https://www.hybrid-analysis.com/search?query={value}"
        if not sha:
            return LookupResult(self.name, "unknown", 0, "No Hybrid Analysis report", link)
        r = _get(self.name, f"{self.BASE}/overview/{sha}", self.headers)
        if r.status_code == 404:
            return LookupResult(self.name, "unknown", 0, "No Hybrid Analysis report", link)
        r.raise_for_status()
        d = r.json()
        v = str(d.get("verdict") or "").lower()
        verdict = {"malicious": "malicious", "suspicious": "suspicious", "whitelisted": "clean"}.get(v, "unknown")
        fam = d.get("vx_family") or ""
        score = d.get("threat_score")
        summary = f"Sandbox verdict: {v or 'n/a'}" + (f" · threat score {score}/100" if score is not None else "")
        if fam:
            summary += f" · family: {fam}"
        res = LookupResult(self.name, verdict, float(score or 0), summary,
                           f"https://www.hybrid-analysis.com/sample/{sha}")
        if fam:
            res.malware.append(fam)
        res.tags = [str(t) for t in d.get("tags") or []][:20]
        res.data = {"verdict": v, "threat_score": score, "family": fam, "type": d.get("type"),
                    "file_name": d.get("last_file_name"), "multiscan": d.get("multiscan_result")}
        return res

    def test(self) -> str:
        r = _get(self.name, f"{self.BASE}/key/current", self.headers)
        r.raise_for_status()
        return "Hybrid Analysis reachable, key accepted"


class IPinfo:
    name = "ipinfo"
    supports = {"ip"}

    def __init__(self):
        self.token = str(settings.get("ipinfo_token") or "")
        if not self.token and not settings.get("context_keyless"):
            raise NotConfigured("IPinfo token not set (or allow keyless context lookups)")

    def _fetch(self, ip: str):
        if self.token:
            return _get(self.name, f"https://api.ipinfo.io/lite/{ip}", params={"token": self.token}, wait=0.2)
        return _get(self.name, f"https://ipinfo.io/{ip}/json", wait=1)

    def lookup(self, etype: str, value: str) -> LookupResult | None:
        if etype != "ip":
            return None
        r = self._fetch(value)
        r.raise_for_status()
        d = r.json()
        if d.get("bogon"):
            return LookupResult(self.name, "unknown", 0, "Private / reserved address (bogon)",
                                f"https://ipinfo.io/{value}", data={"bogon": True})
        asn, as_name = d.get("asn"), d.get("as_name")
        if not asn and d.get("org"):  # keyless format: "AS15169 Google LLC"
            asn, _, as_name = str(d["org"]).partition(" ")
        cc = d.get("country_code") or (d.get("country") if len(str(d.get("country") or "")) == 2 else "")
        res = LookupResult(self.name, "unknown", 0,
                           " · ".join(filter(None, [f"{asn} {as_name or ''}".strip() if asn else "",
                                                    d.get("country") or cc, d.get("city")])) or "No data",
                           f"https://ipinfo.io/{value}")
        res.data = {"asn": asn, "as_name": as_name, "as_domain": d.get("as_domain"), "country": cc,
                    "country_name": d.get("country") if len(str(d.get("country") or "")) > 2 else None,
                    "city": d.get("city"), "hostname": d.get("hostname")}
        return res

    def test(self) -> str:
        self._fetch("8.8.8.8").raise_for_status()
        return "IPinfo reachable" + (", token accepted" if self.token else " (no token)")


CONTEXT_CLASSES = (Shodan, Censys, CrowdSec, Pulsedive, HybridAnalysis, IPinfo)


def available(etype: str | None = None) -> list:
    out = []
    for cls in CONTEXT_CLASSES:
        if etype and etype not in cls.supports:
            continue
        try:
            out.append(cls())
        except NotConfigured:
            continue
    return out


def geo_from(results: list[LookupResult]) -> dict | None:
    """Best ASN / country for an IP from context results (IPinfo first)."""
    for name in ("ipinfo", "censys", "shodan", "crowdsec"):
        r = next((x for x in results if x.provider == name), None)
        if r and (r.data.get("country") or r.data.get("asn")):
            return {"country": (r.data.get("country") or "")[:2].upper() or None, "asn": r.data.get("asn"),
                    "as_name": r.data.get("as_name") or r.data.get("org"), "source": name}
    return None

