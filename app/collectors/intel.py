"""Collectors that pull from threat-intel platforms as primary sources."""
from __future__ import annotations

from datetime import timedelta

from ..intel import NotConfigured, make_ioc
from ..intel.clients import OTX, AnyRun, ThreatFox, URLScan
from ..models import utcnow
from ..processing.pipeline import RawItem
from .base import Collector, SkipCollector, parse_dt


class OTXCollector(Collector):
    kind = "otx"
    category = "intel"
    label = "AlienVault OTX pulses"
    fields = [("mode", "Mode: subscribed | search", "subscribed"),
              ("query", "Search query (search mode)", "ransomware")]

    def fetch(self) -> list[RawItem]:
        try:
            otx = OTX()
        except NotConfigured as e:
            raise SkipCollector(str(e))
        if self.cfg.get("mode") == "search" and self.cfg.get("query"):
            pulses = otx.search_pulses(self.cfg["query"], limit=30)
        else:
            since = self.source.last_run or (utcnow() - timedelta(days=3))
            pulses = otx.subscribed(since.strftime("%Y-%m-%dT%H:%M:%S"), limit=50)
        out = []
        for p in pulses:
            fams = [f.get("display_name") if isinstance(f, dict) else f for f in p.get("malware_families") or []]
            adv = p.get("adversary") or ""
            body = "\n".join(filter(None, [
                p.get("description", ""),
                f"Adversary: {adv}" if adv else "",
                f"Malware families: {', '.join(filter(None, fams))}" if fams else "",
                f"Targeted countries: {', '.join(p.get('targeted_countries') or [])}" if p.get("targeted_countries") else "",
                f"Industries: {', '.join(p.get('industries') or [])}" if p.get("industries") else "",
                f"ATT&CK: {', '.join(a.get('id', a) if isinstance(a, dict) else a for a in p.get('attack_ids') or [])}"
                if p.get("attack_ids") else "",
                "References: " + " ".join(p.get("references") or []) if p.get("references") else "",
            ]))
            out.append(RawItem(
                external_id=p.get("id", ""),
                title=p.get("name", "(pulse)"),
                url=f"https://otx.alienvault.com/pulse/{p.get('id', '')}",
                author=p.get("author_name", ""),
                content=body,
                published_at=parse_dt(p.get("created") or p.get("modified")),
                kind="pulse",
                tags=list(filter(None, (p.get("tags") or []) + fams + ([adv] if adv else []))),
                raw={"tlp": p.get("tlp"), "indicator_count": len(p.get("indicators") or [])},
                indicators=otx.pulse_indicators(p, limit=300),
            ))
        return out


class URLScanCollector(Collector):
    kind = "urlscan"
    category = "intel"
    label = "urlscan.io search"
    fields = [("query", "Search query", "verdicts.malicious:true AND date:>now-1d")]

    def fetch(self) -> list[RawItem]:
        query = self.cfg.get("query") or "verdicts.malicious:true AND date:>now-1d"
        try:
            client = URLScan(require_key=True)
        except NotConfigured as e:
            raise SkipCollector(str(e))
        results = client.search(query, size=100)
        out = []
        for r in results:
            task, page = r.get("task") or {}, r.get("page") or {}
            url = page.get("url") or task.get("url") or ""
            tags = task.get("tags") or []
            brands = [b.get("name", b) if isinstance(b, dict) else b
                      for b in ((r.get("verdicts") or {}).get("brands") or [])]
            inds = [x for x in (make_ioc(url, "url"), make_ioc(page.get("domain", ""), "domain"),
                                make_ioc(page.get("ip", ""), "ip") if page.get("ip") else None) if x]
            out.append(RawItem(
                external_id=r.get("_id", url),
                title=f"Scan: {page.get('domain') or url}" + (f" ({', '.join(brands)})" if brands else ""),
                url=f"https://urlscan.io/result/{r.get('_id', '')}/",
                author="urlscan.io",
                content=f"URL: {url}\nIP: {page.get('ip', '')}\nCountry: {page.get('country', '')}\n"
                        f"ASN: {page.get('asnname', '')}\nTags: {', '.join(tags)}\nBrands: {', '.join(brands)}",
                published_at=parse_dt(task.get("time")),
                kind="scan",
                tags=tags + brands,
                raw={"screenshot": r.get("screenshot")},
                indicators=inds,
            ))
        return out


class AnyRunCollector(Collector):
    """Runs a TI Lookup query (e.g. a family name) and stores matching sandbox tasks."""

    kind = "anyrun"
    category = "intel"
    label = "ANY.RUN TI Lookup query"
    fields = [("query", "TI Lookup query", 'threatName:"lumma"'), ("depth", "Lookback days", "7")]

    def fetch(self) -> list[RawItem]:
        try:
            ar = AnyRun()
        except NotConfigured as e:
            raise SkipCollector(str(e))
        query = self.cfg.get("query")
        if not query:
            raise SkipCollector("no query configured")
        data = ar.ti_search(query, int(self.cfg.get("depth") or 7))
        threats = ar._threats(data)
        inds = ar._related_iocs(data, 100)
        out = []
        for t in (data.get("sourceTasks") or [])[:100]:
            uuid = t.get("uuid") or t.get("taskUuid") or t.get("related", "")
            out.append(RawItem(
                external_id=str(uuid),
                title=f"ANY.RUN task – {query}" + (f" [{t.get('threatLevel')}]" if t.get("threatLevel") else ""),
                url=t.get("related") or (f"https://app.any.run/tasks/{uuid}" if uuid else ""),
                author="ANY.RUN",
                content=f"Query: {query}\nThreats: {', '.join(threats)}\nTags: {', '.join(t.get('tags') or [])}",
                published_at=parse_dt(t.get("date")),
                kind="analysis",
                tags=(t.get("tags") or []) + threats[:5],
                indicators=inds[:50],
            ))
        return out


class ThreatFoxCollector(Collector):
    kind = "threatfox"
    category = "intel"
    label = "abuse.ch ThreatFox (recent IOCs)"
    fields = []

    def fetch(self) -> list[RawItem]:
        try:
            tf = ThreatFox()
        except NotConfigured as e:
            raise SkipCollector(str(e))
        rows = tf.recent(days=1)
        # group IOCs by malware family into one item per family per day
        groups: dict[str, list[dict]] = {}
        for row in rows:
            groups.setdefault(row.get("malware_printable") or "Unknown", []).append(row)
        out = []
        day = utcnow().strftime("%Y-%m-%d")
        for fam, items in groups.items():
            inds = []
            for row in items[:300]:
                raw = row.get("ioc", "")
                kind = {"ip:port": "ip", "domain": "domain", "url": "url", "md5_hash": "md5",
                        "sha256_hash": "sha256", "sha1_hash": "sha1"}.get(row.get("ioc_type", ""))
                ex = make_ioc(raw, kind)
                if ex:
                    inds.append(ex)
            types = sorted({r.get("threat_type", "") for r in items})
            out.append(RawItem(
                external_id=f"{day}:{fam}",
                title=f"ThreatFox: {len(items)} new IOC(s) for {fam}",
                url=f"https://threatfox.abuse.ch/browse/malware/{items[0].get('malware', '')}/",
                author="abuse.ch",
                content=f"Family: {fam}\nThreat types: {', '.join(types)}\n"
                        f"Reporters: {', '.join(sorted({r.get('reporter', '') for r in items})[:10])}",
                published_at=parse_dt(items[0].get("first_seen")),
                kind="pulse",
                tags=[fam] + sorted({t for r in items for t in (r.get("tags") or [])})[:20],
                indicators=inds,
            ))
        return out
