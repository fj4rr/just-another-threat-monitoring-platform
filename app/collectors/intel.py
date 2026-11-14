"""Collectors that pull from threat-intel platforms as primary sources."""
from __future__ import annotations

from datetime import timedelta

from ..intel import NotConfigured, make_ioc
from ..intel.clients import OTX, AnyRun, ThreatFox, URLScan
from ..models import utcnow
from ..processing.pipeline import RawItem
from .base import BackfillCapability, Collector, SkipCollector, parse_dt


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
            raise SkipCollector(str(e)) from e
        if self.cfg.get("mode") == "search" and self.cfg.get("query"):
            pulses = otx.search_pulses(self.cfg["query"], limit=30)
        else:
            since = self.source.last_run or (utcnow() - timedelta(days=3))
            pulses = otx.subscribed(since.strftime("%Y-%m-%dT%H:%M:%S"), limit=50)
        return [self.to_raw(otx, p) for p in pulses]

    def backfill_capability(self) -> BackfillCapability:
        if self.cfg.get("mode") == "search":
            return BackfillCapability(False, note="OTX pulse search is not time-bounded; use a subscribed source")
        return BackfillCapability(True, "subscribed pulses modified in the range (modified_since, paged)", None,
                                  "only pulses from users and groups you subscribe to on OTX")

    def backfill(self, since, until, progress):
        try:
            otx = OTX()
        except NotConfigured as e:
            raise SkipCollector(str(e)) from e
        for page in range(1, 101):
            data = otx._get("pulses/subscribed", {"limit": 50, "page": page,
                                                  "modified_since": since.strftime("%Y-%m-%dT%H:%M:%S")})
            pulses = data.get("results", [])
            progress(f"page {page}")
            raws = [self.to_raw(otx, p) for p in pulses]
            yield [r for r in raws if r.published_at is None or r.published_at <= until]
            if not data.get("next") or not pulses:
                return

    def to_raw(self, otx, p: dict) -> RawItem:
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
        return RawItem(
            external_id=p.get("id", ""),
            title=p.get("name", "(pulse)"),
            url=f"https://otx.alienvault.com/pulse/{p.get('id', '')}",
            author=p.get("author_name", ""),
            content=body,
            published_at=parse_dt(p.get("created") or p.get("modified")),
            kind="pulse",
            tags=list(filter(None, (p.get("tags") or []) + fams + ([adv] if adv else []))),
            raw={"tlp": p.get("tlp"), "indicator_count": len(p.get("indicators") or []),
                 "targeted_countries": [str(c) for c in (p.get("targeted_countries") or [])][:20]},
            indicators=otx.pulse_indicators(p, limit=300),
        )


class URLScanCollector(Collector):
    kind = "urlscan"
    category = "intel"
    label = "urlscan.io search"
    fields = [("query", "Search query", "verdicts.malicious:true AND date:>now-1d")]

    def backfill_capability(self) -> BackfillCapability:
        return BackfillCapability(False, note="search results are quota-limited; widen the date in the query instead")

    def fetch(self) -> list[RawItem]:
        query = self.cfg.get("query") or "verdicts.malicious:true AND date:>now-1d"
        try:
            client = URLScan(require_key=True)
        except NotConfigured as e:
            raise SkipCollector(str(e)) from e
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

    def backfill_capability(self) -> BackfillCapability:
        return BackfillCapability(False, note="TI Lookup quota is small; raise 'Lookback days' on the source instead")

    def fetch(self) -> list[RawItem]:
        try:
            ar = AnyRun()
        except NotConfigured as e:
            raise SkipCollector(str(e)) from e
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
            raise SkipCollector(str(e)) from e
        return self._group(tf.recent(days=1), lambda _row: utcnow().strftime("%Y-%m-%d"))

    def backfill_capability(self) -> BackfillCapability:
        return BackfillCapability(True, "recent IOCs grouped per family and day", 7,
                                  "the ThreatFox API returns at most the last 7 days")

    def backfill(self, since, until, progress):
        try:
            tf = ThreatFox()
        except NotConfigured as e:
            raise SkipCollector(str(e)) from e
        days = max(1, min(7, (until - since).days + 1))
        progress(f"get_iocs for {days} day(s)")
        rows = [r for r in tf.recent(days=days)
                if (dt := parse_dt(r.get("first_seen"))) is None or since <= dt <= until]
        yield self._group(rows, lambda row: str(row.get("first_seen") or "")[:10] or utcnow().strftime("%Y-%m-%d"))

    def _group(self, rows: list[dict], day_of) -> list[RawItem]:
        # group IOCs by malware family into one item per family per day
        groups: dict[tuple[str, str], list[dict]] = {}
        for row in rows:
            groups.setdefault((day_of(row), row.get("malware_printable") or "Unknown"), []).append(row)
        out = []
        for (day, fam), items in groups.items():
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


class RansomwareLiveCollector(Collector):
    """Leak-site victim posts via ransomware.live (an aggregator; JATMP never visits leak sites)."""

    kind = "ransomwarelive"
    category = "intel"
    label = "ransomware.live leak-site victims"
    fields = [("country", "Only victims in this country (ISO-2 code, optional)", "ID"),
              ("group", "Only this group (optional)", "akira")]

    def _victims(self, rl) -> list[dict]:
        if self.cfg.get("country"):
            return rl.country_victims(str(self.cfg["country"]))
        if self.cfg.get("group"):
            return rl.group_victims(str(self.cfg["group"]).lower())
        return rl.recent_victims()

    @staticmethod
    def _to_raws(victims: list[dict], rl) -> list[RawItem]:
        out = []
        for v in victims:
            if not v["victim"] or not v["group"]:
                continue
            # the victim's website is deliberately kept out of the text: it is the victim, not an indicator
            body = "\n".join(filter(None, [
                f"Ransomware group {v['group']} listed {v['victim']} on its leak site.",
                f"Country: {v['country']}" if v["country"] else "",
                f"Sector: {v['sector']}" if v["sector"] else "",
                f"Attack date (claimed): {v['attackdate'][:10]}" if v["attackdate"] else "",
            ]))
            out.append(RawItem(
                external_id=v["id"] or f"{v['group']}:{v['victim']}"[:500],
                title=f"{v['group']} claims {v['victim']}",
                url=v["permalink"] or f"https://www.ransomware.live/group/{v['group']}",
                author="ransomware.live", content=body, published_at=parse_dt(v["discovered"] or v["attackdate"]),
                kind="post", tags=[v["group"], "leak-site"] + ([f"country:{v['country']}"] if v["country"] else []),
                raw={"victim": v["victim"], "group": v["group"], "country": v["country"], "sector": v["sector"],
                     "website": v["website"], "api": "pro" if rl.pro else "free"},
            ))
        return out

    def fetch(self) -> list[RawItem]:
        from ..intel.darkweb import RansomwareLive

        rl = RansomwareLive()
        raws = self._to_raws(self._victims(rl), rl)
        if self.cfg.get("country") or self.cfg.get("group"):
            # country / group lists return the full history; the scheduled run only keeps fresh posts
            cutoff = (self.source.last_run or utcnow() - timedelta(days=14)) - timedelta(days=2)
            raws = [r for r in raws if not r.published_at or r.published_at >= cutoff]
        return raws

    def backfill_capability(self) -> BackfillCapability:
        if self.cfg.get("country") or self.cfg.get("group"):
            return BackfillCapability(True, "the full victim list for the configured country / group", None,
                                      "ransomware.live keeps history back to 2021 for most groups")
        return BackfillCapability(False, note="the recent list only holds the last 100 victims; add a source "
                                              "with a country or group to backfill")

    def backfill(self, since, until, progress):
        from ..intel.darkweb import RansomwareLive

        progress("victim list")
        rl = RansomwareLive()
        yield [r for r in self._to_raws(self._victims(rl), rl) if r.published_at and since <= r.published_at <= until]
