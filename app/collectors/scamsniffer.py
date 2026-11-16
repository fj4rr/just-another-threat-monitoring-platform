"""ScamSniffer's open crypto phishing blocklist (GPL-3.0, github.com/scamsniffer/scam-database).

The repository keeps one file per day of newly listed domains (``blacklist/archive/YYYY-MM-DD.json``), published
with a 7-day delay. Each day becomes one item with the domains as indicators. The domains are already confirmed
phishing, so they are marked malicious on arrival instead of spending enrichment quota.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from ..models import utcnow
from ..processing.pipeline import RawItem
from .base import BackfillCapability, Collector

ARCHIVE = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/archive/{day}.json"
REPO = "https://github.com/scamsniffer/scam-database"
DELAY_DAYS = 7  # the public list lags a week behind
LOOKBACK_DAYS = 4  # days checked per scheduled run (a missed day is picked up on the next run)
MAX_DOMAINS = 500  # indicators per day


def _int(v, default: int, lo: int, hi: int) -> int:
    try:
        return min(max(int(v), lo), hi)
    except (TypeError, ValueError):
        return default


class ScamSnifferCollector(Collector):
    kind = "scamsniffer"
    category = "intel"
    label = "ScamSniffer crypto phishing domains"
    fields = [("max_domains", f"Domains kept per day (default {MAX_DOMAINS})", str(MAX_DOMAINS))]

    def _day(self, c, day: datetime) -> RawItem | None:
        stamp = day.strftime("%Y-%m-%d")
        r = c.get(ARCHIVE.format(day=stamp))
        if r.status_code == 404:  # not published yet
            return None
        r.raise_for_status()
        data = r.json()
        domains = data.get("domains", data) if isinstance(data, dict) else data
        domains = sorted({str(d).strip().lower().strip(".") for d in domains or [] if d and "." in str(d)})
        if not domains:
            return None
        from ..intel import make_ioc

        cap = _int(self.cfg.get("max_domains"), MAX_DOMAINS, 1, 5000)
        inds = [x for x in (make_ioc(d, "domain") for d in domains[:cap]) if x]
        shown = ", ".join(domains[:40])
        return RawItem(
            external_id=f"scamsniffer:{stamp}",
            title=f"ScamSniffer: {len(domains):,} crypto phishing domains listed on {stamp}",
            url=f"{REPO}/blob/main/blacklist/archive/{stamp}.json", author="ScamSniffer",
            content=(f"Crypto phishing and wallet drainer domains (fake airdrop, token-claim and wallet pages) added "
                     f"to the ScamSniffer blocklist on {stamp}. Crypto scam / drainer.\n\nDomains: {shown}"
                     + (f" … and {len(domains) - 40:,} more" if len(domains) > 40 else "")),
            published_at=day.replace(hour=12), kind="analysis", tags=["crypto phishing", "wallet drainer"],
            raw={"domains": len(domains), "listed_by": "scamsniffer",
                 "listed_summary": "Listed by ScamSniffer as a crypto phishing / wallet drainer domain"},
            indicators=inds)

    def _days(self, since: datetime, until: datetime):
        day = until.replace(hour=0, minute=0, second=0, microsecond=0)
        while day >= since.replace(hour=0, minute=0, second=0, microsecond=0):
            yield day
            day -= timedelta(days=1)

    def fetch(self) -> list[RawItem]:
        until = utcnow() - timedelta(days=DELAY_DAYS - 1)
        out = []
        with self.client() as c:
            for day in self._days(until - timedelta(days=LOOKBACK_DAYS), until):
                raw = self._day(c, day)
                if raw:
                    out.append(raw)
        return out

    def backfill_capability(self) -> BackfillCapability:
        return BackfillCapability(True, "one archive file per day since 2022-05-31", None,
                                  "the public list lags a week behind")

    def backfill(self, since, until, progress):
        with self.client() as c:
            for day in self._days(max(since, datetime(2022, 5, 31)), until):
                progress(day.strftime("%Y-%m-%d"))
                raw = self._day(c, day)
                yield [raw] if raw else []
