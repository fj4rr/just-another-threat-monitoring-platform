"""MISP events as a source (pull side of the MISP integration, see app/intel/misp.py)."""
from __future__ import annotations

from datetime import timedelta

from ..intel import NotConfigured
from ..models import utcnow
from ..processing.pipeline import RawItem
from .base import BackfillCapability, Collector, SkipCollector


class MISPCollector(Collector):
    kind = "misp"
    category = "intel"
    label = "MISP events"
    fields = [("tags", "Only events with these tags (comma list, optional)", "tlp:green, ransomware"),
              ("days", "First run: look back this many days", "7")]

    def fetch(self) -> list[RawItem]:
        from ..intel.misp import MISP, event_to_raw

        try:
            client = MISP()
        except NotConfigured as e:
            raise SkipCollector(str(e)) from e
        try:
            days = max(1, min(int(self.cfg.get("days") or 7), 365))
        except ValueError:
            days = 7
        # overlap the previous run by an hour: MISP timestamps are per edit, duplicates are skipped on ingest
        since = (self.source.last_run - timedelta(hours=1)) if self.source.last_run else utcnow() - timedelta(days=days)
        out: list[RawItem] = []
        for page in range(1, 6):
            events = client.search_events(since, self._tags(), limit=50, page=page)
            out += [event_to_raw(ev, client.url) for ev in events]
            if len(events) < 50:
                break
        return out

    def _tags(self) -> list[str] | None:
        return [t.strip() for t in str(self.cfg.get("tags") or "").split(",") if t.strip()] or None

    def backfill_capability(self) -> BackfillCapability:
        return BackfillCapability(True, "events changed since the start of the range (restSearch, paged)", None,
                                  "limited to what your MISP user may see")

    def backfill(self, since, until, progress):
        from ..intel.misp import MISP, event_to_raw

        try:
            client = MISP()
        except NotConfigured as e:
            raise SkipCollector(str(e)) from e
        for page in range(1, 201):
            events = client.search_events(since, self._tags(), limit=100, page=page)
            progress(f"page {page}")
            raws = [event_to_raw(ev, client.url) for ev in events]
            yield [r for r in raws if r.published_at is None or r.published_at <= until]
            if len(events) < 100:
                return
