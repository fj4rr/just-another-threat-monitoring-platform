"""MISP events as a source (pull side of the MISP integration, see app/intel/misp.py)."""
from __future__ import annotations

from datetime import timedelta

from ..intel import NotConfigured
from ..models import utcnow
from ..processing.pipeline import RawItem
from .base import Collector, SkipCollector


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
        tags = [t.strip() for t in str(self.cfg.get("tags") or "").split(",") if t.strip()]
        out: list[RawItem] = []
        for page in range(1, 6):
            events = client.search_events(since, tags or None, limit=50, page=page)
            out += [event_to_raw(ev, client.url) for ev in events]
            if len(events) < 50:
                break
        return out
