from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from .. import __version__, netguard
from ..models import Source
from ..processing.pipeline import RawItem

USER_AGENT = f"JATMP/{__version__} (+threat-monitoring; self-hosted)"


class SkipCollector(Exception):
    """Raised when a collector cannot run (e.g. missing API key). Not an error."""


@dataclass
class BackfillCapability:
    """How far back a collector can reach and how. ``max_days`` None = as far as the provider keeps data."""

    supported: bool
    method: str = ""
    max_days: int | None = None
    note: str = ""


Progress = Callable[[str], None]

# The topic filter (processing/topics.py) as a source setting. Since 0.13 every news and social collector offers it
# (RSS, Telegram, X, Mastodon, Bluesky); intel feeds are on topic by nature.
FILTER_FIELD = ("filter", "Topic filter (optional): 'security' keeps only security-related entries, 'cyber' is "
                          "stricter for general news and general channels, 'fraud' keeps only scam reports", "security")


class Collector:
    kind = ""
    category = "news"
    label = ""
    # config fields the UI should render: (name, label, placeholder)
    fields: list[tuple[str, str, str]] = []

    def __init__(self, source: Source):
        self.source = source
        self.cfg = source.config or {}

    def client(self, **headers) -> httpx.Client:
        h = {"User-Agent": USER_AGENT, "Accept": "application/json, */*"}
        h.update({k.replace("_", "-"): v for k, v in headers.items()})
        return netguard.client(timeout=30, headers=h)  # SSRF guard + size cap (audit 2026-11 S-3, S-4)

    def fetch(self) -> list[RawItem]:  # pragma: no cover - interface
        raise NotImplementedError

    def keep(self, raws: list[RawItem]) -> list[RawItem]:
        """Entries of ``raws`` that match the source's topic filter (all when it has none). Applied by the jobs to
        what ``fetch`` and ``backfill`` return, for every source kind (PM review 2026-11, item 10)."""
        from ..processing import topics

        return topics.keep(raws, self.cfg.get("filter"))

    _keep = keep  # the name used before 0.13

    # ---- historical backfill (app/backfill.py). Collectors that support it override both methods.
    def backfill_capability(self) -> BackfillCapability:
        return BackfillCapability(False, note="this collector only sees what the provider currently lists")

    def backfill(self, since: datetime, until: datetime, progress: Progress) -> Iterator[list[RawItem]]:
        """Yield pages of items published between ``since`` and ``until`` (naive UTC), newest first."""
        raise NotImplementedError
        yield []  # pragma: no cover


def in_window(dt: datetime | None, since: datetime, until: datetime) -> bool:
    return dt is not None and since <= dt <= until


def parse_dt(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC).replace(tzinfo=None)
    s = str(value).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d"):
        try:
            dt = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s[:26], fmt)
            if dt.tzinfo:
                dt = dt.astimezone(UTC).replace(tzinfo=None)
            return dt
        except ValueError:
            continue
    return None
