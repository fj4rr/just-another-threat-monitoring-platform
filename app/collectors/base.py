from __future__ import annotations

from datetime import UTC, datetime

import httpx

from .. import __version__
from ..models import Source
from ..processing.pipeline import RawItem

USER_AGENT = f"JATMP/{__version__} (+threat-monitoring; self-hosted)"


class SkipCollector(Exception):
    """Raised when a collector cannot run (e.g. missing API key). Not an error."""


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
        return httpx.Client(timeout=30, headers=h, follow_redirects=True)

    def fetch(self) -> list[RawItem]:  # pragma: no cover - interface
        raise NotImplementedError


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
