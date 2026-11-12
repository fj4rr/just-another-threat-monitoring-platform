from __future__ import annotations

import calendar
from datetime import UTC, datetime

import feedparser

from ..processing.pipeline import RawItem
from .base import Collector, SkipCollector


class RSSCollector(Collector):
    kind = "rss"
    category = "news"
    label = "RSS / Atom feed"
    fields = [("url", "Feed URL", "https://example.com/feed/")]

    def fetch(self) -> list[RawItem]:
        url = self.cfg.get("url")
        if not url:
            raise SkipCollector("no feed URL configured")
        if not str(url).lower().startswith(("http://", "https://")):
            raise SkipCollector("feed URL must start with http:// or https://")
        with self.client(Accept="application/rss+xml, application/atom+xml, application/xml, */*") as c:
            resp = c.get(url)
            resp.raise_for_status()
            if len(resp.content) > 10 * 1024 * 1024:
                raise RuntimeError("feed larger than 10 MB, refusing to parse")
        feed = feedparser.parse(resp.content)
        if feed.bozo and not feed.entries:
            head = " ".join(resp.content[:80].decode("utf-8", "replace").split())
            raise RuntimeError(f"could not parse feed ({resp.headers.get('content-type', '?')}): "
                               f"{feed.bozo_exception}; body starts with: {head!r}")
        out = []
        for e in feed.entries[:100]:
            published = None
            for key in ("published_parsed", "updated_parsed"):
                if e.get(key):
                    published = datetime.fromtimestamp(calendar.timegm(e[key]), tz=UTC).replace(tzinfo=None)
                    break
            content = ""
            if e.get("content"):
                content = " ".join(c.get("value", "") for c in e.content)
            content = content or e.get("summary", "")
            tags = [t.get("term", "") for t in e.get("tags", []) if t.get("term")]
            out.append(
                RawItem(
                    external_id=e.get("id") or e.get("link") or e.get("title", ""),
                    title=e.get("title", ""),
                    url=e.get("link", ""),
                    author=e.get("author", ""),
                    content=content,
                    published_at=published,
                    kind="post" if self.source.category == "social" else "article",
                    tags=tags,
                )
            )
        return out
