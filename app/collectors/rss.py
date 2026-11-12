from __future__ import annotations

import calendar
from datetime import datetime

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
        with self.client(Accept="application/rss+xml, application/atom+xml, application/xml, */*") as c:
            resp = c.get(url)
            resp.raise_for_status()
        feed = feedparser.parse(resp.content)
        if feed.bozo and not feed.entries:
            raise RuntimeError(f"could not parse feed: {feed.bozo_exception}")
        out = []
        for e in feed.entries[:100]:
            published = None
            for key in ("published_parsed", "updated_parsed"):
                if e.get(key):
                    published = datetime.utcfromtimestamp(calendar.timegm(e[key]))
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
