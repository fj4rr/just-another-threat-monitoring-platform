from __future__ import annotations

from ..processing.pipeline import RawItem
from .base import BackfillCapability, Collector, SkipCollector, parse_dt

PUBLIC_API = "https://public.api.bsky.app/xrpc"
BACKFILL_MAX_PAGES = 60  # 6,000 posts


class BlueskyCollector(Collector):
    """Reads a public author feed via the unauthenticated Bluesky AppView API."""

    kind = "bluesky"
    category = "social"
    label = "Bluesky account"
    fields = [("handle", "Handle", "vxunderground.bsky.social")]

    def _handle(self) -> str:
        handle = (self.cfg.get("handle") or "").lstrip("@").strip()
        if not handle:
            raise SkipCollector("no handle configured")
        return handle

    def _page(self, c, handle: str, limit: int, cursor: str | None = None) -> dict:
        params = {"actor": handle, "limit": limit, "filter": "posts_no_replies"}
        if cursor:
            params["cursor"] = cursor
        r = c.get(f"{PUBLIC_API}/app.bsky.feed.getAuthorFeed", params=params)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def to_raw(entry: dict, handle: str) -> RawItem:
        post = entry.get("post", {})
        rec = post.get("record", {})
        author = post.get("author", {})
        text = rec.get("text", "")
        # include link-card text and full URLs from facets (text often truncates links)
        links = []
        for facet in rec.get("facets", []) or []:
            for feat in facet.get("features", []):
                if feat.get("uri"):
                    links.append(feat["uri"])
        embed = post.get("embed") or {}
        ext = embed.get("external") or {}
        if ext:
            links.append(ext.get("uri", ""))
            text += f"\n\n{ext.get('title', '')}\n{ext.get('description', '')}"
        reposted = entry.get("reason", {}).get("$type", "").endswith("reasonRepost")
        uri = post.get("uri", "")
        rkey = uri.rsplit("/", 1)[-1]
        web = f"https://bsky.app/profile/{author.get('handle', handle)}/post/{rkey}"
        title = text.strip().split("\n")[0][:180] or "(post)"
        return RawItem(
            external_id=uri, title=("[repost] " if reposted else "") + title, url=web,
            author="@" + author.get("handle", handle),
            content=text + ("\n\nLinks: " + " ".join(links) if links else ""),
            published_at=parse_dt(rec.get("createdAt") or post.get("indexedAt")), kind="post",
            tags=list(rec.get("tags") or []),
            raw={"likes": post.get("likeCount", 0), "reposts": post.get("repostCount", 0), "links": links})

    def fetch(self) -> list[RawItem]:
        handle = self._handle()
        with self.client() as c:
            data = self._page(c, handle, 50)
        return [self.to_raw(e, handle) for e in data.get("feed", [])]

    def backfill_capability(self) -> BackfillCapability:
        return BackfillCapability(True, "author feed, paged back with the API cursor", None,
                                  f"up to {BACKFILL_MAX_PAGES * 100:,} posts per account per run")

    def backfill(self, since, until, progress):
        handle = self._handle()
        cursor = None
        with self.client() as c:
            for page in range(1, BACKFILL_MAX_PAGES + 1):
                data = self._page(c, handle, 100, cursor)
                raws = [self.to_raw(e, handle) for e in data.get("feed", [])]
                progress(f"page {page}")
                yield [r for r in raws if r.published_at and since <= r.published_at <= until]
                cursor = data.get("cursor")
                # reposts can be older than the window while newer own posts follow; stop on own posts only
                own = [r for r in raws if r.published_at and not r.title.startswith("[repost]")]
                if not cursor or not raws or (own and min(r.published_at for r in own) < since):
                    return
