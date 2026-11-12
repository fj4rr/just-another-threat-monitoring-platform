from __future__ import annotations

from ..processing.pipeline import RawItem
from .base import Collector, SkipCollector, parse_dt

PUBLIC_API = "https://public.api.bsky.app/xrpc"


class BlueskyCollector(Collector):
    """Reads a public author feed via the unauthenticated Bluesky AppView API."""

    kind = "bluesky"
    category = "social"
    label = "Bluesky account"
    fields = [("handle", "Handle", "vxunderground.bsky.social")]

    def fetch(self) -> list[RawItem]:
        handle = (self.cfg.get("handle") or "").lstrip("@").strip()
        if not handle:
            raise SkipCollector("no handle configured")
        with self.client() as c:
            r = c.get(f"{PUBLIC_API}/app.bsky.feed.getAuthorFeed",
                      params={"actor": handle, "limit": 50, "filter": "posts_no_replies"})
            r.raise_for_status()
            data = r.json()
        out = []
        for entry in data.get("feed", []):
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
            out.append(
                RawItem(
                    external_id=uri,
                    title=("[repost] " if reposted else "") + title,
                    url=web,
                    author="@" + author.get("handle", handle),
                    content=text + ("\n\nLinks: " + " ".join(links) if links else ""),
                    published_at=parse_dt(rec.get("createdAt") or post.get("indexedAt")),
                    kind="post",
                    tags=[t for t in (rec.get("tags") or [])],
                    raw={"likes": post.get("likeCount", 0), "reposts": post.get("repostCount", 0),
                         "links": links},
                )
            )
        return out
