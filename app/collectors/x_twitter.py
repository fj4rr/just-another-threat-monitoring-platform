from __future__ import annotations

from .. import settings
from ..processing.pipeline import RawItem
from .base import Collector, SkipCollector, parse_dt
from .rss import RSSCollector

API = "https://api.x.com/2"


class XCollector(Collector):
    """X (Twitter) timeline. Uses the official API v2 when a bearer token is configured,
    otherwise an optional RSS bridge URL (e.g. a self-hosted RSSHub / Nitter instance)."""

    kind = "x"
    category = "social"
    label = "X (Twitter) account"
    fields = [
        ("username", "Username", "vxunderground"),
        ("rss_bridge", "RSS bridge URL (optional, used when no API token)", "http://rsshub:1200/twitter/user/vxunderground"),
    ]

    def fetch(self) -> list[RawItem]:
        username = (self.cfg.get("username") or "").lstrip("@").strip()
        token = settings.get("x_bearer_token")
        if token and username:
            return self._api(username, token)
        bridge = self.cfg.get("rss_bridge")
        if bridge:
            proxy_src = type("S", (), {"config": {"url": bridge}, "category": "social"})()
            items = RSSCollector(proxy_src).fetch()  # type: ignore[arg-type]
            for it in items:
                it.author = it.author or f"@{username}"
            return items
        raise SkipCollector("no X bearer token and no RSS bridge configured")

    def _api(self, username: str, token: str) -> list[RawItem]:
        with self.client(Authorization=f"Bearer {token}") as c:
            uid = self.cfg.get("user_id")
            if not uid:
                r = c.get(f"{API}/users/by/username/{username}")
                r.raise_for_status()
                uid = r.json()["data"]["id"]
                self.source.config = {**self.cfg, "user_id": uid}
            params = {
                "max_results": 50,
                "tweet.fields": "created_at,entities,public_metrics",
                "exclude": "replies",
            }
            if self.cfg.get("since_id"):
                params["since_id"] = self.cfg["since_id"]
            r = c.get(f"{API}/users/{uid}/tweets", params=params)
            if r.status_code == 429:
                raise RuntimeError("X API rate limit reached (429)")
            r.raise_for_status()
            data = r.json()
        tweets = data.get("data", [])
        if tweets:
            self.source.config = {**self.source.config, "since_id": tweets[0]["id"]}
        out = []
        for t in tweets:
            text = t.get("text", "")
            urls = [u.get("expanded_url", "") for u in (t.get("entities", {}) or {}).get("urls", [])]
            hashtags = [h.get("tag", "") for h in (t.get("entities", {}) or {}).get("hashtags", [])]
            out.append(
                RawItem(
                    external_id=t["id"],
                    title=text.split("\n")[0][:180],
                    url=f"https://x.com/{username}/status/{t['id']}",
                    author=f"@{username}",
                    content=text + ("\n\nLinks: " + " ".join(urls) if urls else ""),
                    published_at=parse_dt(t.get("created_at")),
                    kind="post",
                    tags=hashtags,
                    raw={"metrics": t.get("public_metrics", {})},
                )
            )
        return out
