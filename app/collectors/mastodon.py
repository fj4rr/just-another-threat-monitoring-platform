from __future__ import annotations

from ..processing.pipeline import RawItem, strip_html
from .base import Collector, SkipCollector, parse_dt


class MastodonCollector(Collector):
    """Public statuses of a Mastodon / fediverse account (e.g. infosec.exchange). No key needed."""

    kind = "mastodon"
    category = "social"
    label = "Mastodon account"
    fields = [("account", "Account (user@instance)", "malware_traffic@infosec.exchange")]

    def fetch(self) -> list[RawItem]:
        acct = (self.cfg.get("account") or "").lstrip("@").strip()
        if "@" not in acct:
            raise SkipCollector("account must look like user@instance")
        user, instance = acct.split("@", 1)
        base = f"https://{instance}/api/v1"
        with self.client() as c:
            acc_id = self.cfg.get("account_id")
            if not acc_id:
                r = c.get(f"{base}/accounts/lookup", params={"acct": user})
                r.raise_for_status()
                acc_id = r.json()["id"]
                self.source.config = {**self.cfg, "account_id": acc_id}
            r = c.get(f"{base}/accounts/{acc_id}/statuses", params={"limit": 40, "exclude_replies": "true"})
            r.raise_for_status()
            statuses = r.json()
        out = []
        for s in statuses:
            boosted = s.get("reblog")
            post = boosted or s
            text = strip_html(post.get("content", ""))
            if post.get("spoiler_text"):
                text = f"[CW: {post['spoiler_text']}] {text}"
            card = post.get("card") or {}
            links = [card.get("url")] if card.get("url") else []
            if card:
                text += f"\n\n{card.get('title', '')}\n{card.get('description', '')}"
            author = (post.get("account") or {}).get("acct", user)
            out.append(RawItem(
                external_id=s.get("uri") or s.get("id", ""),
                title=("[boost] " if boosted else "") + (text.split("\n")[0][:180] or "(post)"),
                url=post.get("url") or s.get("url") or "",
                author="@" + (author if "@" in author else f"{author}@{instance}"),
                content=text + ("\n\nLinks: " + " ".join(links) if links else ""),
                published_at=parse_dt(s.get("created_at")),
                kind="post",
                tags=[t.get("name", "") for t in post.get("tags") or [] if t.get("name")],
                raw={"favourites": post.get("favourites_count", 0), "boosts": post.get("reblogs_count", 0)},
            ))
        return out
