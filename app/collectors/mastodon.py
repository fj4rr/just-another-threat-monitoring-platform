from __future__ import annotations

from ..processing.pipeline import RawItem, strip_html
from .base import BackfillCapability, Collector, SkipCollector, parse_dt

BACKFILL_MAX_PAGES = 100  # 4,000 statuses


class MastodonCollector(Collector):
    """Public statuses of a Mastodon / fediverse account (e.g. infosec.exchange). No key needed."""

    kind = "mastodon"
    category = "social"
    label = "Mastodon account"
    fields = [("account", "Account (user@instance)", "malware_traffic@infosec.exchange")]

    def _account(self, c) -> tuple[str, str, str]:
        acct = (self.cfg.get("account") or "").lstrip("@").strip()
        if "@" not in acct:
            raise SkipCollector("account must look like user@instance")
        user, instance = acct.split("@", 1)
        base = f"https://{instance}/api/v1"
        acc_id = self.cfg.get("account_id")
        if not acc_id:
            r = c.get(f"{base}/accounts/lookup", params={"acct": user})
            r.raise_for_status()
            acc_id = r.json()["id"]
            self.source.config = {**self.cfg, "account_id": acc_id}
        return base, str(acc_id), instance

    @staticmethod
    def to_raw(s: dict, instance: str, user: str = "") -> RawItem:
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
        return RawItem(
            external_id=s.get("uri") or s.get("id", ""),
            title=("[boost] " if boosted else "") + (text.split("\n")[0][:180] or "(post)"),
            url=post.get("url") or s.get("url") or "",
            author="@" + (author if "@" in author else f"{author}@{instance}"),
            content=text + ("\n\nLinks: " + " ".join(links) if links else ""),
            published_at=parse_dt(s.get("created_at")), kind="post",
            tags=[t.get("name", "") for t in post.get("tags") or [] if t.get("name")],
            raw={"favourites": post.get("favourites_count", 0), "boosts": post.get("reblogs_count", 0)})

    def fetch(self) -> list[RawItem]:
        with self.client() as c:
            base, acc_id, instance = self._account(c)
            r = c.get(f"{base}/accounts/{acc_id}/statuses", params={"limit": 40, "exclude_replies": "true"})
            r.raise_for_status()
            statuses = r.json()
        return [self.to_raw(s, instance) for s in statuses]

    def backfill_capability(self) -> BackfillCapability:
        return BackfillCapability(True, "account statuses, paged back with max_id", None,
                                  f"up to {BACKFILL_MAX_PAGES * 40:,} statuses per account per run")

    def backfill(self, since, until, progress):
        with self.client() as c:
            base, acc_id, instance = self._account(c)
            max_id = None
            for page in range(1, BACKFILL_MAX_PAGES + 1):
                params = {"limit": 40, "exclude_replies": "true"}
                if max_id:
                    params["max_id"] = max_id
                r = c.get(f"{base}/accounts/{acc_id}/statuses", params=params)
                r.raise_for_status()
                statuses = r.json()
                if not statuses:
                    return
                progress(f"page {page}")
                raws = [self.to_raw(s, instance) for s in statuses]
                yield [x for x in raws if x.published_at and since <= x.published_at <= until]
                max_id = statuses[-1].get("id")
                oldest = parse_dt(statuses[-1].get("created_at"))
                if oldest and oldest < since:
                    return
