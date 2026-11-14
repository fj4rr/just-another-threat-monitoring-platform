from __future__ import annotations

import calendar
import re
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

import feedparser

from ..processing.pipeline import RawItem, strip_html
from .base import BackfillCapability, Collector, SkipCollector, in_window, parse_dt

MAX_FEED_BYTES = 10 * 1024 * 1024
WP_MAX_PAGES = 60  # 6,000 posts per source per backfill run
WAYBACK_MAX_SNAPSHOTS = 80


# "filter: security" keeps only entries about security from general technology feeds (many Indonesian
# outlets publish one tech feed for gadgets, apps and cyber incidents alike). English and Indonesian terms.
SECURITY_RE = re.compile(
    r"\b(?:hack(?:ed|er|ers|ing)?|breach(?:ed|es)?|malware|ransomware|phish(?:ing)?|vulnerab\w*|exploit\w*|"
    r"cyber\w*|leak(?:ed|s)?|ddos|scam\w*|fraud\w*|spyware|botnet|trojan|zero[\s-]?day|cve-\d{4}|stealer|"
    r"backdoor|deface\w*|infostealer|data breach|"
    r"peretas|peretasan|diretas|meretas|retas|kebocoran|bocor|siber|penipuan|penipu|phising|pishing|"
    r"pembobolan|dibobol|membobol|pencurian data|data pribadi|pembajakan akun|dibajak|serangan (?:siber|ransomware|ddos)|"
    r"kejahatan digital|keamanan digital|modus|mengatasnamakan|judi online|judol|bssn|pdns|pusat data nasional|"
    r"skimming|social engineering|rekayasa sosial|kode otp|apk palsu|undangan pernikahan)\b", re.I)


def _entry_time(e) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        if e.get(key):
            return datetime.fromtimestamp(calendar.timegm(e[key]), tz=UTC).replace(tzinfo=None)
    return None


class RSSCollector(Collector):
    kind = "rss"
    category = "news"
    label = "RSS / Atom feed"
    fields = [("url", "Feed URL", "https://example.com/feed/"),
              ("filter", "Topic filter (optional): 'security' keeps only security-related entries", "security")]

    def _keep(self, raws: list[RawItem]) -> list[RawItem]:
        if str(self.cfg.get("filter") or "").strip().lower() != "security":
            return raws
        return [r for r in raws if SECURITY_RE.search(f"{r.title}\n{strip_html(r.content)[:3000]}\n{' '.join(r.tags)}")]

    def _url(self) -> str:
        url = self.cfg.get("url")
        if not url:
            raise SkipCollector("no feed URL configured")
        if not str(url).lower().startswith(("http://", "https://")):
            raise SkipCollector("feed URL must start with http:// or https://")
        return str(url)

    def _parse(self, content: bytes, content_type: str = "") -> list[RawItem]:
        feed = feedparser.parse(content)
        if feed.bozo and not feed.entries:
            head = " ".join(content[:80].decode("utf-8", "replace").split())
            raise RuntimeError(f"could not parse feed ({content_type or '?'}): "
                               f"{feed.bozo_exception}; body starts with: {head!r}")
        out = []
        for e in feed.entries[:500]:
            content_txt = ""
            if e.get("content"):
                content_txt = " ".join(c.get("value", "") for c in e.content)
            content_txt = content_txt or e.get("summary", "")
            tags = [t.get("term", "") for t in e.get("tags", []) if t.get("term")]
            out.append(RawItem(
                external_id=e.get("id") or e.get("link") or e.get("title", ""), title=e.get("title", ""),
                url=e.get("link", ""), author=e.get("author", ""), content=content_txt, published_at=_entry_time(e),
                kind="post" if self.source.category == "social" else "article", tags=tags))
        return self._keep(out)

    def fetch(self) -> list[RawItem]:
        url = self._url()
        with self.client(Accept="application/rss+xml, application/atom+xml, application/xml, */*") as c:
            resp = c.get(url)
            resp.raise_for_status()
            if len(resp.content) > MAX_FEED_BYTES:
                raise RuntimeError("feed larger than 10 MB, refusing to parse")
        return self._parse(resp.content, resp.headers.get("content-type", ""))[:100]

    # ------------------------------------------------------------------ backfill
    def backfill_capability(self) -> BackfillCapability:
        return BackfillCapability(True, "WordPress REST API when the site has one, otherwise Internet Archive "
                                        "snapshots of the feed", None,
                                  "WordPress sites return every post in the range; archive snapshots only "
                                  "contain what the feed listed when it was archived")

    def wordpress_root(self) -> str | None:
        """Site root whose /wp-json/wp/v2/posts answers, or None."""
        url = self._url()
        parts = urlsplit(url)
        host_root = f"{parts.scheme}://{parts.netloc}"
        cands = []
        path = parts.path
        for marker in ("/feed", "/rss", "/atom"):
            if marker in path:
                cands.append(host_root + path[:path.index(marker)])
        cands.append(host_root)
        with self.client() as c:
            for root in dict.fromkeys(r.rstrip("/") for r in cands):
                try:
                    r = c.get(f"{root}/wp-json/wp/v2/posts", params={"per_page": 1, "_fields": "id"}, timeout=10)
                except Exception:  # noqa: S112 - probing; any failure means "not WordPress here"
                    continue
                if r.status_code == 200 and r.headers.get("x-wp-total") is not None:
                    return root
        return None

    def wordpress_count(self, root: str, since: datetime, until: datetime) -> int | None:
        with self.client() as c:
            r = c.get(f"{root}/wp-json/wp/v2/posts", timeout=15, params={
                "per_page": 1, "_fields": "id", "after": since.isoformat(), "before": until.isoformat()})
        try:
            return int(r.headers.get("x-wp-total", ""))
        except ValueError:
            return None

    def _wp_pages(self, root: str, since: datetime, until: datetime, progress):
        with self.client() as c:
            for page in range(1, WP_MAX_PAGES + 1):
                r = c.get(f"{root}/wp-json/wp/v2/posts", timeout=30, params={
                    "after": since.isoformat(), "before": until.isoformat(), "per_page": 100, "page": page,
                    "orderby": "date", "order": "desc", "_fields": "id,guid,date_gmt,link,title,content,excerpt"})
                if r.status_code == 400 and page > 1:  # past the last page
                    return
                r.raise_for_status()
                posts = r.json()
                if not posts:
                    return
                total_pages = r.headers.get("x-wp-totalpages", "?")
                progress(f"WordPress page {page}/{total_pages}")
                yield self._keep([RawItem(
                    external_id=(p.get("guid") or {}).get("rendered") or p.get("link") or str(p.get("id")),
                    title=strip_html((p.get("title") or {}).get("rendered", "")), url=p.get("link", ""),
                    content=(p.get("content") or {}).get("rendered") or (p.get("excerpt") or {}).get("rendered", ""),
                    published_at=parse_dt(p.get("date_gmt")), kind="article") for p in posts])
                if total_pages != "?" and page >= int(total_pages):
                    return

    def _wayback_pages(self, since: datetime, until: datetime, progress):
        url = self._url()
        with self.client() as c:
            r = c.get("https://web.archive.org/cdx/search/cdx", timeout=60, params={
                "url": url, "from": since.strftime("%Y%m%d"), "to": until.strftime("%Y%m%d"), "output": "json",
                "filter": "statuscode:200", "collapse": "timestamp:8", "fl": "timestamp,original"})
            r.raise_for_status()
            rows = r.json()[1:] if r.text.strip() else []
            if not rows:
                progress("no archived snapshots of this feed in the range")
                return
            step = max(1, len(rows) // WAYBACK_MAX_SNAPSHOTS)
            picked = rows[::step][:WAYBACK_MAX_SNAPSHOTS]
            for n, (stamp, original) in enumerate(reversed(picked), 1):
                time.sleep(1.5)  # be polite to the Internet Archive
                progress(f"archive snapshot {n}/{len(picked)} ({stamp[:8]})")
                try:
                    snap = c.get(f"https://web.archive.org/web/{stamp}id_/{original}", timeout=60)
                    snap.raise_for_status()
                    raws = self._parse(snap.content[:MAX_FEED_BYTES], snap.headers.get("content-type", ""))
                except Exception as e:  # one broken snapshot must not end the backfill
                    progress(f"snapshot {stamp[:8]} skipped: {type(e).__name__}")
                    continue
                yield [x for x in raws if in_window(x.published_at, since, until)]

    def backfill(self, since: datetime, until: datetime, progress):
        root = self.wordpress_root()
        if root:
            progress(f"WordPress API at {root}")
            yield from self._wp_pages(root, since, until, progress)
        else:
            progress("no WordPress API; using Internet Archive snapshots")
            yield from self._wayback_pages(since, until, progress)
