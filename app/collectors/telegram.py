"""Public Telegram channels.

Two ways in, chosen per run:

* **Web preview** (default, no account): ``https://t.me/s/<channel>``, the read-only page Telegram serves for
  every public channel that has not turned it off. 20 posts per page, older pages with ``?before=<id>``.
* **MTProto** (optional, ``pip install -r requirements-telegram.txt``): Telethon with the user's own api_id /
  api_hash from my.telegram.org and a session created once with ``python manage.py telegram-login``. Reaches
  channels without a web preview and pages back further. Used automatically when it is configured; a source
  can force either way with ``via = web | mtproto``.

Both produce the same external id (``<channel>/<message id>``), so switching between them never duplicates
posts. Only public channels are read: no joining, no private groups, no posting.
"""
from __future__ import annotations

import html
import re
import time
from datetime import datetime

from .. import settings
from ..processing.pipeline import RawItem
from .base import BackfillCapability, Collector, SkipCollector, parse_dt

CHANNEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
WEB_BASE = "https://t.me/s/"
WEB_MAX_PAGES = 150  # 3,000 posts per backfill run
WEB_PAGE_DELAY = 1.0  # seconds between preview pages
MTPROTO_FETCH = 50
MTPROTO_BACKFILL_MAX = 5000

_WRAP = re.compile(r'<div class="tgme_widget_message_wrap')
_POST = re.compile(r'data-post="([^"/]+)/(\d+)"')
_TEXT = re.compile(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', re.S)
_TIME = re.compile(r'<time datetime="([^"]+)"')
_VIEWS = re.compile(r'tgme_widget_message_views">([^<]+)<')
_FWD = re.compile(r'tgme_widget_message_forwarded_from_name"[^>]*>(?:<span[^>]*>)?([^<]+)<')
_DOC = re.compile(r'tgme_widget_message_document_title[^>]*>([^<]+)<')
_PREVIEW = re.compile(r'<a class="tgme_widget_message_link_preview" href="([^"]+)"(.*?)</a>', re.S)
_PREVIEW_TITLE = re.compile(r'link_preview_title[^>]*>([^<]+)<')
_PREVIEW_DESC = re.compile(r'link_preview_description[^>]*>(.*?)</div>', re.S)
_HREF = re.compile(r'<a [^>]*href="(https?://[^"]+)"')
_TAG = re.compile(r"<[^>]+>")
_TITLE = re.compile(r'<meta property="og:title" content="([^"]*)"')
_CHANNEL_INFO = re.compile(r"tgme_channel_info")


def channel_name(raw: str) -> str:
    """'@vxunderground', 't.me/s/vxunderground', 'https://t.me/vxunderground/123' -> 'vxunderground'."""
    v = (raw or "").strip()
    v = re.sub(r"^(?:https?://)?(?:www\.)?(?:t\.me|telegram\.me)/(?:s/)?", "", v, flags=re.I)
    v = v.lstrip("@").split("/")[0].split("?")[0]
    if not CHANNEL_RE.match(v):
        raise SkipCollector("channel must be a public username, e.g. vxunderground or https://t.me/vxunderground")
    return v


def _html_text(fragment: str) -> str:
    """Message HTML to plain text, keeping line breaks."""
    t = re.sub(r"<br\s*/?>", "\n", fragment or "", flags=re.I)
    t = _TAG.sub("", t)
    t = html.unescape(t)
    return "\n".join(" ".join(line.split()) for line in t.splitlines()).strip()


def _views(s: str) -> int:
    s = (s or "").strip().upper()
    mult = 1_000_000 if s.endswith("M") else 1_000 if s.endswith("K") else 1
    try:
        return int(float(s.rstrip("KM")) * mult)
    except ValueError:
        return 0


def make_raw(channel: str, msg_id: int, text: str, when: datetime | None, *, views: int = 0, forwarded: str = "",
             links: list[str] | None = None, files: list[str] | None = None, title: str = "") -> RawItem | None:
    """One post as a RawItem; posts without any text (a bare photo or sticker) are dropped."""
    links = [u for u in dict.fromkeys(links or []) if u.startswith(("http://", "https://"))][:20]
    body = text.strip()
    if files:
        body += "\n\n" + "\n".join(f"[file: {f}]" for f in files)
    if not body.strip():
        return None
    first = next((ln for ln in body.splitlines() if ln.strip()), "")
    head = ("[fwd] " if forwarded else "") + (first[:180] or "(post)")
    content = body
    if forwarded:
        content = f"Forwarded from {forwarded}\n\n{content}"
    if links:
        content += "\n\nLinks: " + " ".join(links)
    key = channel.lower()
    return RawItem(
        external_id=f"{key}/{msg_id}", title=head, url=f"https://t.me/{channel}/{msg_id}",
        author=f"@{channel}", content=content, published_at=when, kind="post",
        raw={"views": views, "forwarded_from": forwarded, "channel": key, "channel_title": title, "message_id": msg_id})


def parse_web(page: str, channel: str) -> list[RawItem]:
    """Posts on one ``t.me/s/<channel>`` page, oldest first (as Telegram lists them)."""
    title_m = _TITLE.search(page)
    title = html.unescape(title_m.group(1)) if title_m else channel
    out = []
    chunks = _WRAP.split(page)[1:]
    for chunk in chunks:
        post = _POST.search(chunk)
        if not post:
            continue
        name, msg_id = post.group(1), int(post.group(2))
        text_m = _TEXT.search(chunk)
        text = _html_text(text_m.group(1)) if text_m else ""
        links = _HREF.findall(text_m.group(1)) if text_m else []
        prev = _PREVIEW.search(chunk)
        if prev:
            links.append(html.unescape(prev.group(1)))
            pt, pd = _PREVIEW_TITLE.search(prev.group(2)), _PREVIEW_DESC.search(prev.group(2))
            extra = "\n".join(filter(None, [html.unescape(pt.group(1)).strip() if pt else "",
                                            _html_text(pd.group(1)) if pd else ""]))
            if extra:
                text = f"{text}\n\n{extra}" if text else extra
        t = _TIME.search(chunk)
        fwd = _FWD.search(chunk)
        raw = make_raw(name, msg_id, text, parse_dt(t.group(1)) if t else None,
                       views=_views((_VIEWS.search(chunk) or [None, ""])[1]),
                       forwarded=html.unescape(fwd.group(1)).strip() if fwd else "",
                       links=[html.unescape(u) for u in links],
                       files=[html.unescape(d).strip() for d in _DOC.findall(chunk)], title=title)
        if raw:
            out.append(raw)
    return out


def mtproto_configured() -> bool:
    if not (settings.get("telegram_api_id") and settings.get("telegram_api_hash") and settings.get("telegram_session")):
        return False
    try:
        import telethon  # noqa: F401
    except ImportError:
        return False
    return True


class TelegramCollector(Collector):
    kind = "telegram"
    category = "social"
    label = "Telegram public channel"
    fields = [("channel", "Channel (username or t.me link)", "vxunderground"),
              ("via", "Via (optional): web | mtproto; empty = MTProto when configured, else the web preview", "")]

    def _via(self) -> str:
        via = str(self.cfg.get("via") or "").strip().lower()
        if via == "mtproto":
            if not mtproto_configured():
                raise SkipCollector("MTProto is not set up: install requirements-telegram.txt, add the API id / hash "
                                    "under Settings → Social and run `python manage.py telegram-login`")
            return "mtproto"
        if via == "web":
            return "web"
        return "mtproto" if mtproto_configured() else "web"

    # ------------------------------------------------------------------ web preview
    def _web_page(self, c, channel: str, before: int | None = None) -> str:
        r = c.get(WEB_BASE + channel, params={"before": before} if before else None)
        if r.status_code == 302 or (r.status_code == 200 and "/s/" not in str(r.url)):
            raise RuntimeError(f"@{channel} has no public web preview; set up MTProto to read it")
        r.raise_for_status()
        return r.text

    def _web_fetch(self, channel: str) -> list[RawItem]:
        with self.client(Accept="text/html") as c:
            page = self._web_page(c, channel)
        raws = parse_web(page, channel)
        if not raws and not _CHANNEL_INFO.search(page):
            raise RuntimeError(f"@{channel} not found, private, or without a public web preview")
        return raws

    # ------------------------------------------------------------------ MTProto
    def _mtproto(self, coro_fn):
        import asyncio

        from telethon import TelegramClient
        from telethon.sessions import StringSession

        api_id = int(str(settings.get("telegram_api_id")).strip())
        api_hash = str(settings.get("telegram_api_hash")).strip()
        session = str(settings.get("telegram_session")).strip()

        async def run():
            client = TelegramClient(StringSession(session), api_id, api_hash, flood_sleep_threshold=60,
                                    device_model="JATMP", app_version="jatmp")
            await client.connect()
            try:
                if not await client.is_user_authorized():
                    raise SkipCollector("Telegram session is not authorised; run `python manage.py telegram-login`")
                return await coro_fn(client)
            finally:
                await client.disconnect()

        return asyncio.run(run())

    @staticmethod
    def _from_message(channel: str, m, title: str = "") -> RawItem | None:
        text = getattr(m, "message", "") or ""
        links = []
        for ent in getattr(m, "entities", None) or []:
            url = getattr(ent, "url", None)
            if url:
                links.append(url)
        media = getattr(m, "media", None)
        webpage = getattr(media, "webpage", None)
        if webpage is not None and getattr(webpage, "url", None):
            links.append(webpage.url)
            text = "\n\n".join(filter(None, [text, getattr(webpage, "title", "") or "",
                                             getattr(webpage, "description", "") or ""]))
        files = []
        doc = getattr(media, "document", None)
        for attr in getattr(doc, "attributes", None) or []:
            if getattr(attr, "file_name", None):
                files.append(attr.file_name)
        fwd = getattr(m, "fwd_from", None)
        fwd_name = (getattr(fwd, "from_name", None) or ("another channel" if fwd else "")) if fwd else ""
        when = getattr(m, "date", None)
        if when is not None and when.tzinfo is not None:
            when = parse_dt(when.isoformat())
        return make_raw(channel, int(m.id), text, when, views=int(getattr(m, "views", 0) or 0), forwarded=fwd_name,
                        links=links, files=files, title=title)

    def _mtproto_fetch(self, channel: str) -> list[RawItem]:
        async def go(client):
            entity = await client.get_entity(channel)
            title = getattr(entity, "title", "") or channel
            msgs = await client.get_messages(entity, limit=MTPROTO_FETCH)
            return [r for r in (self._from_message(channel, m, title) for m in msgs) if r]

        return self._mtproto(go)

    # ------------------------------------------------------------------ interface
    def fetch(self) -> list[RawItem]:
        channel = channel_name(self.cfg.get("channel", ""))
        if self._via() == "mtproto":
            return self._mtproto_fetch(channel)
        return self._web_fetch(channel)

    def backfill_capability(self) -> BackfillCapability:
        if mtproto_configured() and str(self.cfg.get("via") or "") != "web":
            return BackfillCapability(True, "channel history over MTProto (Telethon)", None,
                                      f"up to {MTPROTO_BACKFILL_MAX:,} posts per channel per run")
        return BackfillCapability(True, "public web preview, paged back with ?before=", None,
                                  f"up to {WEB_MAX_PAGES * 20:,} posts per channel per run")

    def backfill(self, since, until, progress):
        channel = channel_name(self.cfg.get("channel", ""))
        if self._via() == "mtproto":
            yield from self._mtproto_backfill(channel, since, until, progress)
            return
        with self.client(Accept="text/html") as c:
            before = None
            for page_no in range(1, WEB_MAX_PAGES + 1):
                page = self._web_page(c, channel, before)
                raws = parse_web(page, channel)
                if not raws:
                    return
                progress(f"page {page_no}")
                yield [r for r in raws if r.published_at and since <= r.published_at <= until]
                oldest = min(raws, key=lambda r: int(r.raw["message_id"]))
                if (oldest.published_at and oldest.published_at < since) or int(oldest.raw["message_id"]) <= 1:
                    return
                before = int(oldest.raw["message_id"])
                time.sleep(WEB_PAGE_DELAY)

    def _mtproto_backfill(self, channel, since, until, progress):
        async def go(client):
            entity = await client.get_entity(channel)
            title = getattr(entity, "title", "") or channel
            out = []
            async for m in client.iter_messages(entity, offset_date=until, limit=MTPROTO_BACKFILL_MAX):
                r = self._from_message(channel, m, title)
                if r and r.published_at and r.published_at < since:
                    break
                if r:
                    out.append(r)
            return out

        raws = self._mtproto(go)
        progress(f"{len(raws)} post(s) over MTProto")
        for i in range(0, len(raws), 100):
            yield raws[i:i + 100]
