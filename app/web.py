"""Template rendering helpers."""
from __future__ import annotations

from datetime import datetime

from fastapi import Request
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from markupsafe import Markup

from . import __version__
from .auth import csrf_token
from .config import BASE_DIR, load_config
from .models import utcnow

templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))
# html=False: raw HTML inside LLM / feed text is escaped; markdown-it also refuses javascript: links.
_md = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")


def md(text: str | None) -> Markup:
    return Markup(_md.render(text or ""))


def timeago(dt: datetime | None) -> str:
    if not dt:
        return "never"
    secs = (utcnow() - dt).total_seconds()
    future = secs < 0
    secs = abs(secs)
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= n:
            v = f"{int(secs // n)}{unit}"
            return f"in {v}" if future else f"{v} ago"
    return "just now"


def safe_href(url: str | None) -> str:
    """Only http(s) links are rendered as clickable; anything else becomes a dead link."""
    u = (url or "").strip()
    return u if u.lower().startswith(("http://", "https://")) else "#"


templates.env.filters["md"] = md
templates.env.filters["timeago"] = timeago
templates.env.filters["safe_href"] = safe_href
templates.env.globals["version"] = __version__

def _misp_configured() -> bool:
    from . import settings

    return bool(settings.get("misp_url") and settings.get("misp_api_key"))


templates.env.globals["misp_configured"] = _misp_configured

VERDICT_CLASS = {"malicious": "crit", "suspicious": "warn", "clean": "good", "unknown": "muted", "": "muted"}
templates.env.globals["verdict_class"] = lambda v: VERDICT_CLASS.get(v or "", "muted")


def render(request: Request, name: str, ctx: dict | None = None, status_code: int = 200):
    cfg = load_config()
    base = {
        "request": request,
        "app_name": cfg.get("app_name", "JATMP"),
        "multi_user": cfg.get("mode") == "multi",
        "csrf": csrf_token(request),
        "path": request.url.path,
        "nonce": getattr(request.state, "csp_nonce", ""),
    }
    base.update(ctx or {})
    return templates.TemplateResponse(request, name, base, status_code=status_code)
