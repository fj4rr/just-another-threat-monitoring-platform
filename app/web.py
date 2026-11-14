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


def current_region(request: Request) -> str:
    """The International / National (Indonesia) view. ``?region=`` switches it and is remembered in the
    session, so sort and pager links do not need to carry it."""
    from .processing.geo import REGIONS, norm_region

    has_session = "session" in request.scope
    q = (request.query_params.get("region") or "").strip().lower()
    if q in REGIONS:
        if has_session:
            request.session["region"] = q
        return q
    return norm_region(request.session.get("region") if has_session else "")


def region_href(request: Request, region: str) -> str:
    url = request.url.remove_query_params(["page", "region"]).include_query_params(region=region)
    return f"{url.path}?{url.query}"


templates.env.globals["region_href"] = region_href


def _geo_globals() -> None:
    from . import gazetteer

    templates.env.globals["country_name"] = gazetteer.country_name
    templates.env.globals["province_name"] = gazetteer.province_name


_geo_globals()


def render(request: Request, name: str, ctx: dict | None = None, status_code: int = 200):
    from .processing.geo import REGIONS

    cfg = load_config()
    base = {
        "request": request,
        "app_name": cfg.get("app_name", "JATMP"),
        "multi_user": cfg.get("mode") == "multi",
        "csrf": csrf_token(request),
        "path": request.url.path,
        "nonce": getattr(request.state, "csp_nonce", ""),
        "region": current_region(request), "regions": REGIONS,
    }
    base.update(ctx or {})
    return templates.TemplateResponse(request, name, base, status_code=status_code)
