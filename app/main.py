from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, jobs
from .auth import LoginRequired
from .config import BASE_DIR, env_flag, is_installed, load_config
from .db import init_db
from .routers import (
    admin,
    api,
    api_v1,
    apikeys_routes,
    auth_routes,
    pages,
    reports_routes,
    settings_routes,
    taxii,
    webhooks_routes,
)
from .web import render

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("apscheduler").setLevel(logging.WARNING)

# Set JATMP_SECURE_COOKIES=1 (and terminate TLS in front of the app) when exposing the
# platform beyond localhost: marks the session cookie Secure and enables HSTS.
SECURE = env_flag("JATMP_SECURE_COOKIES")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    if is_installed():
        jobs.start()
    yield
    jobs.shutdown()


app = FastAPI(title="JATMP – Threat Monitoring", version=__version__, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


def _csp(nonce: str) -> str:
    # Everything is served from this origin (Chart.js is vendored). Inline <script> blocks
    # carry the per-request nonce; inline style attributes stay allowed (Chart.js + templates).
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )


@app.middleware("http")
async def setup_guard(request: Request, call_next):
    path = request.url.path
    if not is_installed() and not (path.startswith("/setup") or path.startswith("/static") or path == "/healthz"):
        return RedirectResponse("/setup", status_code=303)
    request.state.csp_nonce = secrets.token_urlsafe(16)
    response = await call_next(request)
    h = response.headers
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "same-origin")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if not path.startswith("/static"):
        h.setdefault("Content-Security-Policy", _csp(request.state.csp_nonce))
        h.setdefault("Cache-Control", "no-store")
    if SECURE:
        h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


# Session middleware must wrap the guard (added last = outermost).
app.add_middleware(
    SessionMiddleware, secret_key=load_config()["secret_key"], session_cookie="jatmp_session",
    max_age=60 * 60 * 12, same_site="lax", https_only=SECURE,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")
for r in (auth_routes.router, pages.router, api_v1.router, api.router, settings_routes.router, reports_routes.router,
          admin.router, apikeys_routes.router, webhooks_routes.router, taxii.router):
    app.include_router(r)


@app.get("/healthz", include_in_schema=False)
def healthz():
    """Liveness probe for Docker / orchestrators. Unauthenticated and secret-free."""
    return {"ok": True, "version": __version__, "installed": is_installed(),
            "scheduler": jobs.scheduler.running}


@app.exception_handler(LoginRequired)
async def _login_required(request: Request, _exc: LoginRequired):
    if request.url.path.startswith(("/api/", "/taxii2")):
        return JSONResponse({"detail": "login required"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
    target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    return RedirectResponse(f"/login?next={quote(target, safe='/?=&')}", status_code=303)


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/taxii2"):  # TAXII 2.1 error message format
        return JSONResponse({"title": str(exc.detail), "http_status": str(exc.status_code)},
                            status_code=exc.status_code, media_type="application/taxii+json;version=2.1",
                            headers=getattr(exc, "headers", None))
    if request.url.path.startswith("/api/"):
        # keep WWW-Authenticate / Retry-After from the exception
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))
    return render(request, "error.html", {"code": exc.status_code, "detail": exc.detail, "user": None},
                  status_code=exc.status_code)
