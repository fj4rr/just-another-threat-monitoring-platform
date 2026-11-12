from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import jobs
from .auth import LoginRequired
from .config import BASE_DIR, is_installed, load_config
from .db import init_db
from .routers import admin, api, auth_routes, pages, settings_routes
from .web import render

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("apscheduler").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    if is_installed():
        jobs.start()
    yield
    jobs.shutdown()


app = FastAPI(title="JATMP – Threat Monitoring", lifespan=lifespan, docs_url=None, redoc_url=None)


@app.middleware("http")
async def setup_guard(request: Request, call_next):
    path = request.url.path
    if not is_installed() and not (path.startswith("/setup") or path.startswith("/static")):
        return RedirectResponse("/setup", status_code=303)
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


# Session middleware must wrap the guard (added last = outermost).
app.add_middleware(
    SessionMiddleware, secret_key=load_config()["secret_key"], session_cookie="jatmp_session",
    max_age=60 * 60 * 12, same_site="lax", https_only=False,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")
for r in (auth_routes.router, pages.router, api.router, settings_routes.router, admin.router):
    app.include_router(r)


@app.exception_handler(LoginRequired)
async def _login_required(request: Request, _exc: LoginRequired):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "login required"}, status_code=401)
    return RedirectResponse(f"/login?next={quote(request.url.path)}", status_code=303)


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    return render(request, "error.html", {"code": exc.status_code, "detail": exc.detail, "user": None},
                  status_code=exc.status_code)
