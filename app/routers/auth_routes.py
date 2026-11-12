from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import jobs
from ..auth import (
    LOCAL_USER,
    audit,
    clear_fails,
    current_user,
    hash_password,
    login_locked,
    needs_rehash,
    password_problems,
    record_fail,
    safe_next,
    verify_csrf,
    verify_password,
)
from ..config import is_installed, is_multi_user
from ..db import get_db
from ..models import User, utcnow
from ..setup_service import perform_install
from ..web import render

router = APIRouter()


@router.get("/setup")
def setup_page(request: Request):
    if is_installed():
        return RedirectResponse("/", status_code=303)
    return render(request, "setup.html", {"user": None, "error": None, "form": {}})


@router.post("/setup", dependencies=[Depends(verify_csrf)])
def setup_submit(
    request: Request,
    mode: str = Form("single"),
    app_name: str = Form("JATMP"),
    admin_username: str = Form(""),
    admin_password: str = Form(""),
    admin_password2: str = Form(""),
    seed_sources: str = Form(""),
    virustotal_api_key: str = Form(""),
    otx_api_key: str = Form(""),
    urlscan_api_key: str = Form(""),
    anyrun_api_key: str = Form(""),
    threatfox_auth_key: str = Form(""),
    x_bearer_token: str = Form(""),
    llm_provider: str = Form("none"),
    llm_base_url: str = Form(""),
    llm_model: str = Form(""),
    llm_api_key: str = Form(""),
):
    if is_installed():
        return RedirectResponse("/", status_code=303)
    form = {"mode": mode, "app_name": app_name, "admin_username": admin_username, "llm_provider": llm_provider,
            "llm_base_url": llm_base_url, "llm_model": llm_model}
    if mode == "multi" and admin_password != admin_password2:
        return render(request, "setup.html", {"user": None, "error": "Passwords do not match.", "form": form})
    try:
        perform_install(
            mode=mode, app_name=app_name.strip()[:40], admin_username=admin_username.strip(),
            admin_password=admin_password, seed_sources=seed_sources == "on",
            api_keys={"virustotal_api_key": virustotal_api_key, "otx_api_key": otx_api_key,
                      "urlscan_api_key": urlscan_api_key, "anyrun_api_key": anyrun_api_key,
                      "threatfox_auth_key": threatfox_auth_key, "x_bearer_token": x_bearer_token},
            llm={"llm_provider": llm_provider, "llm_base_url": llm_base_url, "llm_model": llm_model,
                 "llm_api_key": llm_api_key},
        )
    except ValueError as e:
        return render(request, "setup.html", {"user": None, "error": str(e), "form": form})
    jobs.start()
    return RedirectResponse("/login" if mode == "multi" else "/", status_code=303)


@router.get("/login")
def login_page(request: Request, next: str = "/"):
    if not is_multi_user():
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", {"user": None, "error": None, "next": safe_next(next)})


@router.post("/login", dependencies=[Depends(verify_csrf)])
def login_submit(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/"),
                 db: Session = Depends(get_db)):
    if not is_multi_user():
        return RedirectResponse("/", status_code=303)
    ip = request.client.host if request.client else "?"
    username = username.strip()[:64]
    key = f"{username.lower()}|{ip}"
    target = safe_next(next)
    if login_locked(key):
        return render(request, "login.html", {"user": None, "next": target,
                                              "error": "Too many failed attempts. Try again in 15 minutes."},
                      status_code=429)
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if not user or user.username == LOCAL_USER or not user.is_active or not verify_password(password, user.password_hash):
        record_fail(key)
        audit(db, None, "login_failed", f"username={username}", request)
        db.commit()
        return render(request, "login.html", {"user": None, "next": target, "error": "Invalid credentials."},
                      status_code=401)
    clear_fails(key)
    request.session.clear()  # new session id/content on login (fixation protection)
    request.session["uid"] = user.id
    user.last_login = utcnow()
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    audit(db, user, "login", "", request)
    db.commit()
    return RedirectResponse(target, status_code=303)


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login" if is_multi_user() else "/", status_code=303)


@router.get("/profile")
def profile(request: Request, user: User = Depends(current_user)):
    return render(request, "profile.html", {"user": user, "msg": None, "error": None})


@router.post("/profile", dependencies=[Depends(verify_csrf)])
def profile_save(request: Request, current: str = Form(""), new: str = Form(""), new2: str = Form(""),
                 display_name: str = Form(""), user: User = Depends(current_user), db: Session = Depends(get_db)):
    user = db.get(User, user.id)
    error = msg = None
    display_name = display_name.strip()
    if display_name and display_name != user.display_name:
        user.display_name = display_name[:120]
        msg = "Profile updated."
    if new:
        if not is_multi_user():
            error = "Passwords are not used in single-user mode."
        elif not verify_password(current, user.password_hash):
            error = "Current password is wrong."
        elif new != new2:
            error = "New passwords do not match."
        elif password_problems(new):
            error = password_problems(new)
        else:
            user.password_hash = hash_password(new)
            audit(db, user, "password_changed", "", request)
            msg = "Password changed."
    db.commit()
    return render(request, "profile.html", {"user": user, "msg": msg, "error": error})
