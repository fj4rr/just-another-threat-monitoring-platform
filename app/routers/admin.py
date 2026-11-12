"""Admin dashboard – multi-user mode only."""
from __future__ import annotations

import os
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import jobs
from ..auth import LOCAL_USER, ROLES, audit, hash_password, password_problems, require, verify_csrf
from ..config import DATA_DIR, is_multi_user
from ..db import get_db
from ..models import AuditLog, CollectorRun, Enrichment, Entity, Insight, Item, Source, User
from ..web import render

router = APIRouter(prefix="/admin")


def _multi_only():
    if not is_multi_user():
        raise HTTPException(404, "The admin dashboard is only available in multi-user mode")


@router.get("", dependencies=[Depends(_multi_only)])
def admin_home(request: Request, msg: str = "", error: str = "", user: User = Depends(require("admin")),
               db: Session = Depends(get_db)):
    users = db.execute(select(User).where(User.username != LOCAL_USER).order_by(User.username)).scalars().all()
    runs = db.execute(select(CollectorRun).order_by(CollectorRun.started_at.desc()).limit(60)).scalars().all()
    logs = db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(100)).scalars().all()
    src_names = {s.id: s.name for s in db.execute(select(Source)).scalars()}
    db_file = DATA_DIR / "jatmp.db"
    stats = {
        "items": db.scalar(select(func.count(Item.id))),
        "entities": db.scalar(select(func.count(Entity.id))),
        "enrichments": db.scalar(select(func.count(Enrichment.id))),
        "insights": db.scalar(select(func.count(Insight.id))),
        "sources": db.scalar(select(func.count(Source.id))),
        "errors": db.scalar(select(func.count(Source.id)).where(Source.last_status == "error")),
        "db_size_mb": round(os.path.getsize(db_file) / 1e6, 1) if db_file.exists() else None,
        "jobs": [{"id": j.id, "next": j.next_run_time} for j in jobs.scheduler.get_jobs()] if jobs.scheduler.running else [],
    }
    by_role = {r: sum(1 for u in users if u.role == r) for r in ROLES}
    return render(request, "admin.html", {"user": user, "users": users, "runs": runs, "logs": logs,
                                          "stats": stats, "roles": ROLES, "src_names": src_names,
                                          "by_role": by_role, "msg": msg, "error": error})


@router.post("/users", dependencies=[Depends(_multi_only), Depends(verify_csrf)])
def create_user(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form("analyst"),
                display_name: str = Form(""), user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    username = username.strip()
    if not username or username == LOCAL_USER or len(username) > 60:
        return RedirectResponse("/admin?error=Invalid+username", status_code=303)
    if role not in ROLES:
        return RedirectResponse("/admin?error=Invalid+role", status_code=303)
    if password_problems(password):
        return RedirectResponse(f"/admin?error={quote(password_problems(password))}", status_code=303)
    if db.execute(select(User).where(User.username == username)).scalar_one_or_none():
        return RedirectResponse("/admin?error=User+already+exists", status_code=303)
    db.add(User(username=username, display_name=display_name or username, role=role,
                password_hash=hash_password(password)))
    audit(db, user, "user_created", f"{username} ({role})", request)
    db.commit()
    return RedirectResponse("/admin?msg=User+created", status_code=303)


@router.post("/users/{user_id}", dependencies=[Depends(_multi_only), Depends(verify_csrf)])
def update_user(user_id: int, request: Request, action: str = Form(...), role: str = Form(""),
                password: str = Form(""), user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if not target or target.username == LOCAL_USER:
        raise HTTPException(404, "user not found")
    admins = db.scalar(select(func.count(User.id)).where(User.role == "admin", User.is_active,
                                                         User.username != LOCAL_USER))
    last_admin = target.role == "admin" and target.is_active and admins <= 1
    if action == "role" and role in ROLES:
        if last_admin and role != "admin":
            return RedirectResponse("/admin?error=Cannot+demote+the+last+admin", status_code=303)
        target.role = role
    elif action == "toggle":
        if last_admin:
            return RedirectResponse("/admin?error=Cannot+disable+the+last+admin", status_code=303)
        target.is_active = not target.is_active
    elif action == "password":
        if password_problems(password):
            return RedirectResponse(f"/admin?error={quote(password_problems(password))}", status_code=303)
        target.password_hash = hash_password(password)
    elif action == "delete":
        if last_admin or target.id == user.id:
            return RedirectResponse("/admin?error=Cannot+delete+yourself+or+the+last+admin", status_code=303)
        db.delete(target)
    else:
        return RedirectResponse("/admin?error=Unknown+action", status_code=303)
    audit(db, user, f"user_{action}", target.username, request)
    db.commit()
    return RedirectResponse("/admin?msg=Updated", status_code=303)
