"""Full-text search over items.

SQLite: an FTS5 table (``items_fts``, external content = ``items``) kept in sync by triggers and built
once on start-up. Queries are turned into quoted prefix terms, so user input can never inject FTS syntax:
``lumma steal`` -> ``"lumma"* "steal"*``. Titles additionally match as plain substrings.
Other databases (PostgreSQL) and SQLite builds without FTS5 fall back to case-insensitive LIKE.
"""
from __future__ import annotations

import logging
import re

from sqlalchemy import column, or_, text

from .models import Item

log = logging.getLogger(__name__)
_TOKEN = re.compile(r"[\w][\w.\-:/@]*", re.UNICODE)
_state = {"fts": None}


def ensure_fts(engine) -> bool:
    """Create the FTS table + triggers if missing; returns whether FTS is usable."""
    if engine.dialect.name != "sqlite":
        _state["fts"] = False
        return False
    try:
        with engine.begin() as conn:
            exists = conn.execute(text("SELECT 1 FROM sqlite_master WHERE name = 'items_fts'")).first()
            if not exists:
                conn.execute(text(
                    "CREATE VIRTUAL TABLE items_fts USING fts5(title, content, content='items', "
                    "content_rowid='id', tokenize='unicode61 remove_diacritics 2')"))
            for ddl in (
                "CREATE TRIGGER IF NOT EXISTS items_fts_ai AFTER INSERT ON items BEGIN "
                "INSERT INTO items_fts(rowid, title, content) VALUES (new.id, new.title, new.content); END",
                "CREATE TRIGGER IF NOT EXISTS items_fts_ad AFTER DELETE ON items BEGIN "
                "INSERT INTO items_fts(items_fts, rowid, title, content) VALUES ('delete', old.id, old.title, old.content); END",
                "CREATE TRIGGER IF NOT EXISTS items_fts_au AFTER UPDATE OF title, content ON items BEGIN "
                "INSERT INTO items_fts(items_fts, rowid, title, content) VALUES ('delete', old.id, old.title, old.content); "
                "INSERT INTO items_fts(rowid, title, content) VALUES (new.id, new.title, new.content); END",
            ):
                conn.execute(text(ddl))
            if not exists:  # index what is already there (one-off on upgrade)
                conn.execute(text("INSERT INTO items_fts(items_fts) VALUES ('rebuild')"))
        _state["fts"] = True
    except Exception as e:  # SQLite compiled without FTS5
        log.warning("full-text search unavailable, falling back to LIKE: %s", e)
        _state["fts"] = False
    return bool(_state["fts"])


def fts_enabled() -> bool:
    if _state["fts"] is None:
        from .db import engine

        ensure_fts(engine)
    return bool(_state["fts"])


def match_query(q: str) -> str:
    terms = _TOKEN.findall(q or "")[:12]
    return " ".join('"' + t.replace('"', '""') + '"*' for t in terms)


def item_text_clause(q: str):
    """WHERE clause matching items whose title or text contains ``q``."""
    q = (q or "").strip()
    like = f"%{q}%"
    m = match_query(q)
    if m and fts_enabled():
        ids = text("SELECT rowid FROM items_fts WHERE items_fts MATCH :fts_q").bindparams(fts_q=m).columns(
            column("rowid"))
        return or_(Item.id.in_(ids), Item.title.ilike(like))
    return or_(Item.title.ilike(like), Item.content.ilike(like))
