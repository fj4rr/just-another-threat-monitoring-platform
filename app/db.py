from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import database_url

_url = database_url()
_is_sqlite = _url.startswith("sqlite")

engine = create_engine(
    _url,
    connect_args={"check_same_thread": False, "timeout": 30} if _is_sqlite else {},
    pool_pre_ping=True,
)

if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@event.listens_for(SessionLocal, "before_flush")
def _truncate_strings(session, _ctx, _instances):
    """SQLite ignores VARCHAR(n); PostgreSQL rejects longer values. Trim instead of failing a whole batch."""
    from sqlalchemy import String, inspect

    for obj in list(session.new) + list(session.dirty):
        for col in inspect(obj).mapper.columns:
            n = getattr(col.type, "length", None)
            if n and isinstance(col.type, String):
                v = getattr(obj, col.key, None)
                if isinstance(v, str) and len(v) > n:
                    setattr(obj, col.key, v[:n])


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    from . import models  # noqa: F401  (register tables)

    Base.metadata.create_all(engine)
    _add_missing_columns()
    from .search import ensure_fts

    ensure_fts(engine)


def _add_missing_columns() -> None:
    """Tiny forward-only migration: add columns that newer versions introduced to tables
    that already exist. ``create_all`` only creates missing *tables*."""
    from sqlalchemy import inspect, text

    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have:
                    continue
                ddl = f"ALTER TABLE {table.name} ADD COLUMN {col.name} {col.type.compile(engine.dialect)}"
                default = getattr(col.default, "arg", None) if col.default is not None and col.default.is_scalar else None
                if isinstance(default, bool):
                    ddl += f" DEFAULT {'TRUE' if default else 'FALSE'}" if not _is_sqlite else f" DEFAULT {int(default)}"
                elif isinstance(default, (int, float)):
                    ddl += f" DEFAULT {default}"
                elif isinstance(default, str) and "'" not in default:
                    ddl += f" DEFAULT '{default}'"  # existing rows get the value instead of NULL
                conn.execute(text(ddl))
            # indexes declared on columns added above (create_all only creates them with new tables)
            for idx in table.indexes:
                idx.create(conn, checkfirst=True)
