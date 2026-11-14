"""Copy every table from the current database to another one (``manage.py copy-db <url>``).

Typical use: move an existing SQLite install to PostgreSQL. The target must be empty; tables are created
there, rows are copied in dependency order in batches, and PostgreSQL id sequences are moved past the
copied ids. The SQLite full-text index is not copied (PostgreSQL searches with ILIKE; a SQLite target
rebuilds it).
"""
from __future__ import annotations

from sqlalchemy import create_engine, func, insert, select, text

from .db import Base
from .db import engine as source_engine

BATCH = 1000


def copy_database(target_url: str, progress=print) -> dict:
    from . import models  # noqa: F401  (register tables)

    dst = create_engine(target_url, pool_pre_ping=True)
    Base.metadata.create_all(dst)
    counts: dict[str, int] = {}
    with source_engine.connect() as src, dst.begin() as out:
        for table in Base.metadata.sorted_tables:
            if out.execute(select(func.count()).select_from(table)).scalar():
                raise RuntimeError(f"target table {table.name} is not empty; copy into an empty database")
        for table in Base.metadata.sorted_tables:
            n, batch = 0, []
            for row in src.execute(select(table)).mappings():
                batch.append(dict(row))
                if len(batch) >= BATCH:
                    out.execute(insert(table), batch)
                    n += len(batch)
                    batch = []
            if batch:
                out.execute(insert(table), batch)
                n += len(batch)
            counts[table.name] = n
            progress(f"{table.name}: {n}")
        if dst.dialect.name == "postgresql":
            for table in Base.metadata.sorted_tables:
                if "id" in table.c and counts.get(table.name):
                    quoted = dst.dialect.identifier_preparer.quote(table.name)  # names come from our own models
                    out.execute(text("SELECT setval(pg_get_serial_sequence(:t, 'id'), "  # noqa: S608
                                     f"(SELECT MAX(id) FROM {quoted}))"), {"t": table.name})
    if dst.dialect.name == "sqlite":
        from .search import ensure_fts

        ensure_fts(dst)
    dst.dispose()
    return counts
