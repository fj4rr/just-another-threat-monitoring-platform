#!/usr/bin/env python
"""Maintenance commands.

    python manage.py collect [SOURCE_ID ...]   run collectors now (all enabled if none given)
    python manage.py enrich                    run one enrichment batch
    python manage.py digest                    generate the AI digest now
    python manage.py reextract                 re-run entity extraction on every item
                                               (after editing the knowledge base)
    python manage.py create-user NAME ROLE     create a user (multi-user mode), prompts for password
    python manage.py seed-sources              add new built-in sources missing from this install
"""
from __future__ import annotations

import getpass
import sys


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1
    cmd, args = argv[0], argv[1:]
    from sqlalchemy import select

    from app import jobs
    from app.db import SessionLocal, init_db
    from app.models import Item, Source

    init_db()
    if cmd == "collect":
        db = SessionLocal()
        ids = [int(a) for a in args] or [s.id for s in db.execute(select(Source).where(Source.enabled)).scalars()]
        db.close()
        for sid in ids:
            print(jobs.run_source(sid))
    elif cmd == "enrich":
        print(jobs.run_enrichment())
    elif cmd == "digest":
        print(jobs.run_digest(force=True))
    elif cmd == "reextract":
        from app.processing.extractor import extract_all, severity_score
        from app.processing.pipeline import link_entities

        from sqlalchemy import delete, func, update

        from app.models import Entity, EntityLink, ItemEntity

        db = SessionLocal()
        # drop links the extractor produced (keep feed-supplied and LLM-found ones), then rebuild
        db.execute(delete(ItemEntity).where(ItemEntity.origin.in_(["regex", "kb", "heuristic"])))
        db.execute(update(Entity).values(mention_count=0))
        db.commit()
        n = 0
        for item in db.execute(select(Item)).scalars():
            text = f"{item.title}\n{item.content}\n{' '.join(item.tags or [])}"
            ex = extract_all(text, strict=item.source.category != "intel")
            link_entities(db, item, ex)
            item.severity = max(item.severity, severity_score(text, ex))
            n += 1
            if n % 200 == 0:
                db.commit()
        db.commit()
        counts = dict(db.execute(select(ItemEntity.entity_id, func.count()).group_by(ItemEntity.entity_id)).all())
        for ent in db.execute(select(Entity)).scalars():
            ent.mention_count = counts.get(ent.id, 0)
        linked = select(EntityLink.src_id).union(select(EntityLink.dst_id))
        res = db.execute(delete(Entity).where(Entity.mention_count == 0, Entity.id.not_in(linked),
                                              Entity.type.in_(["malware", "actor"])))
        db.commit()
        print(f"re-extracted {n} items, removed {res.rowcount} orphaned entities")
    elif cmd == "seed-sources":
        from app.setup_service import seed_missing_sources

        db = SessionLocal()
        added = seed_missing_sources(db)
        db.commit()
        for src in added:
            print(f"+ {src.name} ({'enabled' if src.enabled else 'disabled'})")
        print(f"added {len(added)} source(s)")
    elif cmd == "create-user":
        from app.auth import ROLES, hash_password, password_problems
        from app.models import User

        if len(args) != 2 or args[1] not in ROLES:
            print(f"usage: create-user NAME {{{'|'.join(ROLES)}}}")
            return 1
        pw = getpass.getpass("Password: ")
        if password_problems(pw):
            print(password_problems(pw))
            return 1
        db = SessionLocal()
        db.add(User(username=args[0], display_name=args[0], role=args[1], password_hash=hash_password(pw)))
        db.commit()
        print("created")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
