#!/usr/bin/env python
"""Maintenance commands.

    python manage.py collect [SOURCE_ID ...]   run collectors now (all enabled if none given)
    python manage.py enrich                    run one enrichment batch
    python manage.py cve-intel                 refresh CISA KEV / EPSS / CVSS for recent CVEs
    python manage.py digest                    generate the AI digest now
    python manage.py reextract                 re-run entity extraction on every item
    python manage.py rescore                   recompute severity scores (keeps entities)
    python manage.py slim                      apply the retention tier now (trim old items' text)
    python manage.py vacuum                    give freed space back to the disk (SQLite VACUUM / PG VACUUM)
    python manage.py copy-db URL               copy this database into an empty one (e.g. SQLite -> PostgreSQL)
                                               (after editing the knowledge base)
    python manage.py create-user NAME ROLE     create a user (multi-user mode), prompts for password
    python manage.py seed-sources              add new built-in sources missing from this install
    python manage.py geotag                    re-run geo attribution (targets, provinces, language) on every item
    python manage.py geoip-update              download the offline GeoIP database (DB-IP Lite, or GeoLite2 with
                                               MAXMIND_LICENSE_KEY) into data/geoip/ and locate IP indicators
    python manage.py fraudtag                  re-run the scam & fraud analysis (scam types, brands, identifiers, score)
    python manage.py sectortag                 re-detect the critical infrastructure sectors (government, finance, health...) of every item
    python manage.py telegram-login            sign in to Telegram once (MTProto, optional) and store the session
    python manage.py quality [options]         precision / recall of the detection rules on the labelled cases in
                                               tests/quality/ (--corrections FILE adds an export of the analysts'
                                               corrections, --json, --summary, --check fails below the baseline,
                                               --update-baseline records the current numbers)
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
    elif cmd == "cve-intel":
        print(jobs.run_cve_intel(force=True))
    elif cmd == "geotag":
        print(jobs.run_geotag(force=True))
    elif cmd == "fraudtag":
        print(jobs.run_fraudtag(force=True))
    elif cmd == "sectortag":
        print(jobs.run_sectortag(force=True))
    elif cmd == "telegram-login":
        return telegram_login()
    elif cmd == "geoip-update":
        from app import geoip, settings

        print(geoip.update(str(settings.get("maxmind_license_key") or "")))
        print(jobs.run_geotag(force=True))
    elif cmd == "digest":
        print(jobs.run_digest(force=True))
    elif cmd == "reextract":
        from sqlalchemy import delete, func, update

        from app.models import Entity, EntityLink, ItemEntity
        from app.processing import fraud, sectors
        from app.processing.extractor import extract_all
        from app.processing.pipeline import link_entities, tag_families
        from app.processing.severity import carry_over, reasons_to_json, score_item

        db = SessionLocal()
        # drop links the extractor produced (keep feed-supplied and LLM-found ones), then rebuild
        db.execute(delete(ItemEntity).where(ItemEntity.origin.in_(["regex", "kb", "heuristic"])))
        db.execute(update(Entity).values(mention_count=0))
        db.commit()
        n = 0
        ids = [i for (i,) in db.execute(select(Item.id).order_by(Item.published_at, Item.id))]
        for c in range(0, len(ids), 200):  # chunks: a big install does not fit in memory at once
            for item in db.execute(select(Item).where(Item.id.in_(ids[c:c + 200]))).unique().scalars():
                # the same steps as pipeline.ingest: entities, intel tags, severity, scam analysis, sectors
                text = f"{item.title}\n{item.content}\n{' '.join(item.tags or [])}"
                ex = extract_all(text, strict=item.source.category != "intel") + tag_families(item.tags, item.source)
                uniq = {(e.type, e.value): e for e in ex}
                score, reasons = score_item(item.title, f"{item.content}\n{' '.join(item.tags or [])}",
                                            list(uniq.values()), item.kind)
                old_detail = item.severity_detail
                for fx in fraud.apply(db, item, item.source.topic or ""):
                    uniq.setdefault((fx.type, fx.value), fx)
                for sx in sectors.apply(item):
                    uniq.setdefault((sx.type, sx.value), sx)
                link_entities(db, item, list(uniq.values()))
                db.flush()
                # keep the enrichment bonus and the last AI assessment (they do not come from the text)
                verdicts = db.execute(select(Entity.type, Entity.verdict).join(
                    ItemEntity, ItemEntity.entity_id == Entity.id).where(ItemEntity.item_id == item.id)).all()
                item.severity, item.severity_detail = carry_over(score, reasons_to_json(reasons), old_detail,
                                                                 [tuple(v) for v in verdicts])
                n += 1
            db.commit()
            db.expunge_all()
        counts = dict(db.execute(select(ItemEntity.entity_id, func.count()).group_by(ItemEntity.entity_id)).all())
        for ent in db.execute(select(Entity)).scalars():
            ent.mention_count = counts.get(ent.id, 0)
        linked = select(EntityLink.src_id).union(select(EntityLink.dst_id))
        res = db.execute(delete(Entity).where(Entity.mention_count == 0, Entity.id.not_in(linked),
                                              Entity.type.in_(["malware", "actor", "md5", "sha1", "sha256", "ip",
                                                               "domain", "url"])))
        db.commit()
        print(f"re-extracted {n} items, removed {res.rowcount} orphaned entities")
    elif cmd == "rescore":
        print(jobs.run_rescore())
    elif cmd == "slim":
        db = SessionLocal()
        try:
            print(f"slimmed {jobs.slim_items(db, limit=10_000_000)} item(s)")
        finally:
            db.close()
    elif cmd == "vacuum":
        from app.db import engine

        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.exec_driver_sql("VACUUM" if engine.dialect.name == "sqlite" else "VACUUM ANALYZE")
        print("done")
    elif cmd == "copy-db":
        if not args:
            print("usage: python manage.py copy-db postgresql+psycopg://user:pass@host:5432/jatmp")
            return 1
        from app.dbcopy import copy_database

        counts = copy_database(args[0])
        print(f"copied {sum(counts.values())} rows; now set JATMP_DATABASE_URL to the new database and restart")
    elif cmd == "quality":
        import json
        from pathlib import Path

        from app import quality

        extra = {}
        if "--corrections" in args:
            i = args.index("--corrections")
            if i + 1 >= len(args):
                print("usage: python manage.py quality --corrections jatmp-corrections.jsonl")
                return 1
            extra = quality.load_extra(Path(args[i + 1]))
        res, base = quality.run(extra=extra), quality.baseline()
        if "--json" in args:
            print(json.dumps({"areas": [r.as_dict() for r in res["areas"]], "rejects": res["rejects"]}, indent=2))
        else:
            print(quality.report_markdown(res, base, errors=0 if "--summary" in args else 10))
        if "--update-baseline" in args:
            if extra:
                print("the baseline is measured on tests/quality only: run without --corrections")
                return 1
            path = quality.DATA_DIR / "baseline.json"
            path.write_text(json.dumps({r.area: {"precision": round(r.precision, 3), "recall": round(r.recall, 3),
                                                 "cases": r.cases} for r in res["areas"]}, indent=2) + "\n",
                            encoding="utf-8", newline="")
            print(f"baseline written to {path}")
        regs = quality.regressions(res, base)
        if regs and "--check" in args:
            print("\nBelow the baseline: " + "; ".join(regs))
            return 1
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


def telegram_login() -> int:
    """Interactive MTProto sign-in. The phone number and login code go to Telegram only; what is stored is the
    session string (Settings -> Social), which lets JATMP read public channels as this account."""
    try:
        from telethon.sessions import StringSession
        from telethon.sync import TelegramClient
    except ImportError:
        print("Telethon is not installed: pip install -r requirements-telegram.txt")
        return 1
    from app import settings

    api_id = str(settings.get("telegram_api_id") or "").strip() or input("api_id (from my.telegram.org): ").strip()
    api_hash = str(settings.get("telegram_api_hash") or "").strip() or getpass.getpass("api_hash: ").strip()
    if not api_id.isdigit() or not api_hash:
        print("api_id must be a number and api_hash is required")
        return 1
    print("Use a separate account if you can: channels you read are visible to Telegram, not to the channel.")
    with TelegramClient(StringSession(), int(api_id), api_hash, device_model="JATMP", app_version="jatmp") as client:
        client.start()  # prompts for the phone number, the login code and the 2FA password if set
        session = client.session.save()
        me = client.get_me()
    for key, value in (("telegram_api_id", api_id), ("telegram_api_hash", api_hash), ("telegram_session", session)):
        if settings.env_locked(key):
            print(f"{key} is set by an environment variable; set it there (session string not printed)")
        else:
            settings.set(key, value)
    print(f"signed in as {getattr(me, 'username', None) or getattr(me, 'id', '?')}; session stored. "
          "Telegram sources now use MTProto.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
