"""0.13.0: the remaining PM review items in scope: topic filters for every source kind (10), Q&A retrieval with
cited items (13), analyst corrections (6) and quality measurement (18)."""
import json
import re
from datetime import timedelta

from sqlalchemy import select

from app import jobs, settings
from app.collectors import REGISTRY
from app.db import session_scope
from app.models import CollectorRun, Entity, Insight, Item, Source, utcnow
from app.processing.extractor import Extracted
from app.processing.pipeline import RawItem, link_entities


def _csrf(client, path="/"):
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get(path).text).group(1)


def _src(db, name, kind="rss", category="news", config=None):
    src = db.execute(select(Source).where(Source.name == name)).scalar_one_or_none()
    if not src:
        src = Source(name=name, kind=kind, category=category,
                     config=config if config is not None else {"url": f"https://{name}.example/feed"})
        db.add(src)
        db.flush()
    return src


# --------------------------------------------------------------------------- item 10: topic filters everywhere
def test_every_news_and_social_collector_offers_the_filter():
    for kind in ("rss", "telegram", "x", "mastodon", "bluesky"):
        assert "filter" in [name for name, _, _ in REGISTRY[kind].fields], kind
    assert "filter" not in [name for name, _, _ in REGISTRY["threatfox"].fields]


def test_telegram_source_is_filtered_before_storing(installed, monkeypatch):
    class FakeTelegram:
        def __init__(self, src):
            self.src = src

        def fetch(self):
            return [RawItem(external_id="tg-1", title="", content="Promo kuliner akhir pekan, diskon 50%", kind="post"),
                    RawItem(external_id="tg-2", title="", content="Situs pemerintah diretas, data warga bocor",
                            kind="post")]

    monkeypatch.setitem(jobs.REGISTRY, "telegram", FakeTelegram)
    with session_scope() as db:
        src = _src(db, "zz-tg-filter", kind="telegram", category="social",
                   config={"channel": "zzchan", "filter": "cyber"})
        sid = src.id
    jobs.run_source(sid)
    with session_scope() as db:
        got = [i.external_id for i in db.execute(select(Item).where(Item.source_id == sid)).unique().scalars()]
        assert got == ["tg-2"]
        run = db.execute(select(CollectorRun).where(CollectorRun.source_id == sid)
                         .order_by(CollectorRun.id.desc())).scalars().first()
        assert "1 off topic" in run.message


def test_rss_filter_still_works_through_the_old_name():
    src = Source(name="t", kind="rss", category="news", config={"url": "https://x.example/rss", "filter": "security"})
    raws = [RawItem(external_id="a", title="New phone launched"), RawItem(external_id="b", title="Bank hacked")]
    assert [r.external_id for r in REGISTRY["rss"](src)._keep(raws)] == ["b"]


# --------------------------------------------------------------------------- item 13: Q&A retrieval
def _qa_items(db):
    a, b = _src(db, "zz-qa-a"), _src(db, "zz-qa-b")
    now = utcnow()
    hosp = Item(source_id=a.id, external_id="qa-1", title="LockBit hits a regional healthcare provider",
                content="The rumah sakit network in Bandung was encrypted.", published_at=now - timedelta(days=2),
                severity=70)
    noise = Item(source_id=a.id, external_id="qa-2", title="New smartphone launch", content="A phone review.",
                 published_at=now - timedelta(days=1), severity=0)
    copy = Item(source_id=b.id, external_id="qa-3", title="LockBit hits a regional healthcare provider",
                content="Syndicated.", published_at=now - timedelta(days=2), severity=70)
    db.add_all([hosp, noise])
    db.flush()
    copy.dup_of = hosp.id
    db.add(copy)
    db.flush()
    link_entities(db, hosp, [Extracted("malware", "lockbit", "LockBit", "ransomware", "kb"),
                             Extracted("sector", "health", "Health", "", "kb")])
    db.flush()
    return hosp, noise, copy


def test_retrieval_finds_by_concept_not_only_words(installed):
    from app.llm.retrieval import find_items, period_days

    with session_scope() as db:
        hosp, noise, copy = _qa_items(db)
        # no word of the question is in the item: the category and the sector carry it
        r = find_items(db, "Any ransomware attacks against hospitals this week?")
        ids = [i.id for i in r.items]
        assert ids[0] == hosp.id and copy.id not in ids and noise.id not in ids
        assert "ransomware (malware type)" in r.concepts and r.days == 7
        assert any("Health" in c for c in r.concepts)
        r = find_items(db, "Apa kabar LockBit?")
        assert r.items[0].id == hosp.id and "LockBit" in r.entities
        assert period_days("serangan hari ini") == 1 and period_days("what happened") == 30
        db.rollback()


def test_answers_cite_their_items(installed, monkeypatch):
    from app.llm import client, insights

    seen = {}

    def fake(system, prompt, max_tokens=2500):
        seen["prompt"] = prompt
        return "LockBit hit a healthcare provider [1]; nothing else [9]."

    monkeypatch.setattr(client, "complete", fake)
    monkeypatch.setattr(client, "provider", lambda: "ollama")
    with session_scope() as db:
        hosp, _, _ = _qa_items(db)
        ins = insights.ask(db, "ransomware on hospitals?")
        assert "[1] " in seen["prompt"] and "Cite the items" in seen["prompt"]
        assert f"[[1]](/items/{hosp.id})" in ins.content and "[9]" in ins.content  # unknown number left alone
        src = ins.data["sources"][0]
        assert src["id"] == hosp.id and src["cited"]
        from app.web import templates

        html = templates.get_template("_exec_summary.html").render(d=ins)
        assert f'href="/items/{hosp.id}"' in html and "Based on 1 item(s)" in html
        db.rollback()


# --------------------------------------------------------------------------- item 6: analyst corrections
def _corr_item(db, key, title, content, ents):
    from app.processing.pipeline import ingest

    ingest(db, _src(db, "zz-corr"), [RawItem(external_id=key, title=title, content=content)])
    db.flush()
    item = db.execute(select(Item).where(Item.external_id == key)).unique().scalar_one()
    if ents:
        link_entities(db, item, ents)
        db.flush()
    return item


def _linked(db, item):
    from app.models import ItemEntity

    return {e.value for e in db.execute(select(Entity).join(ItemEntity, ItemEntity.entity_id == Entity.id)
                                        .where(ItemEntity.item_id == item.id)).scalars()}


def test_unlink_sticks_and_can_be_undone(installed):
    from app import corrections

    with session_scope() as db:
        item = _corr_item(db, "corr-1", "Pegasus returns to the stage", "The musical Pegasus opens tonight.",
                          [Extracted("malware", "pegasus", "Pegasus", "spyware", "kb")])
        ent = db.execute(select(Entity).where(Entity.type == "malware", Entity.value == "pegasus")).scalar_one()
        corr = corrections.create(db, None, "unlink", item_id=item.id, entity_id=ent.id, reason="a musical")
        assert "pegasus" not in _linked(db, item)
        # re-extraction / AI extraction / a merge try to link it again: blocked
        link_entities(db, item, [Extracted("malware", "pegasus", "Pegasus", "spyware", "llm")])
        db.flush()
        assert "pegasus" not in _linked(db, item)
        assert "removed from this item" in corrections.describe(corr) and "a musical" in corrections.describe(corr)
        corrections.undo(db, corr, None)
        assert "pegasus" in _linked(db, item) and not corr.active
        db.rollback()


def test_false_positive_everywhere_and_blocked_for_new_items(installed):
    from app import corrections

    with session_scope() as db:
        fam = [Extracted("malware", "zzbogus", "ZzBogus", "stealer", "heuristic")]
        a = _corr_item(db, "corr-2a", "ZzBogus seen", "text", fam)
        b = _corr_item(db, "corr-2b", "ZzBogus again", "text", fam)
        ent = db.execute(select(Entity).where(Entity.value == "zzbogus")).scalar_one()
        corrections.create(db, None, "false_positive", entity_id=ent.id, reason="a product name")
        assert "zzbogus" not in _linked(db, a) | _linked(db, b) and ent.mention_count == 0
        c = _corr_item(db, "corr-2c", "ZzBogus once more", "text", fam)
        assert "zzbogus" not in _linked(db, c)
        assert ent.meta["false_positive"]["reason"] == "a product name"
        db.rollback()


def test_analyst_verdict_wins_over_providers(installed):
    from app import corrections
    from app.intel import LookupResult
    from app.processing import enrichment

    class Prov:
        name, supports = "zzp", {"ip"}

        def lookup(self, etype, value):
            return LookupResult("zzp", "malicious", 90, "zz says malicious")

    with session_scope() as db:
        item = _corr_item(db, "corr-3", "Scanner seen", "Traffic from 185.220.101.99 hit the honeypot", [])
        ent = db.execute(select(Entity).where(Entity.value == "185.220.101.99")).scalar_one()
        corrections.create(db, None, "verdict", entity_id=ent.id, value="clean", reason="our own scanner")
        enrichment.enrich_entity(db, ent, [Prov()])
        assert ent.verdict == "clean" and ent.meta["analyst"]["by"] == ""
        # raising it to malicious gives the item the enrichment bonus, like a provider would
        before = item.severity
        corrections.create(db, None, "verdict", entity_id=ent.id, value="malicious", reason="it attacked us")
        assert ent.verdict == "malicious" and item.severity == min(100, before + 12)
        from app.models import Correction

        active = db.execute(select(Correction).where(Correction.entity_id == ent.id, Correction.active)).scalars().all()
        assert len(active) == 1 and active[0].value == "malicious"  # the newer verdict replaced the older one
        db.rollback()


def test_not_a_scam_report_survives_reanalysis(installed):
    from app import corrections
    from app.processing import fraud

    with session_scope() as db:
        item = _corr_item(db, "corr-4", "Waspada penipuan undangan pernikahan APK",
                          "Penipu mengirim file APK lewat WhatsApp yang mencuri data perbankan korban.", [])
        assert item.fraud_score > 0
        corrections.create(db, None, "not_scam", item_id=item.id, reason="an awareness poster")
        assert item.fraud_score == 0 and not any(t in fraud.FRAUD_TYPES for t in
                                                 [e.type for e in db.execute(select(Entity)).scalars()
                                                  if e.value in _linked(db, item)])
        fraud.retag_item(db, item)  # the fraud re-analysis after an upgrade
        assert item.fraud_score == 0
        db.rollback()


def test_corrections_api_page_and_export(client, multi_user_mode):
    from app import quality

    with session_scope() as db:
        item = _corr_item(db, "corr-5", "Bitter taste of defeat for the home team", "A bitter match.",
                          [Extracted("actor", "bitter", "Bitter", "", "kb")])
        ent = db.execute(select(Entity).where(Entity.type == "actor", Entity.value == "bitter")).scalar_one()
        iid, eid = item.id, ent.id
    r = client.post("/login", data={"username": multi_user_mode["username"], "password": multi_user_mode["password"],
                                    "csrf_token": _csrf(client, "/login")}, follow_redirects=False)
    assert r.status_code in (302, 303)
    tok = _csrf(client, f"/items/{iid}")
    page = client.get(f"/items/{iid}").text
    assert 'data-post="/api/corrections"' in page and "data-prompt" in page
    r = client.post("/api/corrections", json={"kind": "unlink", "item_id": iid, "entity_id": eid,
                                              "reason": "football, not the APT"}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 200 and r.json()["ok"]
    assert client.post("/api/corrections", json={"kind": "bogus"}, headers={"X-CSRF-Token": tok}).status_code == 400
    page = client.get("/corrections").text
    assert "football, not the APT" in page and "Undo" in page and "Most corrected" in page
    lines = client.get("/api/corrections/export.jsonl").text.strip().splitlines()
    case = next(json.loads(x) for x in lines if "correction:" in x and "Bitter taste" in x)
    assert case["area"] == "families" and case["reject"] == ["bitter"]
    assert quality.evaluate_rejects([case])["total"] == 1
    from app.models import AuditLog

    with session_scope() as db:
        assert db.execute(select(AuditLog).where(AuditLog.action == "correction_unlink")).first()
    assert Insight and settings and timedelta  # imported for the module's other tests


# --------------------------------------------------------------------------- fix: an item is never a copy of itself
def test_original_is_never_a_copy_of_itself(installed):
    from app.processing.pipeline import find_original, fingerprint

    with session_scope() as db:
        a, b = _src(db, "zz-self-a"), _src(db, "zz-self-b")
        text = "Ransomware group claims an attack on a regional hospital network, data of patients leaked online today"
        fp = fingerprint("Zzself story", text)
        orig = Item(source_id=a.id, external_id="self-o", title="Zzself story", content=text, fingerprint=fp,
                    published_at=utcnow() - timedelta(hours=5))
        db.add(orig)
        db.flush()
        copy = Item(source_id=b.id, external_id="self-c", title="Zzself story", content=text, fingerprint=fp,
                    published_at=utcnow() - timedelta(hours=3), dup_of=orig.id)
        db.add(copy)
        db.flush()
        assert find_original(db, orig) is None  # the copy points back at it: it is the original
        assert find_original(db, copy) == orig.id
        orig.dup_of = orig.id  # what the 0.10.1 one-off could leave behind
        db.commit()
        oid = orig.id
    jobs.run_dedup()
    with session_scope() as db:
        assert db.get(Item, oid).dup_of is None
