"""0.12.0: trust and coverage items of the 2026-11 PM review (one counting rule, severity rules version, verdicts
that age, source health, enrichment queue and pacing, redaction for cloud AI)."""
import threading
import time
from datetime import timedelta

from sqlalchemy import select

from app import jobs, settings, sourcehealth
from app.db import session_scope
from app.intel import LookupResult
from app.models import CollectorRun, Entity, Item, ItemEntity, Notification, Source, utcnow
from app.processing import enrichment, trends
from app.processing.extractor import Extracted
from app.processing.pipeline import RawItem, ingest, link_entities


def _src(db, name, kind="rss", category="news"):
    src = db.execute(select(Source).where(Source.name == name)).scalar_one_or_none()
    if not src:
        src = Source(name=name, kind=kind, category=category, config={"url": f"https://{name}.example/feed"})
        db.add(src)
        db.flush()
    return src


# --------------------------------------------------------------------------- item 1: one counting rule
def test_copies_count_once_everywhere(installed):
    with session_scope() as db:
        a, b, c = _src(db, "zz-count-a"), _src(db, "zz-count-b"), _src(db, "zz-count-c")
        orig = Item(source_id=a.id, external_id="cnt-o", title="Zzcount story", published_at=utcnow() - timedelta(hours=3))
        db.add(orig)
        db.flush()
        copies = [Item(source_id=s.id, external_id=f"cnt-{s.id}", title="Zzcount story",
                       published_at=utcnow() - timedelta(hours=2), dup_of=orig.id) for s in (b, c)]
        db.add_all(copies)
        db.flush()
        for it in [orig, *copies]:
            link_entities(db, it, [Extracted("malware", "zzcountware", "ZzCountWare", "stealer", "kb")])
        db.flush()
        top = {r["name"]: r for r in trends.top_entities(db, "malware", days=1, limit=500)}
        assert top["ZzCountWare"]["count"] == 1 and top["ZzCountWare"]["sources"] == 3
        ov = trends.overview(db, days=1)
        assert ov["items_all"] - ov["items"] >= 2
        per_source = {r["name"]: r["count"] for r in trends.source_breakdown(db, days=1)}
        assert per_source["zz-count-b"] == 1  # per-outlet figures still count the copy
        tl = trends.timeline(db, days=1)
        assert sum(sum(v) for v in tl["series"].values()) <= ov["items"]
        db.rollback()


# --------------------------------------------------------------------------- item 4: severity rules version
def test_severity_rules_version_rescores_once(installed):
    from app.processing.severity import RULES_VERSION

    with session_scope() as db:
        ingest(db, _src(db, "zz-sevver"), [RawItem(external_id="sv-1", title="Zero-day exploited in the wild")])
    settings.set("severity_version", 0)
    assert jobs.run_rescore_if_outdated().startswith("re-scored")
    assert int(settings.get("severity_version")) == RULES_VERSION
    assert jobs.run_rescore_if_outdated() == "severity scores are up to date"


# --------------------------------------------------------------------------- item 5: verdicts that age
class _Prov:
    name = "zzprov"
    supports = {"ip", "domain", "url", "md5", "sha1", "sha256"}

    def __init__(self, verdicts):
        self.verdicts = verdicts

    def lookup(self, etype, value):
        v = self.verdicts.get(value)
        return LookupResult(self.name, v, 0, f"zz says {v}") if v else None


def test_stale_malicious_verdict_is_rechecked_and_may_fall(installed, monkeypatch):
    with session_scope() as db:
        src = _src(db, "zz-stale")
        ingest(db, src, [RawItem(external_id="st-1", title="C2 server", content="beacon to 185.220.101.77 seen")])
        db.flush()
        ent = db.execute(select(Entity).where(Entity.value == "185.220.101.77")).scalar_one()
        item = db.execute(select(Item).where(Item.external_id == "st-1")).unique().scalar_one()
        old = utcnow() - timedelta(days=45)
        ent.verdict, ent.enriched_at, ent.verdict_at = "malicious", old, old
        item.severity_detail = item.severity_detail + [{"label": "indicator confirmed malicious (ip)", "points": 12}]
        item.severity += 12
        before, eid, iid = item.severity, ent.id, item.id
        assert enrichment.verdict_is_stale(ent, 30)
    monkeypatch.setattr(enrichment, "available_providers", lambda: [_Prov({"185.220.101.77": "unknown"})])
    settings.set("enrich_families", False)
    try:
        with session_scope() as db:
            q = enrichment.queue_status(db)
            assert q["stale"] >= 1
            assert "stale verdict" in enrichment.run_batch(db)
    finally:
        settings.set("enrich_families", True)
    with session_scope() as db:
        ent, item = db.get(Entity, eid), db.get(Item, iid)
        assert ent.verdict == "unknown" and ent.verdict_at > utcnow() - timedelta(minutes=5)
        assert item.severity == before - 12
        assert not any(d["label"].startswith("indicator confirmed") for d in item.severity_detail)


def test_aged_verdicts_leave_the_feeds(installed):
    from app.routers.api_v1 import _ioc_rows

    with session_scope() as db:
        now = utcnow()
        rows = [Entity(type="ip", value="198.51.100.41", display="198.51.100.41", verdict="malicious",
                       enriched_at=now - timedelta(days=70)),  # aged, no verdict_at (pre-0.12 row)
                Entity(type="ip", value="198.51.100.42", display="198.51.100.42", verdict="malicious",
                       enriched_at=now, verdict_at=now - timedelta(days=5)),
                Entity(type="sha256", value="a" * 64, display="a" * 64, verdict="malicious",
                       enriched_at=now - timedelta(days=400))]  # hashes never age
        db.add_all(rows)
        db.flush()
        it = Item(source_id=_src(db, "zz-aged-feed").id, external_id="aged-1", title="indicators")
        db.add(it)
        db.flush()
        db.add_all([ItemEntity(item_id=it.id, entity_id=e.id, origin="regex") for e in rows])
        db.flush()
        got = {r["value"] for r in _ioc_rows(db, ["ip", "sha256"], ["malicious"], "", None, 0, 0, 5000, fresh_only=True)}
        assert "198.51.100.42" in got and "a" * 64 in got and "198.51.100.41" not in got
        every = {r["value"] for r in _ioc_rows(db, ["ip"], ["malicious"], "", None, 0, 0, 5000)}
        assert "198.51.100.41" in every  # the API list itself still shows it, with its verdict date
        from app.stix import Bundle

        b = Bundle()
        oid = b.entity(rows[1])
        assert b.objects[oid]["valid_until"] > b.objects[oid]["valid_from"]
        db.rollback()


def test_blocklist_listing_refreshes_the_verdict(installed):
    from app.processing.pipeline import mark_listed

    with session_scope() as db:
        ent = Entity(type="domain", value="zz-phish.example", display="zz-phish.example", verdict="malicious",
                     enriched_at=utcnow() - timedelta(days=90), verdict_at=utcnow() - timedelta(days=90))
        db.add(ent)
        db.flush()
        mark_listed(db, [Extracted("domain", "zz-phish.example", "zz-phish.example")], "zzlist", "listed")
        assert ent.verdict_at > utcnow() - timedelta(minutes=1)
        db.rollback()


# --------------------------------------------------------------------------- item 8: source health
def test_source_health_quiet_and_failing(installed):
    now = utcnow()
    with session_scope() as db:
        quiet, failing = _src(db, "zz-health-quiet"), _src(db, "zz-health-failing")
        failing.last_status, failing.last_run = "error", now
        for h in range(10, 0, -1):  # productive every hour until 2 days ago
            db.add(CollectorRun(job=f"source:{quiet.id}", source_id=quiet.id, status="ok", new_items=2,
                                finished_at=now - timedelta(days=2, hours=h)))
        for h in range(30, -1, -2):  # failing for 30 h
            db.add(CollectorRun(job=f"source:{failing.id}", source_id=failing.id, status="error",
                                finished_at=now - timedelta(hours=h)))
        db.add(Item(source_id=quiet.id, external_id="hq-1", title="last one", content="short",
                    collected_at=now - timedelta(days=2)))
        db.flush()
        rep = sourcehealth.report(db)
        assert rep[quiet.id]["quiet"] and rep[quiet.id]["usual_gap_text"] == "1 h"
        assert rep[quiet.id]["summary_only"]
        assert rep[failing.id]["failing_long"] and rep[failing.id]["state"] == "failing"
        assert sourcehealth.check(db) >= 2
        sourcehealth.check(db)  # once per day
        day = now.date().isoformat()
        assert len(db.execute(select(Notification).where(Notification.key == f"srcquiet:{quiet.id}:{day}")).all()) == 1
        db.rollback()


def test_sources_tab_shows_health(client):
    page = client.get("/settings?tab=sources").text
    assert "this week" in page


# --------------------------------------------------------------------------- item 11: queue and pacing
def test_providers_run_at_their_own_pace():
    class Slow:
        supports = {"ip"}

        def __init__(self, name):
            self.name = name

        def lookup(self, etype, value):
            time.sleep(0.2)
            return LookupResult(self.name, "unknown", 0, "")

    todo = [(i, "ip", f"192.0.2.{i}") for i in range(1, 4)]
    t0 = time.perf_counter()
    out = enrichment.prefetch(todo, [Slow("a"), Slow("b"), Slow("c")])
    assert time.perf_counter() - t0 < 1.2  # 3 providers x 3 lookups x 0.2 s would take 1.8 s one after another
    assert all(set(v) == {"a", "b", "c"} for v in out.values())


def test_throttle_gap_does_not_block_other_providers():
    from app.intel.clients import _Throttle

    th = _Throttle()
    th.wait("slowprov", 0)
    t = threading.Thread(target=th.wait, args=("slowprov", 1.0))
    t.start()
    time.sleep(0.05)
    t0 = time.perf_counter()
    th.wait("fastprov", 0.1)
    assert time.perf_counter() - t0 < 0.3
    t.join()


def test_queue_and_pace_on_the_ioc_page(client):
    from app.intel import quota

    settings.set("virustotal_api_key", "vt-zz")
    try:
        pace = {p["provider"]: p for p in quota.pace()}
        assert pace["virustotal"]["lasts_hours"] == round(400 / 8 * 10 / 60, 1)
        assert pace["virustotal"]["spread_batch"] == 400 // 144
        page = client.get("/iocs").text
        assert "waiting" in page and "capacity" in page and "would spread them over the day" in page
    finally:
        settings.set("virustotal_api_key", "")


# --------------------------------------------------------------------------- item 14: redaction for cloud AI
def test_redaction_masks_personal_data_only():
    from app.llm.redact import Redactor

    r = Redactor()
    out = r("Pelaku dari nomor 0812-3456-7890, transfer ke rekening BCA 1234567890, email x.y@example.com, "
            "NIK 3171234567890123. Rp 1.500.000.000 hilang. IP 45.155.205.233, CVE-2024-3400, "
            "wallet 0x52908400098527886E0F7030069857D2E4169EE7. Lagi 0812 3456 7890.")
    for gone in ("0812", "1234567890", "x.y@example.com", "3171234567890123"):
        assert gone not in out
    for kept in ("Rp 1.500.000.000", "45.155.205.233", "CVE-2024-3400", "0x52908400098527886E0F7030069857D2E4169EE7",
                 "[phone 1]", "[account 1]", "[email 1]", "[number 1]"):
        assert kept in out
    assert out.count("[phone 1]") == 2 and "[phone 2]" not in out


def test_cloud_prompts_are_redacted(installed, monkeypatch):
    from app.llm import client, redact

    sent = {}
    monkeypatch.setattr(client, "_anthropic", lambda s, p, m: sent.update(p=p) or "ok")
    monkeypatch.setattr(client, "_ollama", lambda s, p, m: sent.update(p=p) or "ok")
    try:
        settings.set("llm_provider", "anthropic")
        assert redact.is_cloud()
        client.complete("sys", "hubungi penipu di 0812-3456-7890")
        assert "0812" not in sent["p"] and "[phone 1]" in sent["p"]
        settings.set("llm_provider", "ollama")
        settings.set("llm_base_url", "http://localhost:11434")
        assert not redact.is_cloud()
        client.complete("sys", "hubungi penipu di 0812-3456-7890")
        assert "0812-3456-7890" in sent["p"]  # local model: nothing leaves the machine
        settings.set("llm_redact", "always")
        client.complete("sys", "hubungi penipu di 0812-3456-7890")
        assert "0812" not in sent["p"]
        settings.set("llm_base_url", "https://api.groq.com/openai/v1")
        settings.set("llm_provider", "openai_compatible")
        assert redact.is_cloud()
    finally:
        for k in ("llm_provider", "llm_base_url", "llm_redact"):
            settings.set(k, settings.SCHEMA[k][0])


def test_ai_tab_saves_the_redaction_setting(client):
    import re

    tok = re.search(r'name="csrf-token" content="([^"]+)"', client.get("/settings?tab=llm").text).group(1)
    try:
        client.post("/settings/values", data={"csrf_token": tok, "group": "llm", "llm_mode": "none",
                                              "llm_redact": "always", "llm_language": "English"})
        assert settings.get("llm_redact") == "always"
        client.post("/settings/values", data={"csrf_token": tok, "group": "llm", "llm_mode": "none",
                                              "llm_redact": "bogus"})
        assert settings.get("llm_redact") == "cloud"  # unknown value: the default
    finally:
        settings.set("llm_redact", "cloud")
