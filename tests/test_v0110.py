"""0.11.0: quick wins from the PM review of 2026-11 (copies, re-score points, ThreatFox, quotas, summary queue,
schedule time zone, TLP on new sources). The docs-numbers check is tests/test_docs_numbers.py."""
import re
from datetime import timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select

from app import jobs, settings
from app.db import session_scope
from app.models import Entity, Item, ItemEntity, Notification, Source, utcnow
from app.processing.extractor import Extracted
from app.processing.pipeline import RawItem, ingest
from app.processing.severity import LLM_SEVERITY_MAX, VERDICT_BONUS, carry_over


def _csrf(client, path="/"):
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get(path).text).group(1)


def _src(db, name, kind="rss", category="news"):
    src = db.execute(select(Source).where(Source.name == name)).scalar_one_or_none()
    if not src:
        src = Source(name=name, kind=kind, category=category, config={"url": f"https://{name}.example/feed"})
        db.add(src)
        db.flush()
    return src


def _sum(detail):
    return sum(int(d.get("points") or 0) for d in detail)


# --------------------------------------------------------------------------- item 3: re-scoring keeps points
def test_carry_over_bonus_and_ai():
    detail = [{"label": "ransomware", "points": 30}]
    # enrichment bonus of the strongest verdict, the AI assessment applied again against the new score
    old = [{"label": "AI assessment (capped)", "points": 20, "origin": "llm", "target": 75}]
    score, out = carry_over(30, detail, old, [("ip", "suspicious"), ("domain", "malicious"), ("url", "")])
    assert score == 30 + VERDICT_BONUS["malicious"] + min(LLM_SEVERITY_MAX, 75 - 42)
    assert _sum(out) == score
    assert any(d["label"] == "indicator confirmed malicious (domain)" for d in out)
    # the model's number is already reached: no AI points
    score, out = carry_over(80, detail, old, [])
    assert score == 80 and not any(d.get("origin") == "llm" for d in out)
    # an AI reason from before 0.11 (no target) keeps its points, still capped
    score, _ = carry_over(30, detail, [{"label": "AI assessment (capped)", "points": 15, "origin": "llm"}], [])
    assert score == 45
    assert carry_over(95, detail, None, [("ip", "malicious")])[0] == 100


def test_rescore_keeps_enrichment_bonus_and_ai_points(installed):
    with session_scope() as db:
        src = _src(db, "zz-rescore-news")
        ingest(db, src, [RawItem(external_id="rs-1", title="Ransomware gang hits hospital",
                                 content="The attackers used 45.155.205.233 for command and control.")])
        db.flush()
        item = db.execute(select(Item).where(Item.external_id == "rs-1")).unique().scalar_one()
        base = item.severity
        ent = db.execute(select(Entity).where(Entity.value == "45.155.205.233")).scalar_one()
        ent.verdict = "malicious"
        item.severity_detail = item.severity_detail + [
            {"label": "indicator confirmed malicious (ip)", "points": 12},
            {"label": "AI assessment (capped)", "points": 20, "origin": "llm", "target": 99}]
        item.severity = min(100, base + 32)
        iid = item.id
    jobs.run_rescore()
    with session_scope() as db:
        item = db.get(Item, iid)
        assert item.severity == min(100, base + VERDICT_BONUS["malicious"] + LLM_SEVERITY_MAX)
        labels = [d["label"] for d in item.severity_detail]
        assert "AI assessment (capped)" in labels and "indicator confirmed malicious (ip)" in labels


def test_ai_reanalysis_does_not_stack(installed):
    from app.llm.insights import apply_llm_extraction

    with session_scope() as db:
        src = _src(db, "zz-ai-twice")
        ingest(db, src, [RawItem(external_id="ai-2", title="Phishing campaign", content="A phishing wave.")])
        db.flush()
        item = db.execute(select(Item).where(Item.external_id == "ai-2")).unique().scalar_one()
        before = item.severity
        for _ in range(3):
            apply_llm_extraction(db, item, {"severity": 95})
        assert item.severity == min(100, before + LLM_SEVERITY_MAX)
        assert _sum(item.severity_detail) == item.severity
        apply_llm_extraction(db, item, {"severity": 0})  # a lower assessment takes the AI points away again
        assert item.severity == before and not any(d.get("origin") == "llm" for d in item.severity_detail)
        apply_llm_extraction(db, item, {"severity": 95})
        assert next(d for d in item.severity_detail if d.get("origin") == "llm")["target"] == 95
        db.rollback()


def test_verdict_upgrade_keeps_breakdown_consistent(installed):
    from app.processing import enrichment

    with session_scope() as db:
        src = _src(db, "zz-bump")
        ingest(db, src, [RawItem(external_id="bump-1", title="C2 seen", content="beacon to 91.92.243.10 today")])
        db.flush()
        item = db.execute(select(Item).where(Item.external_id == "bump-1")).unique().scalar_one()
        ent = db.execute(select(Entity).where(Entity.value == "91.92.243.10")).scalar_one()
        before = item.severity
        enrichment._bump_items(db, ent, "", "suspicious")
        enrichment._bump_items(db, ent, "suspicious", "malicious")
        assert item.severity == min(100, before + VERDICT_BONUS["malicious"])
        confirmed = [d for d in item.severity_detail if d["label"].startswith("indicator confirmed")]
        assert confirmed == [{"label": "indicator confirmed malicious (ip)", "points": VERDICT_BONUS["malicious"]}]
        db.rollback()


# --------------------------------------------------------------------------- item 7: ThreatFox merges later IOCs
def _tf_raw(ips):
    inds = [Extracted("ip", ip, ip, "", "feed") for ip in ips]
    return RawItem(external_id="2026-11-18:ZzFamily", title=f"ThreatFox: {len(ips)} new IOC(s) for ZzFamily",
                   content="Family: ZzFamily", kind="pulse", tags=["ZzFamily"], indicators=inds,
                   merge_title="ThreatFox: {n} IOC(s) for ZzFamily")


def test_threatfox_adds_later_iocs_to_the_day_item(installed):
    with session_scope() as db:
        src = _src(db, "zz-threatfox", kind="threatfox", category="intel")
        # no flush in between on purpose: links added earlier in the same session (or batch) must be seen
        assert len(ingest(db, src, [_tf_raw(["185.1.1.1", "185.1.1.2"])])) == 1
        assert ingest(db, src, [_tf_raw(["185.1.1.2", "185.1.1.3"]),
                                _tf_raw(["185.1.1.3", "185.1.1.4", "185.1.1.5"])]) == []
        db.flush()
        items = db.execute(select(Item).where(Item.source_id == src.id)).unique().scalars().all()
        assert len(items) == 1
        item = items[0]
        ips = {link.entity.value for link in db.execute(select(ItemEntity).where(ItemEntity.item_id == item.id)
                                                         ).scalars() if link.entity.type == "ip"}
        assert ips == {"185.1.1.1", "185.1.1.2", "185.1.1.3", "185.1.1.4", "185.1.1.5"}
        assert item.title == "ThreatFox: 5 IOC(s) for ZzFamily"
        assert any(d["label"] == "5 indicator(s)" for d in item.severity_detail)
        db.rollback()


def test_threatfox_groups_by_first_seen_day():
    from app.collectors.intel import ThreatFoxCollector

    src = Source(name="tf", kind="threatfox", category="intel", config={})
    rows = [{"ioc": "185.2.2.2:443", "ioc_type": "ip:port", "malware_printable": "ZzFam", "first_seen": "2026-11-17 23:50:00 UTC"},
            {"ioc": "185.2.2.3:443", "ioc_type": "ip:port", "malware_printable": "ZzFam", "first_seen": "2026-11-18 00:10:00 UTC"}]
    raws = ThreatFoxCollector(src)._group(rows, ThreatFoxCollector._day)
    assert sorted(r.external_id for r in raws) == ["2026-11-17:ZzFam", "2026-11-18:ZzFam"]
    assert all(r.merge_title for r in raws)


# --------------------------------------------------------------------------- item 2: copies
def test_feed_hides_copies_and_item_pages_name_them(client):
    with session_scope() as db:
        a, b = _src(db, "zz-outlet-a"), _src(db, "zz-outlet-b")
        orig = Item(source_id=a.id, external_id="dup-o", title="Zzqx syndicated breach story", content="x",
                    published_at=utcnow() - timedelta(hours=2))
        db.add(orig)
        db.flush()
        copy = Item(source_id=b.id, external_id="dup-c", title="Zzqx syndicated breach story (copy)", content="x",
                    published_at=utcnow() - timedelta(hours=1), dup_of=orig.id)
        db.add(copy)
        db.flush()
        oid, cid = orig.id, copy.id
    page = client.get("/feed?q=Zzqx").text
    assert f'href="/items/{oid}"' in page and f'href="/items/{cid}"' not in page
    assert "1 copy hidden" in page
    page = client.get("/feed?q=Zzqx&copies=1").text
    assert f'href="/items/{cid}"' in page and ">copy</a>" in page
    assert "Copy of" in client.get(f"/items/{cid}").text
    assert "Copy of" in client.get(f"/items/{cid}/preview").text
    assert "Also carried by 1 other outlet" in client.get(f"/items/{oid}").text


# --------------------------------------------------------------------------- item 15: summary queue rebuilt
def test_auto_summary_queue_is_rebuilt(installed, monkeypatch):
    from app.llm import client as llm_client

    with session_scope() as db:
        src = _src(db, "zz-requeue")
        rows = [Item(source_id=src.id, external_id="rq-hot", title="hot", severity=80),
                Item(source_id=src.id, external_id="rq-low", title="low", severity=10),
                Item(source_id=src.id, external_id="rq-old", title="old", severity=90,
                     collected_at=utcnow() - timedelta(days=3)),
                Item(source_id=src.id, external_id="rq-done", title="done", severity=90, llm_summary="ok"),
                Item(source_id=src.id, external_id="rq-hist", title="hist", severity=90, origin="backfill")]
        db.add_all(rows)
        db.flush()
        ids = {r.external_id: r.id for r in rows}
    seen = []
    monkeypatch.setattr(llm_client, "is_configured", lambda: True)
    monkeypatch.setattr(jobs, "_maybe_auto_summarize", lambda item_ids: seen.extend(item_ids))
    settings.set("llm_auto_summarize", True)
    try:
        jobs.requeue_auto_summaries()
    finally:
        settings.set("llm_auto_summarize", False)
    assert ids["rq-hot"] in seen
    assert not {ids["rq-low"], ids["rq-old"], ids["rq-done"], ids["rq-hist"]} & set(seen)


# --------------------------------------------------------------------------- item 12: quotas for every provider
def test_quota_status_and_warnings(client):
    from app.intel import quota

    today = __import__("datetime").date.today().isoformat()
    settings.set("greynoise_api_key", "gn-test")
    settings.set("_budget_greynoise", {"day": today, "count": 40})
    settings.set("_budget_abuseipdb", {"day": today, "count": 3})  # used today without a key: still listed
    try:
        rows = {q["provider"]: q for q in quota.status()}
        assert rows["greynoise"]["exhausted"] and rows["greynoise"]["limit"] == 40
        assert rows["abuseipdb"]["used"] == 3 and not rows["abuseipdb"]["exhausted"]
        assert "virustotal" not in rows  # not configured, not used
        with session_scope() as db:
            jobs._check_quota(db)
            jobs._check_quota(db)  # once per provider and day
            n = db.execute(select(Notification).where(Notification.key == f"quota:greynoise:{today}")).scalars().all()
            assert len(n) == 1 and "GreyNoise" in n[0].title
        assert "GreyNoise" in client.get("/settings?tab=enrichment").text
        assert "Provider quota today" in client.get("/iocs").text
    finally:
        for k in ("greynoise_api_key", "_budget_greynoise", "_budget_abuseipdb"):
            settings.set(k, None if k.startswith("_") else "")


# --------------------------------------------------------------------------- item 16: schedule time zone
def test_schedule_settings_validate_and_apply(client):
    assert settings.parse_hhmm("7:05") == (7, 5) and settings.parse_hhmm("24:00") is None
    assert settings.parse_hhmm("07:5") is None and settings.parse_hhmm("x") is None
    assert settings.valid_timezone("Asia/Jakarta") and not settings.valid_timezone("Mars/Base")
    tok = _csrf(client, "/settings?tab=general")
    client.post("/settings/values", data={"csrf_token": tok, "group": "general", "schedule_timezone": "Asia/Jakarta",
                                          "digest_time": "7:00", "housekeeping_time": "25:99"})
    try:
        assert settings.get("schedule_timezone") == "Asia/Jakarta"
        assert settings.get("digest_time") == "07:00"
        assert settings.get("housekeeping_time") == "03:30"  # invalid: kept
        client.post("/settings/values", data={"csrf_token": tok, "group": "general", "schedule_timezone": "Mars/Base"})
        assert settings.get("schedule_timezone") == "Asia/Jakarta"  # unknown zone: kept
        jobs.schedule_daily_jobs()
        job = jobs.scheduler.get_job("digest")
        assert job.trigger.timezone == ZoneInfo("Asia/Jakarta")
        assert str(job.trigger.fields[job.trigger.FIELD_NAMES.index("hour")]) == "7"
        assert "Next AI executive summary" in client.get("/settings?tab=general").text
    finally:
        for k in ("schedule_timezone", "digest_time", "housekeeping_time"):
            settings.set(k, settings.SCHEMA[k][0])
        for job_id in jobs.DAILY_JOBS:
            if jobs.scheduler.get_job(job_id):
                jobs.scheduler.remove_job(job_id)


# --------------------------------------------------------------------------- item 19: TLP on new sources
def test_add_source_asks_for_tlp(client):
    page = client.get("/settings?tab=sources").text
    assert 'name="tlp" required' in page and "counts as CLEAR" in page
    tok = _csrf(client, "/settings?tab=sources")
    r = client.post("/settings/sources", data={"csrf_token": tok, "kind": "rss", "name": "zz-amber-feed",
                                               "cfg_url": "https://amber.example/feed", "tlp": "amber"},
                    follow_redirects=False)
    assert r.status_code == 303
    with session_scope() as db:
        src = db.execute(select(Source).where(Source.name == "zz-amber-feed")).scalar_one()
        assert src.tlp == "AMBER"
        db.delete(src)
    assert "have no TLP" in client.get("/settings?tab=sharing").text
