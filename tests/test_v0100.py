"""0.10: dashboard periods with the backfill note, critical infrastructure sectors, the scam & fraud dashboard, the backfill page's
Stop button, the executive summary, and the faster scam / blocklist processing."""
from datetime import timedelta

from sqlalchemy import func, select

from app import jobs
from app.db import session_scope
from app.llm.insights import digest_data, digest_markdown
from app.models import CollectorRun, Enrichment, Entity, Insight, Item, ItemEntity, Source, utcnow
from app.processing import fraud, sectors, trends
from app.processing.extractor import Extracted
from app.processing.pipeline import RawItem, ingest, link_entities, mark_listed


# --------------------------------------------------------------------------- sectors
def test_sector_detection():
    d = sectors.detect
    assert d("Ransomware hits regional hospital, patient records stolen", "") == ["health"]
    assert d("Serangan ransomware lumpuhkan layanan rumah sakit", "") == ["health"]
    assert "finance" in d("Phishing campaign targets bank customers", "Fake bank login pages.")
    assert "government" in d("Situs pemkab diretas", "Peretas menyusupi situs desa.example.go.id")
    assert "transportation" in d("Airline data breach exposes passengers", "")
    assert "energy" in d("Pertamina dikabarkan jadi korban kebocoran data", "")
    assert "defense" in d("Defense contractor breached by APT", "")
    assert "ict" in d("Telecom operator hit by Salt Typhoon", "")
    assert "food" in d("Zero-days in supermarket refrigeration controllers", "")
    # one weak mention in the body is not enough; MITRE "defense evasion" and the "IT Army" are not the defence sector
    assert d("New stealer spotted", "It can also read a bank statement.") == []
    assert d("Loader uses defense evasion tricks", "The IT Army of Ukraine claimed it.") == []
    # round-ups only count their title
    assert d("Week in review: new loaders", "hospital hospital hospital bank bank") == []
    # sectors stated by the feed (ransomware.live victim sector, OTX industries)
    assert d("New victim: acme", "", feed_sector="Healthcare") == ["health"]
    assert set(sectors.feed_sectors(["Financial Services", "Telecommunication", "Not Found"])) == {"finance", "ict"}
    many = d("Bank, hospital, airline, telecom and ministry all hit",
             "The bank, the hospital, the airline, the telecom operator and the ministry confirmed it.")
    assert len(many) == sectors.MAX_SECTORS
    # audit 2026-11 D-9: one title word is no sector, and a scam victim's bank is not an attacked finance sector
    assert d("Bank account scams rise in Jakarta", "") == []
    assert d("Hospital food vendor hit by phishing", "") == []
    assert d("Penipuan transfer bank", "Nasabah bank mentransfer ke rekening penipu.", scam=True) == []
    assert d("Bank BSI dibobol ransomware", "Layanan perbankan nasabah lumpuh.", scam=True) == ["finance"]


def test_sectors_on_ingest_and_breakdown(client):
    with session_scope() as db:
        src = db.execute(select(Source).where(Source.kind == "rss")).scalars().first()
        ingest(db, src, [RawItem(external_id="v0100-sector-1", title="Ransomware attack on hospital network",
                                 content="Patients were diverted; the hospital restored systems from backups.")])
        db.flush()
        db.expire_all()
        item = db.execute(select(Item).where(Item.external_id == "v0100-sector-1")).scalar_one()
        assert [link.entity.value for link in item.entity_links if link.entity.type == "sector"] == ["health"]
        rows = {r["category"]: r for r in trends.sector_breakdown(db, 7)}
        assert len(rows) == 8 and rows["health"]["count"] >= 1 and rows["health"]["label"] == "Health"
        # re-tagging is idempotent
        before = db.scalar(select(func.count(ItemEntity.id)).join(Entity).where(Entity.type == "sector"))
        sectors.retag_all(db)
        assert db.scalar(select(func.count(ItemEntity.id)).join(Entity).where(Entity.type == "sector")) == before
    data = client.get("/api/stats/categories?type=sector&days=7").json()
    assert any(r["category"] == "health" and r["count"] >= 1 for r in data)
    assert client.get("/api/stats/categories?type=sector&scope=fraud&days=7").status_code == 200


# --------------------------------------------------------------------------- periods
def test_buckets_switch_to_weeks():
    labels, step, key = trends.buckets(30)
    assert step == 1 and len(labels) == 30 and key(labels[5]) == labels[5]
    labels, step, key = trends.buckets(365)
    assert step == 7 and len(labels) == 53
    assert key(labels[3]) == labels[3] and key((trends._since(365) + timedelta(days=10)).date()) == labels[1]
    assert trends.norm_period("15") == 15 and trends.norm_period("999") == 7 and trends.norm_period("x") == 7


def test_dashboard_period_and_backfill_note(client):
    r = client.get("/?days=90")
    assert r.status_code == 200
    assert 'aria-label="Dashboard period"' in r.text and "Last 3 months" in r.text
    assert "not every source can be backfilled" in r.text and 'href="/backfill"' in r.text
    # remembered in the session
    r = client.get("/")
    assert "Last 3 months" in r.text
    r = client.get("/?days=7")
    assert "Last 7 days" in r.text
    for url in ("/api/stats/timeline?days=365", "/api/stats/kpi_series?days=180", "/api/stats/trending?type=malware&days=90",
                "/api/stats/trending_timeline?type=cve&days=365", "/api/stats/sources?days=30&scope=fraud"):
        assert client.get(url).status_code == 200, url
    assert client.get("/api/stats/timeline?days=365").json()["step"] == 7


# --------------------------------------------------------------------------- scam & fraud dashboard
def test_fraud_dashboard_and_nav(client):
    with session_scope() as db:
        src = db.execute(select(Source).where(Source.kind == "rss")).scalars().first()
        ingest(db, src, [RawItem(external_id="v0100-fraud-1",
                                 title="Waspada penipuan APK undangan pernikahan mengatasnamakan BCA",
                                 content="Korban kehilangan Rp 25 juta setelah memasang file APK undangan palsu. "
                                         "Pelaku membobol rekening nasabah bank.")])
    r = client.get("/fraud?days=30")
    assert r.status_code == 200
    assert "Scam &amp; fraud landscape" in r.text and 'id="c-scam-tl"' in r.text and 'data-kpi="reports"' in r.text
    # sidebar: two dashboards, scam pages under Intelligence, no tabs any more
    assert 'href="/fraud/identifiers"' in r.text and "Cyber threats" in r.text and 'class="tabs"' not in r.text
    for url in ("/api/stats/fraud/overview?days=30", "/api/stats/fraud/kpi_series?days=30",
                "/api/stats/fraud/timeline?days=30", "/api/stats/categories?type=scam_type&days=30",
                "/api/stats/categories?type=brand_category&days=30"):
        assert client.get(url).status_code == 200, url
    tl = client.get("/api/stats/fraud/timeline?days=30").json()
    assert any(s["key"] == "apk_lure" and sum(s["data"]) >= 1 for s in tl["series"])
    assert client.get("/api/stats/fraud/overview?days=30").json()["reports"] >= 1
    with session_scope() as db:
        sid = db.execute(select(Entity.id).where(Entity.type == "sector", Entity.value == "finance")).scalar_one()
    r = client.get(f"/fraud/items?sector={sid}&country=ID&days=30")
    assert r.status_code == 200 and "<h1>Scam reports</h1>" in r.text


# --------------------------------------------------------------------------- backfill page
def test_backfill_stop_aborts_queued_and_hides_button(client):
    with session_scope() as db:
        sid = db.execute(select(Source.id)).scalars().first()
        batch = jobs._new_batch("backfill")
        db.add(CollectorRun(job=f"backfill:{sid}", source_id=sid, status="running", batch_id=batch,
                            started_at=utcnow()))
        db.add(CollectorRun(job=f"backfill:{sid}", source_id=sid, status="queued", batch_id=batch,
                            started_at=utcnow()))
    page = client.get("/backfill").text
    assert 'data-job-running="backfill"' in page and "job-bar" in page
    csrf = page.split('name="csrf-token" content="')[1].split('"')[0]
    r = client.post("/api/backfill/stop", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and "1 queued source(s) cancelled" in r.json()["message"]
    st = client.get("/api/jobs/status").json()["jobs"]["backfill"]
    assert st["running"] and st["stopping"] and st["label"].startswith("Stopping")
    with session_scope() as db:
        runs = db.execute(select(CollectorRun).where(CollectorRun.batch_id == batch)).scalars().all()
        assert sorted(r.status for r in runs) == ["aborted", "running"]
        for run in runs:  # the worker would finish the running one after its current page
            run.status, run.finished_at = "ok", utcnow()
    jobs._cancelled.discard(batch)
    assert not client.get("/api/jobs/status").json()["jobs"]["backfill"]["running"]
    # with nothing running the Stop button is rendered hidden
    assert 'data-job-running="backfill" hidden' in client.get("/backfill").text


# --------------------------------------------------------------------------- executive summary
def test_digest_json_is_cleaned_and_rendered(client):
    raw = """Sure! {"headline": "**Six** zero-days hit refrigeration controllers",
      "level": "High", "points": [{"title": "Give plugin SQLi", "detail": "Versions $\\\\le$ 2.9.3 are affected."},
      "- Linux kernel crash bug"], "actions": ["1. Patch the Give plugin", "", "Isolate controllers"]}"""
    d = digest_data(raw)
    assert d["headline"] == "Six zero-days hit refrigeration controllers" and d["level"] == "high"
    assert d["points"][0]["detail"] == "Versions ≤ 2.9.3 are affected."
    assert d["points"][1] == {"title": "Linux kernel crash bug", "detail": ""}
    assert d["actions"] == ["Patch the Give plugin", "Isolate controllers"]
    assert digest_data("no json here") == {} and digest_data('{"points": []}') == {}
    md = digest_markdown(d)
    assert md.startswith("**High** · Six zero-days") and "**Actions today**" in md
    with session_scope() as db:
        db.add(Insight(kind="digest", title="Executive summary test", content=md, data=d, model="test:test"))
    from app.web import templates

    with session_scope() as db:
        ins = db.execute(select(Insight).where(Insight.title == "Executive summary test")).scalar_one()
        html = templates.get_template("_exec_summary.html").render(d=ins)
    assert 'class="level high"' in html and "Actions today" in html and "exec-points" in html
    page = client.get("/insights").text
    assert "Executive summary test" in page and "exec-points" in page


# --------------------------------------------------------------------------- efficiency
def test_batch_entity_lookup_and_mark_listed(client):
    with session_scope() as db:
        src = db.execute(select(Source).where(Source.kind == "scamsniffer")).scalar_one()
        inds = [Extracted("domain", f"v0100-drain{i}.example", f"v0100-drain{i}.example", "", "feed") for i in range(40)]
        ingest(db, src, [RawItem(external_id="v0100-ss-1", title="ScamSniffer test day", content="Crypto scam / drainer.",
                                 indicators=inds, raw={"listed_by": "scamsniffer", "listed_summary": "listed"})])
        db.flush()
        db.expire_all()
        item = db.execute(select(Item).where(Item.external_id == "v0100-ss-1")).scalar_one()
        assert sum(1 for link in item.entity_links if link.entity.type == "domain") == 40
        ents = db.execute(select(Entity).where(Entity.value.like("v0100-drain%"))).scalars().all()
        assert all(e.verdict == "malicious" and e.enriched_at for e in ents)
        assert db.scalar(select(func.count(Enrichment.id)).where(Enrichment.provider == "scamsniffer",
                                                                 Enrichment.entity_id.in_([e.id for e in ents]))) == 40
        # listing again adds no second enrichment row; linking again adds no second link
        assert mark_listed(db, inds, "scamsniffer", "listed") == 40
        assert link_entities(db, item, inds) == 0
        db.flush()
        assert db.scalar(select(func.count(Enrichment.id)).where(Enrichment.provider == "scamsniffer",
                                                                 Enrichment.entity_id.in_([e.id for e in ents]))) == 40


def test_velocity_cache_and_fast_retag(client):
    with session_scope() as db:
        cache: dict = {}
        now = utcnow()
        a = fraud.velocity(db, "phishing", now, cache)
        assert fraud.velocity(db, "phishing", now - timedelta(minutes=5), cache) == a and len(cache) == 1
        n_items = db.scalar(select(func.count(Item.id)))
        scams_before = db.scalar(select(func.count(Item.id)).where(Item.fraud_score > 0))
        links_before = db.scalar(select(func.count(ItemEntity.id)).join(Entity).where(Entity.type.in_(fraud.FRAUD_TYPES)))
        assert fraud.retag_all(db) == n_items
        assert db.scalar(select(func.count(Item.id)).where(Item.fraud_score > 0)) == scams_before
        assert db.scalar(select(func.count(ItemEntity.id)).join(Entity)
                         .where(Entity.type.in_(fraud.FRAUD_TYPES))) == links_before


# --------------------------------------------------------------------------- stray CSS, charge names
KADENCE = (".kadence-column487659_4668c2-bd > .kt-inside-inner-col{padding-top:20px;padding-right:20px;}"
           ".kadence-column487659_4668c2-bd{position:relative;}@media all and (max-width: 1024px){"
           ".kadence-column487659_4668c2-bd > .kt-inside-inner-col{flex-direction:column;justify-content:center;}}")


def test_strip_css_keeps_code_and_prose():
    from app.processing.pipeline import strip_css, strip_html

    assert strip_html(f"<p>{KADENCE} In this article A former FBI supervisor</p>") == \
        "In this article A former FBI supervisor"
    assert strip_html("We’ll update. .kb-btn .kt-button{font-weight:normal;font-style:normal;} Next.") == \
        "We’ll update. Next."
    for keep in ('Use {"user": "x", "pass": "y"} as payload.', "if (x) { y = 1; }", "function f(){ return a; }",
                 "unsafe { String::from_utf8_unchecked(result) }", "time: 10:30; then {note: ok;} fine"):
        assert strip_css(keep) == keep


def test_charge_names_are_no_scam_cue():
    body = ("A former FBI supervisor pleaded guilty to wire fraud and money laundering after stealing crypto. "
            "He memorised wallet seed phrases from FBI systems, including a dark web marketplace case.")
    assert fraud.scam_types("FBI agent stole $2.47m in crypto from criminal wallets", body) == []
    assert fraud.scam_types("Romance scam ring charged with wire fraud", "")[0][0] == "romance"
    assert fraud.scam_types("Seed phrase phishing", "He defrauded victims through a fake wallet page.")


def test_content_cleanup_job(client):
    from app import settings as st

    with session_scope() as db:
        src = db.execute(select(Source).where(Source.kind == "rss")).scalars().first()
        db.add(Item(source_id=src.id, external_id="v0100-css-1", title="Store-added reviews",
                    content=f"{KADENCE} Countdowns that keep resetting make products look scarce.", published_at=utcnow()))
    st.set("content_version", 0)
    assert jobs.run_content_cleanup() == "cleaned 1 item(s)"
    with session_scope() as db:
        item = db.execute(select(Item).where(Item.external_id == "v0100-css-1")).scalar_one()
        assert item.content == "Countdowns that keep resetting make products look scarce."
    assert jobs.run_content_cleanup() == "stored content is up to date"
