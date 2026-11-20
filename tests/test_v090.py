"""0.9.0: Telegram collector, ScamSniffer, and the scam & fraud section (scam types, brands, scammer identifiers,
fraud score, pages, data minimisation)."""
import re
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import jobs, settings
from app.collectors import DEFAULT_SOURCES, REGISTRY, source_key
from app.collectors.base import SkipCollector
from app.collectors.rss import RSSCollector
from app.collectors.scamsniffer import ScamSnifferCollector
from app.collectors.telegram import TelegramCollector, channel_name, make_raw, parse_web
from app.db import session_scope
from app.models import Enrichment, Entity, Item, ItemEntity, Source, utcnow
from app.processing import fraud
from app.processing.pipeline import RawItem, ingest


def _csrf(client, path="/"):
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get(path).text).group(1)


def _src(db, name, *, kind="rss", category="news", topic="", config=None):
    src = db.execute(select(Source).where(Source.name == name)).scalar_one_or_none()
    if not src:
        src = Source(name=name, kind=kind, category=category, topic=topic,
                     config=config or {"url": f"https://{name.lower().replace(' ', '')}.example/feed"})
        db.add(src)
        db.flush()
    return src


def _analyse(title, body="", **kw):
    return fraud.analyse(title, body, usd_rate=16_000, extract_identifiers=True, **kw)


# --------------------------------------------------------------------------- scam types
def test_scam_types_strong_weak_and_not_malware_news():
    keys = lambda t, b="", **kw: [k for k, _, _ in fraud.scam_types(t, b, **kw)]  # noqa: E731
    assert keys("Waspada investasi bodong berkedok robot trading")[0] == "investment"
    assert "illegal_loan" in keys("Satgas tutup 500 pinjol ilegal")
    # weak phrases need a scam word somewhere in the item
    assert keys("New phishing kit targets Microsoft 365 users", "The kit steals session cookies.") == []
    assert "phishing" in keys("Phishing scam targets bank customers", "")
    assert keys("Android malware spreads as APK", "The trojan steals SMS.") == []
    assert "apk_lure" in keys("Penipuan undangan pernikahan", "Pelaku mengirim file .apk lewat WhatsApp.")
    # a generic scam word alone: only from a fraud-topic source or when repeated / in the title
    assert keys("Ransomware hits hospital", "Officials called it a scam.") == []
    assert keys("Ransomware hits hospital", "Officials called it a scam.", topic="fraud") == ["other"]
    assert keys("Scam alert: fake toll messages", "The scam texts ask for a payment.") == ["other"]
    assert keys("Dulu dipuja kini dituduh penipu", "Ia membantah.") == []  # a lone word in a headline
    assert keys("A week in security", "Fake job offers, romance scams and a pig butchering ring.") == []
    assert keys("Hoaks catut nama menteri", "Foto itu hasil suntingan.") == []  # political hoax, not a scam
    assert keys("CyberStrikeAI in the wild", "It pulls code from VCS repositories.") == []


def test_brands_need_impersonation_context():
    names = lambda t, b="": {n for n, _ in fraud.brands(t, b)}  # noqa: E731
    assert "BCA" in names("Penipuan mengatasnamakan BCA beredar di WhatsApp")
    assert "WhatsApp" not in names("Penipuan mengatasnamakan BCA beredar lewat WhatsApp")
    assert "FBI" not in names("FBI warns of pig butchering scams")  # the one issuing the warning
    assert "DANA" in names("Link DANA Kaget palsu menyebar") and "DANA" not in names("Penipuan dana bantuan palsu")
    assert "Bank Mandiri" not in names("Pelaku bekerja secara mandiri, kata polisi soal penipuan")


# --------------------------------------------------------------------------- identifiers (UU PDP rules)
def test_identifiers_scammer_only():
    text = ("Pelaku menghubungi korban dari nomor 0812-3456-7890 lalu meminta transfer ke rekening BCA 1234567890 "
            "a.n. Budi. Hubungi call center resmi 0811-1500-998 untuk melapor. Nomor milik korban 0813 9999 8888 "
            "ikut tersebar. Saldo dikirim ke DANA 0857-1234-5678. USDT dikirim ke wallet "
            "0x52908400098527886E0F7030069857D2E4169EE7.")
    got = {(e.type, e.value) for e in fraud.identifiers(text)}
    assert ("phone", "+6281234567890") in got
    assert ("bank_account", "bca:1234567890") in got
    assert ("ewallet", "dana:+6285712345678") in got
    assert ("crypto_wallet", "0x52908400098527886e0f7030069857d2e4169ee7") in got
    assert ("phone", "+628111500998") not in got  # official
    assert ("phone", "+6281399998888") not in got  # victim's
    assert not any("budi" in v.lower() for _, v in got)  # holder names are never stored
    # nothing at all from items that are not about a scam
    r = _analyse("Router firmware update", "Call support at 0812-3456-7890 for help.")
    assert r.score == 0 and not r.entities


def test_identifier_extraction_can_be_turned_off():
    r = fraud.analyse("Penipuan pinjol ilegal", "Penipu menghubungi dari nomor 081234567890.", usd_rate=1,
                      extract_identifiers=False)
    assert r.score > 0 and not [e for e in r.entities if e.type in fraud.IDENT_TYPES]


# --------------------------------------------------------------------------- losses, victims, score
@pytest.mark.parametrize("text,expected", [
    ("Korban kehilangan Rp 1,5 miliar.", 1.5e9),
    ("Total kerugian mencapai Rp500.000.000.", 5e8),
    ("Kerugian ditaksir Rp 2,3 triliun", 2.3e12),
    ("Victims lost $2.5 million to the scheme.", 2.5e6 * 16_000),
    ("Victims lost $500,000.", 5e5 * 16_000),
    ("Harga paket data Rp 50.000 per bulan.", 0.0),  # no loss word: a price, not a loss
    ("Akibat penipuan, 702 ribu rekening diblokir, menyelamatkan dana Rp 811 miliar.", 0.0),  # saved, not lost
])
def test_losses_idr(text, expected):
    assert fraud.losses_idr(text, 16_000) == pytest.approx(expected)


def test_victims_and_formatting():
    assert fraud.victims("Polisi mencatat 1.200 korban di 12 provinsi") == 1200
    assert fraud.victims("ratusan korban melapor") == 200
    assert fraud.victims("more than 3,400 victims") == 3400
    assert fraud.fmt_idr(1.5e9) == "Rp 1.5 billion" and fraud.fmt_idr(2e12) == "Rp 2 trillion"
    assert fraud.fmt_idr(750_000) == "Rp 750,000"


def test_fraud_score_explained():
    r = _analyse("Investasi bodong mengatasnamakan OJK, 1.000 korban rugi Rp 3 miliar",
                 "Bareskrim menangkap tersangka. Penipu menghubungi korban dari nomor 0812 3456 7890.")
    labels = " | ".join(d["label"] for d in r.reasons)
    for part in ("Investment scam", "impersonates OJK", "reported losses", "1,000 victims", "identifiers",
                 "official warning"):
        assert part in labels
    assert r.score == min(100, sum(d["points"] for d in r.reasons)) and 60 <= r.score <= 100
    assert r.loss_idr == pytest.approx(3e9) and r.victims == 1000


def test_spread_velocity(installed):
    with session_scope() as db:
        src = _src(db, "Zzfraud velocity")
        now = utcnow()
        raws = [RawItem(external_id=f"vel-{i}", title=f"Penipuan lowongan kerja palsu Zzvel {i}",
                        content="Modus penipuan lowongan kerja palsu di media sosial.",
                        published_at=now - timedelta(days=1, hours=i)) for i in range(6)]
        raws.append(RawItem(external_id="vel-old", title="Penipuan lowongan kerja palsu Zzvel lama",
                            content="Modus lama.", published_at=now - timedelta(days=10)))
        ingest(db, src, raws)
        db.flush()
        r = fraud.analyse("Lowongan kerja palsu lagi", "Penipuan lowongan kerja palsu marak.", db=db, at=now,
                          usd_rate=1, extract_identifiers=False)
        assert any(d["label"].startswith("spreading: 6 reports") for d in r.reasons)


# --------------------------------------------------------------------------- pipeline, API, outbound rules
@pytest.fixture()
def scam_item(installed):
    with session_scope() as db:
        src = _src(db, "Zzfraud desk", topic="fraud")
        ingest(db, src, [RawItem(
            external_id="zzscam-1", title="Zzscam: penipuan APK undangan pernikahan mengatasnamakan BRI",
            content=("Pelaku mengirim file APK undangan pernikahan lewat WhatsApp. Korban di Jawa Barat kehilangan "
                     "Rp 120 juta. Nomor penipu 0812-1111-2222 sudah diblokir. Malware SpyNote ikut terpasang."),
            published_at=utcnow() - timedelta(hours=2))])
    with session_scope() as db:
        item = db.execute(select(Item).where(Item.external_id == "zzscam-1")).unique().scalar_one()
        types = {link.entity.type: link.entity for link in item.entity_links}
        return {"id": item.id, "score": item.fraud_score, "types": set(types), "phone": types.get("phone"),
                "brand": types.get("brand")}


def test_ingest_scores_and_links(scam_item):
    assert scam_item["score"] > 30
    assert {"scam_type", "brand", "phone"} <= scam_item["types"]
    assert scam_item["brand"].display == "BRI"
    with session_scope() as db:
        item = db.get(Item, scam_item["id"])
        assert item.fraud_loss_idr == pytest.approx(1.2e8)
        assert any("Malicious APK lure" in d["label"] for d in item.fraud_detail)


def test_identifiers_never_leave(client, scam_item):
    item = client.get(f"/api/v1/items/{scam_item['id']}").json()
    assert item["fraud"]["score"] == scam_item["score"] and "apk_lure" in item["fraud"]["scam_types"]
    assert "BRI" in item["fraud"]["brands"] and item["fraud"]["detail"]
    assert not [e for e in item["entities"] if e["type"] in fraud.IDENT_TYPES]
    assert client.get(f"/api/v1/stix/entities/{scam_item['phone'].id}").status_code == 404
    r = client.get("/api/v1/entities?type=phone")
    assert r.status_code == 400  # not an API entity type


def test_watched_identifier_emits_no_webhook(installed, scam_item):
    from app import webhooks
    from app.models import User, Watch, Webhook, WebhookDelivery

    with session_scope() as db:
        user = db.execute(select(User)).scalars().first()
        db.add(Webhook(name="zz", url="https://hooks.example/x", events=["entity.watched"], salt="s"))
        db.add(Watch(user_id=user.id, entity_id=scam_item["phone"].id))
        db.flush()
        before = db.query(WebhookDelivery).count()
        webhooks.on_new_items(db, [scam_item["id"]])
        db.flush()
        assert db.query(WebhookDelivery).count() == before
        db.rollback()


def test_fraud_pages(client, scam_item):
    page = client.get("/fraud").text
    assert "Scams &amp; fraud" in page and "Malicious APK lure" in page and "BRI" in page
    assert "Zzscam" in client.get("/feed/scams?days=0").text
    assert "Zzscam" in client.get("/feed/scams?days=0&min_score=1&sort=loss").text
    # 0.14.1: the scam reports are the second feed; the old address keeps its filters
    old = client.get("/fraud/items?days=0&min_score=1", follow_redirects=False)
    assert old.status_code == 301 and old.headers["location"] == "/feed/scams?days=0&min_score=1"
    assert 'href="/feed/scams" class="active"' in client.get("/feed/scams?days=0").text
    assert 'href="/feed" class="active"' in client.get("/feed").text
    assert "Malicious APK lure" in client.get("/fraud/scams?days=0").text
    assert "BRI" in client.get("/fraud/brands?days=0&category=bank").text
    ids = client.get("/fraud/identifiers").text
    assert "+6281211112222" in ids and "scammer" in ids.lower()
    assert "+6281211112222" in client.get("/fraud/identifiers?q=0812-1111-2222").text
    assert client.get("/fraud/identifiers?type=nope&days=-5").status_code == 200
    # National view: the item names Jawa Barat, so it stays
    assert "Zzscam" in client.get("/feed/scams?days=0&region=id").text
    # item page, preview and the identifier's own page
    item = client.get(f"/items/{scam_item['id']}").text
    assert "Fraud score" in item
    assert "fraud score" in client.get(f"/items/{scam_item['id']}/preview").text
    ent = client.get(f"/entities/{scam_item['phone'].id}").text
    assert "scammer identifier" in ent and "STIX" not in ent and "Enrich now" not in ent
    assert "Scam reports" in client.get(f"/entities/{scam_item['brand'].id}").text
    assert "/fraud" in client.get("/").text  # nav entry


def test_fraudtag_job_and_retention(installed, scam_item):
    with session_scope() as db:
        db.add(Entity(type="phone", value="+6289900000001", display="+6289900000001",
                      first_seen=utcnow() - timedelta(days=900), last_seen=utcnow() - timedelta(days=800)))
        db.add(Entity(type="crypto_wallet", value="0x" + "ab" * 20, display="0x" + "ab" * 20, category="eth",
                      first_seen=utcnow() - timedelta(days=900), last_seen=utcnow() - timedelta(days=800)))
    with session_scope() as db:
        assert jobs.prune_identifiers(db) >= 1
    with session_scope() as db:
        assert not db.execute(select(Entity).where(Entity.value == "+6289900000001")).first()
        assert db.execute(select(Entity).where(Entity.value == "0x" + "ab" * 20)).first()  # not personal data
        # re-analysis keeps links unique and counters right
        item = db.get(Item, scam_item["id"])
        before = {link.entity_id for link in item.entity_links}
        fraud.retag_item(db, item)
        db.flush()
        after = [link.entity_id for link in db.execute(select(ItemEntity).where(ItemEntity.item_id == item.id)).scalars()]
        assert set(after) == before and len(after) == len(set(after))
    assert "analysed" in jobs.run_fraudtag(force=True)
    assert int(settings.get("fraud_version")) == fraud.RULES_VERSION
    assert jobs.run_fraudtag() == "fraud analysis is up to date"


# --------------------------------------------------------------------------- Telegram
TG_PAGE = """<html><head><meta property="og:title" content="Zz Channel"></head><body>
<div class="tgme_channel_info"></div>
<div class="tgme_widget_message_wrap js-widget_message_wrap"><div class="tgme_widget_message js-widget_message" data-post="zzchan/41">
<div class="tgme_widget_message_text js-message_text" dir="auto"><b>Leak</b> claimed by group X<br/><br/>Details: <a href="https://example.org/post?a=1&amp;b=2">link</a></div>
<div class="tgme_widget_message_footer"><span class="tgme_widget_message_views">12.5K</span><a class="tgme_widget_message_date" href="https://t.me/zzchan/41"><time datetime="2026-11-10T08:00:00+00:00" class="time">08:00</time></a></div></div></div>
<div class="tgme_widget_message_wrap js-widget_message_wrap"><div class="tgme_widget_message js-widget_message" data-post="zzchan/42">
<div class="tgme_widget_message_forwarded_from accent_color">Forwarded from <a class="tgme_widget_message_forwarded_from_name" href="https://t.me/other"><span dir="auto">Other &amp; Co</span></a></div>
<div class="tgme_widget_message_document_title accent_color" dir="auto">dump_sample.txt</div>
<time datetime="2026-11-11T09:30:00+00:00" class="time">09:30</time></div></div>
<div class="tgme_widget_message_wrap js-widget_message_wrap"><div class="tgme_widget_message js-widget_message" data-post="zzchan/43">
<a class="tgme_widget_message_photo_wrap" href="https://t.me/zzchan/43"></a><time datetime="2026-11-12T09:30:00+00:00" class="time">09:30</time></div></div>
</body></html>"""


def test_telegram_web_preview_parser():
    raws = parse_web(TG_PAGE, "zzchan")
    assert [r.external_id for r in raws] == ["zzchan/41", "zzchan/42"]  # the bare photo is dropped
    first, second = raws
    assert first.title == "Leak claimed by group X" and "Details: link" in first.content
    assert "https://example.org/post?a=1&b=2" in first.content and first.url == "https://t.me/zzchan/41"
    assert first.raw["views"] == 12500 and first.published_at.isoformat() == "2026-11-10T08:00:00"
    assert first.raw["channel_title"] == "Zz Channel" and first.author == "@zzchan"
    assert second.title.startswith("[fwd] ") and "Forwarded from Other & Co" in second.content
    assert "[file: dump_sample.txt]" in second.content


def test_telegram_channel_names_and_mode(installed):
    assert channel_name("https://t.me/s/vxunderground?before=10") == "vxunderground"
    assert channel_name("@Some_Channel") == "Some_Channel"
    assert channel_name("t.me/abcde/123") == "abcde"
    for bad in ("", "ab", "https://t.me/+invitehash", "bad name", "javascript:alert(1)"):
        with pytest.raises(SkipCollector):
            channel_name(bad)
    src = Source(name="zz tg", kind="telegram", category="social", config={"channel": "zzchan"})
    assert TelegramCollector(src)._via() == "web"  # no MTProto configured
    with pytest.raises(SkipCollector):
        TelegramCollector(Source(name="x", kind="telegram", category="social",
                                 config={"channel": "zzchan", "via": "mtproto"}))._via()
    assert TelegramCollector(src).backfill_capability().supported
    assert make_raw("zzchan", 1, "   ", None) is None
    # same external id whichever way a post arrives (web preview or MTProto)
    assert make_raw("ZzChan", 7, "hi", None).external_id == "zzchan/7"


def test_telegram_fetch_and_backfill_paging(installed, monkeypatch):
    pages = {None: TG_PAGE, 41: TG_PAGE.replace('data-post="zzchan/4', 'data-post="zzchan/3')}
    seen = []

    class Resp:
        def __init__(self, text, url):
            self.text, self.url, self.status_code = text, url, 200

        def raise_for_status(self):
            pass

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, params=None):
            before = (params or {}).get("before")
            seen.append(before)
            return Resp(pages.get(before, "<html></html>"), url)

    monkeypatch.setattr(TelegramCollector, "client", lambda self, **h: Client())
    monkeypatch.setattr("app.collectors.telegram.WEB_PAGE_DELAY", 0)
    src = Source(name="zz tg", kind="telegram", category="social", config={"channel": "zzchan"})
    assert len(TelegramCollector(src).fetch()) == 2
    from datetime import datetime

    batches = list(TelegramCollector(src).backfill(datetime(2026, 1, 1), datetime(2026, 12, 31), lambda m: None))
    assert seen[1:] == [None, 41, 31] and sum(len(b) for b in batches) == 4


# --------------------------------------------------------------------------- ScamSniffer and RSS fraud filter
def test_scamsniffer_day_marks_domains_malicious(installed, monkeypatch):
    class Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"domains": ["claim-zzdrop.example", "zzdrainer-app.example", "claim-zzdrop.example"]}

    class Client:
        def get(self, url):
            assert url.endswith("/2026-11-08.json")
            return Resp()

    from datetime import datetime

    src = Source(name="ScamSniffer zz", kind="scamsniffer", category="intel", topic="fraud", config={})
    raw = ScamSnifferCollector(src)._day(Client(), datetime(2026, 11, 8))
    assert raw.title.startswith("ScamSniffer: 2 crypto phishing domains") and len(raw.indicators) == 2
    with session_scope() as db:
        s = _src(db, "ScamSniffer zz", kind="scamsniffer", category="intel", topic="fraud", config={"max_domains": "500"})
        ingest(db, s, [raw])
        db.flush()
        ent = db.execute(select(Entity).where(Entity.value == "zzdrainer-app.example")).scalar_one()
        assert ent.verdict == "malicious" and ent.enriched_at is not None
        assert db.execute(select(Enrichment).where(Enrichment.entity_id == ent.id,
                                                   Enrichment.provider == "scamsniffer")).scalar_one()
        item = db.execute(select(Item).where(Item.external_id == "scamsniffer:2026-11-08")).unique().scalar_one()
        assert item.fraud_score > 0


def test_rss_fraud_filter():
    src = Source(name="x", kind="rss", category="news", config={"url": "https://x.example/feed", "filter": "fraud"})
    raws = [RawItem(external_id="a", title="[HOAKS] Video banjir lama", content="Video itu dari 2019."),
            RawItem(external_id="b", title="[HOAKS] Link pendaftaran bansos palsu", content="Waspada penipuan.")]
    assert [r.external_id for r in RSSCollector(src)._keep(raws)] == ["b"]


# --------------------------------------------------------------------------- sources and settings
def test_default_sources_and_registry():
    assert {"telegram", "scamsniffer"} <= set(REGISTRY)
    keys = [source_key(s["kind"], s["config"]) for s in DEFAULT_SOURCES]
    assert len(keys) == len(set(keys))
    fraud_src = [s for s in DEFAULT_SOURCES if s.get("topic") == "fraud"]
    assert len(fraud_src) >= 4 and all(s["kind"] in REGISTRY for s in fraud_src)
    assert any(s["kind"] == "telegram" and s.get("enabled", True) for s in DEFAULT_SOURCES)


def test_source_topic_and_settings_tab(client, installed):
    with session_scope() as db:
        sid = _src(db, "Zztopic src").id
    token = _csrf(client, "/settings")
    r = client.post(f"/settings/sources/{sid}", data={"csrf_token": token, "action": "save", "name": "Zztopic src",
                                                      "topic": "fraud", "cfg_url": "https://zztopic.example/feed"},
                    follow_redirects=False)
    assert r.status_code == 303
    with session_scope() as db:
        assert db.get(Source, sid).topic == "fraud"
    page = client.get("/settings?tab=fraud").text
    assert "fraud_identifier_days" in page and "Re-analyse items" in page
    assert "telegram_api_hash" in client.get("/settings?tab=social").text
    r = client.post("/api/items/fraudtag", headers={"X-CSRF-Token": token})
    assert r.status_code == 200 and r.json()["ok"]
