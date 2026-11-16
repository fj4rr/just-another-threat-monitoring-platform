"""0.9.1: Indonesian general news sections with the stricter 'cyber' filter, and built-in sources that join an
existing install automatically (without bringing back the ones the user deleted)."""
from sqlalchemy import select

from app import settings, setup_service
from app.collectors import DEFAULT_SOURCES, REGISTRY, source_key
from app.collectors.rss import RSSCollector
from app.db import session_scope
from app.models import Notification, Source
from app.processing.pipeline import RawItem


def _keep(filter_: str, *pairs):
    src = Source(name="x", kind="rss", category="news", config={"url": "https://x.example/feed", "filter": filter_})
    raws = [RawItem(external_id=str(i), title=t, content=b) for i, (t, b) in enumerate(pairs)]
    return [r.title for r in RSSCollector(src)._keep(raws)]


def test_cyber_filter_for_general_news():
    noise = [
        ("Tabung Gas Bocor, Warung Nasi Ludes Terbakar", "Api cepat membesar."),
        ("Perempuan Selundupkan 200 Pil Alprazolam", "Modus pelaku menyembunyikan pil di pakaian."),
        ("Main Mata Penggawa KPK", "Pihak yang mengatasnamakan lembaga itu membantah."),
        ("Bus Dibajak di Tol", "Penumpang selamat."),
        ("Mengenal bagaimana modus pencucian uang bekerja", ""),
    ]
    signal = [
        ("BI: Jumlah serangan siber relatif kecil", "Kepercayaan harus dijaga."),
        ("OJK Siapkan Aplikasi Anti-Scam", "Bisa cek nomor hingga rekening penipu."),
        ("Data 6 juta nasabah diduga bocor di forum gelap", ""),
        ("Situs pemda diretas, muncul iklan judi online", ""),
        ("Polisi bongkar sindikat penipuan online berkedok lowongan kerja", ""),
        ("Waspada investasi bodong berkedok robot trading", ""),
    ]
    kept = _keep("cyber", *noise, *signal)
    assert kept == [t for t, _ in signal]
    # the tech-section filter still lets the ambiguous words through, as before
    assert "Tabung Gas Bocor, Warung Nasi Ludes Terbakar" in _keep("security", *noise)


def test_indonesian_news_sections_are_built_in():
    news = [s for s in DEFAULT_SOURCES if (s["config"] or {}).get("filter") == "cyber"]
    assert len(news) >= 14 and all(s["language"] == "id" and s["kind"] in REGISTRY for s in news)
    assert {"Detik News", "Antara Terkini", "BBC News Indonesia"} <= {s["name"] for s in news}
    keys = [source_key(s["kind"], s["config"]) for s in DEFAULT_SOURCES]
    assert len(keys) == len(set(keys))


def test_auto_seed_adds_new_builtins_once(installed, monkeypatch):
    spec = {"name": "Zz new builtin", "kind": "rss", "category": "news", "interval_minutes": 60, "country": "ID",
            "language": "id", "config": {"url": "https://zz-builtin.example/rss", "filter": "cyber"}}
    key = source_key("rss", spec["config"])
    # the install marked every built-in source as offered, so a restart without changes adds nothing
    assert setup_service.auto_seed_sources() == []
    monkeypatch.setattr(setup_service, "DEFAULT_SOURCES", [*DEFAULT_SOURCES, spec])
    assert setup_service.auto_seed_sources() == ["Zz new builtin"]
    assert key in settings.get(setup_service.SEEN_KEY)
    with session_scope() as db:
        src = db.execute(select(Source).where(Source.name == "Zz new builtin")).scalar_one()
        assert src.config["filter"] == "cyber" and src.enabled
        assert db.execute(select(Notification).where(Notification.title.like("1 new built-in source%"))).first()
        db.delete(src)  # the user removes it ...
    assert setup_service.auto_seed_sources() == []  # ... and it stays removed
    with session_scope() as db:  # the manual button still adds every missing one
        added = setup_service.seed_missing_sources(db)
        assert [s.name for s in added] == ["Zz new builtin"]
        for s in added:
            db.delete(s)


def test_first_run_after_upgrade_adds_missing(installed, monkeypatch):
    spec = {"name": "Zz upgrade builtin", "kind": "rss", "category": "news", "interval_minutes": 60,
            "config": {"url": "https://zz-upgrade.example/rss"}}
    monkeypatch.setattr(setup_service, "DEFAULT_SOURCES", [*DEFAULT_SOURCES, spec])
    before = settings.get(setup_service.SEEN_KEY)
    settings.set(setup_service.SEEN_KEY, None)  # an install from 0.9.0 or older has nothing recorded
    try:
        assert "Zz upgrade builtin" in setup_service.auto_seed_sources()
    finally:
        with session_scope() as db:
            for s in db.execute(select(Source).where(Source.name == "Zz upgrade builtin")).scalars():
                db.delete(s)
        settings.set(setup_service.SEEN_KEY, before)
