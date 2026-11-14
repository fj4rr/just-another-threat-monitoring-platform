"""0.8.0: geography (target / source / infrastructure countries), Indonesian provinces, Bahasa Indonesia,
the International / National (ID) view and the maps."""
import json
import re
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app import gazetteer, geoip, jobs, settings
from app.collectors import DEFAULT_SOURCES, REGISTRY
from app.db import session_scope
from app.intel import LookupResult
from app.models import Entity, Item, ItemGeo, Source, utcnow
from app.processing import geo, trends
from app.processing.extractor import extract_all
from app.processing.geo import analyse, detect_language
from app.processing.pipeline import RawItem, ingest
from app.processing.severity import score_item


def _csrf(client, path="/"):
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get(path).text).group(1)


def _source(db, name, *, country="", language="", category="news", kind="rss"):
    src = db.execute(select(Source).where(Source.name == name)).scalar_one_or_none()
    if not src:
        src = Source(name=name, kind=kind, category=category, config={"url": f"https://{name.lower()}.example/feed"},
                     country=country, language=language)
        db.add(src)
        db.flush()
    return src


def _targets(res, **kw):
    return dict(res.top(**kw))


# --------------------------------------------------------------------------- language
def test_detect_language():
    assert detect_language("Peretas mengklaim telah membobol sistem dan data pribadi jutaan warga bocor di forum") == "id"
    assert detect_language("Attackers exploited the flaw in the wild and the vendor has released a fix for it") == "en"
    assert detect_language("Lumma") == ""


# --------------------------------------------------------------------------- target vs attribution
def test_attacker_country_is_not_a_target():
    r = analyse("Russian hackers target Indonesian government agencies")
    assert "RU" in r.attributed and "RU" not in _targets(r)
    assert "ID" in _targets(r)
    r = analyse("Microsoft patches zero-day", "The flaw was exploited by China-nexus threat actors and Iran-linked groups.")
    assert {"CN", "IR"} <= r.attributed and not r.top()
    r = analyse("North Korean IT workers infiltrate US companies", "The scheme targeted firms in the United States.")
    assert "KP" in r.attributed and "US" in _targets(r)
    r = analyse("Peretas asal China bobol server pemerintah", "Serangan dikaitkan dengan Rusia.", lang="id")
    assert {"CN", "RU"} <= r.attributed and "CN" not in _targets(r)


def test_place_names_and_precision():
    r = analyse("Ransomware attack hits hospitals in Germany", "Several hospitals in Germany and Austria were hit.")
    assert "DE" in _targets(r)
    assert not analyse("Lazarus targets crypto firms in Latin America").top()  # not the US
    assert not analyse("DIY smart home tips").top()  # "DIY" is only Yogyakarta in Indonesian text
    assert not analyse("Apple fixes Jordan", "Michael Jordan bought a Turkey sandwich at Chad's diner.").top()
    # leak-site victim postings carry the victim country in brackets
    r = analyse("According to Ransomware.live, Qilin has added fittleworth.com (GB) to its victims.")
    assert "GB" in _targets(r)
    # countries the feed supplies always count
    r = analyse("Pulse", "", feed_countries=["Indonesia", "SG", "Atlantis"])
    assert {"ID", "SG"} <= set(_targets(r)) and r.feed == {"ID", "SG"}


def test_indonesian_places_institutions_and_provinces():
    r = analyse("Iklan judi online sisipi situs Pemkot Palu dan Kota Batu", "Situs bpbd.malangkab.go.id juga disusupi.",
                lang="id")
    assert "ID" in _targets(r)
    assert {"ID-ST", "ID-JI"} <= set(dict(r.top_provinces()))
    r = analyse("Data breach at BPJS Kesehatan exposes 279 million records")
    assert _targets(r) == {"ID": pytest.approx(3.0)} and not r.top_provinces()
    r = analyse("Ransomware hits Surabaya hospital", "The hospital in Surabaya, East Java, restored systems.")
    assert dict(r.top_provinces()).get("ID-JI")
    # "RI", "Tanah Air", "AS" are Indonesian shorthand and only read in Indonesian text
    assert "ID" in _targets(analyse("Asing ungkap RI jadi target serangan", lang="id"))
    assert not analyse("RI and AS are mentioned here", lang="en").top()
    # weak acronyms (BCA, BRI) need Indonesian text or another Indonesian signal
    assert not analyse("BCA BRI", "BCA BRI", lang="en").top()
    assert "ID" in _targets(analyse("BCA dan BRI ingatkan nasabah", lang="id"))


def test_normalise_country_names():
    assert gazetteer.normalise_country("United States of America") == "US"
    assert gazetteer.normalise_country("id") == "ID"
    assert gazetteer.normalise_country("Korea, Republic of") == "KR"
    assert gazetteer.normalise_country("Narnia") == "" and gazetteer.normalise_country("XX") == ""


# --------------------------------------------------------------------------- pipeline + region filter
@pytest.fixture()
def geo_items(installed):
    now = utcnow() - timedelta(hours=1)
    with session_scope() as db:
        idsrc = _source(db, "Zzgeo Berita", country="ID", language="id")
        ensrc = _source(db, "Zzgeo News", country="US")
        ingest(db, idsrc, [
            RawItem("zg-1", "Zzgeo Data warga Jawa Barat bocor setelah server Pemprov diretas",
                    content="Peretas mengklaim telah membobol sistem dan menjual data pribadi di forum.", published_at=now),
            RawItem("zg-2", "Zzgeo Jepang jadi target serangan siber", content="Perusahaan di Jepang menjadi korban.",
                    published_at=now),
            RawItem("zg-3", "Zzgeo Tips keamanan akun", content="Pengguna diminta mengganti kata sandi secara berkala.",
                    published_at=now),
        ])
        ingest(db, ensrc, [
            RawItem("zg-4", "Zzgeo Ransomware hits hospitals in Germany", content="Hospitals in Germany were hit.",
                    published_at=now),
            RawItem("zg-5", "Zzgeo Ransomware gang leaks data of Indonesian bank", content="The bank in Jakarta confirmed.",
                    published_at=now),
        ])
        db.commit()
        rows = {i.external_id: i for i in db.execute(select(Item).where(Item.external_id.like("zg-%"))).scalars()}
        return {k: v.id for k, v in rows.items()}


def test_ingest_stores_geo(geo_items):
    with session_scope() as db:
        i1 = db.get(Item, geo_items["zg-1"])
        assert i1.lang == "id" and i1.src_country == "ID"
        rows = db.execute(select(ItemGeo).where(ItemGeo.item_id == i1.id)).scalars().all()
        assert {(r.country, r.region) for r in rows} == {("ID", "ID-JB")}
        i4 = db.get(Item, geo_items["zg-4"])
        assert i4.lang == "en" and i4.src_country == "US"
        assert {r.country for r in db.execute(select(ItemGeo).where(ItemGeo.item_id == i4.id)).scalars()} == {"DE"}


def test_region_clause(geo_items):
    with session_scope() as db:
        nat = {i for (i,) in db.execute(geo.scoped(select(Item.id), "id").where(Item.external_id.like("zg-%")))}
    # Indonesian target (1, 5), Indonesian outlet without another target (3); not Japan (2) or Germany (4)
    assert nat == {geo_items["zg-1"], geo_items["zg-3"], geo_items["zg-5"]}
    assert geo.region_clause("intl") is None and geo.region_clause("bogus") is None


def test_feed_region_switch_and_filters(client, geo_items):
    page = client.get("/feed?region=id&q=Zzgeo&days=0").text
    assert "Zzgeo Data warga" in page and "Germany" not in page and "National view" in page
    # remembered in the session
    assert "Zzgeo Jepang" not in client.get("/feed?q=Zzgeo&days=0").text
    page = client.get("/feed?region=intl&q=Zzgeo&days=0").text
    assert "Zzgeo Jepang" in page and "Zzgeo Ransomware hits hospitals" in page
    page = client.get("/feed?country=DE&q=Zzgeo&days=0").text
    assert "hospitals in Germany" in page and "Zzgeo Data warga" not in page
    page = client.get("/feed?province=ID-JB&days=0").text
    assert "Zzgeo Data warga" in page and "Zzgeo Jepang" not in page
    assert "Zzgeo Jepang" in client.get("/feed?lang=id&q=Zzgeo&days=0").text
    assert "Zzgeo Ransomware hits" not in client.get("/feed?src_country=ID&q=Zzgeo&days=0").text
    # bad filter values are ignored, not errors
    assert client.get("/feed?country=XX&province=nope&lang=fr").status_code == 200


def test_geo_page_dashboard_and_stats(client, geo_items):
    for region in ("intl", "id"):
        assert client.get(f"/?region={region}").status_code == 200
        r = client.get("/geo?days=0")
        assert r.status_code == 200 and 'data-map="world"' in r.text and 'data-map="indonesia"' in r.text
        stats = client.get("/api/stats/geo?days=0").json()
        assert {"targets", "provinces", "sources", "languages", "infra", "world_values", "id_values"} <= set(stats)
    client.get("/?region=intl")
    stats = client.get("/api/stats/geo?days=0").json()
    assert stats["world_values"]["DE"] >= 1 and stats["id_values"]["ID-JB"] >= 1
    assert "Indonesia by province" in client.get("/?region=id").text
    assert "Target countries" in client.get("/?region=intl").text
    for path in ("/api/stats/overview", "/api/stats/timeline", "/api/stats/kpi_series", "/api/stats/trending",
                 "/api/stats/categories", "/api/stats/sources", "/api/stats/iocs", "/api/stats/top"):
        assert client.get(path + "?region=id").status_code == 200, path


def test_item_page_and_preview_show_geo(client, geo_items):
    page = client.get(f"/items/{geo_items['zg-1']}").text
    assert "Jawa Barat" in page and "Bahasa Indonesia" in page
    assert "Jawa Barat" in client.get(f"/items/{geo_items['zg-1']}/preview").text


def test_api_v1_geo(client, geo_items):
    client.get("/?region=intl")
    data = client.get("/api/v1/items?q=Zzgeo&limit=50").json()["data"]
    by_id = {d["id"]: d for d in data}
    g = by_id[geo_items["zg-1"]]["geo"]
    assert g == {"targets": [{"country": "ID", "provinces": ["ID-JB"]}], "source_country": "ID", "language": "id"}
    de = client.get("/api/v1/items?country=de&q=Zzgeo").json()["data"]
    assert [d["id"] for d in de] == [geo_items["zg-4"]]
    nat = {d["id"] for d in client.get("/api/v1/items?region=id&q=Zzgeo").json()["data"]}
    assert geo_items["zg-2"] not in nat and geo_items["zg-1"] in nat
    assert client.get(f"/api/v1/items/{geo_items['zg-5']}").json()["geo"]["targets"][0]["country"] == "ID"


def test_geotag_job_is_versioned(geo_items):
    settings.set("geo_version", None)
    assert jobs.run_geotag().startswith("geo-tagged")
    assert int(settings.get("geo_version")) == geo.GEO_VERSION
    assert jobs.run_geotag() == "geography is up to date"


def test_report_scope(geo_items):
    from app import reports
    from app.db import SessionLocal

    since, until = utcnow() - timedelta(days=1), utcnow() + timedelta(minutes=1)
    db = SessionLocal()
    try:
        nat = reports.gather(db, since, until, {"findings"}, counts={"findings": 50}, region="id")
        intl = reports.gather(db, since, until, {"findings"}, counts={"findings": 50})
    finally:
        db.close()
    assert nat["region"] == "id" and nat["title"].endswith("· Indonesia") and intl["region"] == "intl"
    assert not any("Germany" in f["title"] for f in nat["findings"])
    assert nat["stats"]["items"] < intl["stats"]["items"]


# --------------------------------------------------------------------------- infrastructure country
def test_infra_country_from_providers(installed, monkeypatch):
    from app.processing.enrichment import infra_country

    monkeypatch.setattr(geoip, "country", lambda ip: "")
    ent = Entity(type="ip", value="203.0.113.7")
    assert infra_country(ent, [LookupResult("otx", "unknown", 0, "", "")]) == ""
    otx = LookupResult("otx", "suspicious", 0, "", "")
    otx.data = {"country": "United States of America"}
    abuse = LookupResult("abuseipdb", "unknown", 0, "", "")
    abuse.data = {"countryCode": "NL"}
    assert infra_country(ent, [otx]) == "US"
    assert infra_country(ent, [otx, abuse]) == "NL"  # AbuseIPDB ranks above OTX
    monkeypatch.setattr(geoip, "country", lambda ip: "SG")
    assert infra_country(ent, [otx, abuse]) == "SG"  # offline GeoIP first


def test_geoip_without_database(installed):
    assert geoip.country("10.0.0.1") == "" and geoip.country("not-an-ip") == ""
    if geoip.database_path() is None:
        assert geoip.country("8.8.8.8") == "" and geoip.status() == {"installed": False}


def test_iocs_country_filter(client, installed):
    with session_scope() as db:
        if not db.execute(select(Entity).where(Entity.value == "198.51.100.77")).scalar_one_or_none():
            db.add(Entity(type="ip", value="198.51.100.77", display="198.51.100.77", country="NL", meta={}))
    client.get("/?region=intl")
    page = client.get("/iocs?type=ip&country=nl").text
    assert "198.51.100.77" in page and "hosted in" in page
    assert "198.51.100.77" not in client.get("/iocs?type=ip&country=DE").text
    with session_scope() as db:
        e = db.execute(select(Entity).where(Entity.value == "198.51.100.77")).scalar_one()
        from app.routers.api_v1 import _entity_dict

        assert _entity_dict(e)["country"] == "NL"


# --------------------------------------------------------------------------- Bahasa Indonesia
def test_rss_security_filter():
    src = Source(name="t", kind="rss", category="news", config={"url": "https://x.example/rss", "filter": "security"})
    coll = REGISTRY["rss"](src)
    raws = [RawItem("1", "Harga HP baru turun"), RawItem("2", "Data pengguna bocor setelah server diretas"),
            RawItem("3", "Waspada modus penipuan undangan pernikahan"), RawItem("4", "New ransomware strain")]
    assert [r.external_id for r in coll._keep(raws)] == ["2", "3", "4"]
    src.config = {"url": "https://x.example/rss"}
    assert len(REGISTRY["rss"](src)._keep(raws)) == 4


def test_indonesian_severity_terms():
    s, reasons = score_item("Data 6 juta NPWP bocor, diduga dijual di dark web",
                            "Peretas mengklaim telah membobol sistem Ditjen Pajak dan menjual jutaan data pribadi.", [])
    labels = [r.label for r in reasons]
    assert "breach / exfiltration" in labels and s >= 15
    # English term and Indonesian synonym share a label: counted once
    _, reasons2 = score_item("Ransomware attack", "Serangan ransomware, pelaku meminta uang tebusan.", [])
    assert [r.label for r in reasons2].count("ransomware") == 1
    assert score_item("Tips cara mengecek HP terkena malware", "", [])[0] < 10


def test_indonesian_family_names():
    text = ("Layanan imigrasi lumpuh\nLayanan imigrasi lumpuh setelah diserang oleh ransomware Brain Cipher. "
            "Polisi mengatakan bahwa trojan perbankan Mamont yang ada di Indonesia sudah menginfeksi ribuan perangkat.")
    fams = {e.display for e in extract_all(text) if e.type == "malware"}
    assert {"Brain Cipher", "Mamont"} <= fams
    # title-case headline: a capitalised verb after the noun is not a family
    assert not [e for e in extract_all("Waspada Malware Baru Incar Pengguna Android di Indonesia yang dan di ke")
                if e.type == "malware" and e.origin == "heuristic"]


def test_default_indonesian_sources():
    ids = [s for s in DEFAULT_SOURCES if s.get("country") == "ID"]
    assert len(ids) >= 8
    assert all(s["config"].get("filter") == "security" and s["language"] == "id" for s in ids)


def test_source_form_saves_country_and_language(client, installed):
    with session_scope() as db:
        sid = _source(db, "Zzgeo Form").id
    tok = _csrf(client, "/settings")
    r = client.post(f"/settings/sources/{sid}", data={"csrf_token": tok, "action": "save", "name": "Zzgeo Form",
                                                      "cfg_url": "https://zzgeo.example/feed", "country": "id",
                                                      "language": "id", "interval_minutes": "60", "category": "news"},
                    follow_redirects=False)
    assert r.status_code == 303
    with session_scope() as db:
        s = db.get(Source, sid)
        assert (s.country, s.language) == ("ID", "id")
    client.post(f"/settings/sources/{sid}", data={"csrf_token": tok, "action": "save", "country": "zz", "language": "xx",
                                                  "cfg_url": "https://zzgeo.example/feed"})
    with session_scope() as db:
        s = db.get(Source, sid)
        assert (s.country, s.language) == ("", "")


# --------------------------------------------------------------------------- maps
def test_map_outlines():
    base = Path(__file__).resolve().parents[1] / "app" / "static" / "geo"
    world = json.loads((base / "world.json").read_text(encoding="utf-8"))
    ids = {s["id"] for s in world["shapes"]}
    assert {"ID", "US", "SG", "MY", "AU"} <= ids and all(s["d"].startswith("M") for s in world["shapes"])
    assert next(s for s in world["shapes"] if s["id"] == "SG").get("c")  # tiny country -> dot
    indo = json.loads((base / "indonesia.json").read_text(encoding="utf-8"))
    shapes = {s["id"] for s in indo["shapes"]}
    # every province is drawn, directly or inside the province it was split from
    assert {gazetteer.MAP_PARENT.get(p, p) for p in gazetteer.PROVINCES} == shapes


def test_geo_stats_rolls_up_new_provinces(installed):
    now = utcnow() - timedelta(hours=2)
    with session_scope() as db:
        src = _source(db, "Zzgeo Papua", country="ID", language="id")
        ingest(db, src, [RawItem("zg-papua", "Zzgeo Situs Pemkab di Merauke diretas", content="Merauke, Papua Selatan.",
                                 published_at=now)])
        db.commit()
        stats = trends.geo_stats(db, 1, "")
    assert {"code": "ID-PS", "count": 1} in [{k: p[k] for k in ("code", "count")} for p in stats["provinces"]]
    assert stats["id_values"].get("ID-PA", 0) >= 1 and "ID-PS" not in stats["id_values"]


def test_migration_adds_defaults(installed, tmp_path):
    """New columns on an existing table get their default instead of NULL."""
    from sqlalchemy import create_engine, text

    import app.db as appdb

    eng = create_engine(f"sqlite:///{(tmp_path / 'old.db').as_posix()}")
    with eng.begin() as c:
        c.execute(text("CREATE TABLE sources (id INTEGER PRIMARY KEY, name VARCHAR(128))"))
        c.execute(text("INSERT INTO sources (id, name) VALUES (1, 'old')"))
    real = appdb.engine
    appdb.engine = eng
    try:
        appdb._add_missing_columns()
    finally:
        appdb.engine = real
    with eng.begin() as c:
        row = c.execute(text("SELECT country, language, enabled FROM sources WHERE id = 1")).one()
    assert row[0] == "" and row[1] == "" and row[2] in (1, True)
