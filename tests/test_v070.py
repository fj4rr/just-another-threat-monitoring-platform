"""0.7.0: historical backfill, retention tiers, full-text search, PostgreSQL safety."""
import re
from datetime import datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from app import backfill, jobs, settings
from app.collectors import REGISTRY
from app.collectors.base import BackfillCapability, Collector
from app.db import session_scope
from app.models import CollectorRun, Entity, Item, Notification, Source, utcnow
from app.processing.pipeline import RawItem, _slim_raw, ingest


def _csrf(client, path="/"):
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get(path).text).group(1)


@pytest.fixture()
def setting(installed):
    touched = []

    def _set(key, value):
        touched.append(key)
        settings.set(key, value)

    yield _set
    for k in touched:
        settings.set(k, None)


def _source(db, name, kind="rss", cfg=None, category="news"):
    src = db.execute(select(Source).where(Source.name == name)).scalar_one_or_none()
    if not src:
        src = Source(name=name, kind=kind, category=category, config=cfg or {})
        db.add(src)
        db.flush()
    return src


def _mock_collector_http(monkeypatch, handler):
    monkeypatch.setattr(Collector, "client", lambda self, **h: httpx.Client(transport=httpx.MockTransport(handler)))


# --------------------------------------------------------------------------- collectors
WP_POSTS = [
    {"id": 1, "guid": {"rendered": "https://blog.example.com/?p=1"}, "date_gmt": "2026-05-02T10:00:00",
     "link": "https://blog.example.com/a", "title": {"rendered": "Zzwp Lumma &amp; friends"},
     "content": {"rendered": "<p>Lumma Stealer returns</p>"}},
    {"id": 2, "guid": {"rendered": "https://blog.example.com/?p=2"}, "date_gmt": "2026-04-20T10:00:00",
     "link": "https://blog.example.com/b", "title": {"rendered": "Zzwp older"}, "content": {"rendered": "x"}},
]


def test_rss_backfill_wordpress(installed, monkeypatch):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/wp-json/wp/v2/posts":
            if req.url.params.get("per_page") == "1":
                return httpx.Response(200, json=[{"id": 1}], headers={"x-wp-total": "2", "x-wp-totalpages": "2"})
            return httpx.Response(200, json=WP_POSTS, headers={"x-wp-total": "2", "x-wp-totalpages": "1"})
        return httpx.Response(404)

    _mock_collector_http(monkeypatch, handler)
    src = Source(name="WP", kind="rss", category="news", config={"url": "https://blog.example.com/feed/"})
    coll = REGISTRY["rss"](src)
    assert coll.backfill_capability().supported
    assert coll.wordpress_root() == "https://blog.example.com"
    assert coll.wordpress_count("https://blog.example.com", datetime(2026, 1, 1), datetime(2026, 6, 1)) == 2
    notes = []
    pages = list(coll.backfill(datetime(2026, 1, 1), datetime(2026, 6, 1), notes.append))
    raws = [r for p in pages for r in p]
    assert [r.external_id for r in raws] == ["https://blog.example.com/?p=1", "https://blog.example.com/?p=2"]
    assert raws[0].title == "Zzwp Lumma & friends" and raws[0].published_at == datetime(2026, 5, 2, 10, 0)
    assert any("WordPress" in n for n in notes)


ARCHIVED_FEED = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Zzwb in window</title><link>https://news.example.org/1</link><guid>wb-1</guid>
<pubDate>Mon, 13 Apr 2026 10:00:00 GMT</pubDate><description>Akira ransomware</description></item>
<item><title>Zzwb too old</title><link>https://news.example.org/2</link><guid>wb-2</guid>
<pubDate>Mon, 05 Jan 2026 10:00:00 GMT</pubDate><description>x</description></item>
</channel></rss>"""


def test_rss_backfill_wayback_fallback(installed, monkeypatch):
    import app.collectors.rss as rss

    monkeypatch.setattr(rss.time, "sleep", lambda s: None)

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "web.archive.org" and req.url.path == "/cdx/search/cdx":
            return httpx.Response(200, json=[["timestamp", "original"], ["20260414000000", "https://news.example.org/feed"]])
        if req.url.host == "web.archive.org":
            assert "id_/" in req.url.path
            return httpx.Response(200, content=ARCHIVED_FEED, headers={"content-type": "application/rss+xml"})
        return httpx.Response(404)  # no WordPress API

    _mock_collector_http(monkeypatch, handler)
    coll = REGISTRY["rss"](Source(name="N", kind="rss", category="news", config={"url": "https://news.example.org/feed"}))
    pages = list(coll.backfill(datetime(2026, 3, 1), datetime(2026, 5, 1), lambda m: None))
    assert [r.title for p in pages for r in p] == ["Zzwb in window"]


def test_social_backfill_paging(installed, monkeypatch):
    def post(i, day):
        return {"post": {"uri": f"at://did/app.bsky.feed.post/{i}", "author": {"handle": "h.bsky.social"},
                         "record": {"text": f"post {i}", "createdAt": f"2026-04-{day:02d}T10:00:00Z"}}}

    def bsky(req: httpx.Request) -> httpx.Response:
        if req.url.params.get("cursor") is None:
            return httpx.Response(200, json={"feed": [post(1, 28), post(2, 20)], "cursor": "c1"})
        return httpx.Response(200, json={"feed": [post(3, 10), post(4, 2)], "cursor": "c2"})

    _mock_collector_http(monkeypatch, bsky)
    coll = REGISTRY["bluesky"](Source(name="B", kind="bluesky", category="social", config={"handle": "h.bsky.social"}))
    pages = list(coll.backfill(datetime(2026, 4, 5), datetime(2026, 4, 25), lambda m: None))
    assert len(pages) == 2  # stopped after the page that reached past the window
    assert [r.content for p in pages for r in p] == ["post 2", "post 3"]

    def masto(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/lookup"):
            return httpx.Response(200, json={"id": "7"})
        if "max_id" not in req.url.params:
            return httpx.Response(200, json=[{"id": "30", "uri": "u30", "content": "<p>a</p>", "created_at": "2026-04-28T00:00:00Z"},
                                             {"id": "20", "uri": "u20", "content": "<p>b</p>", "created_at": "2026-04-15T00:00:00Z"}])
        assert req.url.params["max_id"] == "20"
        return httpx.Response(200, json=[{"id": "10", "uri": "u10", "content": "<p>c</p>", "created_at": "2026-03-01T00:00:00Z"}])

    _mock_collector_http(monkeypatch, masto)
    mc = REGISTRY["mastodon"](Source(name="M", kind="mastodon", category="social", config={"account": "x@inst.example"}))
    got = [r.external_id for p in mc.backfill(datetime(2026, 4, 1), datetime(2026, 4, 20), lambda m: None) for r in p]
    assert got == ["u20"]
    assert not REGISTRY["x"](Source(name="X", kind="x", category="social", config={})).backfill_capability().supported
    tf = REGISTRY["threatfox"](Source(name="T", kind="threatfox", category="intel", config={})).backfill_capability()
    assert tf.supported and tf.max_days == 7


def test_effective_since_clamps(setting):
    until = utcnow()
    s, note = backfill.effective_since(until - timedelta(days=60), until, BackfillCapability(True, max_days=7))
    assert (until - s).days == 7 and "7 days" in note
    setting("retention_days", 20)
    s, note = backfill.effective_since(until - timedelta(days=60), until, BackfillCapability(True))
    assert (until - s).days <= 20 and "retention" in note
    with pytest.raises(ValueError):
        backfill.window(since="2026-05-01", until="2026-04-01")


# --------------------------------------------------------------------------- the backfill job
class _HistoryCollector(Collector):
    kind = "rss"
    category = "news"
    calls = []

    def fetch(self):
        return []

    def backfill_capability(self):
        if self.cfg.get("nope"):
            return BackfillCapability(False, note="not here")
        return BackfillCapability(True, "test pages")

    def backfill(self, since, until, progress):
        old = utcnow() - timedelta(days=200)
        _HistoryCollector.calls.append((since, until))
        progress("page 1")
        yield [RawItem(external_id=f"hist-{i}", title=f"Zzhist Medusalocker ransomware report {i}",
                       content="Zzhistword detail", published_at=old + timedelta(days=i)) for i in range(3)]
        progress("page 2")
        yield [RawItem(external_id="hist-3", title="Zzhist BlackSuit wave", published_at=old)]


def test_backfill_job_end_to_end(client, monkeypatch, setting):
    monkeypatch.setitem(jobs.REGISTRY, "rss", _HistoryCollector)
    jobs._abort_stale_runs()
    with session_scope() as db:
        ok = _source(db, "History feed", cfg={"url": "https://h.example/feed"})
        no = _source(db, "History none", cfg={"url": "https://n.example/feed", "nope": True})
        since, until = backfill.window(days=365)
        monkeypatch.setattr(jobs, "run_now", lambda *a, **k: None)  # run it inline below
        batch = jobs.queue_backfill(db, [ok.id, no.id], since, until)
        assert jobs.status(db)["jobs"]["backfill"]["running"]
        ok_id = ok.id
    jobs.run_backfill(batch, since.isoformat(), until.isoformat())
    with session_scope() as db:
        runs = {r.source_id: r for r in db.execute(select(CollectorRun).where(CollectorRun.batch_id == batch)).scalars()}
        assert runs[ok_id].status == "ok" and runs[ok_id].new_items == 4 and "4 new of 4 fetched" in runs[ok_id].message
        assert [r.status for sid, r in runs.items() if sid != ok_id] == ["skipped"]
        items = db.execute(select(Item).where(Item.title.like("Zzhist%"))).unique().scalars().all()
        assert len(items) == 4 and {i.origin for i in items} == {"backfill"}
        n = db.execute(select(Notification).where(Notification.key == f"batch:{batch}")).scalar_one()
        assert "4 historical items from 1 source" in n.title
        fam = db.execute(select(Entity).where(Entity.type == "malware", Entity.value == "medusa")).scalar_one()
        assert fam.first_seen < utcnow() - timedelta(days=150)  # moved back to the historical date
        from app.processing import trends

        assert fam.id not in {t["id"] for t in trends.trending(db, "malware", limit=500)}  # history is not "trending"
        assert not jobs.status(db)["jobs"]["backfill"]["running"]
    page = client.get("/feed?q=Zzhist&days=0").text
    assert ">history<" in page
    assert client.get("/api/v1/items?q=Zzhist").json()["data"][0]["origin"] == "backfill"
    # a second run of the same range adds nothing
    with session_scope() as db:
        b2 = jobs.queue_backfill(db, [ok_id], since, until)
    jobs.cancel_backfill(b2)
    jobs.run_backfill(b2, since.isoformat(), until.isoformat())
    with session_scope() as db:
        assert db.execute(select(CollectorRun.status).where(CollectorRun.batch_id == b2)).scalar() == "aborted"


def test_backfill_page_estimate_and_start(client, monkeypatch, setting):
    monkeypatch.setattr(backfill, "_probe", lambda src, s, u: {"method": "WordPress API (test)", "estimate": 42,
                                                                "exact": True} if src.kind == "rss" else {})
    with session_scope() as db:
        rss = _source(db, "Estimate feed", cfg={"url": "https://e.example/feed"})
        xs = _source(db, "Estimate X", kind="x", category="social", cfg={"username": "x"})
        ids = [rss.id, xs.id]
    page = client.get("/backfill").text
    assert "Historical backfill" in page and "Storage" in page and "not supported" in page
    tok = _csrf(client, "/backfill")
    r = client.post("/api/backfill/estimate", json={"source_ids": ids, "days": 90}, headers={"X-CSRF-Token": tok})
    rows = {row["id"]: row for row in r.json()["rows"]}
    assert rows[ids[0]]["estimate"] == 42 and rows[ids[0]]["exact"] and not rows[ids[1]]["supported"]
    assert client.post("/api/backfill/estimate", json={"source_ids": [], "days": 7},
                       headers={"X-CSRF-Token": tok}).status_code == 400
    assert client.post("/api/backfill/start", json={"source_ids": [ids[1]], "days": 7},
                       headers={"X-CSRF-Token": tok}).status_code == 400  # nothing supports it
    monkeypatch.setattr(jobs, "run_now", lambda *a, **k: None)
    jobs._abort_stale_runs()
    first = client.post("/api/backfill/start", json={"source_ids": ids, "days": 7}, headers={"X-CSRF-Token": tok}).json()
    assert first["batch"].startswith("backfill-") and "1 source" in first["message"]
    again = client.post("/api/backfill/start", json={"source_ids": ids, "days": 7}, headers={"X-CSRF-Token": tok}).json()
    assert again.get("running") is True
    assert "Stopping" in client.post("/api/backfill/stop", headers={"X-CSRF-Token": tok}).json()["message"]
    jobs._abort_stale_runs()


def test_backfilled_iocs_are_not_enriched_by_default(installed, monkeypatch, setting):
    from app.processing import enrichment

    looked = []

    class Fake:
        name, supports = "fake", {"ip", "domain", "url", "md5", "sha1", "sha256"}

        def lookup(self, t, v):
            looked.append(v)
            return None

    monkeypatch.setattr(enrichment, "available_providers", lambda: [Fake()])
    setting("enrich_families", False)
    setting("enrichment_batch", 100)  # other tests leave newer pending IOCs; make room for this one
    with session_scope() as db:
        src = _source(db, "Old IOC feed")
        ingest(db, src, [RawItem(external_id="old-ioc", title="Zzold beacon 45.9.21.77",
                                 published_at=utcnow() - timedelta(days=300))], origin="backfill")
        db.commit()
        enrichment.run_batch(db)
        assert "45.9.21.77" not in looked
        setting("enrich_backfill", True)
        enrichment.run_batch(db)
        assert "45.9.21.77" in looked


# --------------------------------------------------------------------------- retention, search, storage
def test_slimming_and_full_text_search(client, setting):
    from app.search import match_query

    long_text = "Zzslim intro words. " + "padding " * 200 + "Zzslimtail secret detail at the end"
    with session_scope() as db:
        src = _source(db, "Slim feed")
        ingest(db, src, [RawItem(external_id="slim-1", title="Zzslim old report on Lynx ransomware", content=long_text,
                                 published_at=utcnow() - timedelta(days=400), raw={"copy": long_text, "tlp": "green"})])
    assert client.get("/api/v1/items?q=Zzslimtail").json()["data"]  # FTS finds words deep in the text
    assert client.get("/api/v1/items?q=zzsli").json()["data"]  # prefix match
    setting("retention_full_days", 180)
    with session_scope() as db:
        assert jobs.slim_items(db) >= 1
        it = db.execute(select(Item).where(Item.external_id == "slim-1")).unique().scalar_one()
        assert it.slimmed_at and len(it.content) < 420 and "copy" not in (it.raw or {}) and it.raw.get("tlp") == "green"
        assert any(link.entity.value == "lynx" for link in it.entity_links)  # entities survive slimming
        assert jobs.slim_items(db) == 0  # idempotent
    assert not client.get("/api/v1/items?q=Zzslimtail").json()["data"]  # trimmed text left the index
    assert client.get("/api/v1/items?q=Zzslim old report").json()["data"]  # the title is still searchable
    assert "trimmed by the retention" in client.get(f"/items/{it.id}").text
    # user input never becomes FTS syntax
    assert match_query('evil" OR NOT x*') == '"evil"* "OR"* "NOT"* "x"*'
    for q in ('"', "NEAR(a b)", "a AND", "*", "col:val", "'; DROP TABLE items; --"):
        assert client.get("/feed", params={"q": q}).status_code == 200, q


def test_raw_slimming_string_guard_and_copy(installed, tmp_path):
    assert _slim_raw({"a": "x" * 3000, "b": "same text", "c": 1}, "same text") == {"c": 1}
    with session_scope() as db:
        s = Source(name="N" * 400, kind="rss", category="news", config={})
        db.add(s)
        db.flush()
        assert len(s.name) == 128  # VARCHAR(128): PostgreSQL would reject the longer value
        db.rollback()
    from app.dbcopy import copy_database

    target = f"sqlite:///{(tmp_path / 'copy.db').as_posix()}"
    counts = copy_database(target, progress=lambda m: None)
    with session_scope() as db:
        assert counts["items"] == db.scalar(select(__import__("sqlalchemy").func.count(Item.id)))
    with pytest.raises(RuntimeError, match="not empty"):
        copy_database(target, progress=lambda m: None)


def test_queries_compile_for_postgresql(installed):
    from sqlalchemy.dialects import postgresql

    from app import sharing
    from app.models import ItemEntity

    stmts = [
        select(Item).join(Source, Source.id == Item.source_id).where(sharing.shareable_item_clause()),
        select(Entity).where(sharing.shareable_entity_clause()),
        select(Item.origin, __import__("sqlalchemy").func.count(Item.id)).group_by(Item.origin),
        select(ItemEntity.entity_id).join(Item, Item.id == ItemEntity.item_id).where(Item.origin != "backfill"),
    ]
    for st in stmts:
        sql = str(st.compile(dialect=postgresql.dialect()))
        assert "SELECT" in sql


def test_ingest_retries_after_a_concurrent_insert(installed, monkeypatch):
    """A scheduled run and a backfill of the same source can store the same entry at the same moment."""
    from sqlalchemy.exc import IntegrityError

    from app.processing import pipeline

    real = pipeline.ingest
    calls = []

    def racing(db, source, raws, progress=None, origin="live"):
        calls.append(origin)
        if len(calls) == 1:
            # the other run commits the entry first, then our insert hits the unique constraint
            with session_scope() as other:
                real(other, other.get(Source, source.id), raws)
            raise IntegrityError("INSERT INTO items", {}, Exception("UNIQUE constraint failed"))
        return real(db, source, raws, progress, origin)

    monkeypatch.setattr(pipeline, "ingest", racing)
    with session_scope() as db:
        src = _source(db, "Race feed")
        db.commit()
        ids = pipeline.ingest_committed(db, src, [RawItem(external_id="race-1", title="Zzrace item")], origin="backfill")
        assert ids == [] and len(calls) == 2  # retried, and the second pass saw the stored entry
        assert db.execute(select(Item).where(Item.external_id == "race-1")).unique().scalar_one().origin == "live"
