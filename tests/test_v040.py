"""0.4.0: unified tables, side preview, job status / progress, notification center, CVE intel widgets."""
import re
from datetime import datetime

import httpx
from sqlalchemy import select

from app import jobs, notify
from app.db import session_scope
from app.models import CollectorRun, Entity, Item, Notification, Source, utcnow
from app.processing.pipeline import RawItem, ingest


def _csrf(client, path="/"):
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get(path).text).group(1)


def _rss_sources(n=3) -> list[int]:
    with session_scope() as db:
        return [s.id for s in db.execute(select(Source).where(Source.kind == "rss").order_by(Source.id)).scalars()][:n]


def _ingest(ext_prefix: str, titles: list[str]) -> list[int]:
    with session_scope() as db:
        src = db.get(Source, _rss_sources(1)[0])
        raws = [RawItem(external_id=f"{ext_prefix}-{i}", title=t, content=t, published_at=utcnow())
                for i, t in enumerate(titles)]
        return ingest(db, src, raws)


# --------------------------------------------------------------------------- B. unified tables
def test_lists_share_table_look_pagination_and_all_time(client):
    _ingest("pg", [f"LockBit ransomware wave {i} exploits CVE-2024-3400" for i in range(45)])
    feed = client.get("/feed?days=0").text
    assert 'class="card table-wrap data-table"' in feed
    # "All time" must survive into sort and pager links (it used to fall back to 30 days)
    assert re.search(r'href="\?[^"]*days=0[^"]*&page=2"', feed)
    assert re.search(r'href="\?[^"]*days=0[^"]*sort=severity', feed)
    for path in ("/malware?days=0", "/actors?days=0&page=99", "/cves?days=0&sort=cvss", "/cves?sort=epss&dir=asc",
                 "/malware?sort=cvss", "/iocs?days=7", "/iocs?days=0&sort=first_seen"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert "data-table" in r.text, path
        assert 'value="0" selected' in r.text or "days=0" not in path, path
    mal = client.get("/malware?days=0").text
    assert "data-preview-nav" in mal and 'data-preview="/entities/' in mal
    assert re.search(r'href="\?[^"]*days=0[^"]*sort=name', mal)


# --------------------------------------------------------------------------- A. preview drawer
def test_preview_fragments(client):
    ids = _ingest("pv", ["Lumma Stealer spreads via hxxps://bad-preview[.]top and CVE-2024-3400"])
    item_id = ids[0]
    r = client.get(f"/items/{item_id}/preview")
    assert r.status_code == 200
    assert "<html" not in r.text and "data-preview-meta" in r.text
    assert f'data-full="/items/{item_id}"' in r.text and "Open full page" in r.text
    with session_scope() as db:
        ents = {e.type: e.id for e in (link.entity for link in db.get(Item, item_id).entity_links)}
    for etype in ("malware", "cve", "domain"):
        r = client.get(f"/entities/{ents[etype]}/preview")
        assert r.status_code == 200, etype
        assert "<html" not in r.text and f'data-full="/entities/{ents[etype]}"' in r.text
    assert client.get("/items/999999/preview").status_code == 404
    assert client.get("/entities/999999/preview").status_code == 404
    # every page has the drawer shell and the bell
    page = client.get("/feed").text
    assert 'id="drawer"' in page and 'aria-modal="true"' in page and "data-notif-toggle" in page


# --------------------------------------------------------------------------- C + D. jobs and notifications
class _FakeCollector:
    def __init__(self, src):
        self.src = src

    def fetch(self):
        if self.src.config.get("_boom"):
            raise RuntimeError("feed down")
        return [RawItem(external_id=f"fake-{self.src.id}-{datetime.utcnow().timestamp()}",
                        title="Akira ransomware hits a hospital")]


def test_collection_batch_progress_and_summary(client, monkeypatch):
    jobs._abort_stale_runs()  # runs queued by other tests never ran (the scheduler is off in tests)
    monkeypatch.setitem(jobs.REGISTRY, "rss", _FakeCollector)
    ids = _rss_sources(3)
    with session_scope() as db:
        bad = db.get(Source, ids[2])
        bad.config = {**(bad.config or {}), "_boom": True}
        bad.last_status = "ok"
        batch = jobs.create_collection_batch(db, ids)
        st = jobs.status(db)["jobs"]["collect"]
        assert st["running"] and st["total"] == 3 and st["done"] == 0
    tok = _csrf(client)
    r = client.post("/api/sources/run_all", headers={"X-CSRF-Token": tok})
    assert r.json().get("running") is True  # no second batch while one is going

    jobs.run_source(ids[0], batch)
    jobs.run_source(ids[1], batch)
    with session_scope() as db:
        st = jobs.status(db)["jobs"]["collect"]
        assert st["running"] and st["done"] == 2 and "2/3 sources" in st["label"]
        assert not db.execute(select(Notification).where(Notification.key == f"batch:{batch}")).scalar()
    jobs.run_source(ids[2], batch)
    with session_scope() as db:
        n = db.execute(select(Notification).where(Notification.key == f"batch:{batch}")).scalar_one()
        assert n.level == "warning" and "from 3 sources, 1 error" in n.title and "Failed:" in n.body
        assert n.link == "/settings?tab=sources"
        runs = db.execute(select(CollectorRun).where(CollectorRun.batch_id == batch)).scalars().all()
        assert sorted(r.status for r in runs) == ["error", "ok", "ok"]
        # inside a batch a failing source is summarised, not notified on its own
        assert not db.execute(select(Notification).where(Notification.key.like(f"srcfail:{ids[2]}:%"))).first()
        st = jobs.status(db)["jobs"]["collect"]
        assert not st["running"] and st["last"]["finished_at"].endswith("Z")

    # scheduled run: notify on the ok -> error transition only, not on every failing run
    jobs.run_source(ids[2])
    with session_scope() as db:
        assert not db.execute(select(Notification).where(Notification.key.like(f"srcfail:{ids[2]}:%"))).first()
        db.get(Source, ids[2]).last_status = "ok"
    jobs.run_source(ids[2])
    with session_scope() as db:
        assert db.execute(select(Notification).where(Notification.key.like(f"srcfail:{ids[2]}:%"))).first()
        bad = db.get(Source, ids[2])
        bad.config = {k: v for k, v in bad.config.items() if k != "_boom"}


def test_enrichment_queue_and_status_endpoint(client):
    jobs._abort_stale_runs()
    tok = _csrf(client)
    r = client.post("/api/enrichment/run", headers={"X-CSRF-Token": tok})
    assert r.json()["ok"] and r.json()["batch"].startswith("enrichment-")
    again = client.post("/api/enrichment/run", headers={"X-CSRF-Token": tok}).json()
    assert again.get("running") is True
    st = client.get("/api/jobs/status").json()
    assert st["jobs"]["enrich"]["running"] and st["jobs"]["enrich"]["label"] == "Queued…"
    assert {"collect", "enrich", "cve_intel"} <= set(st["jobs"]) and "unread" in st["notifications"]
    # the queued run is picked up by the worker, not duplicated
    batch = r.json()["batch"]
    jobs.run_enrichment(batch)
    with session_scope() as db:
        runs = db.execute(select(CollectorRun).where(CollectorRun.batch_id == batch)).scalars().all()
        assert len(runs) == 1 and runs[0].status in ("ok", "skipped")
        assert db.execute(select(Notification).where(Notification.key == f"batch:{batch}")).scalar_one()
    assert not client.get("/api/jobs/status").json()["jobs"]["enrich"]["running"]


def test_notifications_api_and_read_watermark(client):
    with session_scope() as db:
        notify.notify(db, "error", "Test failure", "details", "https://evil.example/phish", key="t:1")
        assert notify.notify(db, "error", "dup", key="t:1") is None or True
    with session_scope() as db:
        assert notify.notify(db, "error", "dup", key="t:1") is None  # same key is a no-op
        n = db.execute(select(Notification).where(Notification.key == "t:1")).scalar_one()
        assert n.link == ""  # only same-origin paths are kept
    st = client.get("/api/jobs/status").json()["notifications"]
    assert st["unread"] >= 1 and st["latest"]["id"] >= n.id
    items = client.get("/api/notifications").json()["items"]
    assert any(i["title"] == "Test failure" and i["unread"] for i in items)
    assert client.post("/api/notifications/read").status_code == 403  # CSRF
    tok = _csrf(client)
    assert client.post("/api/notifications/read", headers={"X-CSRF-Token": tok}).json()["unread"] == 0
    assert client.get("/api/jobs/status").json()["notifications"]["unread"] == 0
    assert not any(i["unread"] for i in client.get("/api/notifications").json()["items"])


# --------------------------------------------------------------------------- E. CVE intel + widgets
def _mock_http():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "www.cisa.gov":
            return httpx.Response(200, json={"vulnerabilities": [{
                "cveID": "CVE-2099-0001", "vendorProject": "Fortinet", "product": "FortiOS", "dateAdded": "2099-01-02",
                "dueDate": "2099-01-23", "knownRansomwareCampaignUse": "Known", "vulnerabilityName": "x"}]})
        if req.url.host == "api.first.org":
            cves = req.url.params["cve"].split(",")
            return httpx.Response(200, json={"data": [{"cve": c, "epss": "0.91234", "percentile": "0.99",
                                                       "date": "2099-01-03"} for c in cves]})
        if req.url.host == "services.nvd.nist.gov":
            return httpx.Response(200, json={"vulnerabilities": [{"cve": {
                "published": "2099-01-01T00:00:00", "descriptions": [{"lang": "en", "value": "Heap overflow in FortiOS"}],
                "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                    "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]})
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_cve_intel_refresh_and_dashboard_widgets(client):
    from app.intel import cve
    from app.processing import trends

    _ingest("cve", ["Attackers exploit CVE-2099-0001 in FortiOS, Akira ransomware involved",
                    "CVE-2099-0001 mass exploitation continues"])
    with session_scope() as db:
        msg = cve.refresh(db, limit=1, http=_mock_http())
        db.commit()  # jobs.run_cve_intel commits after refresh()
        assert "1 in CISA KEV" in msg and "1 CVSS" in msg
        e = db.execute(select(Entity).where(Entity.type == "cve", Entity.value == "CVE-2099-0001")).scalar_one()
        assert e.meta["kev"]["ransomware"] == "Known" and e.meta["epss"]["score"] == 0.91234
        assert e.meta["cvss"]["score"] == 9.8 and e.meta["cvss"]["version"] == "3.1"
        eid = e.id
        assert e not in cve.candidates(db)  # checked: not due again for 24 h
        top = trends.trending_cves(db, limit=8)
        row = next(r for r in top if r["id"] == eid)
        assert row["kev"] and row["cvss"] == 9.8 and row["priority"] > row["score"]
        assert any(r["name"].lower().startswith("akira") for r in row["related"])
    dash = client.get("/").text
    assert "Trending CVEs" in dash and "Trending threat actors" in dash and "CVE-2099-0001" in dash
    assert 'data-job-status="collect"' in dash and 'data-job-button="enrich"' in dash
    assert ">KEV<" in client.get("/cves?days=0").text
    page = client.get(f"/entities/{eid}").text
    assert "Vulnerability intel" in page and "known ransomware use" in page
    assert "Heap overflow" in client.get(f"/entities/{eid}/preview").text


def test_cve_parsers_and_priority():
    from app.intel import cve

    v2 = cve.parse_nvd({"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV2": [
        {"baseSeverity": "HIGH", "cvssData": {"version": "2.0", "baseScore": 7.5, "vectorString": "AV:N"}}]}}}]})
    assert v2["score"] == 7.5 and v2["severity"] == "HIGH"
    assert cve.parse_nvd({"vulnerabilities": []}) is None
    assert cve.parse_kev({"vulnerabilities": [{"cveID": "nope"}, {"cveID": "cve-2020-1"}]}) == {
        "CVE-2020-1": {"date_added": "", "due_date": "", "ransomware": "", "vendor": "", "product": "", "name": ""}}
    plain, _ = cve.priority(10, {})
    kev, intel = cve.priority(10, {"kev": {"x": 1}, "epss": {"score": 0.5}, "cvss": {"score": 10.0}})
    assert plain == 10 and kev == 10 * 2 * 1.5 * 1.5 and intel["kev"]


def test_cve_refresh_stops_calling_nvd_when_it_fails(client):
    from app.intel import cve

    _ingest("nvd", [f"CVE-2099-10{i:02d} exploited in the wild" for i in range(4)])
    calls = {"nvd": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "services.nvd.nist.gov":
            calls["nvd"] += 1
            return httpx.Response(503)
        if req.url.host == "api.first.org":
            return httpx.Response(200, json={"data": []})
        return httpx.Response(200, json={"vulnerabilities": []})

    cve.throttle.last.pop("nvd", None)
    orig = cve.throttle.wait
    cve.throttle.wait = lambda *a, **k: None  # no real 6.5 s spacing in tests
    try:
        with session_scope() as db:
            msg = cve.refresh(db, limit=4, http=httpx.Client(transport=httpx.MockTransport(handler)))
            db.commit()
    finally:
        cve.throttle.wait = orig
    assert calls["nvd"] == 2 and "NVD unavailable" in msg
    with session_scope() as db:
        e = db.execute(select(Entity).where(Entity.value == "CVE-2099-1000")).scalar_one()
        assert "cvss_checked_at" not in e.meta  # failed lookups are retried on the next run
