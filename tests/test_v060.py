"""0.6.0: relationship graph, on-demand infrastructure context, STIX 2.1 export, TAXII 2.1 server."""
import base64
import re

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import apikeys, settings
from app.auth import local_user
from app.db import session_scope
from app.models import Entity, EntityLink, Item, Source, utcnow
from app.processing.pipeline import RawItem, ingest

UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


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


def _ingest(src_name, rows, **src_kw) -> list[int]:
    with session_scope() as db:
        src = db.execute(select(Source).where(Source.name == src_name)).scalar_one_or_none()
        if not src:
            src = Source(name=src_name, kind="rss", category="news", config={}, **src_kw)
            db.add(src)
            db.flush()
        return ingest(db, src, [RawItem(external_id=ext, title=t, content=t, published_at=utcnow(), raw=raw or {})
                                for ext, t, raw in rows])


@pytest.fixture()
def graph_items(installed):
    _ingest("Graph feed", [
        ("g-1", "Zzgraph Lumma Stealer spreads from hxxp://lumma-graph[.]top/gate exploiting CVE-2024-3400", None),
        ("g-2", "Zzgraph second report on hxxp://lumma-graph[.]top/gate infrastructure", None),
        ("g-3", "Zzgraph red report on Lumma Stealer", {"tlp": "red"}),
    ])
    with session_scope() as db:
        ids = [db.execute(select(Item.id).where(Item.external_id == ext)).scalar_one() for ext in ("g-1", "g-2", "g-3")]
        dom = db.execute(select(Entity).where(Entity.type == "url", Entity.value.like("%lumma-graph.top%"))).scalars().first()
        fam = db.execute(select(Entity).where(Entity.type == "malware", Entity.value == "lumma stealer")).scalar_one()
        dom.verdict, dom.enriched_at = "malicious", utcnow()
        if not db.execute(select(EntityLink).where(EntityLink.src_id == dom.id, EntityLink.dst_id == fam.id)).first():
            db.add(EntityLink(src_id=dom.id, dst_id=fam.id, relation="attributed-to", provider="virustotal"))
        return {"items": ids, "ioc": dom.id, "family": fam.id}


# --------------------------------------------------------------------------- F. graph
def test_item_and_entity_graphs(client, graph_items):
    from app.processing import graph

    iid = graph_items["items"][0]
    g = client.get(f"/api/items/{iid}/graph").json()
    nodes = {n["id"]: n for n in g["nodes"]}
    assert nodes[f"i{iid}"]["center"] and f"e{graph_items['family']}" in nodes and f"e{graph_items['ioc']}" in nodes
    assert nodes[f"e{graph_items['ioc']}"]["verdict"] == "malicious"
    kinds = {e["kind"] for e in g["edges"]}
    assert {"mention", "enrichment", "shared"} <= kinds  # the second report shares the URL
    assert all(e["source"] in nodes and e["target"] in nodes for e in g["edges"])
    with session_scope() as db:
        small = graph.item_graph(db, db.get(Item, iid), limit=3)
    assert len(small["nodes"]) == 3 and small["truncated"]
    eg = client.get(f"/api/entities/{graph_items['family']}/graph").json()
    assert any(n["kind"] == "item" for n in eg["nodes"]) and any(e["kind"] == "enrichment" for e in eg["edges"])
    assert client.get("/api/items/999999/graph").status_code == 404
    page = client.get(f"/items/{iid}").text
    assert f'data-graph="/api/items/{iid}/graph"' in page and "/static/js/graph.js" in page
    assert 'data-graph="/api/entities/' in client.get(f"/entities/{graph_items['family']}").text
    assert client.get("/static/js/graph.js").status_code == 200


# --------------------------------------------------------------------------- O3. context providers
def _mock_context(monkeypatch, handler):
    from app.intel import clients, context

    monkeypatch.setattr(context, "_client", lambda headers=None: httpx.Client(
        transport=httpx.MockTransport(handler), headers=headers or {}))
    monkeypatch.setattr(clients.throttle, "wait", lambda *a, **k: None)


def _handler(req: httpx.Request) -> httpx.Response:
    host, path = req.url.host, req.url.path
    if host == "internetdb.shodan.io":
        return httpx.Response(200, json={"ip": "45.9.20.1", "ports": [443, 22], "hostnames": ["c2.bad-host.top"],
                                         "vulns": ["CVE-2023-48795"], "tags": ["c2"], "cpes": []})
    if host == "api.platform.censys.io":
        assert req.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json={"result": {"resource": {
            "services": [{"port": 443, "protocol": "HTTP", "threats": [{"name": "Cobalt Strike"}]}, {"port": 22, "protocol": "SSH"}],
            "autonomous_system": {"asn": 64500, "name": "Bad Hosting"}, "location": {"country_code": "NL"}}}})
    if host == "cti.api.crowdsec.net":
        return httpx.Response(200, json={"reputation": "malicious", "behaviors": [{"label": "SSH Bruteforce"}],
                                         "scores": {"overall": {"total": 4}}, "location": {"country": "NL"}})
    if host == "pulsedive.com":
        return httpx.Response(200, json={"risk": "high", "threats": [{"name": "Cobalt Strike"}], "feeds": [{"name": "x"}]})
    if host == "www.hybrid-analysis.com":
        if path.endswith("/search/hash"):
            return httpx.Response(200, json=[{"sha256": "e" * 64, "verdict": "malicious"}])
        return httpx.Response(200, json={"verdict": "malicious", "threat_score": 88, "vx_family": "Lumma Stealer",
                                         "tags": ["stealer"]})
    if host == "ipinfo.io":
        return httpx.Response(200, json={"ip": "45.9.20.1", "org": "AS64500 Bad Hosting BV", "country": "NL",
                                         "city": "Amsterdam"})
    return httpx.Response(404)


def test_context_providers_parse(monkeypatch, setting):
    from app.intel import NotConfigured, context

    _mock_context(monkeypatch, _handler)
    with pytest.raises(NotConfigured):
        context.Shodan()  # keyless lookups are opt-in
    setting("context_keyless", True)
    setting("censys_api_token", "tok")
    setting("crowdsec_api_key", "k")
    setting("pulsedive_api_key", "k")
    setting("hybrid_analysis_api_key", "k")
    sh = context.Shodan().lookup("ip", "45.9.20.1")
    assert sh.data["ports"] == [22, 443] and sh.verdict == "suspicious" and sh.data["api"] == "internetdb"
    ce = context.Censys().lookup("ip", "45.9.20.1")
    assert ce.data["asn"] == 64500 and "Cobalt Strike" in ce.data["threats"] and ce.verdict == "suspicious"
    assert context.CrowdSec().lookup("ip", "45.9.20.1").verdict == "malicious"
    pd = context.Pulsedive().lookup("domain", "bad-host.top")
    assert pd.verdict == "malicious" and pd.malware == ["Cobalt Strike"]
    ha = context.HybridAnalysis().lookup("md5", "f" * 32)
    assert ha.verdict == "malicious" and ha.malware == ["Lumma Stealer"] and ha.permalink.endswith("e" * 64)
    ip = context.IPinfo().lookup("ip", "45.9.20.1")
    assert ip.data["asn"] == "AS64500" and ip.data["country"] == "NL"
    assert context.geo_from([sh, ip])["source"] == "ipinfo"
    assert {p.name for p in context.available("ip")} >= {"shodan", "censys", "crowdsec", "ipinfo"}
    assert [p.name for p in context.available("sha256")] == ["hybrid-analysis"]


def test_context_lookup_endpoint_and_page(client, monkeypatch, setting):
    _mock_context(monkeypatch, _handler)
    setting("context_keyless", True)
    _ingest("Context feed", [("ctx-1", "Zzctx beacon to 45.9.20.1 observed", None)])
    with session_scope() as db:
        eid = db.execute(select(Entity.id).where(Entity.type == "ip", Entity.value == "45.9.20.1")).scalar_one()
    page = client.get(f"/entities/{eid}").text
    assert "Context lookup" in page
    r = client.post(f"/api/entities/{eid}/context", headers={"X-CSRF-Token": _csrf(client)})
    assert r.status_code == 200 and "shodan" in r.json()["message"]
    with session_scope() as db:
        e = db.get(Entity, eid)
        assert e.meta["geo"]["country"] == "NL" and e.verdict == "suspicious"
    page = client.get(f"/entities/{eid}").text
    assert "Infrastructure context" in page and ">443<" in page and "NL" in page
    with session_scope() as db:
        dom = db.execute(select(Entity.id).where(Entity.type == "cve")).scalars().first()
    assert client.post(f"/api/entities/{dom}/context", headers={"X-CSRF-Token": _csrf(client)}).status_code == 400


def test_context_runs_when_ioc_turns_malicious(monkeypatch, setting):
    from app import jobs
    from app.intel import LookupResult
    from app.processing.enrichment import enrich_entity

    queued = []
    monkeypatch.setattr(jobs, "run_now", lambda fn, *a: queued.append((fn.__name__, a)))

    class Fake:
        name, supports = "virustotal", {"ip"}

        def lookup(self, t, v):
            return LookupResult("virustotal", "malicious")

    setting("context_on_malicious", True)
    with session_scope() as db:
        e = Entity(type="ip", value="203.0.113.77", display="203.0.113.77", verdict="")
        db.add(e)
        db.flush()
        enrich_entity(db, e, [Fake()])
        assert queued and queued[0][0] == "run_context_lookup" and queued[0][1] == (e.id,)
        queued.clear()
        enrich_entity(db, e, [Fake()], auto_context=False)
        assert not queued


# --------------------------------------------------------------------------- N3. STIX
def _validate_bundle(b: dict) -> dict:
    assert b["type"] == "bundle" and re.fullmatch(f"bundle--{UUID}", b["id"])
    objs = {o["id"]: o for o in b["objects"]}
    for o in b["objects"]:
        assert re.fullmatch(rf"{o['type']}--{UUID}", o["id"]), o["id"]
        assert o["spec_version"] == "2.1"
        if o["type"] != "marking-definition":
            assert o["created"].endswith("Z") and o["modified"] >= o["created"]
        for ref in o.get("object_marking_refs", []) + o.get("object_refs", []):
            assert ref in objs, ref
        if o["type"] == "relationship":
            assert o["source_ref"] in objs and o["target_ref"] in objs
        if o["type"] == "indicator":
            assert o["pattern_type"] == "stix" and o["pattern"].startswith("[") and o["valid_from"]
        if o["type"] == "report":
            assert o["object_refs"] and o["published"]
        if o["type"] == "malware":
            assert o["is_family"] is True and o["malware_types"]
    return objs


def test_stix_patterns_and_bundles(client, graph_items):
    from app import stix

    e = Entity(type="url", value="http://x.example/a'b\\c")
    assert stix.pattern(e) == "[url:value = 'http://x.example/a\\'b\\\\c']"
    assert stix.pattern(Entity(type="sha256", value="a" * 64)) == f"[file:hashes.'SHA-256' = '{'a' * 64}']"
    assert stix.pattern(Entity(type="ip", value="2001:db8::1")).startswith("[ipv6-addr:value")
    iid = graph_items["items"][0]
    r = client.get(f"/api/v1/stix/items/{iid}")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/stix+json")
    objs = _validate_bundle(r.json())
    types = {o["type"] for o in objs.values()}
    assert {"report", "malware", "indicator", "vulnerability", "relationship", "identity", "marking-definition"} <= types
    rel = next(o for o in objs.values() if o["type"] == "relationship")
    assert rel["relationship_type"] == "indicates" and objs[rel["target_ref"]]["type"] == "malware"
    report = next(o for o in objs.values() if o["type"] == "report")
    assert objs[report["object_marking_refs"][0]]["name"] == "TLP:WHITE"
    again = client.get(f"/api/v1/stix/items/{iid}").json()
    assert {o["id"] for o in again["objects"]} == set(objs)  # stable ids
    red = graph_items["items"][2]
    assert client.get(f"/api/v1/stix/items/{red}").status_code == 404
    bundle = client.get("/api/v1/stix/bundle?since_days=0&limit=500").json()
    names = {o.get("name") for o in _validate_bundle(bundle).values()}
    assert "Zzgraph red report on Lumma Stealer" not in names
    ent = client.get(f"/api/v1/stix/entities/{graph_items['family']}").json()
    eobjs = _validate_bundle(ent)
    assert any(o["type"] == "indicator" for o in eobjs.values())
    assert "⇩ STIX" in client.get(f"/items/{iid}").text


# --------------------------------------------------------------------------- N3. TAXII
@pytest.fixture()
def taxii_key(installed):
    with session_scope() as db:
        _, token = apikeys.create(db, local_user(db), "taxii", ["read"])
    return token


def test_taxii_discovery_collections_and_paging(client, graph_items, taxii_key):
    fresh = TestClient(client.app)
    h = {"Authorization": f"Bearer {taxii_key}", "Accept": "application/taxii+json;version=2.1"}
    d = fresh.get("/taxii2/", headers=h)
    assert d.status_code == 200 and d.headers["content-type"].startswith("application/taxii+json")
    assert d.json()["api_roots"][0].endswith("/taxii2/api/")
    basic = base64.b64encode(f"any:{taxii_key}".encode()).decode()
    assert fresh.get("/taxii2/api/", headers={"Authorization": f"Basic {basic}"}).json()["versions"]
    cols = {c["title"]: c for c in fresh.get("/taxii2/api/collections/", headers=h).json()["collections"]}
    ind, rep = cols["JATMP indicators"], cols["JATMP reports"]
    assert ind["can_read"] and not ind["can_write"] and re.fullmatch(UUID, ind["id"])
    assert fresh.get(f"/taxii2/api/collections/{ind['id']}/", headers=h).json()["id"] == ind["id"]

    p1 = fresh.get(f"/taxii2/api/collections/{rep['id']}/objects/?limit=1", headers=h)
    body = p1.json()
    assert body["more"] and body["next"] and "x-taxii-date-added-first" in p1.headers
    _validate_bundle({"type": "bundle", "id": "bundle--00000000-0000-0000-0000-000000000000", "objects": body["objects"]})
    first = {o["id"] for o in body["objects"] if o["type"] == "report"}
    p2 = fresh.get(f"/taxii2/api/collections/{rep['id']}/objects/?limit=1&next={body['next']}", headers=h).json()
    assert {o["id"] for o in p2["objects"] if o["type"] == "report"} - first
    only = fresh.get(f"/taxii2/api/collections/{ind['id']}/objects/?match[type]=indicator", headers=h).json()
    assert only["objects"] and {o["type"] for o in only["objects"]} == {"indicator"}
    late = fresh.get(f"/taxii2/api/collections/{ind['id']}/objects/?added_after=2999-01-01T00:00:00.000Z", headers=h)
    assert late.json()["objects"] == [] and not late.json()["more"]
    man = fresh.get(f"/taxii2/api/collections/{ind['id']}/manifest/", headers=h).json()
    assert man["objects"] and {"id", "date_added", "version", "media_type"} <= set(man["objects"][0])
    # no red items in the reports collection
    allrep = fresh.get(f"/taxii2/api/collections/{rep['id']}/objects/?limit=1000", headers=h).json()["objects"]
    assert "Zzgraph red report on Lumma Stealer" not in {o.get("name") for o in allrep}
    assert fresh.get("/taxii2/", headers={**h, "Accept": "text/html"}).status_code == 406
    nf = fresh.get("/taxii2/api/collections/nope/", headers=h)
    assert nf.status_code == 404 and nf.json()["http_status"] == "404"
    assert fresh.get(f"/taxii2/api/collections/{ind['id']}/objects/?next=@@", headers=h).status_code == 400


def test_taxii_requires_key_in_multi_user_mode(client, multi_user_mode):
    r = TestClient(client.app).get("/taxii2/")
    assert r.status_code == 401 and r.headers.get("www-authenticate") == "Bearer"
