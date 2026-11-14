"""0.5.0: new intel providers, sharing rules, API keys + REST v1 + IOC feeds, webhooks, dark web tier 1, MISP."""
import hashlib
import hmac
import json
import re

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import settings, sharing, webhooks
from app.db import session_scope
from app.intel import LookupResult
from app.models import (
    ApiKey,
    Enrichment,
    Entity,
    EntityLink,
    Item,
    Notification,
    Source,
    User,
    Webhook,
    WebhookDelivery,
    utcnow,
)
from app.processing.pipeline import RawItem, ingest


def _csrf(client, path="/"):
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get(path).text).group(1)


@pytest.fixture()
def setting(installed):
    """settings.set() that is undone after the test."""
    touched = []

    def _set(key, value):
        touched.append(key)
        settings.set(key, value)

    yield _set
    for k in touched:
        settings.set(k, None)


def _source(db, name, kind="rss", **kw) -> Source:
    src = db.execute(select(Source).where(Source.name == name)).scalar_one_or_none()
    if not src:
        src = Source(name=name, kind=kind, category="intel" if kind != "rss" else "news", config={}, **kw)
        db.add(src)
        db.flush()
    return src


def _ingest(src_name, rows, kind="rss", **src_kw) -> list[int]:
    with session_scope() as db:
        src = _source(db, src_name, kind, **src_kw)
        return ingest(db, src, [RawItem(external_id=ext, title=t, content=t, published_at=utcnow(), raw=raw or {})
                                for ext, t, raw in rows])


def _mock(monkeypatch, handler):
    """Route every intel-client HTTP call through ``handler``."""
    from app.intel import clients

    monkeypatch.setattr(clients, "_client", lambda headers=None: httpx.Client(
        transport=httpx.MockTransport(handler), headers=headers or {}))
    monkeypatch.setattr(clients.throttle, "wait", lambda *a, **k: None)


# --------------------------------------------------------------------------- O1 providers + consensus
def test_new_providers_parse_responses(monkeypatch, setting):
    from app.intel.clients import AbuseIPDB, GreyNoise, MalwareBazaar, URLhaus

    setting("threatfox_auth_key", "k")
    setting("greynoise_api_key", "k")
    setting("abuseipdb_api_key", "k")

    def handler(req: httpx.Request) -> httpx.Response:
        host, body = req.url.host, req.content.decode()
        if host == "mb-api.abuse.ch":
            if "deadbeef" in body:
                return httpx.Response(200, json={"query_status": "hash_not_found"})
            return httpx.Response(200, json={"query_status": "ok", "data": [{
                "sha256_hash": "a" * 64, "md5_hash": "b" * 32, "signature": "Lumma Stealer", "file_type": "exe",
                "tags": ["lumma"]}]})
        if host == "urlhaus-api.abuse.ch":
            if req.url.path.endswith("/url/"):
                return httpx.Response(200, json={"query_status": "ok", "url_status": "online", "threat": "malware_download",
                                                 "payloads": [{"signature": "Remcos", "response_sha256": "c" * 64}]})
            return httpx.Response(200, json={"query_status": "ok", "url_count": 2,
                                             "urls": [{"url": "http://x/1", "url_status": "offline"}]})
        if host == "api.greynoise.io":
            if req.url.path.endswith("1.1.1.1"):
                return httpx.Response(200, json={"noise": False, "riot": True, "classification": "benign", "name": "Cloudflare"})
            return httpx.Response(404, json={})
        if host == "api.abuseipdb.com":
            ip = req.url.params["ipAddress"]
            return httpx.Response(200, json={"data": {"abuseConfidenceScore": 0 if ip == "1.1.1.1" else 90,
                                                      "totalReports": 12, "isWhitelisted": ip == "1.1.1.1"}})
        return httpx.Response(404)

    _mock(monkeypatch, handler)
    mb = MalwareBazaar().lookup("sha256", "a" * 64)
    assert mb.verdict == "malicious" and mb.malware == ["Lumma Stealer"] and {r.type for r in mb.related} == {"md5"}
    assert MalwareBazaar().lookup("md5", "deadbeef" * 4).verdict == "unknown"
    assert MalwareBazaar().lookup("ip", "1.2.3.4") is None
    uh = URLhaus().lookup("url", "http://evil.example/x.exe")
    assert uh.verdict == "malicious" and uh.score == 90 and "Remcos" in uh.malware
    assert URLhaus().lookup("domain", "evil.example").verdict == "suspicious"  # only offline URLs
    gn = GreyNoise().lookup("ip", "1.1.1.1")
    assert gn.verdict == "clean" and gn.data["riot"] and "benign-service" in gn.tags
    assert GreyNoise().lookup("ip", "5.6.7.8").verdict == "unknown"
    assert AbuseIPDB().lookup("ip", "5.6.7.8").verdict == "malicious"
    assert AbuseIPDB().lookup("ip", "1.1.1.1").verdict == "clean"


def test_greynoise_benign_overrides_weak_signals(installed):
    from app.processing.enrichment import _consensus

    ent = Entity(type="ip", value="1.1.1.1", verdict="")
    gn = LookupResult("greynoise", "clean", data={"riot": True})
    otx = LookupResult("otx", "malicious", data={"pulse_count": 2})
    abuse = LookupResult("abuseipdb", "suspicious")
    assert _consensus(ent, [otx, abuse]) == "suspicious"
    assert _consensus(ent, [otx, abuse, gn]) == "clean"
    # a strong provider still wins over GreyNoise
    assert _consensus(ent, [gn, LookupResult("virustotal", "malicious")]) == "malicious"


def test_provider_test_endpoint(client):
    tok = _csrf(client)
    assert client.post("/api/intel/test/nope", headers={"X-CSRF-Token": tok}).status_code == 404
    r = client.post("/api/intel/test/greynoise", headers={"X-CSRF-Token": tok})
    assert r.status_code == 400 and "not set" in r.json()["detail"]
    page = client.get("/settings?tab=intel").text
    assert 'data-post="/api/intel/test/malwarebazaar"' in page


# --------------------------------------------------------------------------- sharing rules
def test_tlp_and_redistribution_rules(client):
    assert sharing.norm_tlp("tlp:amber+strict") == "AMBER" and sharing.norm_tlp("white") == "CLEAR"
    assert sharing.norm_tlp("nonsense") == ""
    red = _ingest("Share test feed", [("s-red", "Zzshare red pulse LockBit", {"tlp": "red"}),
                                      ("s-ok", "Zzshare green pulse LockBit", {"tlp": "green"})])
    ar = _ingest("Share test anyrun", [("s-ar", "Zzshare anyrun task LockBit", None)], kind="anyrun")
    with session_scope() as db:
        r, g, a = db.get(Item, red[0]), db.get(Item, red[1]), db.get(Item, ar[0])
        assert r.tlp == "RED" and not sharing.item_shareable(r)
        assert sharing.item_shareable(g) and not sharing.item_shareable(a)
        ids = {i for (i,) in db.execute(sharing.shareable_item_ids())}
        assert g.id in ids and r.id not in ids and a.id not in ids


# --------------------------------------------------------------------------- API keys + REST v1
def _new_key(client, scopes=("read",), name="t"):
    tok = _csrf(client, "/profile")
    r = client.post("/profile/api-keys", data={"csrf_token": tok, "name": name, "scopes": list(scopes),
                                               "expires_days": "30"})
    assert r.status_code == 200
    return re.search(r'value="(jatmp_[0-9a-f]{8}_[^"]+)"', r.text).group(1)


def test_api_keys_auth_scopes_rate_limit_and_revoke(client, setting):
    token = _new_key(client)
    with session_scope() as db:
        key = db.execute(select(ApiKey).order_by(ApiKey.id.desc())).scalars().first()
        assert key.secret_hash == hashlib.sha256(token.split("_", 2)[2].encode()).hexdigest()
        assert token not in json.dumps(key.scopes) and key.scopes == ["read"]
    h = {"Authorization": f"Bearer {token}"}
    fresh = TestClient(client.app)  # no session cookie: the key alone authenticates
    assert fresh.get("/api/v1/items?limit=1", headers=h).status_code == 200
    bad = fresh.get("/api/v1/items", headers={"Authorization": "Bearer jatmp_00000000_nope"})
    assert bad.status_code == 401 and bad.headers.get("www-authenticate") == "Bearer"
    assert fresh.get("/api/v1/feeds/iocs.txt", headers=h).status_code == 403  # no export scope
    setting("api_rate_limit", 2)
    codes = [fresh.get("/api/v1/trending", headers=h).status_code for _ in range(4)]
    assert 429 in codes and "retry-after" in fresh.get("/api/v1/trending", headers=h).headers
    with session_scope() as db:
        kid = db.execute(select(ApiKey.id).order_by(ApiKey.id.desc())).scalar()
    tok = _csrf(client, "/profile")
    client.post(f"/profile/api-keys/{kid}/revoke", data={"csrf_token": tok})
    assert fresh.get("/api/v1/items", headers=h).status_code == 401
    page = client.get("/profile").text
    assert "revoked" in page and token not in page  # the secret is never shown again


def test_api_requires_auth_in_multi_user_mode(client, multi_user_mode):
    fresh = TestClient(client.app)
    r = fresh.get("/api/v1/items")
    assert r.status_code == 401 and r.headers.get("www-authenticate") == "Bearer"
    assert fresh.get("/api/v1/docs", follow_redirects=False).headers["location"].startswith("/login")


def test_v1_items_entities_and_sharing(client):
    _ingest("V1 feed", [(f"v1-{i}", f"Zzvone Akira ransomware wave {i} hits CVE-2024-3400", None) for i in range(5)]
            + [("v1-red", "Zzvone secret red item", {"tlp": "red"})])
    r = client.get("/api/v1/items?q=Zzvone&limit=2").json()
    assert len(r["data"]) == 2 and r["next_cursor"]
    titles = [d["title"] for d in r["data"]]
    r2 = client.get(f"/api/v1/items?q=Zzvone&limit=10&cursor={r['next_cursor']}").json()
    assert not set(titles) & {d["title"] for d in r2["data"]}
    every = r["data"] + r2["data"]
    assert len(every) == 5 and not any("red" in d["title"] for d in every)  # TLP:RED never leaves
    one = client.get(f"/api/v1/items/{every[0]['id']}").json()
    assert one["tlp"] == "CLEAR" and "content" in one and one["entities"]
    with session_scope() as db:
        red_id = db.execute(select(Item.id).where(Item.title == "Zzvone secret red item")).scalar()
    assert client.get(f"/api/v1/items/{red_id}").status_code == 404
    assert client.get("/api/v1/items?since=yesterday").status_code == 400
    assert client.get("/api/v1/items?since=2000-01-01T00:00:00Z&q=Zzvone").json()["data"]
    assert client.get("/api/v1/entities?type=bogus").status_code == 400
    mal = client.get("/api/v1/entities?type=malware&q=akira").json()["data"]
    assert mal and mal[0]["type"] == "malware"
    detail = client.get(f"/api/v1/entities/{mal[0]['id']}").json()
    assert detail["recent_items"] and "providers" not in detail  # provider details are off by default
    assert client.get("/api/v1/trending?type=cve").status_code == 200
    docs = client.get("/api/v1/docs").text
    assert "/api/v1/feeds/iocs.{fmt}" in docs and "Bearer" in docs
    assert "/api/v1/items" in client.get("/api/v1/openapi.json").json()["paths"]


def test_ioc_feeds_formats_and_filters(client):
    with session_scope() as db:
        src = _source(db, "Feed test source")
        ids = ingest(db, src, [RawItem(external_id="feed-1", published_at=utcnow(),
                                       title="Zzfeed stealer C2 at hxxp://bad-feed-one[.]top/gate and good-feed-two[.]top")])
        db.flush()
        for e in (link.entity for link in db.get(Item, ids[0]).entity_links):
            if e.type == "domain":
                e.enriched_at = utcnow()
                e.verdict = "malicious" if "bad-feed-one" in e.value else "clean"
                if e.verdict == "malicious":
                    db.add(Enrichment(entity_id=e.id, provider="virustotal", verdict="malicious"))
                    db.add(Enrichment(entity_id=e.id, provider="urlhaus", verdict="malicious"))
    txt = client.get("/api/v1/feeds/iocs.txt?type=domain&since_days=0").text.splitlines()
    assert "bad-feed-one.top" in txt and "good-feed-two.top" not in txt
    rows = client.get("/api/v1/feeds/iocs.json?type=domain&verdict=malicious,clean&since_days=0").json()
    by = {r["value"]: r for r in rows["data"]}
    assert by["bad-feed-one.top"]["confidence"] == 85 and by["good-feed-two.top"]["confidence"] == 0
    assert rows["count"] == len(rows["data"])
    hi = client.get("/api/v1/feeds/iocs.json?type=domain&verdict=malicious,clean&since_days=0&min_confidence=50").json()
    assert {r["value"] for r in hi["data"]} >= {"bad-feed-one.top"} and "good-feed-two.top" not in {r["value"] for r in hi["data"]}
    csv_text = client.get("/api/v1/feeds/iocs.csv?since_days=0").text
    assert csv_text.startswith("type,value,verdict,confidence") and "bad-feed-one.top" in csv_text
    assert client.get("/api/v1/feeds/iocs.xml").status_code == 404
    assert client.get("/api/v1/feeds/iocs.txt?verdict=evil").status_code == 400
    assert client.get("/api/v1/iocs?type=domain&verdict=malicious").json()["data"]


# --------------------------------------------------------------------------- webhooks
def test_webhook_url_guard():
    assert webhooks.check_url("https://127.0.0.1/x", allow_private=False)
    assert webhooks.check_url("https://10.1.2.3/x", allow_private=False)
    assert webhooks.check_url("http://169.254.169.254/latest/meta-data", allow_private=False)
    assert webhooks.check_url("ftp://93.184.216.34/x", allow_private=False)
    assert webhooks.check_url("https://user:pw@93.184.216.34/x", allow_private=False)
    assert webhooks.check_url("https://93.184.216.34/hook", allow_private=False) is None
    assert webhooks.check_url("https://127.0.0.1/x", allow_private=True) is None


def test_webhook_events_signature_and_retries(client, setting):
    setting("webhook_min_severity", 1)
    received = []

    def ok(req: httpx.Request) -> httpx.Response:
        received.append(req)
        return httpx.Response(204)

    with session_scope() as db:
        hook = Webhook(name="t-generic", url="https://93.184.216.34/hook", kind="generic",
                       events=["item.high_severity", "job.failed"], salt=webhooks.new_salt())
        slack = Webhook(name="t-slack", url="https://93.184.216.34/slack", kind="slack", events=["job.failed"],
                        salt=webhooks.new_salt())
        db.add_all([hook, slack])
        db.flush()
        hid, sid = hook.id, slack.id
    _ingest("Webhook feed", [("wh-1", "Zzhook LockBit ransomware zero-day exploited in the wild", None)])
    from app import jobs

    with session_scope() as db:
        ids = [i for (i,) in db.execute(select(Item.id).where(Item.title.like("Zzhook%")))]
        assert webhooks.on_new_items(db, ids) == 1
        from app import notify

        notify.notify(db, "error", "Source failing: Zz", "boom")  # job.failed for both hooks
    with session_scope() as db:
        pend = db.execute(select(WebhookDelivery).where(WebhookDelivery.webhook_id.in_([hid, sid]))).scalars().all()
        assert sorted(d.event for d in pend) == ["item.high_severity", "job.failed", "job.failed"]
        msg = webhooks.deliver_pending(db, http=httpx.Client(transport=httpx.MockTransport(ok)))
    assert msg == "3/3 delivered"
    generic = [r for r in received if r.url.path == "/hook"]
    r0 = generic[0]
    with session_scope() as db:
        secret = webhooks.secret_for(db.get(Webhook, hid))
    expect = "sha256=" + hmac.new(secret.encode(), r0.headers["x-jatmp-timestamp"].encode() + b"." + r0.content,
                                  hashlib.sha256).hexdigest()
    assert r0.headers["x-jatmp-signature"] == expect and json.loads(r0.content)["event"] in EVENT_NAMES
    slack_body = json.loads(next(r for r in received if r.url.path == "/slack").content)
    assert set(slack_body) == {"text"} and "Source failing" in slack_body["text"]

    # failures back off and eventually give up
    with session_scope() as db:
        d = WebhookDelivery(webhook_id=hid, event="job.failed", payload={"event": "job.failed", "data": {}})
        db.add(d)
        db.flush()
        boom = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500, text="nope")))
        webhooks.attempt(db, d, boom)
        assert d.status == "pending" and d.attempts == 1 and d.next_attempt_at > utcnow()
        for _ in range(4):
            webhooks.attempt(db, d, boom)
        assert d.status == "failed" and "HTTP 500" in d.error
    assert jobs.run_webhooks()  # the scheduled job runs without error


EVENT_NAMES = set(webhooks.EVENTS)


def test_webhook_settings_ui(client, setting):
    tok = _csrf(client, "/settings?tab=webhooks")
    r = client.post("/settings/webhooks", data={"csrf_token": tok, "name": "local", "url": "https://127.0.0.1/x",
                                                "kind": "generic", "events": ["job.failed"]})
    assert r.status_code == 400 and "private" in r.text
    setting("webhooks_allow_private", True)
    r = client.post("/settings/webhooks", data={"csrf_token": tok, "name": "local", "url": "https://127.0.0.1/x",
                                                "kind": "generic", "events": ["job.failed"]})
    assert r.status_code == 200 and "Signing secret" in r.text
    with session_scope() as db:
        hook = db.execute(select(Webhook).where(Webhook.name == "local")).scalar_one()
        assert hook.salt and webhooks.secret_for(hook) not in json.dumps({"u": hook.url, "s": hook.salt})
        hid = hook.id
    r = client.post(f"/settings/webhooks/{hid}", data={"csrf_token": tok, "action": "test"}, follow_redirects=False)
    # nothing listens on 127.0.0.1:443 here, so the test delivery fails and says so
    assert r.status_code == 303 and "Test%20failed" in r.headers["location"]
    page = client.get("/settings?tab=webhooks").text
    assert "local" in page and "failed" in page
    client.post(f"/settings/webhooks/{hid}", data={"csrf_token": tok, "action": "delete"})
    with session_scope() as db:
        assert db.get(Webhook, hid) is None


# --------------------------------------------------------------------------- dark web tier 1
class _FakeRL:
    pro = True

    def groups(self):
        return ["akira", "lockbit5"]

    def group_info(self, group):
        return {"description": "Akira is a ransomware group.", "firstseen": "2023-03-01",
                "vulnerabilities": [{"CVE": "CVE-2023-20269"}], "tools": [{"tools": ["AnyDesk"]}]} if group else None

    def group_victims(self, group):
        from app.intel.darkweb import normalise_victim

        return [normalise_victim(v) for v in [
            {"post_title": "PT Contoh", "group_name": "akira", "country": "ID", "activity": "Manufacturing",
             "discovered": "2026-11-10 10:00:00"},
            {"victim": "Acme", "group": "akira", "country": "US", "discovered": "2026-11-12 08:00:00"}]]


def test_ransomware_deep_dive_and_victim_normalisation(client, monkeypatch):
    from app.intel import darkweb

    v = darkweb.normalise_victim({"post_title": "X", "group_name": "y", "country": "id", "published": "2026-01-02"})
    assert v["victim"] == "X" and v["group"] == "y" and v["country"] == "ID" and v["attackdate"] == "2026-01-02"
    with session_scope() as db:
        ent = db.execute(select(Entity).where(Entity.type == "malware", Entity.value == "akira")).scalar_one_or_none()
        if ent is None:
            _ingest("Akira feed", [("ak-1", "Akira ransomware attack", None)])
            ent = db.execute(select(Entity).where(Entity.type == "malware", Entity.value == "akira")).scalar_one()
        res = darkweb.ransomware_deep_dive(ent, _FakeRL())
        assert res.data["group"] == "akira" and res.data["victims_total"] == 2
        assert res.data["countries"][0][0] in ("ID", "US") and res.data["recent"][0]["victim"] == "Acme"
        assert res.data["cves"] == ["CVE-2023-20269"] and res.data["tools"] == ["AnyDesk"]
        eid = ent.id
    real = darkweb.ransomware_deep_dive
    monkeypatch.setattr(darkweb, "ransomware_deep_dive", lambda ent, rl=None: real(ent, _FakeRL()))
    tok = _csrf(client)
    r = client.post(f"/api/entities/{eid}/deepdive", headers={"X-CSRF-Token": tok})
    assert r.status_code == 200 and "2 leak-site victim" in r.json()["message"]
    with session_scope() as db:
        assert db.execute(select(Enrichment).where(Enrichment.entity_id == eid, Enrichment.provider == "ransomware.live")).scalar()
        cve = db.execute(select(Entity).where(Entity.value == "CVE-2023-20269")).scalar_one()
        assert db.execute(select(EntityLink).where(EntityLink.src_id == eid, EntityLink.dst_id == cve.id)).scalar()
    page = client.get(f"/entities/{eid}").text
    assert "Leak sites" in page and "PT Contoh" in page


def test_infostealer_exposure_and_free_api_rate_guard(installed, monkeypatch):
    from app.intel import darkweb

    class FakeHR:
        def overview(self, domains):
            return [{"domain": "contoh.go.id", "compromised_employees": 4, "compromised_users": 120,
                     "sensitive_applications": ["vpn"]}]

    res = darkweb.infostealer_exposure("www.contoh.go.id", FakeHR())
    assert "4 employee(s) and 120 user(s)" in res.summary and res.verdict == "unknown"
    assert "password" not in json.dumps(res.data).lower()

    monkeypatch.setattr(darkweb, "_client", lambda *a, **k: httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[]))))
    darkweb._free_calls.clear()
    rl = darkweb.RansomwareLive()
    assert not rl.pro
    rl.recent_victims()
    with pytest.raises(RuntimeError, match="one request per minute"):
        rl.recent_victims()  # fails fast instead of sleeping inside a web request


# --------------------------------------------------------------------------- MISP
MISP_EVENT = {
    "id": "42", "uuid": "5f0c-uuid", "info": "Zzmisp Qakbot campaign", "timestamp": "1763100000",
    "threat_level_id": "1", "Orgc": {"name": "CERT-X"},
    "Tag": [{"name": "tlp:amber"}, {"name": "banking"}],
    "Galaxy": [{"type": "mitre-intrusion-set", "GalaxyCluster": [{"value": "APT28"}]},
               {"type": "malpedia", "GalaxyCluster": [{"value": "Qakbot"}]}],
    "Attribute": [{"type": "ip-dst|port", "value": "45.9.20.1|443"}, {"type": "domain", "value": "Qak-c2.Example"},
                  {"type": "filename|sha256", "value": "x.exe|" + "d" * 64}, {"type": "comment", "value": "hi"}],
    "Object": [{"Attribute": [{"type": "url", "value": "http://qak.example/a"}]}],
}


def test_misp_event_mapping():
    from app.intel.misp import event_to_raw

    raw = event_to_raw(MISP_EVENT, "https://misp.example")
    assert raw.external_id == "5f0c-uuid" and raw.url == "https://misp.example/events/view/42"
    assert raw.raw["tlp"] == "AMBER" and "APT28" in raw.content and "Qakbot" in raw.tags
    assert {(i.type, i.value) for i in raw.indicators} == {
        ("ip", "45.9.20.1"), ("domain", "qak-c2.example"), ("sha256", "d" * 64), ("url", "http://qak.example/a")}


class _FakeMISP:
    url = "https://misp.example"

    def __init__(self):
        self.events = []

    def add_event(self, event):
        self.events.append(event)
        return {"id": str(100 + len(self.events)), "uuid": f"u{len(self.events)}"}

    def event_url(self, i):
        return f"{self.url}/events/view/{i}"


def test_misp_push_rules(client, setting):
    from app.intel.misp import PushRefused, push_entity, push_item

    fake = _FakeMISP()
    ids = _ingest("MISP push feed", [("mp-1", "Zzpush Qakbot loader drops hxxp://qak-push[.]top/x", None),
                                     ("mp-2", "Zzpush red", {"tlp": "red"})])
    pulled = _ingest("MISP pulled", [("mp-3", "Zzpush from misp", None)], kind="misp")
    with session_scope() as db:
        item = db.get(Item, ids[0])
        res = push_item(db, item, fake)
        assert res["created"] and res["url"].endswith("/events/view/101")
        ev = fake.events[0]
        assert {"name": "tlp:clear"} in ev["Tag"] and any(t["name"].startswith("jatmp:malware=") for t in ev["Tag"])
        assert any(a["type"] == "url" and a["value"].startswith("http://qak-push.top") for a in ev["Attribute"])
        assert item.raw["misp_pushed"]["id"] == "101"
        assert push_item(db, item, fake)["created"] is False and len(fake.events) == 1  # no duplicates
        with pytest.raises(PushRefused, match="sharing rules"):
            push_item(db, db.get(Item, ids[1]), fake)
        with pytest.raises(PushRefused, match="came from MISP"):
            push_item(db, db.get(Item, pulled[0]), fake)
        fam = db.execute(select(Entity).where(Entity.type == "malware", Entity.value == "qakbot")).scalar_one()
        out = push_entity(db, fam, fake)
        assert out["created"] and fam.meta["misp_pushed"]["indicators"] >= 1
    tok = _csrf(client)
    r = client.post(f"/api/misp/push/item/{ids[0]}", headers={"X-CSRF-Token": tok})
    assert r.status_code == 400 and "not set" in r.json()["detail"]  # MISP not configured in tests


def test_settings_tabs_render(client):
    for tab in ("sharing", "webhooks", "misp", "intel", "sources"):
        r = client.get(f"/settings?tab={tab}")
        assert r.status_code == 200, tab
    assert "api_max_tlp" in client.get("/settings?tab=sharing").text
    assert "misp_url" in client.get("/settings?tab=misp").text
    assert 'name="redistribute"' in client.get("/settings?tab=sources").text
    with session_scope() as db:
        assert db.execute(select(User)).first()
        assert not db.execute(select(Notification).where(Notification.title == "never")).first()
