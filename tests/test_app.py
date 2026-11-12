"""End-to-end tests through the ASGI app (single-user install from conftest)."""
import re
from datetime import datetime, timedelta

from sqlalchemy import select

from app.db import session_scope
from app.models import Entity, Item, Source
from app.processing.pipeline import RawItem, ingest


def _csrf(client, path="/"):
    html = client.get(path).text
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def _ingest_sample():
    with session_scope() as db:
        src = db.execute(select(Source).where(Source.kind == "rss")).scalars().first()
        raws = [
            RawItem(external_id="e1", title="New Lumma Stealer campaign abuses hxxps://c2[.]evil-domain[.]top",
                    url="javascript:alert(1)", content="<p>Hash 5d41402abc4b2a76b9719d911017c592 seen, CVE-2024-3400 exploited</p>",
                    published_at=datetime(2026, 11, 10, 12, 0)),
            RawItem(external_id="e1", title="duplicate inside the same batch"),
            RawItem(external_id="e2", title="Future dated", url="https://example.com/x",
                    published_at=datetime.utcnow() + timedelta(days=3)),
        ]
        new = ingest(db, src, raws)
        db.commit()
        return src.id, new


def test_pages_render_and_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "script-src 'self' 'nonce-" in csp
    assert "frame-ancestors 'none'" in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    assert f'nonce="{nonce}"' in r.text  # inline scripts carry the request nonce
    assert "cdnjs.cloudflare.com" not in r.text  # Chart.js is vendored
    for path in ("/feed", "/malware", "/actors", "/cves", "/iocs", "/watchlist", "/insights", "/settings", "/profile"):
        assert client.get(path).status_code == 200, path
    assert client.get("/healthz").json()["ok"] is True
    assert client.get("/static/js/vendor/chart.umd.min.js").status_code == 200


def test_ingest_dedupes_sanitises_and_extracts(client):
    src_id, new = _ingest_sample()
    assert len(new) == 2  # duplicate external_id skipped
    with session_scope() as db:
        item = db.get(Item, new[0])
        assert item.url == ""  # javascript: dropped
        assert "Hash 5d41402abc4b2a76b9719d911017c592" in item.content  # HTML stripped
        types = {link.entity.type: link.entity.value for link in item.entity_links}
        assert types.get("malware") == "lumma stealer"
        assert types.get("cve") == "CVE-2024-3400"
        assert types.get("md5") == "5d41402abc4b2a76b9719d911017c592"
        assert "evil-domain.top" in types.get("domain", "")
        fut = db.get(Item, new[1])
        assert fut.published_at <= datetime.utcnow()
        # second ingest of the same batch creates nothing
        assert ingest(db, db.get(Source, src_id), [RawItem(external_id="e1", title="x")]) == []
    page = client.get(f"/items/{new[0]}")
    assert page.status_code == 200
    assert "javascript:" not in page.text
    assert client.get("/feed?entity=1&days=0&page=-3&min_sev=999").status_code == 200


def test_csrf_and_roles_on_api(client):
    assert client.post("/api/sources/run_all").status_code == 403  # no token
    tok = _csrf(client)
    r = client.post("/api/sources/run_all", headers={"X-CSRF-Token": tok})
    assert r.status_code == 200 and r.json()["ok"]
    with session_scope() as db:
        ent = db.execute(select(Entity).where(Entity.type == "malware")).scalars().first()
    r = client.post(f"/api/watch/{ent.id}", headers={"X-CSRF-Token": tok})
    assert r.json()["watching"] is True
    assert client.get(f"/entities/{ent.id}").status_code == 200
    assert client.post(f"/api/watch/{ent.id}", headers={"X-CSRF-Token": tok}).json()["watching"] is False
    assert client.get("/api/stats/overview?days=-99999").status_code == 200  # clamped, no 500
    assert client.get("/api/stats/trending?limit=0").status_code == 200
    assert client.post("/api/items/999999/summarize", headers={"X-CSRF-Token": tok}).status_code == 404


def test_settings_secret_handling(client):
    tok = _csrf(client, "/settings?tab=intel")
    r = client.post("/settings/values", data={"csrf_token": tok, "group": "intel", "virustotal_api_key": "vt-secret-123"},
                    follow_redirects=False)
    assert r.status_code == 303
    page = client.get("/settings?tab=intel").text
    assert "vt-secret-123" not in page  # never echoed back
    assert "configured" in page
    # blank keeps, checkbox clears
    client.post("/settings/values", data={"csrf_token": tok, "group": "intel", "virustotal_api_key": ""})
    from app import settings
    assert settings.get("virustotal_api_key") == "vt-secret-123"
    client.post("/settings/values", data={"csrf_token": tok, "group": "intel", "virustotal_api_key": "",
                                          "virustotal_api_key__clear": "on"})
    assert settings.get("virustotal_api_key") == ""
    # source URLs must be http(s)
    r = client.post("/settings/sources", data={"csrf_token": tok, "kind": "rss", "name": "bad", "cfg_url": "file:///etc/passwd"})
    assert r.status_code == 400


def test_multi_user_login_flow(client, multi_user_mode):
    r = client.get("/feed", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login?next=")
    assert client.get("/api/stats/overview").status_code == 401
    tok = _csrf(client, "/login")
    bad = client.post("/login", data={"csrf_token": tok, "username": "admin", "password": "nope", "next": "//evil"})
    assert bad.status_code == 401
    ok = client.post("/login", data={"csrf_token": tok, "username": "admin", "password": multi_user_mode["password"],
                                     "next": "//evil.example"}, follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/"  # open redirect blocked
    assert client.get("/admin").status_code == 200
    tok = _csrf(client, "/admin")
    r = client.post("/admin/users", data={"csrf_token": tok, "username": "viewer1", "password": "ViewerPass9", "role": "viewer"},
                    follow_redirects=False)
    assert r.status_code == 303 and "msg=User+created" in r.headers["location"]
    client.post("/logout", data={"csrf_token": tok})
    # viewer cannot trigger collectors
    tok = _csrf(client, "/login")
    client.post("/login", data={"csrf_token": tok, "username": "viewer1", "password": "ViewerPass9"})
    tok = _csrf(client)
    assert client.post("/api/sources/run_all", headers={"X-CSRF-Token": tok}).status_code == 403
    assert client.get("/settings").status_code == 403
    client.post("/logout", data={"csrf_token": tok})
