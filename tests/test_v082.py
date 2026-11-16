"""0.8.2: dashboard rework: radar with CVEs and actors, globe, actor and CVE breakdowns, trend type switch,
CVSS / EPSS explanations, scrolling geography lists."""
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import knowledge
from app.db import session_scope
from app.models import Entity, Source, utcnow
from app.processing import trends
from app.processing.pipeline import RawItem, ingest


@pytest.fixture()
def v082_items(installed):
    now = utcnow() - timedelta(hours=2)
    with session_scope() as db:
        src = db.execute(select(Source).where(Source.name == "Zz082 News")).scalar_one_or_none()
        if not src:
            src = Source(name="Zz082 News", kind="rss", category="news", config={"url": "https://zz082.example/feed"})
            db.add(src)
            db.flush()
        ingest(db, src, [
            RawItem("z82-1", "Zz082 APT28 exploits CVE-2026-50001 against ministries in Germany",
                    content="Fancy Bear used the flaw. Lumma Stealer was also seen.", published_at=now),
            RawItem("z82-2", "Zz082 Scattered Spider and FIN7 hit retailers in France",
                    content="CVE-2026-50002 was used for access.", published_at=now),
        ])
        for cve, meta in (("cve-2026-50001", {"kev": {"product": "X"}}),
                          ("cve-2026-50002", {"epss": {"score": 0.02}, "cvss": {"score": 9.8}})):
            e = db.execute(select(Entity).where(Entity.type == "cve", Entity.value.in_((cve, cve.upper())))
                           ).scalar_one_or_none()
            if e is not None:
                e.meta = meta
        db.commit()
    return True


def test_actor_category():
    assert knowledge.actor_category("APT28") == "nation-state"
    assert knowledge.actor_category("Scattered Spider") == "extortion"
    assert knowledge.actor_category("FIN7") == "cybercrime"
    assert knowledge.actor_category("Hellcat") == "ransomware"
    assert knowledge.actor_category("Some New Group") == "unclassified"
    # every listed actor is in the knowledge base and has a known category
    assert set(knowledge.ACTOR_KIND) <= set(knowledge.ACTORS)
    assert set(knowledge.ACTOR_KIND.values()) <= set(knowledge.ACTOR_CATEGORIES)


def test_cve_risk_buckets():
    assert trends.cve_risk({"kev": {"x": 1}, "epss": {"score": 0.9}}) == "kev"
    assert trends.cve_risk({"epss": {"score": 0.15}, "cvss": {"score": 9.9}}) == "epss"
    assert trends.cve_risk({"epss": {"score": 0.01}, "cvss": {"score": 9.1}}) == "critical"
    assert trends.cve_risk({"cvss": {"score": 7.0}}) == "high"
    assert trends.cve_risk({"cvss": {"score": 5.0}}) == "lower"
    assert trends.cve_risk({"epss": {"score": 0.01}}) == "unscored"
    assert trends.cve_risk({}) == "pending" and trends.cve_risk(None) == "pending"


def test_breakdowns_and_overview(client, v082_items):
    with session_scope() as db:
        cve = {r["category"]: r["count"] for r in trends.cve_breakdown(db, 30)}
        actor = {r["category"]: r["count"] for r in trends.actor_breakdown(db, 30)}
        ov = trends.overview(db, 7)
        series = trends.kpi_series(db, 14)
        top = trends.trending(db, "actor", limit=50)
    assert cve.get("kev", 0) >= 1 and cve.get("critical", 0) >= 1
    assert actor.get("nation-state", 0) >= 1 and actor.get("extortion", 0) >= 1 and actor.get("cybercrime", 0) >= 1
    assert ov["actors"] >= 3 and "new_actors" in ov
    assert len(series["actors"]) == 14 and sum(series["actors"]) >= 3
    assert {t["name"]: t["category"] for t in top}.get("APT28") == "nation-state"
    # through the API, with the type switch
    assert any(r["category"] == "kev" for r in client.get("/api/stats/categories?type=cve&days=30").json())
    assert any(r["category"] == "nation-state" for r in client.get("/api/stats/categories?type=actor&days=30").json())
    assert all("category" in r for r in client.get("/api/stats/categories?days=30").json())
    for t in ("malware", "cve", "actor", "bogus"):
        d = client.get(f"/api/stats/trending_timeline?type={t}&limit=5&days=30").json()
        assert {"labels", "series"} <= set(d) and len(d["labels"]) == 30


def test_dashboard_layout(client, v082_items):
    page = client.get("/?region=intl").text
    for marker in ('data-globe="world"', 'id="v-dash-top"', 'data-radar-type="cve"', 'data-radar-type="actor"',
                   'data-kpi="actors"', 'id="trend-type"', 'id="c-cve-risk"', 'id="c-actor-cat"', 'data-tip="epss"',
                   "/static/js/globe.js"):
        assert marker in page, marker
    assert "Most-mentioned families" not in page and 'id="c-top"' not in page
    # the AI digest card only appears when an LLM is configured (none in the test install)
    assert "AI digest</h2>" not in page
    # tiles come before the volume chart, the trending tables before the over-time chart
    assert page.index('data-kpi="items"') < page.index('id="c-timeline"') < page.index("Trending CVEs") < page.index('id="c-trend"')
    assert page.index('id="c-cat"') < page.index("Notable recent items") < page.index('id="c-src"') < page.index('id="c-ioc"')


def test_globe_top_is_limited_to_ten():
    from app.web import templates

    rows = [{"code": c, "count": 20 - i, "related": []} for i, c in
            enumerate(["US", "ID", "DE", "FR", "GB", "JP", "CN", "RU", "IN", "BR", "AU", "CA"])]
    top = templates.env.globals["globe_top"](rows, False)
    assert len(top) == 10 and top[0] == {"code": "US", "shape": "US", "name": "United States", "count": 20, "related": []}
    prov = templates.env.globals["globe_top"]([{"code": "ID-KU", "count": 3}], True)
    assert prov[0]["shape"] == "ID-KI"


def test_cve_list_explains_cvss_and_epss(client, v082_items):
    page = client.get("/cves?days=30").text
    assert 'data-tip="cvss"' in page and 'data-tip="epss"' in page


def test_geo_lists_scroll(client):
    page = client.get("/geo?days=0").text
    assert page.count('class="list-fill"') == 2 and 'geo-grid even' in page
