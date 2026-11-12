"""Severity scoring, extraction precision, enrichment consensus, feed sorting, AI settings, reports."""
import re
from datetime import datetime, timedelta

from sqlalchemy import select

from app import settings
from app.db import session_scope
from app.intel import LookupResult
from app.llm import presets
from app.models import Entity, Item, Source
from app.processing.extractor import extract_all, extract_candidate_families, extract_iocs, refang
from app.processing.pipeline import RawItem, ingest
from app.processing.severity import score_item


def _csrf(client, path="/"):
    html = client.get(path).text
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


# --------------------------------------------------------------------------- severity
def test_severity_ranks_campaign_above_patch_note_and_noise():
    campaign, _ = score_item("Hackers Deploy Malware in Fresh ScreenConnect Campaign",
                              "The attackers exploited a vulnerability to bypass ScreenConnect authentication.", [], "article")
    patch, r2 = score_item("Google Chrome Fixes 83 Security Flaws, Including 5 Critical Ones that Could Enable RCE Attacks",
                           "Google released a Chrome security update that addresses 83 vulnerabilities.", [], "article")
    noise, _ = score_item("Microsoft confirms Windows security updates installation issues",
                          "The November security updates are failing to install on Windows 11.", [], "article")
    zero, r4 = score_item("Zero-day in Ivanti EPMM actively exploited, CISA adds CVE-2026-1 to KEV",
                          "Attackers exploited the flaw in the wild to deploy a backdoor.", [], "article")
    assert zero > campaign > patch > noise == 0
    assert any(r.label == "patch / advisory only" and r.points < 0 for r in r2)
    assert any(r.label == "zero-day" for r in r4)
    # an exploited bug being patched is still urgent: the patch dampener is cancelled
    exploited_patch, r5 = score_item("Vendor patches zero-day exploited in the wild", "fixes", [], "article")
    assert not any(r.label == "patch / advisory only" for r in r5) and exploited_patch >= 30


def test_severity_dampens_roundups_and_caps_victim_posts():
    roundup, _ = score_item("Week in review: top 10 security stories", "ransomware zero-day critical exploited", [], "article")
    plain, _ = score_item("Ransomware gang exploits zero-day", "ransomware zero-day critical exploited", [], "article")
    assert roundup < plain
    ents = extract_all("incransom ransomware group has added Example Corp to its victims.")
    post, _ = score_item("According to Ransomware.live, incransom ransomware group has added Example Corp to its victims.",
                               "", ents, "post")
    assert post <= 35
    assert 0 <= score_item("", "", [], "article")[0] <= 100


def test_severity_entity_signals_and_title_bonus():
    ents = extract_all("Lumma Stealer sample 5d41402abc4b2a76b9719d911017c592 hxxp://c2[.]evil[.]top CVE-2024-1234 T1059")
    _, reasons = score_item("Lumma Stealer campaign", "", ents, "article")
    labels = {r.label for r in reasons}
    assert "known malware family" in labels and "1 CVE(s)" in labels and "ATT&CK techniques" in labels
    assert any(label.endswith("indicator(s)") for label in labels)
    in_title, _ = score_item("Ransomware hits hospital", "details", [], "article")
    in_body, _ = score_item("Incident at hospital", "ransomware details", [], "article")
    assert in_title > in_body


# --------------------------------------------------------------------------- extraction
def test_refang_more_variants_and_url_hash_filtering():
    assert refang("hxxps[:]//evil[.]com/a") == "https://evil.com/a"
    assert refang("evil\\.com and bad[://]x[.]net") == "evil.com and bad://x.net"
    text = ("see https://github.com/x/y/commit/5d41402abc4b2a76b9719d911017c592aabbccdd and the real md5 "
            "5d41402abc4b2a76b9719d911017c592 and Chrome 131.0.6778.85 fixed, c2 at 45.33.32.156, version 1.2.3.4, build 10.20.30.40")
    found = {(e.type, e.value) for e in extract_iocs(text, strict=False)}
    assert ("md5", "5d41402abc4b2a76b9719d911017c592") in found
    assert not any(t == "sha1" for t, _ in found)  # commit SHA inside a URL is not a sample hash
    assert ("ip", "45.33.32.156") in found
    assert ("ip", "1.2.3.4") not in found and ("ip", "10.20.30.40") not in found
    # vendor / media domains are never indicators even in non-strict (intel) mode
    found = {e.value for e in extract_iocs("report at https://unit42.paloaltonetworks.com/x and hxxps://evil-c2[.]top/p", strict=False)}
    assert not any("paloaltonetworks" in v for v in found) and "evil-c2.top" in found


def test_legit_tools_are_not_new_families():
    ents = extract_candidate_families("The ConnectWise RAT and AnyDesk remote tool were abused; the Remus malware was dropped.", set())
    names = {e.display for e in ents}
    assert "ConnectWise" not in names and "AnyDesk" not in names
    assert "Remus" in names


# --------------------------------------------------------------------------- enrichment
def test_consensus_and_failure_handling(installed):
    from app.processing import enrichment

    class Prov:
        name = "fake"
        supports = {"md5"}

        def __init__(self, res=None, exc=None):
            self.res, self.exc = res, exc

        def lookup(self, etype, value):
            if self.exc:
                raise self.exc
            return self.res

    with session_scope() as db:
        src = db.execute(select(Source).where(Source.kind == "rss")).scalars().first()
        ingest(db, src, [RawItem(external_id="enr1", title="Sample seen", content="hash 6d41402abc4b2a76b9719d911017c599",
                                 published_at=datetime(2026, 11, 11))])
        db.commit()
        ent = db.execute(select(Entity).where(Entity.value == "6d41402abc4b2a76b9719d911017c599")).scalar_one()
        item = db.execute(select(Item).where(Item.external_id == "enr1")).scalar_one()
        before = item.severity
        # every provider errors -> verdict stays "" so the re-check pass retries soon
        enrichment.enrich_entity(db, ent, [Prov(exc=RuntimeError("quota"))])
        assert ent.verdict == "" and ent.enriched_at is not None
        # lone OTX pulse mention is only suspicious; VT malicious wins; items get a severity bump
        otx = LookupResult("otx", "malicious", 30, "3 pulses", data={"pulse_count": 3})
        enrichment.enrich_entity(db, ent, [Prov(res=otx)])
        assert ent.verdict == "suspicious"
        vt = LookupResult("virustotal", "malicious", 90, "40/70 engines", malware=["Trojan.Lumma/LummaC2"])
        enrichment.enrich_entity(db, ent, [Prov(res=vt)])
        assert ent.verdict == "malicious"
        db.flush()
        db.refresh(item)
        assert item.severity == min(100, before + enrichment.VERDICT_BONUS["malicious"])
        assert any(d["label"].startswith("indicator confirmed malicious") for d in item.severity_detail)
        fam = db.execute(select(Entity).where(Entity.type == "malware", Entity.value == "lumma stealer")).scalar_one_or_none()
        assert fam is not None
    assert enrichment.resolve_family("trojan.play/generic") is None  # ambiguous token alone is not an attribution
    assert enrichment.resolve_family("Play") is not None  # but the exact label is


# --------------------------------------------------------------------------- feed & item page
def test_feed_sorting_and_item_breakdown(client):
    with session_scope() as db:
        src = db.execute(select(Source).where(Source.kind == "rss")).scalars().first()
        new = ingest(db, src, [
            RawItem(external_id="f1", title="Zero-day actively exploited in the wild", content="critical rce",
                    published_at=datetime.utcnow() - timedelta(hours=1)),
            RawItem(external_id="f2", title="Annual survey results", content="nothing", published_at=datetime.utcnow()),
        ])
        db.commit()
    for sort, direction in (("severity", "desc"), ("title", "asc"), ("source", "asc"), ("time", "desc"), ("bogus", "x")):
        r = client.get(f"/feed?sort={sort}&dir={direction}&days=0")
        assert r.status_code == 200
    html = client.get("/feed?sort=severity&dir=desc&days=0").text
    assert html.index("Zero-day actively exploited") < html.index("Annual survey results")
    assert 'aria-sort="descending"' in html
    assert 'class="seg"' not in html  # the separate sort buttons are gone, headers sort now
    page = client.get(f"/items/{new[0]}").text
    assert "Severity" in page and "zero-day" in page and "Correlated items" in page
    dash = client.get("/").text
    assert "days · <a" not in dash and "newly seen · <a" not in dash  # duplicate tile text links removed, icons stay
    assert 'class="icon" href="/feed?days=7"' in dash


# --------------------------------------------------------------------------- AI settings
def test_ai_settings_mode_vendor_mapping(client):
    assert presets.resolve("local", "ollama") == {"llm_provider": "ollama", "llm_base_url": "http://localhost:11434", "llm_model": "llama3.1"}
    assert presets.resolve("cloud", "anthropic")["llm_provider"] == "anthropic"
    assert presets.resolve("cloud", "nope") == {"llm_provider": "none"}
    assert presets.infer("openai_compatible", "https://openrouter.ai/api/v1") == ("cloud", "openrouter")
    assert presets.infer("openai_compatible", "http://localhost:1234/v1") == ("local", "lmstudio")
    tok = _csrf(client, "/settings?tab=llm")
    page = client.get("/settings?tab=llm").text
    assert "Where should the AI run?" in page and "Load models" in page
    r = client.post("/settings/values", data={"csrf_token": tok, "group": "llm", "llm_mode": "cloud", "vendor_cloud": "groq",
                                              "llm_model": "", "llm_base_url": "", "llm_api_key": "gsk-test",
                                              "llm_language": "English"}, follow_redirects=False)
    assert r.status_code == 303
    assert settings.get("llm_provider") == "openai_compatible"
    assert settings.get("llm_base_url") == "https://api.groq.com/openai/v1"
    assert settings.get("llm_model") == "llama-3.3-70b-versatile"
    assert settings.get("llm_mode") == "cloud" and settings.get("llm_vendor") == "groq"
    assert "gsk-test" not in client.get("/settings?tab=llm").text
    # switching off keeps the key but disables the provider
    client.post("/settings/values", data={"csrf_token": tok, "group": "llm", "llm_mode": "none", "llm_language": "English"})
    assert settings.get("llm_provider") == "none" and settings.get("llm_api_key") == "gsk-test"
    # model listing validates input and reports unreachable servers as 400, not 500
    r = client.post("/api/llm/models", json={"mode": "local", "vendor": "ollama", "base_url": "http://127.0.0.1:9"},
                    headers={"X-CSRF-Token": tok})
    assert r.status_code == 400 and "reach" in r.json()["detail"]
    assert client.post("/api/llm/models", json={"mode": "x"}, headers={"X-CSRF-Token": tok}).status_code == 400


# --------------------------------------------------------------------------- reports
def test_report_builder_formats(client):
    assert client.get("/reports").status_code == 200
    tok = _csrf(client, "/reports")
    base = {"csrf_token": tok, "preset": "30", "sections": ["overview", "malware", "iocs", "items", "cves", "actors", "new", "digest"],
            "min_sev": "0", "limit": "20"}
    for fmt, mime, magic in (("csv", "text/csv", b"\xef\xbb\xbf"), ("md", "text/markdown", b"# "),
                             ("docx", "wordprocessingml", b"PK"), ("pdf", "application/pdf", b"%PDF")):
        r = client.post("/reports/build", data={**base, "format": fmt})
        assert r.status_code == 200, (fmt, r.text[:200])
        assert mime in r.headers["content-type"] and r.content.startswith(magic)
        assert "attachment" in r.headers["content-disposition"]
    csv_text = client.post("/reports/build", data={**base, "format": "csv"}).text
    assert "## Trending malware families" in csv_text and "## Notable items" in csv_text
    assert "Zero-day actively exploited" in csv_text
    # explicit dates and validation
    r = client.post("/reports/build", data={**base, "format": "md", "start": "2026-11-01", "end": "2026-11-12"})
    assert r.status_code == 200 and b"2026-11-01" in r.content
    assert client.post("/reports/build", data={**base, "format": "md", "start": "2026-11-12", "end": "2026-11-01"}).status_code == 400
    assert client.post("/reports/build", data={**base, "format": "exe"}).status_code == 400
    assert client.post("/reports/build", data={**base, "format": "pdf", "csrf_token": "bad"}).status_code == 403
