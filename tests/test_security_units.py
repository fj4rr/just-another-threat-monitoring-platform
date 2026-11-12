from app import settings
from app.auth import (
    clear_fails,
    hash_password,
    login_locked,
    needs_rehash,
    password_problems,
    record_fail,
    safe_next,
    verify_password,
)
from app.processing.pipeline import safe_url, strip_html
from app.web import safe_href


def test_password_hash_roundtrip_and_upgrade():
    h = hash_password("CorrectHorse9")
    assert verify_password("CorrectHorse9", h)
    assert not verify_password("wrong", h)
    assert not needs_rehash(h)
    legacy = "pbkdf2_sha256$240000$00$00"
    assert needs_rehash(legacy)
    assert not verify_password("x", "garbage")


def test_password_policy():
    assert password_problems("short1A")
    assert password_problems("alllowercase1")
    assert password_problems("NoDigitsHere")
    assert password_problems("Ok" + "x" * 300 + "1")
    assert password_problems("CorrectHorse9") is None


def test_safe_next_blocks_open_redirects():
    assert safe_next("/feed?q=x") == "/feed?q=x"
    assert safe_next("//evil.example") == "/"
    assert safe_next("/\\evil.example") == "/"
    assert safe_next("https://evil.example") == "/"
    assert safe_next("") == "/"


def test_login_lockout_window():
    key = "unit|127.0.0.1"
    clear_fails(key)
    for _ in range(5):
        assert not login_locked(key)
        record_fail(key)
    assert login_locked(key)
    clear_fails(key)
    assert not login_locked(key)


def test_safe_url_and_href_reject_dangerous_schemes():
    assert safe_url("javascript:alert(1)") == ""
    assert safe_url("data:text/html,hi") == ""
    assert safe_url(" https://example.com/a ") == "https://example.com/a"
    assert safe_href("javascript:alert(1)") == "#"
    assert safe_href("https://example.com") == "https://example.com"


def test_strip_html_decodes_entities():
    assert strip_html("<p>Tom &amp; Jerry &#8217;s <script>x()</script>list&nbsp;</p>") == "Tom & Jerry ’s list"


def test_settings_coercion_is_clamped():
    assert settings.coerce_form_value("vt_min_interval", "-5") == 0
    assert settings.coerce_form_value("enrichment_interval", "0") == 2
    assert settings.coerce_form_value("enrichment_batch", "9999") == 100
    assert settings.coerce_form_value("llm_provider", "evil") == "none"
    assert settings.coerce_form_value("llm_provider", "ollama") == "ollama"
    assert settings.coerce_form_value("enrichment_enabled", "on") is True
