"""0.14.1: a cut-off or fenced JSON answer still becomes an executive summary, and a busy provider is retried."""
import httpx
import pytest

from app import settings
from app.llm import client
from app.llm.insights import digest_data

TRUNCATED = """```json
{ "headline": "Suspected China-linked actors used AI agents to exploit a zero-day in medical imaging software.",
  "level": "high",
  "points": [ { "title": "Zero-day in MONAI Label", "detail": "Unauthenticated remote code execution, exploited in the wild." },
              { "title": "Agents did the discovery", "detail": "The campaign used autonomous agents to find and weaponise the"""


def test_a_cut_off_json_summary_is_repaired():
    d = digest_data(TRUNCATED)
    assert d["level"] == "high" and d["headline"].startswith("Suspected China-linked actors")
    # the complete point is kept, the sentence the model never finished is dropped
    assert d["points"][0]["detail"].endswith("exploited in the wild.")
    assert d["points"][1] == {"title": "Agents did the discovery", "detail": ""}
    assert d["actions"] == []


def test_fences_chatter_and_unusable_answers():
    assert digest_data('```json\n{"headline": "One line", "level": "LOW"}\n```') == {
        "headline": "One line", "level": "low", "points": [], "actions": []}
    assert digest_data('Here you go: {"headline": "One line"} – hope it helps!')["headline"] == "One line"
    assert digest_data('{"headline": "say \\"hi\\"", "points": []}')["headline"] == 'say "hi"'
    assert digest_data('{"headline": "Trailing comma", "points": [{"title": "x",},],}')["points"] == [
        {"title": "x", "detail": ""}]
    assert digest_data('{"headline": "cut in the mid') == {}  # nothing usable survived
    assert digest_data("{ not json at all") == {} and digest_data("no json here") == {}


def test_the_digest_refuses_to_store_a_raw_json_dump(installed, monkeypatch):
    from app.db import session_scope
    from app.llm.insights import daily_digest

    monkeypatch.setattr(client, "complete", lambda *a, **k: '```json\n{"headl')
    try:
        settings.set("llm_provider", "openai_compatible")
        with session_scope() as db, pytest.raises(client.LLMError, match="usable JSON"):
            daily_digest(db)
    finally:
        settings.set("llm_provider", settings.SCHEMA["llm_provider"][0])


# --------------------------------------------------------------------------- a busy provider
class _Resp:
    def __init__(self, status: int, payload=None, text=""):
        self.status_code, self._payload, self.text = status, payload, text

    def json(self):
        if self._payload is None:
            raise ValueError("not JSON")
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(f"server error {self.status_code}",
                                        request=httpx.Request("POST", "https://llm.example/v1/chat/completions"),
                                        response=self)


def _fake_transport(monkeypatch, responses: list):
    calls: list[str] = []

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, url, json=None):
            calls.append(url)
            return responses.pop(0)

    monkeypatch.setattr(client.netguard, "client", lambda **kw: _Client())
    monkeypatch.setattr(client, "RETRY_WAIT", 0)
    return calls


def _answer(text: str, finish: str = "stop"):
    return _Resp(200, {"choices": [{"message": {"content": text}, "finish_reason": finish}]})


def _busy(code: int = 503):
    return _Resp(code, {"error": {"code": code, "message": "This model is currently experiencing high demand."}})


@pytest.fixture
def _cloud():
    settings.set("llm_provider", "openai_compatible")
    settings.set("llm_base_url", "https://llm.example/v1")
    settings.set("llm_redact", "never")
    try:
        yield
    finally:
        for key in ("llm_provider", "llm_base_url", "llm_redact"):
            settings.set(key, settings.SCHEMA[key][0])


def test_a_busy_provider_is_tried_again(installed, monkeypatch, _cloud):
    calls = _fake_transport(monkeypatch, [_busy(), _busy(429), _answer("the summary")])
    assert client.complete("sys", "prompt") == "the summary"
    assert len(calls) == 3


def test_a_provider_that_stays_busy_reports_what_it_said(installed, monkeypatch, _cloud):
    calls = _fake_transport(monkeypatch, [_busy(), _busy(), _busy()])
    with pytest.raises(client.LLMError) as err:
        client.complete("sys", "prompt")
    assert len(calls) == client.RETRY_ATTEMPTS
    assert "503" in str(err.value) and "high demand" in str(err.value) and "attempts" in str(err.value)


def test_a_rejected_request_is_not_repeated(installed, monkeypatch, _cloud):
    calls = _fake_transport(monkeypatch, [_Resp(400, {"error": {"message": "unknown model"}})])
    with pytest.raises(client.LLMError, match="unknown model"):
        client.complete("sys", "prompt")
    assert len(calls) == 1


def test_an_answer_cut_off_before_it_started_says_so(installed, monkeypatch, _cloud):
    _fake_transport(monkeypatch, [_answer("", "length")])
    with pytest.raises(client.LLMError, match="token limit"):
        client.complete("sys", "prompt", max_tokens=1500)
    _fake_transport(monkeypatch, [_answer("half an ans", "length")])  # a partial answer is still returned
    assert client.complete("sys", "prompt", max_tokens=1500) == "half an ans"
