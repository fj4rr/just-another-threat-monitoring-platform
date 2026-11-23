"""0.14.2: a provider that is only busy is told apart from a bad request, so the API answers 503 and the daily
executive summary is queued again later instead of being lost for the day."""
import re

import httpx
import pytest

from app import jobs, settings
from app.llm import client


def _csrf(test_client, path="/"):
    return re.search(r'name="csrf-token" content="([^"]+)"', test_client.get(path).text).group(1)


def _status_error(code: int, message: str) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "https://llm.example/v1/chat/completions")
    response = httpx.Response(code, json={"error": {"code": code, "message": message}}, request=request)
    return httpx.HTTPStatusError(f"server error {code}", request=request, response=response)


def test_a_busy_provider_is_its_own_error():
    busy = client._server_error(_status_error(503, "This model is currently experiencing high demand."), "the LLM server")
    assert isinstance(busy, client.LLMBusy) and "high demand" in str(busy) and "3 attempts" in str(busy)
    wrong = client._server_error(_status_error(400, "unknown model gemini-9"), "the LLM server")
    assert isinstance(wrong, client.LLMError) and not isinstance(wrong, client.LLMBusy)


def test_the_digest_endpoint_answers_503_while_the_model_is_busy(client_with_llm, monkeypatch):
    from app.llm import insights

    monkeypatch.setattr(insights.client, "complete",
                        lambda *a, **k: (_ for _ in ()).throw(client.LLMBusy("the LLM server answered HTTP 503")))
    r = client_with_llm.post("/api/insights/digest", headers={"X-CSRF-Token": _csrf(client_with_llm)})
    assert r.status_code == 503 and "503" in r.json()["detail"]


def test_a_busy_model_queues_the_summary_again(monkeypatch):
    queued = {}

    class _Scheduler:
        running = True

        def add_job(self, func, trigger, **kw):
            queued.update(kw)

    monkeypatch.setattr(jobs, "scheduler", _Scheduler())
    assert jobs._retry_digest_later(client.LLMBusy("busy"), force=False, attempt=0) == 20
    assert queued["kwargs"] == {"force": False, "attempt": 1}
    assert jobs._retry_digest_later(client.LLMBusy("busy"), force=True, attempt=1) == 60
    assert queued["kwargs"] == {"force": True, "attempt": 2}
    # the attempts are used up, and another kind of error is not repeated at all
    assert jobs._retry_digest_later(client.LLMBusy("busy"), force=False, attempt=2) == 0
    assert jobs._retry_digest_later(client.LLMError("no usable JSON"), force=False, attempt=0) == 0


@pytest.fixture
def client_with_llm(client):
    settings.set("llm_provider", "openai_compatible")
    settings.set("llm_base_url", "https://llm.example/v1")
    try:
        yield client
    finally:
        for key in ("llm_provider", "llm_base_url"):
            settings.set(key, settings.SCHEMA[key][0])
