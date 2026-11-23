"""LLM providers: local (Ollama), any OpenAI-compatible server (LM Studio, vLLM,
llama.cpp, OpenRouter, OpenAI...), or Anthropic Claude via the official SDK."""
from __future__ import annotations

import logging
import time

import httpx

from .. import netguard, settings

log = logging.getLogger(__name__)
# A local model may take minutes for a long brief, but a hung server must not hold a scheduler worker forever
# (audit 2026-11 E-4): 10 s to connect, at most 5 minutes for the answer.
LLM_TIMEOUT = httpx.Timeout(300, connect=10)

# Models that accept the server-side refusal fallback parameter.
_FALLBACK_MODELS = {"claude-fable-5-2", "claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}


# A cloud model under load answers 429 or 503 ("this model is currently experiencing high demand"), and a
# connection is sometimes dropped mid-request. Both are usually over in seconds, so the call is repeated instead
# of failing the digest or the analysis for the day.
RETRY_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}
RETRY_ATTEMPTS = 3
RETRY_WAIT = 4.0  # seconds before the second attempt, doubled before each further one


class LLMError(Exception):
    pass


class LLMNotConfigured(LLMError):
    pass


class LLMBusy(LLMError):
    """The provider is temporarily unavailable (high demand, rate limit, a dropped connection), so the same
    request may well work in a few minutes. Callers that can wait retry later instead of giving up for the day."""


def _retrying(call, what: str):
    """Run an HTTP call again while the server says it is busy or the connection drops."""
    wait = RETRY_WAIT
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            return call()
        except httpx.HTTPStatusError as e:
            if e.response.status_code not in RETRY_STATUS or attempt == RETRY_ATTEMPTS:
                raise
            why = f"HTTP {e.response.status_code}"
        except (httpx.ConnectTimeout, httpx.PoolTimeout, httpx.ReadError, httpx.RemoteProtocolError) as e:
            if attempt == RETRY_ATTEMPTS:
                raise
            why = f"{type(e).__name__}"
        log.warning("%s: %s, retrying in %.0fs (attempt %d of %d)", what, why, wait, attempt + 1, RETRY_ATTEMPTS)
        time.sleep(wait)
        wait *= 2


def provider() -> str:
    return (settings.get("llm_provider") or "none").lower()


def is_configured() -> bool:
    return provider() != "none"


def model_name() -> str:
    p = provider()
    m = settings.get("llm_model") or ""
    if p == "anthropic" and (not m or m == "llama3.1"):
        return "claude-opus-5-5"
    return m


def complete(system: str, prompt: str, max_tokens: int = 4000) -> str:
    p = provider()
    if p == "none":
        raise LLMNotConfigured("No LLM provider configured (Settings → AI)")
    from . import redact

    if redact.enabled():  # personal data never goes to a cloud model (setting llm_redact; PM review, item 14)
        r = redact.Redactor()
        system, prompt = r(system), r(prompt)
        if r.count:
            log.info("redacted %d personal data value(s) from the AI prompt", r.count)
    if p == "ollama":
        return _ollama(system, prompt, max_tokens)
    if p == "openai_compatible":
        return _openai_compatible(system, prompt, max_tokens)
    if p == "anthropic":
        return _anthropic(system, prompt, max_tokens)
    raise LLMError(f"unknown provider {p}")


def _server_error(e: httpx.HTTPStatusError, name: str) -> LLMError:
    """A readable message out of a provider's error body: "high demand" rather than a wall of JSON."""
    msg = None
    try:
        body = e.response.json()
        err = body.get("error") if isinstance(body, dict) else None
        msg = err.get("message") if isinstance(err, dict) else err if isinstance(err, str) else None
    except ValueError:
        pass
    msg = " ".join(str(msg or e.response.text or "").split())[:300]
    code = e.response.status_code
    busy = code in RETRY_STATUS
    tried = f" after {RETRY_ATTEMPTS} attempts" if busy else ""
    return (LLMBusy if busy else LLMError)(f"{name} answered HTTP {code}{tried}: {msg}")


def _answer(out: str, cut_off: bool, max_tokens: int) -> str:
    """An answer that ran into the token limit. A reasoning model can spend the whole budget on thinking and
    return nothing at all; a partial answer is kept, because the callers repair what they can (insights)."""
    if cut_off:
        log.warning("the model stopped at the %d-token limit with %d characters of answer", max_tokens, len(out))
    if not out:
        raise LLMError(f"the model answered nothing, after stopping at the {max_tokens}-token limit"
                       if cut_off else "the model returned an empty answer")
    return out


def _ollama(system: str, prompt: str, max_tokens: int) -> str:
    base = (settings.get("llm_base_url") or "http://localhost:11434").rstrip("/")
    body = {
        "model": model_name(),
        "stream": False,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        "options": {"num_predict": max_tokens, "num_ctx": 16384},
    }

    def call():
        with netguard.client(timeout=LLM_TIMEOUT) as c:
            r = c.post(f"{base}/api/chat", json=body)
        r.raise_for_status()
        return r.json()

    try:
        data = _retrying(call, "Ollama")
    except httpx.HTTPStatusError as e:
        raise _server_error(e, "Ollama") from e
    except httpx.HTTPError as e:
        raise LLMBusy(f"Ollama request failed: {e}") from e
    except ValueError as e:
        raise LLMError("Ollama returned a non-JSON response") from e
    out = (data.get("message") or {}).get("content", "").strip()
    return _answer(out, data.get("done_reason") == "length", max_tokens)


def _openai_compatible(system: str, prompt: str, max_tokens: int) -> str:
    base = (settings.get("llm_base_url") or "http://localhost:1234/v1").rstrip("/")
    key = settings.get("llm_api_key") or ""
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    body = {
        "model": model_name(),
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
    }

    def call():
        with netguard.client(timeout=LLM_TIMEOUT, headers=headers) as c:
            r = c.post(f"{base}/chat/completions", json=body)
        r.raise_for_status()
        return r.json()

    try:
        data = _retrying(call, "LLM request")
    except httpx.HTTPStatusError as e:
        raise _server_error(e, "the LLM server") from e
    except httpx.HTTPError as e:
        raise LLMBusy(f"LLM request failed: {e}") from e
    except ValueError as e:
        raise LLMError("LLM server returned a non-JSON response") from e
    choices = data.get("choices") or []
    if not choices:
        raise LLMError("LLM returned no choices")
    out = ((choices[0].get("message") or {}).get("content") or "").strip()
    return _answer(out, choices[0].get("finish_reason") == "length", max_tokens)


def _anthropic(system: str, prompt: str, max_tokens: int) -> str:
    try:
        import anthropic
    except ImportError as e:  # pragma: no cover
        raise LLMError("pip install anthropic") from e
    key = settings.get("llm_api_key") or None
    kw = {"max_retries": RETRY_ATTEMPTS}  # the SDK repeats 429, 5xx and 529 (overloaded) by itself
    client = anthropic.Anthropic(api_key=key, **kw) if key else anthropic.Anthropic(**kw)
    model = model_name()
    kwargs = dict(
        model=model,
        max_tokens=max(max_tokens, 8000),
        system=system,
        messages=[{"role": "user", "content": prompt}],
        output_config={"effort": "medium"},
    )
    try:
        if model in _FALLBACK_MODELS:
            # Re-run on a fallback model if a safety classifier declines (threat-intel text
            # about malware can occasionally trip the cyber classifier).
            with client.beta.messages.stream(
                **kwargs, betas=["server-side-fallback-2026-07-01"], fallbacks="default"
            ) as stream:
                resp = stream.get_final_message()
        else:
            with client.messages.stream(**kwargs) as stream:
                resp = stream.get_final_message()
    except anthropic.AuthenticationError as e:
        raise LLMError("Anthropic API key rejected") from e
    except anthropic.NotFoundError as e:
        raise LLMError(f"Anthropic model '{model}' not found") from e
    except anthropic.RateLimitError as e:
        raise LLMBusy("Anthropic rate limit reached, try again later") from e
    except anthropic.APIStatusError as e:
        kind = LLMBusy if e.status_code in RETRY_STATUS else LLMError
        raise kind(f"Anthropic API error {e.status_code}: {e.message}") from e
    except anthropic.APIConnectionError as e:
        raise LLMBusy(f"Could not reach Anthropic API: {e}") from e
    if resp.stop_reason == "refusal":
        raise LLMError("The model declined this request")
    out = "".join(b.text for b in resp.content if b.type == "text").strip()
    return _answer(out, resp.stop_reason == "max_tokens", max(max_tokens, 8000))


def test_connection() -> str:
    out = complete("You are a connectivity check.", "Reply with exactly: OK", max_tokens=20)
    return out[:200]


def list_models(provider_name: str, base_url: str = "", api_key: str = "") -> list[str]:
    """Live model list from a local server or a provider. Used by the Settings page.
    ``api_key`` falls back to the saved key when empty."""
    provider_name = (provider_name or "").lower()
    key = api_key or settings.get("llm_api_key") or ""
    try:
        if provider_name == "ollama":
            base = (base_url or settings.get("llm_base_url") or "http://localhost:11434").rstrip("/")
            with netguard.client(timeout=15) as c:
                r = c.get(f"{base}/api/tags")
            r.raise_for_status()
            names = [m.get("name") or m.get("model") for m in r.json().get("models") or []]
        elif provider_name == "openai_compatible":
            base = (base_url or settings.get("llm_base_url") or "http://localhost:1234/v1").rstrip("/")
            headers = {"Authorization": f"Bearer {key}"} if key else {}
            with netguard.client(timeout=20, headers=headers) as c:
                r = c.get(f"{base}/models")
            r.raise_for_status()
            data = r.json()
            rows = data.get("data") if isinstance(data, dict) else data
            names = [m.get("id") if isinstance(m, dict) else str(m) for m in rows or []]
        elif provider_name == "anthropic":
            import anthropic

            client = anthropic.Anthropic(api_key=key) if key else anthropic.Anthropic()
            names = [m.id for m in client.models.list(limit=100).data]
        else:
            raise LLMError("choose a vendor first")
    except LLMError:
        raise
    except httpx.HTTPStatusError as e:
        raise LLMError(f"server answered {e.response.status_code}: {e.response.text[:200]}") from e
    except httpx.HTTPError as e:
        raise LLMError(f"could not reach the server: {e}") from e
    except Exception as e:  # SDK / JSON errors
        raise LLMError(f"{type(e).__name__}: {str(e)[:200]}") from e
    return sorted({str(n) for n in names if n})[:500]
