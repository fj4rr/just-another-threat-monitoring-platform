"""LLM providers: local (Ollama), any OpenAI-compatible server (LM Studio, vLLM,
llama.cpp, OpenRouter, OpenAI...), or Anthropic Claude via the official SDK."""
from __future__ import annotations

import logging

import httpx

from .. import settings

log = logging.getLogger(__name__)

# Models that accept the server-side refusal fallback parameter.
_FALLBACK_MODELS = {"claude-fable-5-2", "claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}


class LLMError(Exception):
    pass


class LLMNotConfigured(LLMError):
    pass


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
    if p == "ollama":
        return _ollama(system, prompt, max_tokens)
    if p == "openai_compatible":
        return _openai_compatible(system, prompt, max_tokens)
    if p == "anthropic":
        return _anthropic(system, prompt, max_tokens)
    raise LLMError(f"unknown provider {p}")


def _ollama(system: str, prompt: str, max_tokens: int) -> str:
    base = (settings.get("llm_base_url") or "http://localhost:11434").rstrip("/")
    body = {
        "model": model_name(),
        "stream": False,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        "options": {"num_predict": max_tokens, "num_ctx": 16384},
    }
    try:
        r = httpx.post(f"{base}/api/chat", json=body, timeout=600)
        r.raise_for_status()
        data = r.json()
    except httpx.HTTPError as e:
        raise LLMError(f"Ollama request failed: {e}") from e
    except ValueError as e:
        raise LLMError("Ollama returned a non-JSON response") from e
    return (data.get("message") or {}).get("content", "").strip()


def _openai_compatible(system: str, prompt: str, max_tokens: int) -> str:
    base = (settings.get("llm_base_url") or "http://localhost:1234/v1").rstrip("/")
    key = settings.get("llm_api_key") or ""
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    body = {
        "model": model_name(),
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
    }
    try:
        r = httpx.post(f"{base}/chat/completions", json=body, headers=headers, timeout=600)
        r.raise_for_status()
        data = r.json()
    except httpx.HTTPError as e:
        detail = getattr(e, "response", None)
        raise LLMError(f"LLM request failed: {e} {detail.text[:300] if detail is not None else ''}") from e
    except ValueError as e:
        raise LLMError("LLM server returned a non-JSON response") from e
    choices = data.get("choices") or []
    if not choices:
        raise LLMError("LLM returned no choices")
    return (choices[0].get("message") or {}).get("content", "").strip()


def _anthropic(system: str, prompt: str, max_tokens: int) -> str:
    try:
        import anthropic
    except ImportError as e:  # pragma: no cover
        raise LLMError("pip install anthropic") from e
    key = settings.get("llm_api_key") or None
    client = anthropic.Anthropic(api_key=key) if key else anthropic.Anthropic()
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
        raise LLMError("Anthropic rate limit reached, try again later") from e
    except anthropic.APIStatusError as e:
        raise LLMError(f"Anthropic API error {e.status_code}: {e.message}") from e
    except anthropic.APIConnectionError as e:
        raise LLMError(f"Could not reach Anthropic API: {e}") from e
    if resp.stop_reason == "refusal":
        raise LLMError("The model declined this request")
    return "".join(b.text for b in resp.content if b.type == "text").strip()


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
            r = httpx.get(f"{base}/api/tags", timeout=15)
            r.raise_for_status()
            names = [m.get("name") or m.get("model") for m in r.json().get("models") or []]
        elif provider_name == "openai_compatible":
            base = (base_url or settings.get("llm_base_url") or "http://localhost:1234/v1").rstrip("/")
            headers = {"Authorization": f"Bearer {key}"} if key else {}
            r = httpx.get(f"{base}/models", headers=headers, timeout=20)
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
