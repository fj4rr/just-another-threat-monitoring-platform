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
        raise LLMNotConfigured("No LLM provider configured (Settings → LLM)")
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
    except httpx.HTTPError as e:
        raise LLMError(f"Ollama request failed: {e}") from e
    return (r.json().get("message") or {}).get("content", "").strip()


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
    except httpx.HTTPError as e:
        detail = getattr(e, "response", None)
        raise LLMError(f"LLM request failed: {e} {detail.text[:300] if detail is not None else ''}") from e
    choices = r.json().get("choices") or []
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
