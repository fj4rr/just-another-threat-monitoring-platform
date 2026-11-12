"""Friendly AI set-up: the UI asks *local or cloud?* and *which vendor?* and this module maps
the answer onto the three low-level settings the client actually uses
(``llm_provider``, ``llm_base_url``, ``llm_model``).

Model lists are suggestions – the Settings page can fetch the live list from the server or
provider, and any model name can be typed in.
"""
from __future__ import annotations

# vendor key -> spec. "provider" is what app.llm.client understands.
LOCAL: dict[str, dict] = {
    "ollama": {"label": "Ollama", "provider": "ollama", "base_url": "http://localhost:11434",
               "models": ["llama3.1", "llama3.2", "qwen2.5:14b", "qwen3:8b", "gemma3:12b", "mistral", "deepseek-r1:14b"],
               "hint": "Install from ollama.com, then `ollama pull llama3.1`. No API key needed."},
    "lmstudio": {"label": "LM Studio", "provider": "openai_compatible", "base_url": "http://localhost:1234/v1",
                 "models": [], "hint": "Start the local server in LM Studio (Developer tab). Models appear via “Load models”."},
    "llamacpp": {"label": "llama.cpp server", "provider": "openai_compatible", "base_url": "http://localhost:8080/v1",
                 "models": [], "hint": "`llama-server -m model.gguf` exposes an OpenAI-compatible API on port 8080."},
    "vllm": {"label": "vLLM", "provider": "openai_compatible", "base_url": "http://localhost:8000/v1", "models": [],
             "hint": "vLLM's OpenAI-compatible server, usually on port 8000."},
    "jan": {"label": "Jan", "provider": "openai_compatible", "base_url": "http://localhost:1337/v1", "models": [],
            "hint": "Enable the local API server in Jan settings."},
    "custom_local": {"label": "Other local server (OpenAI-compatible)", "provider": "openai_compatible", "base_url": "",
                     "models": [], "hint": "Any server that speaks the OpenAI chat-completions API. Enter its base URL (ending in /v1)."},
}

CLOUD: dict[str, dict] = {
    "anthropic": {"label": "Anthropic (Claude)", "provider": "anthropic", "base_url": "",
                  "models": ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-2"],
                  "key_url": "https://console.anthropic.com/", "hint": "Uses the official Claude SDK."},
    "openai": {"label": "OpenAI", "provider": "openai_compatible", "base_url": "https://api.openai.com/v1",
               "models": ["gpt-5", "gpt-5-mini", "gpt-4.1", "gpt-4.1-mini"], "key_url": "https://platform.openai.com/api-keys"},
    "openrouter": {"label": "OpenRouter (many models, one key)", "provider": "openai_compatible",
                   "base_url": "https://openrouter.ai/api/v1",
                   "models": ["anthropic/claude-sonnet-4.5", "openai/gpt-5", "google/gemini-2.5-pro",
                              "meta-llama/llama-3.3-70b-instruct", "qwen/qwen3-235b-a22b"],
                   "key_url": "https://openrouter.ai/keys"},
    "groq": {"label": "Groq", "provider": "openai_compatible", "base_url": "https://api.groq.com/openai/v1",
             "models": ["llama-3.3-70b-versatile", "openai/gpt-oss-120b", "qwen/qwen3-32b"],
             "key_url": "https://console.groq.com/keys"},
    "gemini": {"label": "Google Gemini", "provider": "openai_compatible",
               "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
               "models": ["gemini-2.5-pro", "gemini-2.5-flash"], "key_url": "https://aistudio.google.com/apikey"},
    "mistral": {"label": "Mistral", "provider": "openai_compatible", "base_url": "https://api.mistral.ai/v1",
                "models": ["mistral-large-latest", "mistral-medium-latest", "mistral-small-latest"],
                "key_url": "https://console.mistral.ai/api-keys"},
    "deepseek": {"label": "DeepSeek", "provider": "openai_compatible", "base_url": "https://api.deepseek.com/v1",
                 "models": ["deepseek-chat", "deepseek-reasoner"], "key_url": "https://platform.deepseek.com/api_keys"},
    "xai": {"label": "xAI (Grok)", "provider": "openai_compatible", "base_url": "https://api.x.ai/v1",
            "models": ["grok-4", "grok-4-fast"], "key_url": "https://console.x.ai/"},
    "together": {"label": "Together AI", "provider": "openai_compatible", "base_url": "https://api.together.xyz/v1",
                 "models": ["meta-llama/Llama-3.3-70B-Instruct-Turbo", "Qwen/Qwen3-235B-A22B-fp8-tput"],
                 "key_url": "https://api.together.ai/settings/api-keys"},
    "custom_cloud": {"label": "Other API (OpenAI-compatible)", "provider": "openai_compatible", "base_url": "",
                     "models": [], "hint": "Any hosted service with an OpenAI-compatible endpoint. Enter base URL and key."},
}

MODES = ("none", "local", "cloud")


def vendors(mode: str) -> dict[str, dict]:
    return LOCAL if mode == "local" else CLOUD if mode == "cloud" else {}


def spec(mode: str, vendor: str) -> dict | None:
    return vendors(mode).get(vendor)


def default_model(mode: str, vendor: str) -> str:
    sp = spec(mode, vendor) or {}
    return (sp.get("models") or [""])[0]


def resolve(mode: str, vendor: str, base_url: str = "", model: str = "") -> dict:
    """Low-level settings for a UI choice. Empty base URL / model fall back to the preset."""
    if mode not in MODES or mode == "none":
        return {"llm_provider": "none"}
    sp = spec(mode, vendor)
    if not sp:
        return {"llm_provider": "none"}
    out = {"llm_provider": sp["provider"]}
    url = (base_url or "").strip() or sp["base_url"]
    if url:
        out["llm_base_url"] = url
    mdl = (model or "").strip() or default_model(mode, vendor)
    if mdl:
        out["llm_model"] = mdl
    return out


def infer(provider: str, base_url: str) -> tuple[str, str]:
    """Best guess of (mode, vendor) for installs configured before the simple UI existed,
    or configured through environment variables."""
    provider = (provider or "none").lower()
    url = (base_url or "").lower()
    if provider == "none":
        return "none", "ollama"
    if provider == "anthropic":
        return "cloud", "anthropic"
    if provider == "ollama":
        return "local", "ollama"
    for key, sp in CLOUD.items():
        if sp["base_url"] and url.startswith(sp["base_url"].lower()):
            return "cloud", key
    for key, sp in LOCAL.items():
        if sp["base_url"] and url.startswith(sp["base_url"].lower()):
            return "local", key
    if "localhost" in url or "127.0.0.1" in url or url.startswith("http://"):
        return "local", "custom_local"
    return "cloud", "custom_cloud"


def ui_catalog() -> dict:
    """What the Settings page needs, JSON-serialisable."""
    return {"local": {k: {kk: vv for kk, vv in v.items() if kk != "provider"} | {"provider": v["provider"]}
                      for k, v in LOCAL.items()},
            "cloud": {k: dict(v) for k, v in CLOUD.items()}}
