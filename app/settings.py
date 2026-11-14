"""Runtime settings stored in the DB (editable from the UI), with env-var overrides."""
from __future__ import annotations

import os
import threading
import time
from typing import Any

from .db import session_scope
from .models import Setting

# key -> (default, env var, label, kind, group)
SCHEMA: dict[str, tuple[Any, str, str, str, str]] = {
    # Threat-intel API keys
    "virustotal_api_key": ("", "VT_API_KEY", "VirusTotal API key", "secret", "intel"),
    "otx_api_key": ("", "OTX_API_KEY", "AlienVault OTX API key", "secret", "intel"),
    "urlscan_api_key": ("", "URLSCAN_API_KEY", "urlscan.io API key", "secret", "intel"),
    "anyrun_api_key": ("", "ANYRUN_API_KEY", "ANY.RUN API key (TI Lookup)", "secret", "intel"),
    "anyrun_api_base": ("https://api.any.run/v1", "ANYRUN_API_BASE", "ANY.RUN API base URL", "text", "intel"),
    "threatfox_auth_key": ("", "ABUSECH_AUTH_KEY", "abuse.ch Auth-Key (ThreatFox, MalwareBazaar, URLhaus; free)",
                           "secret", "intel"),
    "greynoise_api_key": ("", "GREYNOISE_API_KEY", "GreyNoise Community API key (free)", "secret", "intel"),
    "abuseipdb_api_key": ("", "ABUSEIPDB_API_KEY", "AbuseIPDB API key (free)", "secret", "intel"),
    "ransomwarelive_api_key": ("", "RANSOMWARELIVE_API_KEY",
                               "ransomware.live PRO API key (free; required for organisational use)", "secret", "intel"),
    # Infrastructure context (on demand)
    "shodan_api_key": ("", "SHODAN_API_KEY", "Shodan API key (optional with keyless lookups: InternetDB)", "secret", "intel"),
    "censys_api_token": ("", "CENSYS_API_TOKEN", "Censys Platform personal access token", "secret", "intel"),
    "censys_org_id": ("", "CENSYS_ORG_ID", "Censys organization ID (optional)", "text", "intel"),
    "crowdsec_api_key": ("", "CROWDSEC_API_KEY", "CrowdSec CTI API key (free)", "secret", "intel"),
    "pulsedive_api_key": ("", "PULSEDIVE_API_KEY", "Pulsedive API key (free)", "secret", "intel"),
    "hybrid_analysis_api_key": ("", "HYBRID_ANALYSIS_API_KEY", "Hybrid Analysis API key (free)", "secret", "intel"),
    "ipinfo_token": ("", "IPINFO_TOKEN", "IPinfo token (free Lite plan)", "secret", "intel"),
    "maxmind_license_key": ("", "MAXMIND_LICENSE_KEY",
                            "MaxMind license key (optional; GeoLite2 instead of DB-IP Lite for offline GeoIP)",
                            "secret", "intel"),
    "hudsonrock_api_key": ("", "HUDSONROCK_API_KEY", "Hudson Rock Cavalier API key (free; infostealer statistics)",
                           "secret", "intel"),
    "nvd_api_key": ("", "NVD_API_KEY", "NVD API key (optional, faster CVSS lookups)", "secret", "intel"),
    # Social
    "x_bearer_token": ("", "X_BEARER_TOKEN", "X (Twitter) API v2 bearer token", "secret", "social"),
    # Enrichment
    "enrichment_enabled": (True, "", "Automatic cross-source enrichment", "bool", "enrichment"),
    "enrichment_interval": (10, "", "Enrichment interval (minutes)", "int", "enrichment"),
    "enrichment_batch": (8, "", "Entities enriched per run", "int", "enrichment"),
    "vt_daily_budget": (400, "", "VirusTotal lookups per day (free tier = 500)", "int", "enrichment"),
    "vt_min_interval": (16, "", "Seconds between VirusTotal calls (free tier = 4/min)", "int", "enrichment"),
    "greynoise_daily_budget": (40, "", "GreyNoise lookups per day (community tier is small)", "int", "enrichment"),
    "abuseipdb_daily_budget": (900, "", "AbuseIPDB lookups per day (free tier = 1000)", "int", "enrichment"),
    "context_keyless": (False, "", "Allow keyless context lookups (Shodan InternetDB, IPinfo): sends the indicator to them",
                        "bool", "enrichment"),
    "context_on_malicious": (False, "", "Run context lookups automatically when an indicator turns malicious", "bool",
                             "enrichment"),
    "context_daily_budget": (100, "", "Context lookups per provider per day", "int", "enrichment"),
    "enrich_backfill": (False, "", "Also enrich indicators that only appear in backfilled (historical) items",
                        "bool", "enrichment"),
    "enrich_families": (True, "", "Pull IOCs for trending malware families from OTX / ANY.RUN", "bool", "enrichment"),
    "cve_intel_enabled": (True, "", "CVE context every 6 h: CISA KEV, FIRST EPSS and NVD CVSS (free, no key)", "bool",
                          "enrichment"),
    # LLM (llm_mode / llm_vendor drive the simple UI; llm_provider is what the client uses)
    "llm_mode": ("none", "", "AI", "select:none,local,cloud", "llm"),
    "llm_vendor": ("ollama", "", "Vendor / runtime", "text", "llm"),
    "llm_provider": ("none", "LLM_PROVIDER", "LLM provider", "select:none,ollama,openai_compatible,anthropic", "llm"),
    "llm_base_url": ("http://localhost:11434", "LLM_BASE_URL", "Base URL (Ollama / OpenAI-compatible)", "text", "llm"),
    "llm_model": ("llama3.1", "LLM_MODEL", "Model name", "text", "llm"),
    "llm_api_key": ("", "LLM_API_KEY", "API key (OpenAI-compatible / Anthropic)", "secret", "llm"),
    "llm_auto_summarize": (False, "", "Auto-summarize new high-severity items", "bool", "llm"),
    "llm_auto_extract": (True, "", "Let the LLM discover malware families not in the knowledge base", "bool", "llm"),
    "llm_daily_digest": (True, "", "Generate a daily AI digest", "bool", "llm"),
    "llm_language": ("English", "", "Language for AI output (e.g. English, Bahasa Indonesia)", "text", "llm"),
    # Sharing: what may leave JATMP through the REST API, exports, webhooks and MISP
    "api_max_tlp": ("GREEN", "", "Highest TLP shared through the API, exports, webhooks and MISP",
                    "select:CLEAR,GREEN,AMBER,RED", "sharing"),
    "api_share_provider_details": (False, "", "Include third-party provider verdicts in API output (check their terms)",
                                   "bool", "sharing"),
    "api_rate_limit": (120, "", "API requests per minute per key", "int", "sharing"),
    "public_base_url": ("", "JATMP_PUBLIC_URL", "Public base URL used in webhook / MISP links (e.g. https://jatmp.example.org)",
                        "text", "sharing"),
    "webhook_min_severity": (70, "", "Webhooks: minimum severity for the new-item event", "int", "sharing"),
    "webhooks_allow_private": (False, "", "Webhooks: allow private / loopback target addresses (SSRF risk)", "bool",
                               "sharing"),
    # MISP
    "misp_url": ("", "MISP_URL", "MISP base URL", "text", "misp"),
    "misp_api_key": ("", "MISP_API_KEY", "MISP automation key", "secret", "misp"),
    "misp_verify_tls": (True, "", "Verify the MISP TLS certificate", "bool", "misp"),
    "misp_distribution": ("0", "", "Distribution of pushed events (0 = your organisation only, 1 = this community, "
                          "2 = connected communities, 3 = all, 4 = sharing group)", "select:0,1,2,3,4", "misp"),
    "misp_sharing_group_id": (0, "", "Sharing group id (distribution 4 only)", "int", "misp"),
    "misp_autopush_min_severity": (0, "", "Push new items to MISP automatically at or above this severity (0 = off)",
                                   "int", "misp"),
    # Housekeeping
    "retention_full_days": (180, "", "Keep the full text for N days; older items keep title, link, entities, "
                            "severity and a snippet (0 = keep everything)", "int", "general"),
    "retention_days": (0, "", "Delete items older than N days (0 = keep forever, slimmed as above)", "int", "general"),
    # Geography
    "geoip_auto_update": (False, "", "Refresh the offline GeoIP database every month (DB-IP Lite, or MaxMind GeoLite2 "
                          "with a license key) for the hosting country of IP indicators", "bool", "general"),
}

# Integer settings are clamped so a typo in the UI cannot disable throttling or flood an API.
INT_BOUNDS: dict[str, tuple[int, int]] = {
    "enrichment_interval": (2, 1440),
    "enrichment_batch": (1, 100),
    "vt_daily_budget": (0, 100_000),
    "vt_min_interval": (0, 3600),
    "retention_days": (0, 3650),
    "retention_full_days": (0, 3650),
    "greynoise_daily_budget": (0, 100_000),
    "abuseipdb_daily_budget": (0, 100_000),
    "api_rate_limit": (1, 100_000),
    "context_daily_budget": (0, 100_000),
    "webhook_min_severity": (0, 100),
    "misp_sharing_group_id": (0, 1_000_000),
    "misp_autopush_min_severity": (0, 100),
}

# Small read cache: settings are consulted many times per request and by every collector
# thread. Entries live for a few seconds; set() invalidates immediately in this process.
_CACHE_TTL = 5.0
_cache: dict[str, tuple[float, Any]] = {}
_cache_lock = threading.Lock()
_MISSING = object()


def get(key: str, default: Any = None) -> Any:
    spec = SCHEMA.get(key)
    if spec and spec[1]:
        env = os.getenv(spec[1])
        if env not in (None, ""):
            return _coerce(env, spec[3])
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        value = hit[1] if hit and hit[0] > now else _MISSING
    if value is _MISSING:
        with session_scope() as db:
            row = db.get(Setting, key)
            value = row.value if row is not None else None
        with _cache_lock:
            _cache[key] = (now + _CACHE_TTL, value)
    if value is not None:
        return value
    if default is not None:
        return default
    return spec[0] if spec else None


def set(key: str, value: Any) -> None:
    with session_scope() as db:
        row = db.get(Setting, key)
        if row is None:
            db.add(Setting(key=key, value=value))
        else:
            row.value = value
    with _cache_lock:
        _cache.pop(key, None)


def invalidate_cache() -> None:
    with _cache_lock:
        _cache.clear()


def env_locked(key: str) -> bool:
    spec = SCHEMA.get(key)
    return bool(spec and spec[1] and os.getenv(spec[1]))


def _coerce(raw: Any, kind: str) -> Any:
    if kind == "bool":
        if isinstance(raw, bool):
            return raw
        return str(raw).lower() in ("1", "true", "yes", "on")
    if kind == "int":
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0
    return raw.strip() if isinstance(raw, str) else raw


def coerce_form_value(key: str, raw: Any) -> Any:
    kind = SCHEMA[key][3]
    val = _coerce(raw, kind)
    if key in INT_BOUNDS:
        lo, hi = INT_BOUNDS[key]
        val = min(max(int(val), lo), hi)
    if kind.startswith("select:") and val not in kind.split(":", 1)[1].split(","):
        val = SCHEMA[key][0]
    return val


def all_for_ui() -> list[dict]:
    out = []
    for key, (_default, env, label, kind, group) in SCHEMA.items():
        val = get(key)
        secret = kind == "secret"
        out.append(
            {
                "key": key,
                "label": label,
                "kind": kind,
                "group": group,
                # secret values never reach the template, only whether one is configured
                "value": "" if secret else val,
                "is_set": bool(val),
                "env_locked": env_locked(key),
                "env": env,
                "options": kind.split(":", 1)[1].split(",") if kind.startswith("select:") else [],
            }
        )
    return out
