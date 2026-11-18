"""Daily lookup budgets per provider: what was used today and what is left (PM review 2026-11, item 12).

The counters are the ``_budget_<provider>`` settings that ``clients._budget_ok`` keeps (they survive restarts).
The Settings → Enrichment tab and the IOC page show them, and the enrichment job warns once a day for every
provider whose budget is used up, not only VirusTotal.
"""
from __future__ import annotations

from datetime import date

from .. import settings
from . import NotConfigured

# provider name -> (label, setting that holds its daily budget)
ENRICHMENT_BUDGETS = {
    "virustotal": ("VirusTotal", "vt_daily_budget"),
    "greynoise": ("GreyNoise", "greynoise_daily_budget"),
    "abuseipdb": ("AbuseIPDB", "abuseipdb_daily_budget"),
}
# on-demand context providers share one budget setting, counted per provider
CONTEXT_BUDGETS = {
    "shodan": "Shodan", "censys": "Censys", "crowdsec": "CrowdSec", "pulsedive": "Pulsedive",
    "hybrid-analysis": "Hybrid Analysis",
}


def used_today(provider: str) -> int:
    state = settings.get(f"_budget_{provider}") or {}
    if isinstance(state, dict) and state.get("day") == date.today().isoformat():
        return int(state.get("count") or 0)
    return 0


def _configured() -> set[str]:
    from ..processing.enrichment import PROVIDER_CLASSES
    from .context import CONTEXT_CLASSES

    out = set()
    for cls in (*PROVIDER_CLASSES, *CONTEXT_CLASSES):
        try:
            cls()
            out.add(cls.name)
        except NotConfigured:
            continue
    return out


def status() -> list[dict]:
    """One row per provider that is configured or was used today: used, limit (0 = no limit), percent, exhausted."""
    configured = _configured()
    rows = [(name, label, int(settings.get(key) or 0), "enrichment") for name, (label, key) in ENRICHMENT_BUDGETS.items()]
    ctx_limit = int(settings.get("context_daily_budget") or 0)
    rows += [(name, label, ctx_limit, "context") for name, label in CONTEXT_BUDGETS.items()]
    out = []
    for name, label, limit, group in rows:
        used = used_today(name)
        if name not in configured and not used:
            continue
        out.append({
            "provider": name, "label": label, "group": group, "used": used, "limit": limit,
            "pct": min(100, round(100 * used / limit)) if limit else 0,
            "exhausted": bool(limit and used >= limit), "configured": name in configured,
        })
    return out
