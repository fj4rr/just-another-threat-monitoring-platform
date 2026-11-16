# Configuration

[← Documentation index](README.md)

API keys and options are managed under **Settings** (admin role). A `.env` file next to `run.py` (see
`.env.example`) is loaded automatically; values set through environment variables take precedence over the UI
and are shown there as locked.

| Service | Variable | Notes |
|---|---|---|
| VirusTotal | `VT_API_KEY` | Free tier allows 4 requests/min and 500/day; both limits are enforced (`vt_min_interval`, `vt_daily_budget`) |
| AlienVault OTX | `OTX_API_KEY` | Free. Subscribe to pulses or users on OTX so the "subscribed" feed has content |
| urlscan.io | `URLSCAN_API_KEY` | The Search API requires a key |
| ANY.RUN | `ANYRUN_API_KEY` | Requires a plan with TI Lookup; the base URL can be changed in Settings. The TI Lookup endpoint (`/v1/intelligence/api/search`) has not been exercised against a real key; the parser is defensive |
| abuse.ch ThreatFox | `ABUSECH_AUTH_KEY` | Free (Auth-Key from auth.abuse.ch) |
| NVD | `NVD_API_KEY` | Optional. CISA KEV, FIRST EPSS and NVD work without a key; with one, CVSS lookups are faster (50 per run instead of 10). The whole CVE lookup can be turned off under Settings → Enrichment |
| abuse.ch MalwareBazaar, URLhaus | `ABUSECH_AUTH_KEY` | Same free Auth-Key as ThreatFox |
| GreyNoise Community | `GREYNOISE_API_KEY` | Free; small daily quota (`greynoise_daily_budget`, default 40) |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | Free tier allows 1,000 checks/day (`abuseipdb_daily_budget`, default 900) |
| ransomware.live | `RANSOMWARELIVE_API_KEY` | Free PRO key; required for organisational use. Without it the personal-use API (one request per minute per endpoint) is used |
| Hudson Rock Cavalier | `HUDSONROCK_API_KEY` | Free key for the infostealer deep dive |
| Shodan | `SHODAN_API_KEY` | Optional: without a key the free InternetDB is used (after allowing keyless context lookups) |
| Censys | `CENSYS_API_TOKEN`, `CENSYS_ORG_ID` | Platform personal access token; free accounts have a small monthly credit |
| CrowdSec CTI | `CROWDSEC_API_KEY` | Free tier |
| Pulsedive | `PULSEDIVE_API_KEY` | Free tier |
| Hybrid Analysis | `HYBRID_ANALYSIS_API_KEY` | Free (vetted) account |
| IPinfo | `IPINFO_TOKEN` | Free Lite token; without one the keyless endpoint is used (after allowing keyless lookups) |
| Offline GeoIP | `MAXMIND_LICENSE_KEY` | Optional. *Download GeoIP database* (Settings → General) or `manage.py geoip-update` fetches DB-IP IP to Country Lite (no account, CC BY 4.0) into `data/geoip/`; with a MaxMind key it fetches GeoLite2 Country instead. Monthly refresh is a setting |
| MISP | `MISP_URL`, `MISP_API_KEY` | Automation key of a MISP user; distribution, sharing group, TLS verification and auto-push under Settings → MISP |
| X / Twitter | `X_BEARER_TOKEN` | API v2 is a paid service; alternatively set `rss_bridge` on each X source |
| LLM | `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | Optional. `LLM_PROVIDER` is `none`, `ollama`, `openai_compatible` or `anthropic`; the Settings page reflects whatever these resolve to |

Runtime and deployment variables:

| Variable | Default | Purpose |
|---|---|---|
| `JATMP_HOST`, `JATMP_PORT` | `127.0.0.1`, `8000` | Bind address |
| `JATMP_DATA_DIR` | `./data` | Location of `config.json` and the SQLite database |
| `JATMP_DATABASE_URL` | SQLite | For example `postgresql+psycopg://jatmp:secret@db:5432/jatmp` (install `requirements-postgres.txt`) |
| `JATMP_SECURE_COOKIES` | `0` | Set to `1` behind HTTPS: `Secure` session cookie and HSTS |
| `JATMP_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxies allowed to set `X-Forwarded-*` (client IP in the audit log) |
| `JATMP_PUBLIC_URL` | empty | Public base URL used for links in API output, webhooks and MISP events |

## Extending the knowledge base

Malware families and actors can be added without touching code. Create `data/knowledge_extra.json`:

```json
{
  "malware": {"WhiteArmor": {"category": "ransomware", "aliases": ["white armor"]}},
  "actors":  {"UNC9999": {"aliases": ["some alias"], "category": "nation-state"}}
}
```

An actor's `category` is optional and feeds the dashboard's *Threat actors by type* chart: `nation-state`,
`ransomware`, `extortion` or `cybercrime`. Actors without one count as unclassified.

Restart, then run `python manage.py reextract` to reprocess existing items.
