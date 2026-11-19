# Configuration

[← Documentation index](README.md)

API keys and options are managed under **Settings**, which requires the admin role. You can also put them in a
`.env` file next to `run.py` (see `.env.example`), which is loaded automatically. A value set through an
environment variable takes precedence over the interface, and Settings shows it as locked.

## API keys

Every provider is optional. JATMP uses whichever ones you configure and skips the rest.

| Service | Variable | Notes |
|---|---|---|
| VirusTotal | `VT_API_KEY` | The free tier allows 4 requests a minute and 500 a day. JATMP keeps to both (`vt_min_interval`, `vt_daily_budget`) |
| AlienVault OTX | `OTX_API_KEY` | Free. Subscribe to pulses or users on OTX, so that the "subscribed" feed has content |
| urlscan.io | `URLSCAN_API_KEY` | The Search API needs a key |
| ANY.RUN | `ANYRUN_API_KEY` | Needs a plan that includes TI Lookup; the base URL can be changed in Settings. The TI Lookup endpoint (`/v1/intelligence/api/search`) hasn't been tested against a real key yet, so the parser is written defensively |
| abuse.ch ThreatFox | `ABUSECH_AUTH_KEY` | Free (an Auth-Key from auth.abuse.ch) |
| abuse.ch MalwareBazaar, URLhaus | `ABUSECH_AUTH_KEY` | The same free Auth-Key as ThreatFox |
| NVD | `NVD_API_KEY` | Optional. CISA KEV, FIRST EPSS and the NVD all work without a key; with one, CVSS lookups are faster (50 per run instead of 10). CVE lookups can be switched off entirely under Settings → Enrichment |
| GreyNoise Community | `GREYNOISE_API_KEY` | Free, with a small daily quota (`greynoise_daily_budget`, default 40) |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | The free tier allows 1,000 checks a day (`abuseipdb_daily_budget`, default 900) |
| ransomware.live | `RANSOMWARELIVE_API_KEY` | A free PRO key, required for use by organisations. Without it, JATMP uses the personal-use API (one request per minute per endpoint) |
| Hudson Rock Cavalier | `HUDSONROCK_API_KEY` | A free key, used for the infostealer deep dive |
| Shodan | `SHODAN_API_KEY` | Optional. Without a key, the free InternetDB is used (once you allow keyless context lookups) |
| Censys | `CENSYS_API_TOKEN`, `CENSYS_ORG_ID` | A Platform personal access token; free accounts get a small monthly credit |
| CrowdSec CTI | `CROWDSEC_API_KEY` | Free tier |
| Pulsedive | `PULSEDIVE_API_KEY` | Free tier |
| Hybrid Analysis | `HYBRID_ANALYSIS_API_KEY` | A free (vetted) account |
| IPinfo | `IPINFO_TOKEN` | A free Lite token. Without one, the keyless endpoint is used (once you allow keyless lookups) |
| Offline GeoIP | `MAXMIND_LICENSE_KEY` | Optional. *Download GeoIP database* (Settings → General) or `manage.py geoip-update` fetches the DB-IP IP to Country Lite database (no account needed, CC BY 4.0) into `data/geoip/`. With a MaxMind key it fetches GeoLite2 Country instead. A monthly refresh can be switched on in Settings |
| MISP | `MISP_URL`, `MISP_API_KEY` | The automation key of a MISP user. Distribution, sharing group, TLS verification and auto-push are under Settings → MISP |
| X / Twitter | `X_BEARER_TOKEN` | API v2 is a paid service. Alternatively, set `rss_bridge` on each X source |
| Telegram (optional) | `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_SESSION` | Not needed for public channels with a web preview. For MTProto you need an application from my.telegram.org, `requirements-telegram.txt`, and a one-off `python manage.py telegram-login` (see [Sources](sources.md#telegram)) |
| AI model | `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | Optional. `LLM_PROVIDER` is `none`, `ollama`, `openai_compatible` or `anthropic`, and the Settings page reflects whatever these resolve to. With a cloud model, personal data is replaced before prompts are sent (*Personal data in prompts*, see [AI processing](how-it-works/ai.md#what-leaves-your-network)) |

How JATMP paces these providers, and how you can see what is left of each daily budget, is explained in
[Enrichment and verdicts](how-it-works/enrichment.md#providers).

## Runtime and deployment

| Variable | Default | Purpose |
|---|---|---|
| `JATMP_HOST`, `JATMP_PORT` | `127.0.0.1`, `8000` | The address and port JATMP listens on |
| `JATMP_DATA_DIR` | `./data` | Where `config.json` and the SQLite database live |
| `JATMP_DATABASE_URL` | SQLite | For example `postgresql+psycopg://jatmp:secret@db:5432/jatmp` (install `requirements-postgres.txt` first) |
| `JATMP_SECURE_COOKIES` | `0` | Set to `1` behind HTTPS, for a `Secure` session cookie and HSTS |
| `JATMP_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxies that may set `X-Forwarded-*` headers (so the audit log shows the real client IP) |
| `JATMP_PUBLIC_URL` | empty | The public address of JATMP, used for links in API output, webhooks and MISP events |
| `JATMP_PRIVATE_HOSTS` | empty | Private hosts JATMP may contact, as comma-separated host names or IP ranges (`ollama, misp.internal, 10.20.0.0/16`). Otherwise feeds, providers, the AI and MISP can only reach public addresses; see [Security](security.md) |
| `JATMP_TIMEZONE` | `UTC` | The time zone of the daily schedule, as an IANA name such as `Asia/Jakarta`. The same as *Time zone of the daily schedule* under Settings → General |

## Daily schedule

Two jobs run once a day: the AI executive summary (`digest_time`, default 06:00) and housekeeping
(`housekeeping_time`, default 03:30). Both times are read in the time zone set under Settings → General
(`schedule_timezone`, or `JATMP_TIMEZONE`), which is UTC by default.

For a team in Indonesia, choose `Asia/Jakarta` (WIB), `Asia/Makassar` (WITA) or `Asia/Jayapura` (WIT), and for
example 07:00 for the summary. If you enter a zone name or time JATMP doesn't recognise, it keeps the previous
value. The General tab shows when both jobs will next run. Times shown elsewhere on the pages stay in UTC.

## Sharing new sources

When you add a source, the form asks for its TLP and tells you whether its items will be shared outside JATMP. A
source without a TLP counts as CLEAR, so its items are shared (up to the maximum TLP set under Settings →
Sharing, GREEN by default). Settings → Sharing also shows how many sources have no TLP. See
[Sharing and delivery](how-it-works/sharing.md#1-tlp).

## Extending the knowledge base

You can add malware families and threat actors without touching the code. Create `data/knowledge_extra.json`:

```json
{
  "malware": {"WhiteArmor": {"category": "ransomware", "aliases": ["white armor"]}},
  "actors":  {"UNC9999": {"aliases": ["some alias"], "category": "nation-state"}}
}
```

An actor's `category` is optional. It feeds the dashboard's *Threat actors by type* chart and can be
`nation-state`, `ransomware`, `extortion` or `cybercrime`; actors without one count as unclassified.

Restart JATMP, then run `python manage.py reextract` so that existing items are checked for the new names.
