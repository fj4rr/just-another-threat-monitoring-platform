# JATMP — Just Another Threat Monitoring Platform

[![CI](https://github.com/fj4rr/just-another-threat-monitoring-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/fj4rr/just-another-threat-monitoring-platform/actions/workflows/ci.yml)

A self-hosted platform for tracking new and emerging malware campaigns.
It combines **cybersecurity news**, **social media** (X, Bluesky, Mastodon) and **threat-intel platforms**
(VirusTotal, AlienVault OTX, urlscan.io, ANY.RUN, ThreatFox), cross-enriches the data between them, and shows
the result on a trend dashboard. Optionally, a local or API-hosted LLM adds extra insight.

Single process, SQLite by default, no JavaScript build step, no external CDN at runtime.

## Screenshots

Dashboard: threat radar, KPIs with sparklines, headline ticker, collection volume, trending families.

![Dashboard](docs/screenshots/dashboard.png)

| Malware family page: timeline, indicators, coverage per source, co-occurring CVEs/actors | Item page: content, extracted entities, correlated items from other sources |
|---|---|
| ![Entity page](docs/screenshots/entity.png) | ![Item page](docs/screenshots/item.png) |

| Feed: sortable table (severity, title + entities, source type, time) | IOC table with verdicts, attributed families and where each indicator was seen |
|---|---|
| ![Feed](docs/screenshots/feed.png) | ![IOCs](docs/screenshots/iocs.png) |

| Malware families: sortable columns, trend score, mentions by type | AI settings: local or cloud, vendor presets, live model list |
|---|---|
| ![Malware families](docs/screenshots/malware.png) | ![AI settings](docs/screenshots/settings.png) |

| Report builder: period, sections and CSV / Markdown / Word / PDF output |
|---|
| ![Report builder](docs/screenshots/reports.png) |

<img src="docs/screenshots/mobile.jpg" alt="Mobile dashboard" width="300">

## Features

| Area | What you get |
|---|---|
| **News sources** | The Hacker News, Cyber Security News, BleepingComputer, SecurityWeek, The Record, Dark Reading, The DFIR Report, Unit 42, Malwarebytes Labs, SANS ISC, Krebs on Security, Cisco Talos, Securelist, Microsoft Security — add any other RSS feed from the UI |
| **Bluesky** (public API, no key) | vx-underground, Marcus Hutchins, MalwareHunterTeam, Kevin Beaumont, Catalin Cimpanu, Will Thomas (BushidoToken), Zack Whittaker, Lorenzo Franceschi-Bicchierai, Dan Goodin, Karsten Hahn, hasherezade, Silas Cutler, Shadowserver, The DFIR Report, ESET Research, Cisco Talos, SentinelLABS, GreyNoise, Huntress, Ransomware.live |
| **Mastodon** (public API, no key) | Marcus Hutchins, Brian Krebs, Brad Duncan (malware-traffic), SANS ISC, Proofpoint Threat Insight, Thomas Roccia, ffforward, Matt Taggart, Kevin Beaumont |
| **X / Twitter** (API v2 bearer token **or** an RSS bridge) | Enabled: vxunderground, MalwareTechBlog, malwrhunterteam. Available but **disabled** by default (enable them in Settings so the API quota isn't burned unintentionally): GossiTheDog, cyb3rops, 1ZRR4H, BushidoToken, TheDFIRReport, Unit42_Intel, abuse_ch, malware_traffic, ESETresearch, MsftSecIntel, executemalware, pr0xylife, g0njxa, Max_Mal_, RedDrip7, fr0gger_, StopMalvertisin, ViriBack, Fox_threatintel, FalconFeedsio, H4ckManac, anyrun_app, ffforward |
| **Threat-intel collectors** | OTX subscribed pulses / search, urlscan.io search, ANY.RUN TI Lookup query, latest ThreatFox IOCs |
| **Entity extraction** | Malware families (~150 families + aliases), threat actors (~45), CVEs, ATT&CK techniques, IOCs (IP, domain, URL, MD5/SHA1/SHA256 — including *defanged* ones such as `hxxp`, `[.]`, `[:]`, `[://]`, `\.`, `(dot)`). Detects **new** families that are not in the knowledge base yet (patterns like “`PipeMagic backdoor`”); legitimate tools that get abused (ConnectWise, AnyDesk…) are never promoted to families. Hashes inside URLs (commit SHAs, tracking ids) and version numbers that look like IPs are ignored; ~200 vendor / media / platform domains are never indicators |
| **Severity (explainable)** | Every item gets a 0–100 score built from signal groups (exploitation, impact, threat class, activity) plus the entities found. Title hits weigh ×1.5; patch notes, roundups/guides and routine leak-site victim posts are damped; confirmed-malicious indicators raise the score later. The item page shows the full breakdown (“why 72?”) |
| **Cross-source enrichment** | IOCs found in news and social posts are checked against VirusTotal, OTX, urlscan and ANY.RUN → consensus verdict plus attributed family (e.g. a hash from a Bluesky post → “Lumma Stealer” from VT), which links it to other articles about that family. OTX-whitelisted infrastructure is marked clean, a lone OTX pulse hit is only *suspicious*, failed lookups are retried, *unknown* results are re-checked after 3 days, and verdicts feed back into item severity. IOCs for trending families are pulled from OTX & ANY.RUN (only pulses that actually name the family) |
| **Correlation** | Item pages rank related items by evidence strength: a shared hash/URL/domain weighs far more than a shared CVE, rare entities more than common ones, other sources and other source *types* get a bonus, and the shared entities are listed. Entity pages show per-source coverage, co-occurrence, related IOCs and enrichment results |
| **Reports** | Report builder: pick a period (quick range or exact dates), the sections (overview, trending families, actors, CVEs, indicators with verdicts, notable items with their severity reasons, new families, latest AI digest) and download **CSV**, **Markdown**, **Word (.docx)** or **PDF** |
| **Dashboard** | Animated: a *threat radar* (trending families as blips that light up as the sweep passes; closer to the centre = hotter), count-up KPIs with sparklines, a headline ticker, staggered card entrance, animated charts, 60-second auto-refresh (respects *prefers-reduced-motion*). Content: KPIs, volume per source type, trending families (score = 7-day rate vs 30-day baseline × source spread), top-5 family timeline, most-mentioned families, malware by type, IOC verdicts, items per source, hottest actors & CVEs |
| **AI (optional)** | Per-item summary + extraction, *threat brief* per family/actor, automatic *daily digest* at 06:00 UTC, Q&A over the collected data. Set-up is a three-way choice — **Off / Local / Cloud** — then a vendor (Local: Ollama, LM Studio, llama.cpp, vLLM, Jan, any OpenAI-compatible server · Cloud: Anthropic, OpenAI, OpenRouter, Groq, Gemini, Mistral, DeepSeek, xAI, Together, any OpenAI-compatible API) and a model picked from the live list the server/provider reports. Output language is configurable (e.g. *Bahasa Indonesia*) |
| **Install modes** | **Single-user** (no login) or **multi-user** (login, admin/analyst/viewer roles, admin dashboard: user management, job status, audit log, system stats) |
| **Other** | Sortable tables everywhere (feed included), per-family IOC lists, per-user watchlist, dark/light theme, keyboard shortcut `/` for search, mobile layout, data retention, Docker with health check |

## Quick start (local)

```bash
python -m venv .venv
```
```bash
.venv\Scripts\activate        # Linux/macOS: source .venv/bin/activate
```
```bash
pip install -r requirements.txt
```
```bash
python install.py             # interactive: choose single / multi user, API keys, LLM
```
```bash
python run.py                 # open http://127.0.0.1:8000
```

Or skip `install.py`: on first launch the web UI shows the same **setup wizard**.
Non-interactive: `python install.py --mode multi --admin admin --password 'StrongPassw0rd'`.

> The web wizard requires no login (no users exist yet). Run the first install on `127.0.0.1`
> (the default) before exposing the port to a network.

### Docker

```bash
cp .env.example .env
```
```bash
docker compose up -d --build
```

The container exposes `/healthz` and ships a `HEALTHCHECK`. Local LLM in a container:
`docker compose --profile llm up -d`, then `docker compose exec ollama ollama pull llama3.1`
and set the base URL to `http://ollama:11434`.

## Configuration

All API keys and options can be set under **Settings** (admin role). A `.env` file next to `run.py`
(see `.env.example`) is loaded automatically; environment variables override the UI and are shown as locked there.

| Service | Key | Notes |
|---|---|---|
| VirusTotal | `VT_API_KEY` | Free tier is 4 req/min, 500/day — already throttled (`vt_min_interval`, `vt_daily_budget`) |
| AlienVault OTX | `OTX_API_KEY` | Free. Subscribe to pulses/users on OTX so the “subscribed” feed has content |
| urlscan.io | `URLSCAN_API_KEY` | The Search API now requires a key |
| ANY.RUN | `ANYRUN_API_KEY` | Requires a plan with **TI Lookup**. The base URL can be changed in Settings |
| abuse.ch ThreatFox | `ABUSECH_AUTH_KEY` | Free (Auth-Key from auth.abuse.ch) |
| X / Twitter | `X_BEARER_TOKEN` | API v2 is paid; alternatively set `rss_bridge` on each X source |

Runtime / deployment variables:

| Variable | Default | Purpose |
|---|---|---|
| `JATMP_HOST`, `JATMP_PORT` | `127.0.0.1`, `8000` | Bind address |
| `JATMP_DATA_DIR` | `./data` | Where `config.json` and the SQLite DB live |
| `JATMP_DATABASE_URL` | SQLite | e.g. `postgresql+psycopg://jatmp:secret@db:5432/jatmp` (install `psycopg[binary]`) |
| `JATMP_SECURE_COOKIES` | `0` | Set to `1` behind HTTPS: `Secure` session cookie + HSTS |
| `JATMP_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxies allowed to set `X-Forwarded-*` (client IP in the audit log) |

### Adding malware families / actors without code changes

Create `data/knowledge_extra.json`:

```json
{
  "malware": {"WhiteArmor": {"category": "ransomware", "aliases": ["white armor"]}},
  "actors":  {"UNC9999": {"aliases": ["some alias"]}}
}
```

Restart, then run `python manage.py reextract` to reprocess existing items.

### After upgrading to 0.3

Scores and their breakdowns are computed on ingest. Existing items keep their old score until you run
`python manage.py rescore` (or press **Re-score all items** in Settings → General); this is a local,
network-free pass over the database. The new `severity_detail` column is added automatically on start-up.

## Security notes

- **Strict Content-Security-Policy**: scripts only from the app's own origin plus a per-request nonce for the
  few inline blocks; no inline event handlers; Chart.js is vendored (`app/static/js/vendor`), so the UI works
  air-gapped. `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP and
  `Cache-Control: no-store` are set on every page.
- **Untrusted feed content**: HTML is stripped and entities decoded on ingest; item URLs are only kept when
  they are `http(s)` (a feed cannot smuggle a `javascript:` link into the UI); markdown from the LLM is
  rendered with raw HTML disabled.
- **Sessions & auth**: signed cookie sessions (`SameSite=Lax`, `HttpOnly`), CSRF synchronizer tokens on every
  POST, PBKDF2-HMAC-SHA256 with 600k iterations (older hashes are upgraded on login), 5 failed logins per
  username+IP lock the account for 15 minutes, open-redirect-safe `next` handling, session reset on login.
- **Settings hygiene**: secret values are never sent back to the browser (only “configured” / “not set”),
  integer settings are clamped (you cannot accidentally disable the VirusTotal throttle), source URLs must be
  `http(s)`.
- API keys set through the UI live in the local database. On shared hosts prefer environment variables, which
  lock the field in the UI. `data/config.json` holds the session secret and is written with mode `0600`.
- Run behind a TLS-terminating reverse proxy when exposing the platform beyond localhost and set
  `JATMP_SECURE_COOKIES=1`.

## Maintenance commands

```bash
python manage.py collect          # run every collector now (or: collect 1 5 7)
python manage.py enrich           # run one enrichment batch
python manage.py digest           # generate the AI digest now
python manage.py reextract        # re-extract entities on every item
python manage.py rescore          # recompute severity with the current rules (also a button in Settings → General)
python manage.py seed-sources     # add new built-in sources to an existing install (also a button in Settings)
python manage.py create-user alice analyst
```

## Development

```bash
pip install -r requirements-dev.txt
```
```bash
ruff check .
```
```bash
pytest
```

Tests run against a throw-away SQLite database (no network, no scheduler) and cover the extractor,
severity scoring, enrichment consensus, feed sorting, the AI settings mapping, the report builder (all four
formats), password/CSRF/redirect handling, feed sanitisation, the settings form and the multi-user login flow.
GitHub Actions runs lint + tests on Python 3.11 and 3.12 and builds the Docker image.

## Architecture

```
app/
  collectors/   rss, bluesky, mastodon, x_twitter, intel (OTX, urlscan, ANY.RUN, ThreatFox)  → RawItem
  processing/   pipeline (dedupe, sanitise, store, link entities) · extractor (IOC/CVE/family/actor)
                severity (explainable 0–100 score) · enrichment (cross-source, consensus, re-checks)
                trends (dashboard aggregations, weighted correlation)
  intel/        API clients: VirusTotal, OTX, urlscan, ANY.RUN, ThreatFox (+ rate limits/budgets)
  llm/          client (Ollama / OpenAI-compatible / Anthropic, live model list) · presets (local/cloud vendors)
                insights (summary, brief, digest, Q&A)
  reports.py    report builder: gather() + CSV / Markdown / Word / PDF exporters
  routers/      pages, api (JSON + actions), settings, reports, admin, auth/setup
  jobs.py       APScheduler: one job per source, enrichment every N minutes, daily digest, housekeeping
  static/       app.css (theme tokens, dark/light) · app.js (CSP-safe behaviours, charts) · motion.js (radar, sparklines)
data/           config.json (install mode, secret), jatmp.db (SQLite)
tests/          pytest suite
```

The default database is SQLite (WAL mode). For larger deployments set `JATMP_DATABASE_URL` to PostgreSQL.
Run a single web worker: the scheduler lives in-process (scale collection by adjusting source intervals).

## Changelog

### 0.3.0

- **Severity rewritten** (`app/processing/severity.py`): grouped signals instead of a flat keyword sum (strongest
  term per group, runner-up at half weight), title matches ×1.5, dampeners for patch notes / roundups / non-incident
  news, a cap for routine leak-site victim posts, entity signals (unknown family, actor, CVE count, indicator count,
  ATT&CK), and a stored breakdown shown on the item page. `manage.py rescore` / Settings → General re-score
  existing items.
- **Extraction**: more defang styles (`[:]`, `[://]`, `\.`, `(dot)`, `fxp`), hashes embedded in URLs and
  tracking ids are skipped, version numbers that look like IPs (`Chrome 131.0.6778.85`, `v1.2.3.4`) are skipped,
  a much larger benign-domain list, and a denylist of legitimate tools (ConnectWise, AnyDesk, PsExec…) for the
  new-family heuristic.
- **Enrichment**: provider consensus (a lone OTX pulse hit is *suspicious*, not malicious; OTX whitelist →
  clean), lookups that all failed are retried after 6 h instead of being marked done forever, *unknown* IOCs are
  re-checked after 3 days, confirmed verdicts raise the severity of the items that mention the IOC, family
  attribution ignores ambiguous tokens (`play`, `hook`…), OTX family searches only accept pulses that name the
  family, fewer secondary urlscan IPs are created.
- **Correlation**: related items are ranked by evidence strength (type weight ÷ log mentions, other-source bonus)
  and list the shared entities.
- **Feed** is a real table with sortable Severity / Title / Source / Time headers; the separate sort buttons are
  gone. Dashboard KPI tiles keep the icon link only (no duplicate “feed →” text links).
- **AI settings** reduced to Off / Local / Cloud + vendor + model, with presets for 6 local runtimes and 10 cloud
  providers, a live “Load models” list, and an advanced base-URL override. The classic `LLM_PROVIDER` /
  `LLM_BASE_URL` / `LLM_MODEL` variables still work and are reflected in the new UI.
- **Report builder** (`/reports`): period, sections, indicator verdict filter, CSV / Markdown / Word / PDF.
- Fix: modal popovers (source edit, severity breakdown) opened inside their card after the entrance animation
  (an identity transform made the card the containing block).
- New dependencies: `python-docx`, `reportlab` (Word / PDF export).

### 0.2.1

- Sortable columns on the Malware / Threat actors / CVEs / IOCs tables; feed can be sorted by time or severity
  and labels the severity column; IOC table shows where each indicator was seen; family/actor pages get an
  Indicators card with a link to all related IOCs (`/iocs?entity=ID`).
- Dashboard: KPI tiles link to their detail pages, radar explains placement with an axis key instead of a
  sentence, "All families" is a button, items-per-source chart shows the top 12 with readable labels.
- Chrome: new radar logo, brand links home, back button, burger menu only on small screens, "Add source"
  moved above the table as a full-width panel, credits in the sidebar.

### 0.2.0

- Security: CSP with nonces, vendored Chart.js, no inline handlers, extra response headers, HSTS/Secure
  cookie switch, PBKDF2 600k with transparent upgrade, open-redirect hardening, source URL scheme checks,
  secret values no longer rendered into Settings, clamped numeric settings and query parameters.
- Bug fixes: `.env` was never loaded outside Docker; feed URLs with `javascript:` scheme reached `<a href>`;
  HTML entities in feeds were dropped instead of decoded; future-dated items showed “in 3h”; deprecated
  `datetime.utcnow()` usage; `canonical_malware` rebuilt the knowledge table on every call; per-entry
  duplicate checks on ingest; N+1 queries on the watchlist; mention counts left stale after retention cleanup.
- UX: no horizontal overflow on phones (dashboard glow extended past the viewport), modal popovers for source edit / password reset (usable on mobile), mobile sidebar with backdrop and
  Escape, “Remove” checkbox for secrets instead of typing `__clear__`, Reset buttons on filters, `/` focuses
  search, ARIA labels, skip link, focus rings, labelled inputs, grouped source list, radar blips fan out when
  scores tie, friendlier empty states.
- Tooling: pytest suite, ruff config, GitHub Actions CI, `.dockerignore`, Docker health check, `/healthz`.

## Credits

Built and maintained by [**fj4rr**](https://github.com/fj4rr) · [github.com/fj4rr/just-another-threat-monitoring-platform](https://github.com/fj4rr/just-another-threat-monitoring-platform).
Issues and pull requests are welcome.

## Notes

- All Bluesky & Mastodon accounts above were verified active on 12 Nov 2026. Exceptions: `vxunderground.bsky.social`
  has no posts yet, and Marcus Hutchins / MalwareHunterTeam rarely post on Bluesky — their main activity is on X
  (and Marcus is also on Mastodon). X handles can't be verified without an API token.
- The ANY.RUN TI Lookup endpoint (`/v1/intelligence/api/search`) has not been tested against a real key, and the
  official documentation could not be checked while writing it; the parser is defensive and the base URL is configurable.
- The severity score is a heuristic (signal groups + entity types, see `app/processing/severity.py`); the item page
  shows the breakdown, enrichment raises it when an indicator is confirmed malicious, and the LLM can raise it during
  analysis. Treat it as triage order, not as a CVSS-like absolute.
- Model names in the AI presets are suggestions that were current when this version was written; use **Load models**
  to see what your server or provider actually offers.
