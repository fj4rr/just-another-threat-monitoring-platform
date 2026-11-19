# Architecture

[← Documentation index](README.md)

This page explains how JATMP is put together: the process model, what happens on start-up and on every request,
how an item travels from a feed into the database, how background jobs work, and where each concern lives in the
code. The tables and columns are described in [Data model](data-model.md); step-by-step recipes for common
changes are in [Extending JATMP](extending.md). The behaviour of each process — the exact rules, weights,
thresholds and timings — is described in [How it works](how-it-works/index.md).

## The big picture

JATMP is a single Python process: a FastAPI web application with an APScheduler `BackgroundScheduler` running in
the same process. There is no message queue, no separate worker and no front-end build step.

```
browser, API client
        │ HTTP
        ▼
┌─ one process: run.py → uvicorn ──────────────────────────┐
│                                                           │
│  FastAPI: middleware → routers → Jinja2 pages / JSON      │
│        │                                                  │
│        ▼                                                  │
│  SQLAlchemy ◀──▶ SQLite (WAL) or PostgreSQL               │
│        ▲                                                  │
│        │                                                  │
│  APScheduler threads                                      │
│    ├─ collectors → pipeline.ingest                        │
│    │     → extractor, severity, fraud, sectors, geo       │
│    ├─ enrichment → intel providers → consensus            │
│    └─ CVE intel, summary, housekeeping, webhooks,         │
│       one-off re-analysis                                 │
│        │                                                  │
│        ▼                                                  │
│  app/netguard.py: every outbound request                  │
│  (SSRF guard, size cap)                                   │
└────────┼──────────────────────────────────────────────────┘
         ▼
     internet: feeds, providers, AI, MISP
```

Consequences of this design that every change has to respect:

- **One web worker.** The scheduler lives in the process, so running two workers would run every collector
  twice. Scale collection by source intervals, not by workers.
- **Threads, not processes.** Collectors and enrichment run in the scheduler's thread pool (10 threads). A job
  that blocks (a slow provider, a regex that backtracks) holds one of those threads; it cannot be killed. Keep
  network timeouts short, keep regular expressions linear (see [Security](security.md)), and push slow side work
  (AI summaries) into a job of its own.
- **One writer on SQLite.** WAL mode lets the web pages read while a job writes, but writes are serialised.
  Long jobs commit in chunks (usually 200–500 rows) so that pages and other jobs are not blocked for long.
- **In-process caches are per process.** The settings cache (5 s), the trending cache (45 s), API-key rate
  windows and manual-action throttles live in memory and reset on restart.

## Start-up sequence

`app/main.py` defines the FastAPI app and a `lifespan` handler. On start:

1. `init_db()` (`app/db.py`) creates missing tables, adds missing columns and indexes
   (`_add_missing_columns`, see [Database and migrations](#database-and-migrations)) and sets up full-text search
   (`app/search.py`).
2. If the install is not finished (`data/config.json` has `installed: false`), the setup token is announced in
   the log (`app/setup_token.py`) and nothing else starts. Every request except `/setup`, `/static` and `/healthz`
   is redirected to the wizard.
3. Otherwise:
    - new built-in sources are added (`setup_service.auto_seed_sources`);
    - secret settings written in plain text by older versions are encrypted
      (`settings.encrypt_stored_secrets`);
    - private hosts the admin already configured are put on the outbound allow-list once
      (`netguard.seed_allowlist`);
    - `jobs.start()` schedules one job per enabled source, the periodic jobs and the one-off re-analysis jobs,
      then starts the scheduler.

The same `perform_install()` (`app/setup_service.py`) is used by the wizard, by `install.py` and by the test
suite's `installed` fixture.

## Request lifecycle

1. **`SessionMiddleware`** (outermost) decodes the signed `jatmp_session` cookie into `request.session`. Sessions
   are stateless: the cookie holds `uid`, `sv` (session version), `csrf` and a few UI choices (dashboard period,
   region).
2. **`setup_guard` middleware** redirects to `/setup` before installation, creates the per-request CSP nonce
   (`request.state.csp_nonce`) and adds the security headers to the response (CSP, `X-Frame-Options`, `nosniff`,
   `Referrer-Policy`, `Permissions-Policy`, COOP, `Cache-Control: no-store`, HSTS when
   `JATMP_SECURE_COOKIES=1`).
3. **Router dependencies** (`app/auth.py`):
    - `current_user` returns the built-in local user in single-user mode; in multi-user mode it loads the user
      from the session and rejects disabled users and sessions whose `sv` no longer matches
      `users.session_version` (raises `LoginRequired`, which an exception handler turns into a redirect to
      `/login?next=…`).
    - `require("viewer" | "analyst" | "admin")` checks the role on top of that.
    - `verify_csrf` checks the synchroniser token on every non-GET request: the `X-CSRF-Token` header (sent by
      `app.js` for `data-post` buttons) or the `csrf_token` form field.
    - The REST API uses `api_v1.principal(scope)` instead: a Bearer (or Basic) API key with the right scope, or
      the browser session.
4. **The handler** works with a SQLAlchemy session from `get_db()` (closed after the request) and returns either
   `web.render(request, "page.html", ctx)` or a dict (JSON).
5. **`web.render`** adds what every template needs: `app_name`, `multi_user`, `csrf`, `nonce`, `path`, `region`.
   Templates extend `base.html`; inline `<script>` blocks must carry `nonce="{{ nonce }}"` or the CSP blocks them.

Everything that leaves JATMP (REST API, IOC feeds, STIX / TAXII, webhooks, MISP pushes) goes through the rules in
`app/sharing.py` (TLP, redistribution) and never includes scammer identifiers (`fraud.IDENT_TYPES`).

## From a feed to the database

### 1. Collection

`jobs.run_source(source_id)` is scheduled every `interval_minutes` per enabled source (and queued by *Run now* /
*Collect now*). It looks up the collector class by `Source.kind` in `collectors.REGISTRY`, calls
`fetch() -> list[RawItem]`, and records the run as a `CollectorRun` row (`running` → `ok`, `skipped` or
`error`). A collector raises `SkipCollector` when it cannot run for a known reason (no API key); that is not an
error and does not notify.

`RawItem` (`app/processing/pipeline.py`) is the only thing collectors produce:

| Field | Meaning |
|---|---|
| `external_id` | Stable id of the entry within its source (GUID, post URI, pulse id). The dedup key. |
| `title`, `url`, `author`, `content`, `published_at` | As the provider gives them. `content` of `kind="article"` is HTML and gets stripped; posts are already text. |
| `kind` | `article`, `post`, `pulse`, `scan` or `analysis`. Affects stripping, dedup across sources (articles only) and severity. |
| `tags` | Provider tags (OTX tags, hashtags). On intel sources they may name malware families. |
| `raw` | Small provider metadata kept on the item (`tlp`, `sector`, `industries`, `listed_by`…). Bulky copies of the content are dropped. |
| `indicators` | IOCs the feed delivers as structured data (pulse indicators, blocklist entries), already typed. |

### 2. Ingest

`pipeline.ingest_committed()` wraps `ingest()` in a transaction and retries on `IntegrityError` (the scheduled
collector and a backfill may store the same entry at the same moment). For every new `RawItem`, `ingest()`:

1. **Skips duplicates** of the same source: one query for the whole batch on `(source_id, external_id)`.
   External ids longer than 500 characters are shortened with a SHA-256 so they stay unique. An entry that is
   already stored but carries a `merge_title` (ThreatFox's one item per family and day) has its new indicators
   added to the stored item instead (`merge_indicators`), which is then re-scored.
2. **Sanitises**: `strip_html` (scripts, tags, entities, stray stylesheet rules) for articles, `safe_url` (only
   `http(s)` links), length limits, future dates clamped to now.
3. **Fingerprints articles** (`fingerprint()`: normalised title without the outlet suffix, plus the start of the
   text for short titles) and marks a syndicated copy of another source's article from the last four days with
   `dup_of`.
4. **Extracts entities** (`extractor.extract_all`): IOCs (refanged, strict mode for news: only defanged
   indicators or link targets count), CVEs, ATT&CK techniques, known families and actors from the knowledge base,
   new family names by pattern ("Zorblax ransomware", Indonesian "ransomware Zorblax"); plus the feed's
   structured indicators and family names from intel-feed tags (`tag_families`).
5. **Scores severity** (`severity.score_item`): explainable 0–100 with reasons, see [Analysis](analysis.md).
6. **Fraud analysis** (`fraud.apply`): scam types, impersonated brands, scammer identifiers, losses, victims and
   the fraud score, see [Scams and fraud](fraud.md).
7. **Sectors** (`sectors.apply`): critical infrastructure sectors.
8. **Links entities** (`link_entities`): one lookup query per entity type, new entities created in one flush,
   `ItemEntity` rows with the `origin` of each extraction, `mention_count` and `first_seen` / `last_seen`
   maintained.
9. **Blocklist verdicts** (`mark_listed`) for curated lists such as ScamSniffer.
10. **Geography** (`geo.tag_item`): language, source country, target countries and Indonesian provinces.

After the commit the trending cache is cleared, and `jobs._after_ingest` queues webhook events and the MISP
auto-push; `_maybe_auto_summarize` queues AI summaries for the separate summary job.

### 3. Enrichment

`jobs.run_enrichment` (every `enrichment_interval` minutes) picks indicators that were never checked, are due for
a re-check, or have an aged malicious / suspicious verdict (`verdict_recheck_days`). `enrichment.prefetch` then
looks the whole batch up with one thread per provider, so each provider works at its own pace, and
`enrichment.enrich_entity` applies the answers one indicator at a time: every configured provider in
`PROVIDER_CLASSES` that supports the indicator type answers with a `LookupResult`; results are stored per provider
in `enrichments`, family labels are mapped to known families (`resolve_family`) and linked (`entity_links`), and
the provider verdicts are combined into the entity's verdict (`_consensus`: malicious wins, a lone OTX mention is
only suspicious, GreyNoise "benign" overrides noisy providers) with its date in `verdict_at`. A verdict that rises
adds `severity.VERDICT_BONUS` to the items that mention the indicator and, when it turns malicious, fires the
`ioc.malicious` webhook; a re-checked verdict that falls takes the bonus back (`_sync_bonus`). Trending families
also get fresh IOCs from OTX / ANY.RUN (`enrich_family`). `enrichment.queue_status` and `intel/quota.py` feed the
queue and quota panels. Details: [Enrichment and verdicts](how-it-works/enrichment.md).

## Background jobs

All jobs are functions in `app/jobs.py`.

| Job | Trigger | What it does |
|---|---|---|
| `run_source` | every `interval_minutes` per source; manual | Collect and ingest one source |
| `run_enrichment` | every `enrichment_interval` min; manual | Look up indicators with the providers |
| `run_cve_intel` | every 6 h; manual | CISA KEV, FIRST EPSS, NVD CVSS into `Entity.meta` |
| `run_webhooks` | every 30 s | Deliver queued webhook events with back-off |
| `run_digest` | daily, `digest_time` (default 06:00 UTC) | AI executive summary |
| `run_housekeeping` | daily, `housekeeping_time` (default 03:30 UTC) | Retention (slimming, deletion), identifier pruning, old runs and notifications |
| `run_auto_summaries` | after ingest, when enabled | AI summaries of new high-severity items, one job at a time |
| `run_backfill` | manual | Historical backfill, one source after another |
| `run_source_health` | hourly (first 15 min after start) | Notify about quiet and long-failing sources (`app/sourcehealth.py`) |
| `run_geoip_update` | monthly, when enabled | Refresh the offline GeoIP database |
| One-off re-analysis | 15–90 s after start | See below |

The daily jobs run in the schedule's time zone (`schedule_timezone`, `jobs.schedule_daily_jobs`); they are
rescheduled when the General settings change. At start-up, `requeue_auto_summaries` rebuilds the in-memory
auto-summary queue from the live items of the last 24 hours that still qualify.

**Runs and progress.** Every run is a `CollectorRun` row. Manual runs are created as `queued` rows under a
`batch_id` first, so the UI shows them at once and a second click finds them (`job_running`, `active_batch`).
Progress is kept in memory (`_live`, written by `_progress`) and served by `jobs.status()` to `/api/jobs/status`,
which `app.js` polls. When the last run of a batch finishes, `_maybe_finish_batch` writes one notification for
the whole batch. Runs left `queued` or `running` by a restart are marked `aborted` on the next start.

**Versioned one-off jobs.** When detection rules change, stored items have to be re-analysed once. Each such
job compares a rules version constant with a value in the `settings` table and does nothing when it is up to
date; it runs a few seconds after start and can be forced from the UI or `manage.py`.

| Job | Version constant | Setting | What it redoes |
|---|---|---|---|
| `run_content_cleanup` | `jobs.CONTENT_VERSION` | `content_version` | Text cleaning of stored items |
| `run_geotag` | `geo.GEO_VERSION` | `geo_version` | Language, targets, provinces, IP hosting country |
| `run_dedup` | `jobs.DEDUP_VERSION` | `dedup_version` | Cross-source fingerprints |
| `run_fraudtag` | `fraud.RULES_VERSION` | `fraud_version` | Scam types, brands, identifiers, fraud score |
| `run_sectortag` | `sectors.RULES_VERSION` | `sector_version` | Critical infrastructure sectors |
| `run_rescore_if_outdated` | `severity.RULES_VERSION` | `severity_version` | Severity from text and linked entities, keeping the enrichment bonus and AI assessment (`severity.carry_over`); runs last, at 90 s |

Entity extraction has no automatic job: changing it only affects new items until an admin runs
`python manage.py reextract` (which rebuilds the extracted links and re-scores, also through `carry_over`).

## Outbound HTTP

Every request JATMP makes on its own goes through `netguard.client()` (`app/netguard.py`), directly or through
`Collector.client()`, `intel.clients._client()`, `intel.cve._client()`, `intel.darkweb._client()`, the MISP client,
the LLM client, the GeoIP download and webhook delivery. The client:

- only reaches public addresses; private, loopback and link-local hosts need an entry in the
  `outbound_private_hosts` setting (webhooks use their own `webhooks_allow_private` switch);
- checks every redirect hop, and connects to the address it checked (a custom httpcore network backend), so DNS
  rebinding does not work;
- reads bodies through a response hook that stops after `max_bytes` of *decompressed* data (20 MB by default);
- behind an environment proxy (`HTTPS_PROXY`…) checks the request URL instead, because the proxy resolves the name.

Never call `httpx.get()` or create an `httpx.Client` directly in application code.

## Caches and throttles

| What | Where | Lifetime | Cleared by |
|---|---|---|---|
| Settings values | `settings._cache` | 5 s | `settings.set()` in the same process |
| Trending lists | `trends._trend_cache` | 45 s | New items (`ingest_committed`) |
| API-key rate windows | `apikeys._windows` | 1 min windows | Time |
| Manual-action throttles | `throttle` | per call window | Time; `throttle.reset()` in tests |
| Provider gaps between calls | `intel.clients._Throttle` (reserves a slot under the lock, sleeps outside it) | per provider | Time; restart |
| Provider daily budgets | `intel.clients._budget_ok`, settings `_budget_<provider>` | per provider and day | Day (survive restarts) |
| AI auto-summary queue | `jobs._summary_queue` (at most 200 ids) | until worked off | Rebuilt at start-up (`requeue_auto_summaries`) |
| Knowledge base patterns | `knowledge.compiled_patterns` (`lru_cache`) | process | Restart |

## Database and migrations

- **Engines.** SQLite (default, `data/jatmp.db`, WAL, `foreign_keys=ON`) or PostgreSQL via
  `JATMP_DATABASE_URL` (`postgresql+psycopg://…`). `python manage.py copy-db URL` copies one into the other.
- **Sessions.** `SessionLocal` has `expire_on_commit=False` and `autoflush=False`. Routes get a session from
  `get_db()`; jobs open `SessionLocal()` themselves and close it in `finally`; scripts and tests use
  `session_scope()` (commit on success, rollback on error).
- **String lengths.** A `before_flush` hook trims strings to the column length, because PostgreSQL rejects what
  SQLite accepts.
- **Migrations are forward-only and automatic.** `create_all` creates new tables; `_add_missing_columns` adds
  columns that a model declares but the table lacks (with the column's scalar default, so existing rows get a
  value) and creates every declared index with `checkfirst`. There is no Alembic. Consequences: never rename or
  drop a column in a release, give new columns a default, and write a versioned one-off job when existing rows
  need computed values.
- **Full-text search.** SQLite: an FTS5 table `items_fts` kept in sync by triggers. PostgreSQL: a GIN index on
  `to_tsvector('simple', title || ' ' || content)`. Both are created by `search.ensure_fts()`; queries go through
  `search.item_text_clause()`, which never passes user input into the query syntax.

## Front end

Server-rendered Jinja2 templates in `app/templates/`, one stylesheet (`static/css/app.css`, theme tokens for dark
and light) and plain JavaScript files with no build step. Because of the CSP there are no inline event
handlers; behaviour is attached through attributes handled in `static/js/app.js`:

| Attribute | Behaviour |
|---|---|
| `data-post="/api/…"` | POST with the CSRF header, show the message as a toast, optionally `data-target` (inject HTML), `data-reload`, `data-busy` |
| `data-confirm="…"` | Ask before a form or button submits |
| `data-preview="/items/1/preview"` | Open a partial page in the side drawer (`_preview_item.html`, `_preview_entity.html`) |
| `data-tip="…"` | Explanation tooltip |

Charts use the vendored Chart.js; the radar and sparklines are in `motion.js`, the relationship graph in
`graph.js`, the maps in `geomap.js` and the dashboard globe in `globe.js` (pre-projected outlines in
`static/geo/`, rebuilt by `scripts/build_geo.py`).

## Module map

### Core (`app/`)

| Module | Responsibility |
|---|---|
| `main.py` | FastAPI app, lifespan (start-up sequence), security headers middleware, `/healthz` |
| `config.py` | `data/config.json` (install mode, secret key, database URL), `DATA_DIR`, `.env` loading |
| `db.py` | Engine, sessions, string trimming, `init_db()` and the forward-only migration |
| `models.py` | All tables (see [Data model](data-model.md)), `utcnow()`, the `with_links()` loader option |
| `settings.py` | Runtime settings: `SCHEMA`, environment overrides, 5 s cache, encryption of secret values |
| `auth.py` | Password hashing, login lockout, CSRF, `current_user` / `require`, session versions, `audit()` |
| `web.py` | Jinja2 environment, filters (`md`, `timeago`, `safe_href`, `idr`), `render()` |
| `setup_service.py`, `setup_token.py` | Install (wizard, `install.py`, tests) and the first-run token |
| `netguard.py` | Outbound HTTP client: SSRF guard, connect to the checked address, size cap, private host list |
| `throttle.py` | Per-user rate limits and one-at-a-time guards for manual actions |
| `csvsafe.py` | CSV writer that neutralises spreadsheet formulas |
| `sharing.py` | TLP and redistribution rules for everything that leaves JATMP |
| `apikeys.py` | API key creation, verification, scopes, rate limiting |
| `webhooks.py` | Events, Slack / Discord / Teams formats, HMAC signatures, delivery and retries |
| `stix.py` | STIX 2.1 objects and bundles (served as TAXII 2.1 by `routers/taxii.py`) |
| `reports.py` | *Threat Intel Findings* report: `gather()` and the PDF / Word / Markdown / CSV exporters |
| `backfill.py` | Backfill reach, estimates and storage statistics (the job itself is `jobs.run_backfill`) |
| `search.py` | Full-text search (SQLite FTS5, PostgreSQL GIN) with a `LIKE` fallback |
| `gazetteer.py` | Countries (names, aliases, demonyms), Indonesian provinces, cities, institutions |
| `geoip.py` | Offline GeoIP database (download, lookup) for the hosting country of IPs |
| `knowledge.py` | Malware families and actors with aliases, everyday-word rules, `knowledge_extra.json` |
| `notify.py` | Notification center (de-duplicated by key, per-user read watermark) |
| `sourcehealth.py` | Source health: last new item, this week against usual, usual gap, failing since, summary-only feeds; quiet / failing notifications |
| `corrections.py` | Analyst corrections (wrong entity here / everywhere, analyst verdict, not a scam report): apply, keep in force, undo, statistics |
| `quality.py` | Precision / recall of the detection rules on `tests/quality/`, corrections as test cases, the CI baseline |
| `jobs.py` | Scheduler, every job, runs, batches, progress, `status()` |
| `dbcopy.py` | `copy-db` between database engines |

### Packages

| Package | Contents |
|---|---|
| `collectors/` | `base.Collector` and one module per source kind; `REGISTRY` and `DEFAULT_SOURCES` in `__init__.py` |
| `processing/` | `pipeline` (ingest), `extractor`, `severity`, `fraud`, `fraudstats`, `sectors`, `geo`, `enrichment`, `trends`, `graph`, `topics` (the topic filters of every news and social source) |
| `intel/` | Provider clients (`clients.py`), `quota` (daily budgets used and their pace), `context` lookups, `darkweb` deep dives, `cve` intel, `misp` push and pull |
| `llm/` | `client` (Ollama, OpenAI-compatible, Anthropic), `presets` (vendors), `insights` (summaries, briefs, executive summary, Q&A), `retrieval` (which items answer a question), `redact` (personal data out of cloud prompts) |
| `routers/` | `pages`, `fraud_pages`, `api` (JSON for the UI and actions), `api_v1` (REST API), `taxii`, `settings_routes`, `reports_routes`, `backfill_routes`, `admin`, `auth_routes` (setup, login, profile), `apikeys_routes`, `webhooks_routes` |
| `templates/` | Pages and partials (`_macros.html`, `_preview_*.html`, `_fraud_row.html`…) |
| `static/` | `css/app.css`, `js/` (`app.js`, `motion.js`, `graph.js`, `geomap.js`, `globe.js`, `vendor/chart.umd.min.js`), `geo/`, `img/` |

### Repository root

| Path | Purpose |
|---|---|
| `manage.py` | Maintenance CLI, see [Maintenance commands](maintenance.md) |
| `run.py` | Starts uvicorn with one worker and trusted proxy headers from `127.0.0.1` |
| `install.py` | Command-line install, interactive or with `--mode`, `--admin`, `--password` |
| `scripts/` | `build_geo.py` (map outlines), `mkdocs_hooks.py` (documentation site) |
| `tests/` | pytest suite: one file per release (`test_v040.py` … `test_v0101.py`) plus core tests |
| `requirements*.txt`, `requirements.lock` | Dependency ranges and the pinned lock, see [Development](development.md#dependencies) |
