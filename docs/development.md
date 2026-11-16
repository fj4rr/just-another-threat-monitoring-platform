# Development and architecture

[← Documentation index](README.md)

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

The test suite runs against a throw-away SQLite database with no network access and no scheduler. It covers
the extractor, severity scoring, enrichment consensus, feed sorting, the AI settings mapping, the report
builder in all four formats, password, CSRF and redirect handling, feed sanitisation, the settings form, the
multi-user login flow, list pagination and filters, the preview fragments, job batches and progress,
notifications, the CVE lookups (against a mocked HTTP transport), geo attribution (targets versus attackers,
Indonesian places and institutions), the region filter, the Indonesian severity terms and the map outlines. GitHub Actions runs lint and tests on Python 3.11 and 3.12 and builds the Docker
image.

## Architecture

```
app/
  collectors/   rss, bluesky, mastodon, x_twitter, intel (OTX, urlscan, ANY.RUN, ThreatFox, ransomware.live),
                misp  → RawItem
  processing/   pipeline (dedupe, sanitise, store, link entities, geo-tag) · extractor (IOC/CVE/family/actor)
                geo (language, target countries and provinces, source country, International / National filter)
                severity (explainable 0–100 score) · enrichment (cross-source, consensus, re-checks)
                trends (dashboard aggregations, weighted correlation) · graph (capped relationship graphs)
  intel/        API clients: VirusTotal, OTX, urlscan, ANY.RUN, ThreatFox, MalwareBazaar, URLhaus, GreyNoise,
                AbuseIPDB (rate limits, budgets, connection tests) · darkweb (ransomware.live, Hudson Rock)
                misp (pull mapping, push, auto-push) · context (Shodan, Censys, CrowdSec, Pulsedive,
                Hybrid Analysis, IPinfo; on demand)
                cve (CISA KEV, FIRST EPSS, NVD CVSS → Entity.meta; risk-weighted CVE priority)
  llm/          client (Ollama / OpenAI-compatible / Anthropic, live model list) · presets (local and cloud vendors)
                insights (summary, brief, digest, Q&A)
  reports.py    Threat Intel Findings: gather() plus PDF / Word / Markdown / CSV exporters
  routers/      pages, api (JSON and actions), api_v1 (REST API + IOC feeds + offline docs), apikeys, webhooks,
                taxii (read-only TAXII 2.1), settings, reports, admin, auth and setup
  gazetteer.py  countries (English and Indonesian names, demonyms), 38 Indonesian provinces, cities, institutions
  geoip.py      offline GeoIP (MaxMind-format database in data/geoip/) for the hosting country of IPs
  sharing.py    TLP and redistribution rules for everything that leaves JATMP
  stix.py       STIX 2.1 objects and bundles (stable per-install ids, TLP markings)
  backfill.py   backfill reach, estimates and storage statistics (the job is jobs.run_backfill)
  search.py     FTS5 full-text search with a LIKE fallback · dbcopy.py (copy-db)
  apikeys.py    API key creation, verification, scopes and rate limiting
  webhooks.py   events, Slack / Discord / Teams formats, HMAC signing, SSRF guard, retries
  jobs.py       APScheduler: one job per source, enrichment every N minutes, CVE intel every 6 h, daily digest,
                housekeeping; manual runs as batches with live progress (status() feeds /api/jobs/status)
  notify.py     notification center (de-duplicated by key, per-user read watermark, 30-day retention)
  templates/    pages, plus _preview_item.html / _preview_entity.html (partial HTML for the side preview)
  static/       app.css (theme tokens, dark and light) · app.js (CSP-safe behaviours, preview drawer, job and
                notification polling, charts) · motion.js (radar, sparklines) · graph.js (force-directed SVG graph)
                geomap.js (choropleth maps) · geo/ (pre-projected Natural Earth outlines: world, Indonesian provinces)
scripts/        build_geo.py (rebuilds static/geo from Natural Earth GeoJSON; not needed at runtime)
data/           config.json (install mode, secret), jatmp.db (SQLite)
tests/          pytest suite
```

SQLite in WAL mode is the default database; for larger deployments (long backfills while collectors run, many
users) point `JATMP_DATABASE_URL` at PostgreSQL. String columns are trimmed to their declared length before
writing, because PostgreSQL rejects what SQLite silently accepts.
Run a single web worker, because the scheduler lives in the process; scale collection by adjusting source
intervals instead.
