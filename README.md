# JATMP — Just Another Threat Monitoring Platform

[![CI](https://github.com/fj4rr/just-another-threat-monitoring-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/fj4rr/just-another-threat-monitoring-platform/actions/workflows/ci.yml)
[![Docs](https://github.com/fj4rr/just-another-threat-monitoring-platform/actions/workflows/docs.yml/badge.svg)](https://fj4rr.github.io/just-another-threat-monitoring-platform/)

📖 **Documentation: [fj4rr.github.io/just-another-threat-monitoring-platform](https://fj4rr.github.io/just-another-threat-monitoring-platform/)**

JATMP is a self-hosted platform for keeping track of new and emerging malware campaigns and scams. It collects
**security news**, **social media** (X, Bluesky, Mastodon, Telegram) and **threat-intelligence platforms**,
extracts the malware families, actors, CVEs and indicators in each item, checks the indicators against intel
providers, correlates everything across sources and shows the result on a trend dashboard. Scam reports get a
dashboard of their own on the same entity graph, and items are sorted into critical infrastructure
sectors. Every item is placed on the map, and the whole interface switches between an
International and a National (Indonesia) view.

It runs as a single process with SQLite by default. There is no JavaScript build step and nothing is loaded from
a CDN at runtime, so it works on an isolated network.

![Cyber threats dashboard](docs/screenshots/dashboard-overview.png)

More in the [screenshot tour](https://fj4rr.github.io/just-another-threat-monitoring-platform/screenshots/).

## Features

- **Collection** from 14 English news feeds and 25 Indonesian ones (tech and general news), about 30 Bluesky and Mastodon accounts, X, public
  Telegram channels (no account needed), OTX, urlscan.io, ANY.RUN, ThreatFox, MISP and ransomware.live. Any RSS
  feed, account or channel can be added. → [Sources](https://fj4rr.github.io/just-another-threat-monitoring-platform/sources/)
- **Analysis**: entity extraction with defang handling, an explainable 0–100 severity score, cross-provider
  verdict consensus (VirusTotal, OTX, abuse.ch, GreyNoise, AbuseIPDB and more), a relationship graph,
  on-demand infrastructure context, trend scoring over 7 days to a year, critical infrastructure sectors and CVE context from CISA KEV,
  FIRST EPSS and NVD.
  → [Analysis](https://fj4rr.github.io/just-another-threat-monitoring-platform/analysis/)
- **Geography**: target, source and hosting countries kept apart, Indonesian provinces, an International /
  National (ID) switch and Bahasa Indonesia support. → [Geography and Indonesia](https://fj4rr.github.io/just-another-threat-monitoring-platform/geography/)
- **Scams and fraud**: scam types, impersonated banks, e-wallets and government bodies, scammer phone numbers,
  accounts and wallets (kept to a minimum under UU PDP), losses in rupiah and a separate fraud score, from news,
  fact-checkers, FBI IC3 and the ScamSniffer blocklist, on their own dashboard. → [Scams and fraud](https://fj4rr.github.io/just-another-threat-monitoring-platform/fraud/)
- **Sharing**: REST API with API keys, IOC blocklist feeds, STIX 2.1 / TAXII 2.1, signed webhooks
  (Slack, Discord, Teams) and two-way MISP, all behind TLP sharing rules. → [Sharing and integrations](https://fj4rr.github.io/just-another-threat-monitoring-platform/integrations/)
- **Reporting and AI**: a *Threat Intel Findings* report as PDF, Word, Markdown or CSV, and optional summaries,
  briefs, a daily executive summary and Q&A from a local or cloud LLM. → [Reporting and AI](https://fj4rr.github.io/just-another-threat-monitoring-platform/reporting-and-ai/)
- **History**: backfill up to a year back, retention tiers, full-text search and optional PostgreSQL.
  → [History and storage](https://fj4rr.github.io/just-another-threat-monitoring-platform/history-and-storage/)
- **Operation**: single-user or multi-user with roles, live job progress, a notification center, a side preview on
  every table, dark and light themes and a phone layout. → [Using JATMP](https://fj4rr.github.io/just-another-threat-monitoring-platform/using-jatmp/)

## Quick start

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
python install.py             # interactive: single / multi user, API keys, LLM
```
```bash
python run.py                 # open http://127.0.0.1:8000
```

Or with Docker: copy `.env.example` to `.env` and run `docker compose up -d --build`. The installer can be
skipped, because the web UI shows the same setup wizard on first launch. Run that first launch on `127.0.0.1`
before exposing the port to a network. See [Getting started](https://fj4rr.github.io/just-another-threat-monitoring-platform/getting-started/) for details.

## Documentation

| | |
|---|---|
| **Set up** | [Getting started](https://fj4rr.github.io/just-another-threat-monitoring-platform/getting-started/) · [Configuration](https://fj4rr.github.io/just-another-threat-monitoring-platform/configuration/) · [Upgrading](https://fj4rr.github.io/just-another-threat-monitoring-platform/upgrading/) · [Maintenance commands](https://fj4rr.github.io/just-another-threat-monitoring-platform/maintenance/) |
| **Use** | [Sources](https://fj4rr.github.io/just-another-threat-monitoring-platform/sources/) · [Using JATMP](https://fj4rr.github.io/just-another-threat-monitoring-platform/using-jatmp/) · [Analysis](https://fj4rr.github.io/just-another-threat-monitoring-platform/analysis/) · [Geography](https://fj4rr.github.io/just-another-threat-monitoring-platform/geography/) · [Scams and fraud](https://fj4rr.github.io/just-another-threat-monitoring-platform/fraud/) · [Integrations](https://fj4rr.github.io/just-another-threat-monitoring-platform/integrations/) · [Reporting and AI](https://fj4rr.github.io/just-another-threat-monitoring-platform/reporting-and-ai/) · [History and storage](https://fj4rr.github.io/just-another-threat-monitoring-platform/history-and-storage/) |
| **Reference** | [Security](https://fj4rr.github.io/just-another-threat-monitoring-platform/security/) · [Development and architecture](https://fj4rr.github.io/just-another-threat-monitoring-platform/development/) · [Changelog](https://fj4rr.github.io/just-another-threat-monitoring-platform/changelog/) |

The site is built with MkDocs from the Markdown in [`docs/`](docs/); to read it offline, run
`pip install -r requirements-docs.txt` and `mkdocs serve`.

## Credits

Built and maintained by [**fj4rr**](https://github.com/fj4rr) ·
[github.com/fj4rr/just-another-threat-monitoring-platform](https://github.com/fj4rr/just-another-threat-monitoring-platform).
Issues and pull requests are welcome.

Map outlines: [Natural Earth](https://www.naturalearthdata.com/) (public domain). Offline GeoIP, when downloaded:
[IP Geolocation by DB-IP](https://db-ip.com) (CC BY 4.0) or MaxMind GeoLite2 under its own licence.
