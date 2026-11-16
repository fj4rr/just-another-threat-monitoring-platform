# JATMP documentation

[← Project README](../README.md)

## Setting up

| Page | What it covers |
|---|---|
| [Getting started](getting-started.md) | Installing from source or with Docker, the setup wizard, running a local LLM next to it |
| [Configuration](configuration.md) | API keys for every provider, runtime and deployment variables, extending the knowledge base |
| [Upgrading](upgrading.md) | What to do when moving to a new version |
| [Maintenance commands](maintenance.md) | `manage.py`: collecting, enriching, re-scoring, geo-tagging, fraud analysis, Telegram sign-in, copying the database, users |

## Using JATMP

| Page | What it covers |
|---|---|
| [Sources](sources.md) | Built-in news, Indonesian news, Bluesky, Mastodon, X, Telegram, scam & fraud and threat-intel sources, and the topic filters |
| [Using JATMP](using-jatmp.md) | Install modes and roles, the two dashboards and their period, tables and the side preview, job status and notifications |
| [Analysis](analysis.md) | Entity extraction, severity scoring, enrichment and consensus, the relationship graph, infrastructure context, correlation, trends, IIV sectors, CVE context |
| [Geography and Indonesia](geography.md) | Target / source / hosting countries, Indonesian provinces, the International / National switch, Bahasa Indonesia |
| [Scams and fraud](fraud.md) | Scam types, impersonated brands, scammer identifiers and personal data (UU PDP), the fraud score, the scam & fraud dashboard and pages |
| [Sharing and integrations](integrations.md) | REST API, IOC feeds, STIX 2.1 / TAXII 2.1, webhooks, MISP, sharing rules (TLP), dark web tier 1 |
| [Reporting and AI](reporting-and-ai.md) | The *Threat Intel Findings* report builder and the optional LLM features |
| [History and storage](history-and-storage.md) | Historical backfill, retention tiers, full-text search, PostgreSQL |
| [Screenshots](screenshots.md) | A tour of the interface |

## Reference

| Page | What it covers |
|---|---|
| [Security](security.md) | CSP, sessions, untrusted content, API keys, webhooks, deployment advice |
| [Development and architecture](development.md) | Running lint and tests, and how the code is organised |
| [Changelog](../CHANGELOG.md) | Every release and what changed |
