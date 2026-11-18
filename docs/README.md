# JATMP documentation

[← Project README](../README.md)

JATMP is a self-hosted platform for monitoring cyber threats and online fraud as they emerge. It reads security
news, social media, threat-intelligence platforms and scam and fraud sources, and keeps track of:

- **Cyber threats**: malware and ransomware families and their campaigns, threat actors, vulnerabilities (with
  CISA KEV, EPSS and CVSS context), ATT&CK techniques and indicators of compromise, checked against intel
  providers. → [Analysis](analysis.md)
- **Scams and fraud**: scam types such as investment and loan fraud, phishing, malicious APKs and crypto drainers,
  impersonated banks, e-wallets and government bodies, scammer identifiers and reported losses.
  → [Scams and fraud](fraud.md)
- **Critical infrastructure**: the sectors each item concerns, following Indonesia's Perpres 82/2022.
  → [Analysis](analysis.md#critical-infrastructure-sectors)
- **Geography**: target, source and hosting countries, Indonesian provinces, and an International / National
  (Indonesia) view across the whole interface. → [Geography and Indonesia](geography.md)

Everything runs through one pipeline and one entity graph, so a scam report links to the malware it installs and a
ransomware campaign to the CVEs it exploits. Two dashboards show the result, one for cyber threats and one for
scams and fraud, and the data can be shared out through the REST API, STIX / TAXII, IOC feeds, webhooks and MISP.

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
| [Analysis](analysis.md) | Entity extraction, severity scoring, enrichment and consensus, the relationship graph, infrastructure context, correlation, trends, critical infrastructure sectors, CVE context |
| [Geography and Indonesia](geography.md) | Target / source / hosting countries, Indonesian provinces, the International / National switch, Bahasa Indonesia |
| [Scams and fraud](fraud.md) | Scam types, impersonated brands, scammer identifiers and personal data (UU PDP), the fraud score, the scam & fraud dashboard and pages |
| [Sharing and integrations](integrations.md) | REST API, IOC feeds, STIX 2.1 / TAXII 2.1, webhooks, MISP, sharing rules (TLP), dark web tier 1 |
| [Reporting and AI](reporting-and-ai.md) | The *Threat Intel Findings* report builder and the optional LLM features |
| [History and storage](history-and-storage.md) | Historical backfill, retention tiers, full-text search, PostgreSQL |
| [Screenshots](screenshots.md) | A tour of the interface |

## How it works

What happens behind the screens, step by step, with the rules and numbers JATMP uses. Start with the overview: it
follows one article from the feed to the dashboard.

| Page | What it covers |
|---|---|
| [How JATMP works](how-it-works/index.md) | The five stages, one article followed end to end, the scheduler's day, where each number comes from, key terms |
| [Collection](how-it-works/collection.md) | Scheduling, what one run of each collector fetches, topic filters, run outcomes and notifications, manual batches, backfill |
| [Ingest and analysis](how-it-works/processing.md) | Duplicates, cleaning, syndicated copies, entity extraction, sectors, linking, blocklist verdicts, geography and the National view |
| [Severity scoring](how-it-works/scoring.md) | Every signal and weight, dampeners, worked examples, enrichment and AI adjustments, re-scoring |
| [Enrichment and verdicts](how-it-works/enrichment.md) | Which indicators are looked up when, providers, gaps and budgets, the consensus rules, family links, CVE intel |
| [Trends and correlation](how-it-works/trends.md) | Counting rules, periods and baselines, the trend score, CVE priority, related items, the graph |
| [AI processing](how-it-works/ai.md) | Item summaries and their guardrails, auto-summaries, briefs, the executive summary, questions, what is sent |
| [Sharing and delivery](how-it-works/sharing.md) | TLP, redistribution and personal-data rules, webhook events, signing and retries, MISP push |
| [Housekeeping and re-analysis](how-it-works/housekeeping.md) | The nightly clean-up, retention, identifier pruning, versioned re-analysis, restarts |

## Developer guide

Start with *Development* to get a working environment, read *Architecture* once, and keep *Extending JATMP* open
while you change things.

| Page | What it covers |
|---|---|
| [Development](development.md) | Setting up, running locally on throw-away data, conventions, the test suite and its fixtures, CI, dependencies and the lock file, the documentation site, the release checklist, troubleshooting |
| [Architecture](architecture.md) | Process model, start-up sequence, request lifecycle, the path from a feed to the database, background jobs and versioned re-analysis, outbound HTTP, caches, database and migrations, front end, module map |
| [Data model](data-model.md) | Every table, the columns that need explaining, entity types and link origins, invariants the code relies on, settings storage and `config.json` |
| [Extending JATMP](extending.md) | Recipes: a collector, an enrichment provider, a setting, detection rules, a re-analysis job, a page, a UI action, the REST API, a column; outbound requests; a security checklist |

## Reference

| Page | What it covers |
|---|---|
| [Security](security.md) | CSP, sessions, untrusted content, outbound requests, API keys, webhooks, deployment advice |
| [Changelog](../CHANGELOG.md) | Every release and what changed |
