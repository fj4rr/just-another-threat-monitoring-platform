# Housekeeping and re-analysis

[← How JATMP works](index.md)

The processes that keep the database small and consistent over time: the nightly clean-up, the retention tiers,
the removal of personal data, the one-off jobs that apply new detection rules to stored items, and what a restart
does. Code: `app/jobs.py`.

## Nightly housekeeping

`run_housekeeping` runs every day at **03:30** in the time zone of the schedule (`housekeeping_time` and
`schedule_timezone` under Settings → General; default 03:30 UTC). In order:

| # | Step | Default | Setting |
|---|---|---|---|
| 1 | Delete job runs (`collector_runs`) started more than **30 days** ago | always | — |
| 2 | Delete notifications older than **30 days** | always | — |
| 3 | **Slim** items published more than **180 days** ago (see below), up to 20,000 per night | on | `retention_full_days` (0 = never) |
| 4 | Delete webhook deliveries older than **30 days** | always | — |
| 5 | **Delete** items published more than *N* days ago, then recount mentions and remove orphaned indicators | **off** | `retention_days` (0 = keep forever) |
| 6 | Delete AI answers (Q&A) older than **90 days** | always | — |
| 7 | **Prune scammer identifiers** not mentioned for **365 days** | on | `fraud_identifier_days` (0 = keep) |

### Slimming (retention tier)

An item past `retention_full_days` keeps everything that analysis and statistics need and loses the bulk:

| Kept | Changed |
|---|---|
| Title, link, source, dates, kind, tags | `content` cut to its first 400 characters (at a word boundary, with " …") |
| All entity links, severity and its reasons, fraud score and its reasons | `raw` keeps only simple values of at most 200 characters (TLP, sector, country…); lists and long texts go |
| Geography (`item_geo`), sectors, AI summary | `slimmed_at` is set; the item page says the text was trimmed and links to the original |

The full-text search index follows automatically (database triggers). Slimming is committed every 1,000 items, so
a large first run (after enabling the setting on an old install) is spread over several nights; `python manage.py
slim` does all of it at once.

Because the text is gone, a later re-analysis of a slimmed item (re-scoring, a rules change) works on the snippet
and may find less. Geography keeps the countries the feed supplied at collection time, which are not in the
snippet.

### Deleting old items

Off by default. When `retention_days` is set, items **published** before the cut-off are deleted together with
their entity links and geography (cascade). Then:

- every entity's `mention_count` is recomputed from the remaining links;
- **indicators** (hashes, IPs, domains, URLs) with no mentions and no enrichment links are deleted;
- **families, actors, CVEs, scam types, brands and sectors are kept** as history, even with no mentions left.

The database file does not shrink by itself after a large deletion; run `python manage.py vacuum`.

### Scammer identifiers (UU PDP)

Phone numbers, bank accounts and e-wallets whose `last_seen` is older than `fraud_identifier_days` (default 365)
are deleted, with their links. `last_seen` is the publication date of the latest item that mentions the
identifier, so an identifier that keeps being reported stays. Crypto wallets are not personal data and are kept.
See [Scams and fraud](../fraud.md#scammer-identifiers-and-personal-data-uu-pdp).

## Re-analysis of stored items

Detection rules improve between versions. Items stored by an older version would otherwise keep the old results,
so several analyses carry a **rules version**:

1. The code holds a version constant (for example `fraud.RULES_VERSION = 5`).
2. The database holds the version the stored items were analysed with (setting `fraud_version`).
3. A few seconds after every start-up, a one-off job compares the two. Equal → it does nothing. Different → it
   re-analyses every stored item and then stores the new version.

| Job | Starts after | Version | Re-does |
|---|---|---|---|
| `run_content_cleanup` | 15 s | `jobs.CONTENT_VERSION` → `content_version` | Removes text that newer cleaning rules strip (stylesheet rules in posts), then re-runs the scam and sector analysis of the items that changed |
| `run_geotag` | 20 s | `geo.GEO_VERSION` → `geo_version` | Language, source country, target countries and provinces of every item; hosting country of every IP from the GeoIP database |
| `run_dedup` | 30 s | `jobs.DEDUP_VERSION` → `dedup_version` | Fingerprints of every article, oldest first, so the first outlet to publish a story stays the original |
| `run_fraudtag` | 40 s | `fraud.RULES_VERSION` → `fraud_version` | Scam types, brands, identifiers, losses, victims and fraud score of every item, oldest first (so the *spreading* check sees earlier reports) |
| `run_sectortag` | 60 s | `sectors.RULES_VERSION` → `sector_version` | Critical infrastructure sectors of every item |
| `run_rescore_if_outdated` | 90 s | `severity.RULES_VERSION` → `severity_version` | Severity of every item from its text and linked entities, keeping the enrichment bonus and the last AI assessment (as *Re-score all items*); last, so it sees the entities the jobs above settled |

They work through the items in chunks of 500 (200 for the content clean-up), commit per chunk and show progress
in the job status. The staggered start keeps them from competing with each other and with the first collection
runs for the database. Geography, fraud and sectors can also be re-run by hand: `manage.py geotag`, `fraudtag`
and `sectortag`, and the geography and scam re-analysis also from the UI (Settings, and *Re-analyse items* on the
scam & fraud dashboard), which ends with a notification. The content clean-up and dedup jobs only run after an
upgrade.

**Not versioned: entity extraction.** Re-extracting would rebuild every link, which is expensive and changes
counts that analysts may rely on, so it only happens on request. Severity is versioned since 0.12 (above) and can
also be recomputed by hand:

| Tool | Does | Notes |
|---|---|---|
| *Re-score all items* (Settings), `manage.py rescore` | Recomputes severity from the stored text and the linked entities | Keeps the *indicator confirmed* bonus and the last AI assessment. No network |
| `manage.py reextract` | Deletes the `regex`, `kb` and `heuristic` links and extracts again; re-scores severity; re-runs the scam and sector analysis; recounts mentions; removes families and actors left without mentions or links | Keeps `feed` and `llm` links, the enrichment bonus and the last AI assessment |

See [Severity scoring](scoring.md#recomputing-scores).

## Monthly GeoIP update

When *update the GeoIP database automatically* is on, `run_geoip_update` downloads a fresh offline database
(DB-IP Lite, or MaxMind GeoLite2 with a license key) at 04:00 UTC on the 5th of every month, then forces a
geo-tagging run so IP hosting countries reflect the new data.

## Start-up and restarts

On start-up (see [Architecture](../architecture.md#start-up-sequence)) JATMP creates missing tables and columns,
adds built-in sources that a newer version introduced, encrypts secrets that an older version stored in plain
text, marks every run that was `queued` or `running` as **aborted**, schedules the jobs and starts the scheduler.

What a restart loses, because it lives in memory:

| State | Effect of a restart |
|---|---|
| Live progress of running jobs | The runs are marked *aborted*; start them again if needed |
| AI auto-summary queue | Rebuilt at start-up from the live items of the last 24 hours that qualify (severity 40 or more, no summary, not a copy) |
| Trend cache (45 s), settings cache (5 s) | Rebuilt on the next request |
| Per-provider gaps between calls, API-key rate windows, per-user action limits | Start fresh |

What survives, because it is in the database: every item, entity and verdict, provider daily budgets, queued
webhook deliveries (sent on the next 30-second tick), rules versions, notifications and the run history.
