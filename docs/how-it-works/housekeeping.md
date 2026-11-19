# Housekeeping and re-analysis

[← How JATMP works](index.md)

This page covers the processes that keep the database small and consistent over time: the nightly clean-up, the
retention tiers, the removal of personal data, the one-off jobs that apply new rules to stored items, and what
happens when JATMP restarts. The code is in `app/jobs.py`.

## Nightly housekeeping

`run_housekeeping` runs every day at **03:30** by default. You can change the time and the time zone under
Settings → General (`housekeeping_time` and `schedule_timezone`); the default time zone is UTC. It works through
these steps in order:

| # | Step | Default | Setting |
|---|---|---|---|
| 1 | Delete job run records started more than **30 days** ago | Always | — |
| 2 | Delete notifications older than **30 days** | Always | — |
| 3 | **Slim** items published more than **180 days** ago (see below), up to 20,000 a night | On | `retention_full_days` (0 = never) |
| 4 | Delete webhook deliveries older than **30 days** | Always | — |
| 5 | **Delete** items published more than *N* days ago, then recount mentions and remove indicators nothing refers to any more | **Off** | `retention_days` (0 = keep forever) |
| 6 | Delete AI answers (questions and answers) older than **90 days** | Always | — |
| 7 | **Prune scammer identifiers** that haven't been mentioned for **365 days** | On | `fraud_identifier_days` (0 = keep) |

### Slimming

Once an item is older than `retention_full_days`, it keeps everything that analysis and statistics need and loses
the bulk:

| Kept | Changed |
|---|---|
| Title, link, source, dates, kind, tags | The text is cut to its first 400 characters (at a word boundary, ending with " …") |
| All entity links, the severity and its reasons, the fraud score and its reasons | The provider data keeps only short simple values (TLP, sector, country…); lists and long texts are removed |
| Geography, sectors, the AI summary | The item is marked as slimmed. Its page says the text was trimmed and links to the original |

The search index updates itself automatically. Slimming is saved every 1,000 items, so on an old installation
where you have just switched it on, the first run is spread over several nights. `python manage.py slim` does it
all at once.

Since the full text is gone, any later re-analysis of a slimmed item (a re-score, or a rules change) works on
the snippet and may find less. Geography keeps the countries the feed provided when the item was collected,
because those aren't in the snippet.

### Deleting old items

This is off by default. When you set `retention_days`, items **published** before the cut-off are deleted,
together with their entity links and geography. After that:

- every entity's mention count is recalculated from the links that remain;
- **indicators** (hashes, IPs, domains, URLs) with no mentions and no enrichment links are deleted;
- **families, actors, CVEs, scam types, brands and sectors are kept** as history, even when nothing mentions them
  any more.

The database file doesn't shrink by itself after a large deletion. Run `python manage.py vacuum` to give the
space back.

### Scammer identifiers (UU PDP)

Phone numbers, bank accounts and e-wallets whose last mention is older than `fraud_identifier_days` (365 by
default) are deleted, together with their links. The last mention is the publication date of the latest item
that names the identifier, so an identifier that keeps being reported is kept. Crypto wallets are not personal
data and are always kept. See [Scams and fraud](../fraud.md#scammer-identifiers-and-personal-data-uu-pdp).

## Re-analysis of stored items

Detection and scoring rules improve from one version to the next. Without re-analysis, items stored by an older
version would keep their old results, and the dashboards would compare items judged by different rules. So each
analysis has a **rules version**:

1. The code holds a version number for the rules (for example `fraud.RULES_VERSION = 5`).
2. The database remembers which version the stored items were analysed with (here, the setting
   `fraud_version`).
3. A few seconds after every start-up, a one-off job compares the two. If they match, it does nothing. If they
   don't, it re-analyses every stored item and then records the new version.

| Job | Starts after | Rules version | What it redoes |
|---|---|---|---|
| `run_content_cleanup` | 15 s | `content_version` | Removes text that newer cleaning rules strip out (stylesheet rules inside posts), then re-runs the scam and sector analysis for the items that changed |
| `run_geotag` | 20 s | `geo_version` | Language, source country, target countries and provinces for every item, and the hosting country of every IP from the GeoIP database |
| `run_dedup` | 30 s | `dedup_version` | The fingerprints of every article, oldest first, so the first outlet to publish a story stays the original |
| `run_fraudtag` | 40 s | `fraud_version` | Scam types, brands, identifiers, losses, victims and the fraud score of every item, oldest first (so the *spreading* check sees the earlier reports) |
| `run_sectortag` | 60 s | `sector_version` | The critical infrastructure sectors of every item |
| `run_rescore_if_outdated` | 90 s | `severity_version` | The severity of every item, from its text and linked entities, keeping the enrichment bonus and the last AI assessment (the same as *Re-score all items*). It runs last, so it sees the entities the jobs above have settled |

These jobs work through the items in chunks of 500 (200 for the content clean-up), save after each chunk, and
show their progress in the job status. Their staggered start times keep them from competing with each other, or
with the first collection runs, for the database.

You can also run some of them by hand. Geography, fraud and sectors have `manage.py geotag`, `fraudtag` and
`sectortag`; geography and the scam analysis can also be started from the interface (Settings, and *Re-analyse
items* on the scam & fraud dashboard), and finish with a notification. Severity has *Re-score all items* and
`manage.py rescore`. The content clean-up and dedup jobs only run after an upgrade.

**Entity extraction has no rules version.** Re-extracting rebuilds every link, which is expensive and changes
mention counts that analysts may rely on, so it only happens when you ask for it:

| Tool | What it does | Notes |
|---|---|---|
| *Re-score all items* (Settings), `manage.py rescore` | Recalculates severity from the stored text and the linked entities | Keeps the *indicator confirmed* bonus and the last AI assessment. No network calls |
| `manage.py reextract` | Deletes the `regex`, `kb` and `heuristic` links and extracts everything again; re-scores severity; re-runs the scam and sector analysis; recounts mentions; removes families and actors left with no mentions or links | Keeps `feed` and `llm` links, the enrichment bonus and the last AI assessment |

See [Severity scoring](scoring.md#recomputing-scores).

## Monthly GeoIP update

When *update the GeoIP database automatically* is on, `run_geoip_update` downloads a fresh offline database
(DB-IP Lite, or MaxMind GeoLite2 if you have a license key) at 04:00 UTC on the 5th of every month. It then
re-runs geo-tagging, so the hosting countries of IPs reflect the new data.

## Start-up and restarts

At start-up (see [Architecture](../architecture.md#start-up-sequence)), JATMP creates any missing tables and
columns, adds built-in sources that a newer version introduced, encrypts secrets that an older version stored in
plain text, marks every run that was still `queued` or `running` as **aborted**, schedules the jobs, starts the
scheduler, and rebuilds the AI auto-summary queue.

Some state lives only in memory, so a restart resets it:

| State | What a restart does |
|---|---|
| Progress of running jobs | The runs are marked *aborted*. Start them again if you need to |
| AI auto-summary queue | Rebuilt from the live items of the last 24 hours that qualify (severity 40 or more, no summary, not a copy) |
| Trend cache (45 s) and settings cache (5 s) | Rebuilt on the next request |
| Gaps between provider calls, API-key rate windows, per-user action limits | Start afresh |

Everything else is in the database and survives a restart: every item, entity and verdict (with its date), the
providers' daily budgets, queued webhook deliveries (sent on the next 30-second tick), the rules versions,
notifications and the run history.
