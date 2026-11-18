# Collection

[← How JATMP works](index.md)

How sources are scheduled, what one run of each collector fetches, how runs are tracked and reported, and how a
manual collection or a historical backfill differs from the scheduled one. The list of built-in sources is in
[Sources](../sources.md); this page is about the process.

## Scheduling

Every **enabled** source has one scheduler job, `source:<id>`, that runs `jobs.run_source`:

| Rule | Value | Why |
|---|---|---|
| Interval | `interval_minutes` of the source, at least **5** | Built-in defaults: Bluesky and Mastodon 30 min, most RSS feeds 60 min, fraud feeds, X and ThreatFox 180 min |
| First run after start-up | 5 s + 3 s × source id | Staggers the first wave so dozens of sources do not start in the same second |
| Overlap | A source never runs twice at the same time from the schedule (`max_instances = 1`) | A slow feed cannot pile up runs |
| Missed runs | Collapsed into one (`coalesce`), started if no more than 10 minutes late | After a pause the source catches up once instead of N times |
| Threads | One pool of 10 threads for every job | A hanging provider blocks one thread, not the platform |

Editing, enabling or disabling a source in Settings re-schedules (or removes) its job at once. Deleting a source
removes its job and its items.

Collectors never decide *when* they run; they only implement `fetch()` (and optionally `backfill()`). Every
request they make goes through the outbound guard (`app/netguard.py`): public addresses only unless allow-listed,
redirects checked hop by hop, response bodies capped at 20 MB after decompression, 30 s timeout. See
[Security](../security.md).

## One run, step by step

```
run_source(source_id)
 │
 ├─ 1. create / claim the CollectorRun row ........ status "running"
 ├─ 2. collector.fetch() .......................... phase "fetching"
 ├─ 3. pipeline.ingest_committed(raw items) ........ phase "storing"  (see Ingest and analysis)
 ├─ 4. source.last_status = "ok", last_run = now
 ├─ 5. side effects of the new items .............. webhook events, MISP auto-push job
 ├─ 6. finish the run ............................. status "ok", "fetched N, new M"
 └─ 7. queue AI auto-summaries .................... only when enabled
```

1. **Run row.** A `CollectorRun` row with `job = "source:<id>"` is created (or, for a manual batch, the row that
   was queued for it is claimed) and set to `running`.
2. **Fetch.** The collector class registered for `Source.kind` is instantiated with the source's configuration
   and asked for its current list of entries, returned as `RawItem`s (see [the table below](#what-one-run-fetches)).
3. **Ingest.** All entries go through the pipeline in one transaction; only new ones are stored. Progress
   ("storing 40/100") is reported every five entries.
4. **Source status.** `last_status`, `last_error` and `last_run` are updated; the Sources tab shows them.
5. **Side effects.** For the new item ids: webhook events (`item.high_severity`, `entity.watched`) are queued,
   and a MISP auto-push job is started when `misp_autopush_min_severity` is above 0. A failure here is logged and
   never fails the run.
6. **Finish.** The run is closed with its status, a message and the number of new items. The in-memory progress is
   copied to the row.
7. **AI.** When *auto-summarize* is on and an LLM is configured, the new ids join the summary queue, which is
   worked off by its own job (see [AI processing](ai.md#auto-summaries)).

Some collectors keep a little state in their source's configuration between runs: Mastodon caches the account
id, X the user id and `since_id`, and the OTX, MISP and ransomware.live collectors use `last_run` to ask only for
what changed since the previous run.

## Run outcomes

| Status | Meaning | Source status | Notification |
|---|---|---|---|
| `ok` | Fetched and stored (zero new items is still `ok`) | `ok` | None for scheduled runs |
| `skipped` | The collector cannot run for a known reason: missing API key, no handle or URL configured, Telegram not signed in. Raised as `SkipCollector` | `skipped` | None; a manual batch mentions how many were skipped |
| `error` | Anything else: HTTP error, parse error, timeout, a rate limit (`429`) | `error`, with the message | **Once**, when a scheduled run turns from not-failing to failing (*Source failing: …*). Later failures of the same source stay quiet until it has recovered |
| `aborted` | The process stopped while the run was queued or running, or a backfill was stopped | unchanged | None |
| `queued` / `running` | In progress. A row older than 3 hours in these states is treated as dead by the status views | — | — |

An error while fetching or storing rolls back what the run stored, so a source either contributes a consistent
batch or nothing. The next scheduled run tries again.

## Source health

A source can fail quietly: a feed that moved returns an empty page, a blocked client gets a 200 with nothing in
it, and every run is `ok` with zero new items. `app/sourcehealth.py` looks at each source's live items and its
last 30 days of run history, and the Sources tab shows the result next to each source:

| Figure | How |
|---|---|
| Last new item | The latest live item it collected (backfills do not count) |
| This week · usual | Live items of the last 7 days, against the weekly average of the 4 weeks before; *below usual* under a third of it |
| Usual gap | The median time between its runs that brought something new; needs at least 3 such gaps |
| Failing for | Since the first failed run of the current streak |
| Summary only | Its news items average fewer than **400** characters of text: the feed carries summaries only, so extraction and severity have little to work with |

Every hour `jobs.run_source_health` raises a notification, once per source, condition and day, when a source is
**quiet** (no new item for **3** times its usual gap, and at least 12 hours) or has been **failing for 24 hours**.
The Sources tab lists the sources that need attention above the table.

## What one run fetches

Each scheduled run asks the provider for its *current* list; entries already stored are skipped at ingest, so
overlap between runs costs nothing but bandwidth.

| Kind | One scheduled run | Item kind | Notes |
|---|---|---|---|
| `rss` | The feed (max 10 MB), first 500 entries parsed, topic filter applied, newest **100** kept | `article` (`post` for social-category sources) | Content is the feed entry's full content if present, else its summary. The article page is not opened |
| `bluesky` | Last **50** posts of the account, without replies | `post` | Public API, no key |
| `mastodon` | Last **40** statuses of the account, without replies | `post` | Account id cached after the first run |
| `x` | Last **50** posts via API v2 (only newer than the last seen id), or the configured RSS bridge | `post` | Skipped without a bearer token or bridge; `429` is an error |
| `telegram` | The channel's public web preview (latest page, 20 posts), or the last **50** messages over MTProto | `post` | Posts without text are skipped |
| `otx` | Subscribed pulses modified since the last run (first run: 3 days), up to 50; or a pulse search (30) | `pulse` | Up to 300 indicators per pulse arrive as structured indicators; pulse TLP, targeted countries and industries are kept |
| `urlscan` | One search (default: malicious verdicts of the last day), **100** results | `scan` | URL, domain and IP of each scan arrive as indicators |
| `anyrun` | One TI Lookup query over the configured lookback (default 7 days), **100** tasks | `analysis` | Never redistributed (provider terms) |
| `threatfox` | IOCs of the last day, grouped into **one item per family per day** (up to 300 IOCs per run) | `pulse` | The item id is `<day>:<family>`, the day ThreatFox first saw the IOCs. A later run that finds new IOCs for a stored day adds them to that item (`RawItem.merge_title`), updates its count and scores it again; no new item and no webhook event |
| `ransomwarelive` | The 100 most recent victims; or the full list of one country / group, keeping posts newer than the last run minus 2 days | `post` | The victim's website is kept out of the text on purpose: it is the victim, not an indicator |
| `misp` | Events changed since the last run minus 1 hour (first run: `days`, default 7), 50 per page, up to 5 pages | `pulse` | Event TLP kept; attributes become indicators |
| `scamsniffer` | The daily list files of the last 4 days (the public list lags 7 days) | `article` | One item per day; its domains are marked malicious on arrival |

Intel sources (category `intel`) are treated differently at ingest: indicators are extracted from plain text,
not only defanged ones, and their tags may name malware families. See
[Ingest and analysis](processing.md#4-entity-extraction).

## Topic filters

An RSS source can carry `filter` in its configuration. The filter runs **inside the collector**, before anything
is stored, so filtered-out entries leave no trace:

| Filter | Keeps an entry when | Used for |
|---|---|---|
| `security` | A security term (English or Indonesian) appears in the title, the first 3,000 characters of the text, or the tags | General technology sections |
| `cyber` | An unambiguous cyber or digital-fraud term appears, **or** the [scam analysis](../fraud.md) recognises a scam type | General news sections, where "bocor" or "modus" usually mean something else |
| `fraud` | The scam analysis recognises a scam type | Fact-checkers, whose feeds are mostly political hoaxes |

The source **topic** *scam & fraud* is a different setting: it does not filter, it changes how the scam analysis
reads the source's items (one scam word is enough for *Other scam*) and lists the source on the fraud overview.

## Runs, batches and progress

- **Scheduled runs** create their row when they start and finish it when they end.
- **Manual collection** (*Collect now*, *Run now*, `manage.py collect`) first creates one `queued` row per source
  under a shared `batch_id` (`collect-<random>`), then starts the runs. The status bar shows the batch as
  "Collecting… 12/40 sources · 85 new", and a second click while it runs finds the active batch instead of
  starting another. *Run now* on a single source is ignored while that source is already running.
- **Progress** of the running step (fetching, storing N/M, phase of an enrichment) is kept in memory and served
  by `/api/jobs/status`, which the page polls; it is not written to the database mid-run, so it never competes
  with the run's own write transaction.
- **Batch summary.** When the last run of a batch finishes, **one** notification summarises it: "Collected 85 new
  items from 40 sources, 2 errors", with the failed source names and how many were skipped. Inside a batch, the
  per-source *Source failing* notification is not sent.
- **Restarts.** On start-up every run still `queued` or `running` is marked `aborted` ("interrupted by a
  restart"); nothing resumes half-way.

## Backfill

A backfill (Manage → Backfill, `queue_backfill`) crawls history instead of the current list:

1. One `queued` run per selected source is created under a `backfill-<random>` batch.
2. A **single worker** works through them one after another. Backfills are long and SQLite has one writer, so
   sources are never crawled in parallel.
3. For each source the collector reports what it can do (`backfill_capability`: supported, method, maximum
   reach). Unsupported sources are `skipped`; the requested start is clamped to the reach (ThreatFox: 7 days).
4. The collector yields **pages** of entries; each page is ingested and committed on its own with
   `origin = "backfill"`, so a stopped or failed backfill keeps the pages it already stored.
5. *Stop* aborts the queued sources at once and lets the source being crawled finish its current page.
6. One notification summarises the batch.

| Collector | How it reaches back |
|---|---|
| RSS on a WordPress site | The site's REST API returns every post in the range (100 per page); the estimate is exact |
| Other RSS | Internet Archive snapshots of the feed (one per day), filtered to the range; only what the feed listed when it was archived |
| Bluesky / Mastodon | The account feed, paged back with the API cursor (up to 6,000 posts / 4,000 statuses per account per run) |
| Telegram | Older web-preview pages (up to 3,000 posts), or MTProto (up to 5,000) |
| OTX / MISP | Subscribed pulses / events modified in the range, paged |
| ThreatFox | The API's maximum of 7 days |
| ransomware.live (country or group source) | The full victim list, back to 2021 for most groups |
| ScamSniffer | One archive file per day since 31 May 2022 |
| X, urlscan, ANY.RUN, ransomware.live recent | Not supported (quota-limited or recent-only) |

Backfilled items keep their publication dates and are marked `backfill`. Their indicators are only sent to the
enrichment providers when the item is from the last 14 days or `enrich_backfill` is on (see
[Enrichment](enrichment.md#which-indicators-a-run-picks)), and they fire no webhooks, MISP pushes or AI summaries. They
count in statistics and trends by their original dates, so last year's history fills the longer dashboard periods
without making anything trend today. See [History and storage](../history-and-storage.md#backfill).
