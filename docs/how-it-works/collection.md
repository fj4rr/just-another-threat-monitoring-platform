# Collection

[← How JATMP works](index.md)

This page explains how sources are scheduled, what each collector fetches on a run, how runs are tracked and
reported, how JATMP notices a source that has stopped working, and how a manual collection or a historical
backfill differs from the normal schedule. For the list of built-in sources, see [Sources](../sources.md).

## Scheduling

Every **enabled** source gets its own scheduled job (`source:<id>`), which runs `jobs.run_source`. These rules
apply:

| Rule | Value | Why |
|---|---|---|
| Interval | The source's `interval_minutes`, at least **5** | The built-in defaults are 30 minutes for Bluesky and Mastodon, 60 for most RSS feeds, and 180 for fraud feeds, X and ThreatFox |
| First run after start-up | 5 s + 3 s × source id | Spreads the first wave out, so dozens of sources don't start in the same second |
| Overlap | A source never runs twice at the same time | A slow feed can't pile up runs |
| Missed runs | Merged into one, as long as it is no more than 10 minutes late | After a pause the source catches up once, not once for every missed turn |
| Threads | All jobs share one pool of 10 threads | A provider that hangs blocks one thread, not the whole platform |

When you edit, enable or disable a source under Settings, its job is rescheduled (or removed) straight away.
Deleting a source removes its job and its items.

Collectors never decide *when* they run; they only know how to fetch. Every request they make goes through
JATMP's outbound guard (`app/netguard.py`), which only allows public addresses unless you allow-list a host,
checks every redirect, stops reading a response after 20 MB (after decompression), and gives up after 30 seconds.
See [Security](../security.md).

## One run, step by step

```
run_source(source_id)
 │
 ├─ 1. create or claim the run record ............ status "running"
 ├─ 2. collector.fetch() .......................... phase "fetching"
 ├─ 3. pipeline.ingest_committed(raw items) ....... phase "storing"  (see Ingest and analysis)
 ├─ 4. update the source's status
 ├─ 5. side effects of the new items .............. webhook events, MISP auto-push
 ├─ 6. close the run .............................. status "ok", "fetched N, new M"
 └─ 7. queue AI auto-summaries .................... only when enabled
```

1. **Run record.** A run record (`CollectorRun`) is created and set to `running`. For a manual batch, the record
   that was already queued for this source is used instead.
2. **Fetch.** The collector for the source's type asks the provider for its current list of entries.
   See [What one run fetches](#what-one-run-fetches).
3. **Ingest.** All entries go through the pipeline in a single transaction, and only new ones are stored.
   Progress ("storing 40/100") is updated every five entries.
4. **Source status.** The source's last status, last error and last run time are updated. You can see them on
   the Sources tab.
5. **Side effects.** For the newly stored items, JATMP queues webhook events (`item.high_severity`,
   `entity.watched`) and, if `misp_autopush_min_severity` is above 0, starts a MISP auto-push. If anything goes
   wrong here it is logged, but the run itself still succeeds.
6. **Close.** The run is closed with its status, a short message and the number of new items.
7. **AI.** If auto-summaries are on and an AI model is configured, the new items join the summary queue, which
   has its own job (see [AI processing](ai.md#auto-summaries)).

Some collectors remember a little between runs so they only ask for what is new: Mastodon keeps the account id,
X keeps the user id and the last post id it saw, and the OTX, MISP and ransomware.live collectors ask for what
changed since their last run.

## Run outcomes

| Status | What it means | Source status | Notification |
|---|---|---|---|
| `ok` | The run fetched and stored entries. Zero new items still counts as `ok` | `ok` | None for scheduled runs |
| `skipped` | The collector can't run for a known reason: a missing API key, no handle or URL, Telegram not signed in | `skipped` | None. A manual batch says how many were skipped |
| `error` | Anything else: an HTTP error, a feed that can't be parsed, a timeout, a rate limit (`429`) | `error`, with the message | Once, when a scheduled run goes from working to failing (*Source failing: …*). After 24 hours of failures, a daily reminder follows until it recovers (see [Source health](#source-health)) |
| `aborted` | The process stopped while the run was queued or running, or someone stopped a backfill | unchanged | None |
| `queued` / `running` | Still in progress. Status views treat a record that has been in these states for over 3 hours as dead | — | — |

If a run fails while fetching or storing, everything it stored is rolled back. A source therefore adds either a
complete batch or nothing at all, and the next scheduled run simply tries again.

## Source health

A source can stop working without ever reporting an error. A feed that has moved may return an empty page, or a
site that blocks JATMP may return a normal-looking response with nothing in it. Every run is then `ok` with zero
new items, and nobody notices.

To catch this, JATMP looks at each source's live items and its last 30 days of run history
(`app/sourcehealth.py`), and shows the result next to the source on the Sources tab:

| Figure | How it is worked out |
|---|---|
| Last new item | When the source last brought in a live item (backfills don't count) |
| This week · usual | Live items from the last 7 days, compared with the weekly average of the 4 weeks before. It is marked *below usual* when it drops under 30% of that average (for sources that usually bring at least 5 a week) |
| Usual gap | The median time between runs that brought something new. It needs at least 3 such gaps before it shows a value |
| Failing for | How long ago the current run of failures started |
| Summary only | The source's news items average fewer than **400** characters of text. The feed only carries summaries, so extraction and severity scoring have little to work with |

Every hour, `jobs.run_source_health` checks two conditions and sends a notification (at most once per source,
condition and day):

- A source is **quiet** when it has brought no new item for **3** times its usual gap, and at least 12 hours.
- A source has been **failing for 24 hours** or more.

The Sources tab also lists the sources that need attention above the table.

## What one run fetches

Each scheduled run asks the provider for its *current* list. Entries that are already stored are skipped during
ingest, so overlap between runs only costs a little bandwidth.

| Type | One scheduled run fetches | Item kind | Notes |
|---|---|---|---|
| `rss` | The feed (up to 10 MB). The first 500 entries are read, the topic filter is applied, and the newest **100** are kept | `article` (`post` for social sources) | The text is the entry's full content if the feed has it, otherwise its summary. The article page itself is never opened |
| `bluesky` | The account's last **50** posts, without replies | `post` | Public API, no key needed |
| `mastodon` | The account's last **40** posts, without replies | `post` | The account id is remembered after the first run |
| `x` | The last **50** posts through API v2 (only ones newer than the last post seen), or the configured RSS bridge | `post` | Skipped without a bearer token or bridge. A `429` rate limit counts as an error |
| `telegram` | The latest page of the channel's public web preview (20 posts), or the last **50** messages over MTProto | `post` | Posts without text are skipped |
| `otx` | Subscribed pulses changed since the last run (3 days on the first run), up to 50; or one pulse search (30 results) | `pulse` | Up to 300 indicators per pulse come in as structured indicators. The pulse's TLP, targeted countries and industries are kept |
| `urlscan` | One search (by default, malicious verdicts from the last day), **100** results | `scan` | The URL, domain and IP of each scan come in as indicators |
| `anyrun` | One TI Lookup query over the configured period (7 days by default), **100** tasks | `analysis` | Never shared outside JATMP (provider terms) |
| `threatfox` | IOCs from the last day, grouped into **one item per family per day** (up to 300 IOCs per run) | `pulse` | The day is the day ThreatFox first saw the IOCs. If a later run finds new IOCs for a family and day that are already stored, it adds them to that item, updates the count in its title and scores it again. No new item is created, so no new webhook event is sent |
| `ransomwarelive` | The 100 most recent victims, or the full list for one country or group (keeping posts newer than the last run minus 2 days) | `post` | The victim's website is deliberately left out of the text: it belongs to the victim and is not an indicator |
| `misp` | Events changed since the last run minus 1 hour (the last `days` days on the first run, 7 by default), 50 per page, up to 5 pages | `pulse` | The event's TLP is kept; attributes become indicators |
| `scamsniffer` | The daily list files of the last 4 days (the public list is published a week late) | `article` | One item per day. Its domains are marked malicious as soon as they arrive |

Intel sources (category `intel`) are handled a little differently during ingest: indicators are taken from plain
text, not just defanged text, and their tags may name malware families. See
[Ingest and analysis](processing.md#4-entity-extraction).

## Topic filters

Any news or social source can have a topic filter (`filter` in its configuration): RSS feeds, Telegram channels,
X, Mastodon and Bluesky accounts (since 0.13; it used to exist for RSS only, so a general Telegram channel brought
in everything). Intel feeds don't offer it. The filter runs on what a collector fetched **before anything is
stored** (`processing/topics.py`, for scheduled runs and backfills alike), so entries it drops leave no trace; the
run message says how many were off topic ("fetched 40, 31 off topic, new 9").

| Filter | Keeps an entry when | Used for |
|---|---|---|
| `security` | A security term (English or Indonesian) appears in the title, the first 3,000 characters of the text, or the tags | General technology sections |
| `cyber` | An unambiguous cyber or digital-fraud term appears, **or** the [scam analysis](../fraud.md) recognises a scam | General news sections and general Telegram or X channels, where words like "bocor" or "modus" usually mean something else |
| `fraud` | The scam analysis recognises a scam | Fact-checkers, whose feeds are mostly about political hoaxes |

The source **topic** *scam & fraud* is a separate setting. It doesn't filter anything. Instead it tells the scam
analysis to treat the source's items as likely scam reports (a single scam word is enough for *Other scam*), and
it lists the source on the fraud overview.

## Runs, batches and progress

- **Scheduled runs** create their record when they start and close it when they finish.
- **Manual collection** (*Collect now*, *Run now*, `manage.py collect`) first creates one `queued` record per
  source, all sharing one batch id, and then starts the runs. The status bar shows the whole batch, for example
  "Collecting… 12/40 sources · 85 new". Clicking again while it runs finds the active batch rather than starting
  a new one, and *Run now* on a source that is already running is ignored.
- **Progress** (fetching, storing N of M, the phase of an enrichment run) is kept in memory and served to the
  page, which polls it. It isn't written to the database during the run, so it never competes with the run's
  own writes.
- **Batch summary.** When the last run of a batch finishes, **one** notification sums it up, for example
  "Collected 85 new items from 40 sources, 2 errors", with the names of the sources that failed and how many were
  skipped. Inside a batch, the per-source *Source failing* notification isn't sent.
- **Restarts.** At start-up, every run that was still `queued` or `running` is marked `aborted` ("interrupted by
  a restart"). Nothing resumes half-way.

## Backfill

A backfill (Manage → Backfill) fetches history instead of the current list. It works like this:

1. One `queued` run is created for each selected source, all in one backfill batch.
2. A **single worker** goes through them one at a time. Backfills are long, and SQLite only allows one writer at
   a time, so sources are never backfilled in parallel.
3. For each source, the collector says what it can do: whether it supports backfill, how, and how far back.
   Sources that can't be backfilled are `skipped`, and the start date is limited to how far the source can reach
   (7 days for ThreatFox, for example).
4. The collector returns entries **page by page**. Each page is stored and committed on its own, marked as
   `backfill`, so a backfill that is stopped or fails keeps everything it already stored.
5. *Stop* cancels the queued sources straight away and lets the current source finish the page it is on.
6. One notification sums up the batch.

| Collector | How far back it can go |
|---|---|
| RSS on a WordPress site | The site's REST API returns every post in the range (100 per page), so the estimate is exact |
| Other RSS | Internet Archive snapshots of the feed (one a day), filtered to the range. You only get what the feed listed when it was archived |
| Bluesky / Mastodon | The account's history, paged back with the API's cursor (up to 6,000 posts / 4,000 statuses per account per run) |
| Telegram | Older pages of the web preview (up to 3,000 posts), or MTProto (up to 5,000) |
| OTX / MISP | Subscribed pulses or events changed within the range |
| ThreatFox | The API's limit of 7 days |
| ransomware.live (country or group source) | The full victim list, back to 2021 for most groups |
| ScamSniffer | One archive file per day, back to 31 May 2022 |
| X, urlscan, ANY.RUN, ransomware.live recent | Not supported (quota-limited or recent-only) |

Backfilled items keep their original publication dates and are marked as `backfill`. Their indicators are only
sent to the enrichment providers if the item is from the last 14 days or `enrich_backfill` is on (see
[Enrichment](enrichment.md#which-indicators-a-run-picks)). They don't trigger webhooks, MISP pushes or AI
summaries, and they don't count towards source health. They do count in statistics and trends, by their
original dates, so last year's history fills the longer dashboard periods without making anything trend today.
See [History and storage](../history-and-storage.md#backfill).
