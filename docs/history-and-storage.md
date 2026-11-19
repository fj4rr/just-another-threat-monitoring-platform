# History and storage

[← Documentation index](README.md)

This page covers backfilling past data, the retention tiers, full-text search, and the optional PostgreSQL
database.

## Backfill

The live collectors only see what each source lists right now. To fill in the past, use **Manage → Backfill**
(admin only). You can pick 7 days, 30 days, 90 days or 1 year, or set your own range.

Each source shows how far back it can go and how:

- **WordPress sites** (which includes many security blogs) return every post in the range through their REST API.
- **Other RSS feeds** are rebuilt from Internet Archive snapshots of the feed.
- **Bluesky, Mastodon, OTX and MISP** page back through their own history.
- **ransomware.live** country and group sources return their full victim lists.
- **ThreatFox** reaches back 7 days.

*Estimate* shows how many items to expect from each source before you start (the figure is exact for WordPress
sites). *Start backfill* and *Stop* are just below the page description; *Stop* only appears while a backfill is
running. The backfill runs in the background, one source at a time, with the usual progress bar and a summary
notification at the end. Stopping cancels the queued sources straight away and lets the current source finish
the page it is working on.

### How backfilled items are treated

Backfilled items keep their original publication dates and are marked as *history*. That means:

- They don't appear as trending in the last 7 days, or as newly seen. They do count when you pick a longer
  dashboard period (15 days to 1 year), which is what they are for.
- Sources that can't be backfilled leave gaps in those longer periods, and the dashboards point this out.
- Their indicators are only sent to the enrichment providers if they are from the last 14 days, unless you
  enable enrichment for backfilled items. That keeps the free quotas for live data.
- They don't trigger webhooks, MISP pushes or AI summaries, and they don't affect source health.

The details are in [Collection](how-it-works/collection.md#backfill).

## Retention tiers

By default, items keep their full text for 180 days. After that, they keep their title, link, entities,
severity and a short snippet, and the bulky provider data is removed. Deleting old items altogether is off by
default. Both settings are under Settings → General. Separately, whenever a feed repeats the full text in its
provider data, that copy is dropped as soon as the item is stored.

What exactly is kept, and when the nightly housekeeping runs, is described in
[Housekeeping and re-analysis](how-it-works/housekeeping.md#nightly-housekeeping).

## Search

Search looks through the title and text of every item, matching the beginnings of words (so `steal` finds
"stealer"). On SQLite it uses the FTS5 full-text index; on PostgreSQL it uses a full-text index of its own. Only a
SQLite build without FTS5 falls back to plain substring matching. Whatever you type is never passed to the search
engine as query syntax.

## PostgreSQL

PostgreSQL is optional and useful for large installations. Start the bundled database with the `postgres`
compose profile, or point `JATMP_DATABASE_URL` at your own server. To move an existing SQLite installation over,
run `python manage.py copy-db` with the new database's URL.
