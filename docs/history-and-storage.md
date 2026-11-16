# History and storage

[← Documentation index](README.md)

Backfilling past data, retention tiers, full-text search and the optional PostgreSQL backend.

## Backfill

Manage → Backfill (admin) crawls further back than the live collectors, with presets of 7 days, 30
days, 90 days and 1 year or a custom range. Each source shows how far it can reach and how: WordPress sites (many
security blogs) return every post in the range through their REST API, other feeds are rebuilt from Internet
Archive snapshots, Bluesky, Mastodon, OTX and MISP page back with their own cursors, ransomware.live country and
group sources return their full victim lists, and ThreatFox reaches 7 days. *Estimate* shows the expected number
of items per source first (exact for WordPress sites). The backfill runs in the background, one source at a time,
with the usual progress bar, a stop button and a summary notification.

Backfilled items keep their original publication dates and are marked *history*, so they never show up as
trending now or as newly seen; their indicators are not sent to the enrichment providers unless you enable it
(free quotas stay with live data), and no webhooks, MISP pushes or AI summaries fire for them.

## Retention tiers

Items keep their full text for 180 days by default; after that they keep the title, link,
entities, severity and a short snippet, and the bulky raw provider data is dropped. Deleting old items is off by
default. Both are set under Settings → General. Copies of the text that some feeds repeat in their raw data are
dropped on ingest.

## Search

Search uses SQLite's FTS5 full-text index (title and text, word-prefix matching) and falls back to substring
matching on PostgreSQL.

## PostgreSQL

PostgreSQL is optional for large installs: start the bundled database with the `postgres` compose profile, or
point `JATMP_DATABASE_URL` at your own, and move an existing SQLite install over with `python manage.py copy-db`.
