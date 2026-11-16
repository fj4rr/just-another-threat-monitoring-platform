# Upgrading

[← Documentation index](README.md)

Schema changes are applied automatically on start-up (new tables and columns; there are no manual migrations). The notes below list what else to do when moving to a version. After any upgrade, run `pip install -r requirements.txt` (or rebuild the Docker image) and restart. The full list of changes is in the [changelog](../CHANGELOG.md).

## Upgrading to 0.10

- New column `insights.data` (the structured executive summary) is created on start-up.
- About a minute after the first start, a background job tags every existing item with its IIV sectors (no
  network requests; `python manage.py sectortag` does the same).
- The scam & fraud rules changed (vendor listicles), so the start-up job re-analyses stored items once, as after
  0.9.
- The dashboard at `/` is now *Cyber threats*; the scam & fraud overview at `/fraud` became a dashboard of its
  own, and the scam pages moved from tabs into the sidebar. Bookmarks keep working.
- The daily AI digest is now a short executive summary. Nothing to configure; the next scheduled or manual run
  writes the new format.

## Upgrading to 0.9.1

- New built-in sources are added automatically on start-up from now on (a notification lists them). The first start
  after this upgrade adds every built-in source the install does not have, the 15 Indonesian news sections
  included; a built-in source you deleted earlier comes back once in that run, so delete it again if needed. After
  that, deleted built-in sources stay deleted.

## Upgrading to 0.9

- New columns `sources.topic`, `items.fraud_score`, `items.fraud_detail`, `items.fraud_loss_idr` and
  `items.fraud_victims` are created on start-up.
- About 40 seconds after the first start, a background job runs the scam & fraud analysis on every existing item
  (*Re-analyse items* under Settings → Scam & fraud does the same, and so does `python manage.py fraudtag`). No
  network requests.
- **Add new built-in sources** under Settings → Sources adds the Telegram channels (vx-underground enabled, three
  disabled), FBI IC3, CekFakta.com, Liputan6 Cek Fakta and ScamSniffer.
- Telegram needs nothing more for public channels. For MTProto, `pip install -r requirements-telegram.txt` and run
  `python manage.py telegram-login` (optional; see [Sources](sources.md#telegram)).
- `manage.py reextract` now also rebuilds the scam types, brands and identifiers.
- Scammer phone numbers, bank accounts and e-wallets not mentioned for 365 days are deleted by the nightly
  housekeeping; change or turn this off under Settings → Scam & fraud.

## Upgrading to 0.8

- New table `item_geo` and columns `items.lang`, `items.src_country`, `sources.country`, `sources.language` and
  `entities.country` are created on start-up. Columns added this way now get their default value on existing rows
  (earlier versions left them NULL).
- About 20 seconds after the first start, a background job assigns target countries, provinces, language and
  source country to every existing item (*Re-run geography* under Settings → General does the same, and so does
  `python manage.py geotag`). No network requests.
- **Add new built-in sources** under Settings → Sources adds the Indonesian news feeds (and, from 0.8.1, Seraphim News and two Indonesian X accounts). Set the country of
  your own outlets under *Edit* so they count for the source-country view (Indonesian ones also for the National
  view).
- For hosting countries without provider lookups, press *Download GeoIP database* (Settings → General or the
  Geography page) or run `python manage.py geoip-update`.
- Run `python manage.py rescore` to apply the Indonesian severity terms to items collected before the upgrade.
- New dependency: `maxminddb` (pure Python), so run `pip install -r requirements.txt` again.
- 0.8.2 changes no schema. Actors you added in `data/knowledge_extra.json` count as *unclassified* on the
  dashboard until you give them a `category` (see [Configuration](configuration.md#extending-the-knowledge-base)).

## Upgrading to 0.7

- New columns `items.origin` and `items.slimmed_at` are added on start-up, and the full-text index is built once
  (a few seconds per 100,000 items).
- **Retention changed.** The default for deleting old items is now *never* (it was 180 days), because a backfill
  of a year would otherwise be deleted the same night; instead, items older than 180 days are slimmed to title,
  link, entities, severity and a snippet. An install where you saved a retention value keeps it, and the backfill
  does not reach further back than that.
- PostgreSQL, Docker: in `.env` set `JATMP_WITH_POSTGRES=1`, `JATMP_DB_PASSWORD=<strong password>` and
  `JATMP_DATABASE_URL=postgresql+psycopg://jatmp:<password>@db:5432/jatmp`, then `docker compose --profile postgres
  up -d --build`. Without Docker: `pip install -r requirements-postgres.txt`. To bring existing data along, run
  `python manage.py copy-db <url>` against the new, empty database before switching `JATMP_DATABASE_URL`.

## Upgrading to 0.6

No schema changes. Context providers are off until a key is set (or keyless lookups are allowed), and context
lookups only run when someone presses *Context lookup* unless the automatic option is enabled. TAXII clients
need an API key with the `read` scope; STIX downloads through the API need `export`.

## Upgrading to 0.5

Automatic on start-up: new tables (`api_keys`, `webhooks`, `webhook_deliveries`) and columns (`sources.tlp`,
`sources.redistribute`, `items.tlp`). Run **Add new built-in sources** under Settings → Sources to get the two
ransomware.live sources (disabled). Existing items have no TLP of their own and count as their source's TLP
(CLEAR unless you set one). In single-user mode the API, like the rest of the app, needs no login; keep such an
install on localhost or use multi-user mode before exposing it.

## Upgrading to 0.4

Nothing to do by hand: on start-up the new `notifications` table is created and the new columns on
`collector_runs` and `users` are added. The first CVE lookup runs three minutes after start-up and fills in
KEV / EPSS / CVSS for CVEs mentioned in the last 30 days; press **Refresh CVE intel** on the CVE page or run
`python manage.py cve-intel` to start it right away.

## Upgrading to 0.3

Severity scores and their breakdowns are computed when an item is ingested. Items collected by an earlier
version keep their old score until you run `python manage.py rescore` or press **Re-score all items** under
Settings → General; this is a local pass over the database and makes no network requests. The new
`severity_detail` column is added automatically on start-up. Word and PDF export need two additional
packages, so run `pip install -r requirements.txt` again.
