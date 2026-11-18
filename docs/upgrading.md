# Upgrading

[← Documentation index](README.md)

Schema changes are applied automatically on start-up (new tables and columns; there are no manual migrations). The notes below list what else to do when moving to a version. After any upgrade, run `pip install -r requirements.txt` (or rebuild the Docker image) and restart. The full list of changes is in the [changelog](../CHANGELOG.md).

## Upgrading to 0.12.0

Trust and coverage items from the product review. No new dependency. One new column (`entities.verdict_at`) is
created on start-up.

- **Counts change.** Every dashboard figure now counts a story that several outlets carry once: *Items
  collected* became *Stories collected* and is lower than before, and so are the timelines, breakdowns, map
  counts, entity mentions and the PDF / Word report totals. *Items per source* still counts every copy.
- **One re-score after the upgrade.** About 90 seconds after the first start, every stored item is re-scored with
  the current severity rules (a background job, no network; it keeps enrichment bonuses and AI assessments) and a
  notification says when it is done. On a large install it takes a few minutes.
- **Verdicts age.** *Malicious* and *suspicious* IPs, domains and URLs are looked up again after 30 days
  (`verdict_recheck_days`) and may come back lower; they leave the IOC export feeds and TAXII once their verdict
  is older than 60 days and was not confirmed again (`verdict_feed_days`). Both are under Settings → Enrichment;
  0 turns them off. Expect your blocklist feed to shrink over the first weeks, and a few more lookups per run.
- **Personal data is redacted** from prompts to a cloud AI model by default. Set *Personal data in prompts* to
  *Never redact* under Settings → AI to keep the old behaviour.
- **Source health notifications**: expect a notification for sources that have been quiet for three times their
  usual gap or failing for a day; the Sources tab lists them.

## Upgrading to 0.11.0

Quick wins from a product review. New dependency `tzdata` (time zones on slim images and Windows): run
`pip install -r requirements.txt -c requirements.lock`, or rebuild the Docker image. No schema changes.

- **Daily schedule.** The executive summary (06:00) and housekeeping (03:30) still run in UTC until you set a
  time zone and times under Settings → General (or `JATMP_TIMEZONE`). A team in Jakarta usually wants
  `Asia/Jakarta` and 07:00; see [Configuration](configuration.md#daily-schedule).
- **The feed hides syndicated copies** by default and says how many it left out; *Show copies* lists them again.
  Bookmarked feed links show fewer rows than before for stories carried by several outlets.
- **Re-scoring keeps points.** *Re-score all items* and `manage.py reextract` now keep the enrichment bonus and
  the last AI assessment. Items re-scored by an older version lost their AI points; *Analyse with AI* again on
  the ones that matter. After an older `reextract`, one *Re-score all items* restores the enrichment bonus (the
  verdicts are stored on the indicators).
- **ThreatFox** items are keyed by the day ThreatFox first saw the IOCs and take in IOCs reported later that day.
  Items stored before the upgrade are not changed.
- **New sources ask for a TLP.** Existing sources without a TLP keep counting as CLEAR (shared); Settings →
  Sharing says how many there are.
- **Quota warnings** now come for every provider with a daily budget (GreyNoise, AbuseIPDB, context providers),
  not only VirusTotal: expect a notification on days a small budget such as GreyNoise's 40 runs out.

## Upgrading to 0.10.1

Fixes from a security, data-processing and efficiency audit. Install the new dependency (`cryptography`) with
`pip install -r requirements.txt -c requirements.lock`, or rebuild the Docker image.

- **API keys are encrypted** in the database on the first start. Keep `data/config.json` with your database
  backups from now on: without it the stored keys cannot be read and must be entered again.
- **Outbound guard.** Feeds, providers, the AI and MISP may only reach public addresses. Private hosts you already
  configured (a local Ollama, an internal MISP, an RSS-Bridge on the LAN, a feed on a `.local` name) are added to
  Settings → Sharing → *Private hosts JATMP may contact* on the first start. Anything private you add later goes
  there by hand (a local AI server is added for you when you save the AI tab in local mode); a blocked request
  says so in the source's error.
- **First-run setup** from another machine (or through Docker's port mapping) asks for a setup token. It is in the
  log (`docker compose logs jatmp`) and in `data/setup-token`.
- New columns (`users.session_version`, `items.fingerprint`, `items.dup_of`) and indexes on `items` and
  `entities` are created on start-up.
- One-off start-up jobs, without network requests: syndicated copies of the same story from different outlets are
  marked (statistics, trending and the executive summary count them once); the scam & fraud analysis and the
  sector tags are recomputed with the new rules.
- Malware families, actors and severity use stricter rules (everyday words such as *Bitter* or *Pegasus* need a
  qualifier, demonyms and platform names are no new family, a guessed family no longer outscores a known one,
  "critical infrastructure" is no critical bug). Stored items keep their old entities until you run
  `python manage.py reextract`, which also recomputes severities.
- `/healthz` no longer reports the version.

## Upgrading to 0.10

- New column `insights.data` (the structured executive summary) is created on start-up.
- About a minute after the first start, a background job tags every existing item with its critical infrastructure sectors (no
  network requests; `python manage.py sectortag` does the same).
- The scam & fraud rules changed (vendor listicles, criminal-charge names), so the start-up job re-analyses stored
  items once, as after 0.9.
- A one-off start-up job removes stylesheet text that some feeds printed into stored items (no network requests).
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
