# Data model

[← Documentation index](README.md)

All tables are SQLAlchemy models in `app/models.py`. Times are naive UTC (`models.utcnow()`); never store
local times or aware datetimes. This page lists what each table is for, the columns whose meaning is not obvious
from their name, and the rules the code relies on. How the tables are created and changed is described under
[Database and migrations](architecture.md#database-and-migrations).

## Overview

```
sources 1──* items 1──* item_entities *──1 entities 1──* enrichments
                │                            │ 1
                ├──* item_geo                ├──* entity_links (src → dst)
                │                            └──* watchlist *──1 users
users 1──* api_keys        webhooks 1──* webhook_deliveries
collector_runs   notifications   insights   audit_log   settings
```

## Content

### `sources`

One configured feed or account.

| Column | Meaning |
|---|---|
| `kind` | Collector key in `collectors.REGISTRY`: `rss`, `bluesky`, `mastodon`, `x`, `telegram`, `otx`, `urlscan`, `anyrun`, `threatfox`, `ransomwarelive`, `misp`, `scamsniffer` |
| `category` | `news`, `social` or `intel`. Intel sources use non-strict IOC extraction and may name families in tags. |
| `config` | Collector settings as JSON (`url`, `handle`, `query`, `filter`…); the keys are the collector's `fields`. Collectors may cache ids here (Mastodon `account_id`). |
| `interval_minutes`, `enabled` | Schedule (minimum 5 minutes). |
| `last_run`, `last_status`, `last_error`, `items_count` | Shown on the Sources tab. `last_status` is `ok`, `error`, `skipped` or `never`. |
| `tlp`, `redistribute` | Sharing rules for the source's items (`""` = CLEAR unless the item has its own TLP; `redistribute` None = the default for the kind). |
| `country`, `language` | The outlet's country and language; empty = detect. |
| `topic` | `""` or `fraud` (scam & fraud sources: a generic scam word is enough, and the source appears in the fraud section). |

### `items`

One collected article, post, pulse, scan or analysis. Unique on `(source_id, external_id)`.

| Column | Meaning |
|---|---|
| `external_id` | Dedup key within the source (max 512 characters; longer ids end in `#sha256:<hash>`). |
| `kind` | `article`, `post`, `pulse`, `scan`, `analysis`. |
| `content` | Plain text, at most 50,000 characters; trimmed to a snippet when the item is slimmed. |
| `tags` | Provider tags plus tags proposed by the AI summary (those are also listed in `raw["llm_tags"]`). |
| `raw` | Small provider metadata (`tlp`, `sector`, `industries`, `listed_by`, `llm_tags`…). |
| `published_at`, `collected_at` | Publication time from the provider (never in the future) and storage time. Statistics use `published_at`; the API's `since` uses `collected_at`. |
| `severity`, `severity_detail` | 0–100 and the reasons as `[{"label", "points"}]`; AI reasons carry `"origin": "llm"` and, from 0.11, `"target"` (the severity the model proposed, applied again by a re-score). |
| `tlp` | The item's own TLP (OTX, MISP); `""` = inherit from the source. |
| `origin` | `live` or `backfill` (historical items do not count as trending). |
| `slimmed_at` | Set when the retention tier trimmed the text. |
| `lang`, `src_country` | Detected language (`en`, `id`, `""`) and the outlet's country. |
| `fraud_score`, `fraud_detail`, `fraud_loss_idr`, `fraud_victims` | Scam analysis. **`fraud_score > 0` is the definition of a scam report** everywhere (pages, statistics, API). |
| `is_digest` | `true` for a newsletter or round-up that wraps several unrelated stories (Talos *Threat Source*, weekly recaps, podcasts). Set when the item is collected and re-set by `manage.py digesttag`. Co-mentions (*Mentioned together with*, the indicators listed for a family) skip these items, and correlation discounts them: see [Trends and correlation](how-it-works/trends.md#correlation). |
| `fingerprint`, `dup_of` | Cross-source dedup for articles. `dup_of` points at the original item (always an original, never another copy); every count of stories (dashboards, trends, reports) counts `coalesce(dup_of, id)` once; only per-outlet figures count items (see [Counting rules](how-it-works/trends.md#counting-rules)). The feed hides copies unless *Show copies* is ticked. |
| `llm_summary`, `llm_at` | AI summary in Markdown. |

`Item.source` is loaded with a join; `Item.entity_links` is loaded lazily, so list pages use
`.options(with_links())` to load all links of a page in one query.

### `entities`

Anything tracked across items. Unique on `(type, value)`; `value` is normalised (lower-case hashes and domains,
`+62…` phone numbers, `bank:number` accounts), `display` is what the UI shows.

| `type` | Notes |
|---|---|
| `malware`, `actor` | From the knowledge base, a pattern, a feed, a provider or the AI. `category` is the malware category or actor kind. |
| `cve`, `technique` | CVE ids and MITRE ATT&CK technique ids. CVE intel (KEV, EPSS, CVSS) is in `meta`. |
| `ip`, `domain`, `url`, `md5`, `sha1`, `sha256` | Indicators (`trends.IOC_TYPES`). `verdict` and `enriched_at` come from enrichment; `verdict_at` (0.12) is when the verdict was last given or confirmed (IPs, domains and URLs age, see [Verdicts that age](how-it-works/enrichment.md#verdicts-that-age)); `meta["analyst"]` (0.13) holds an analyst's verdict, which enrichment keeps; `country` is the hosting country of an IP, never a target. |
| `scam_type`, `brand` | Fraud taxonomy (`fraud.NAMED_TYPES`). |
| `phone`, `bank_account`, `ewallet`, `crypto_wallet` | Scammer identifiers (`fraud.IDENT_TYPES`): personal data, **never** returned by the API, feeds, STIX / TAXII, webhooks or MISP; phones, accounts and e-wallets are deleted after `fraud_identifier_days` without mentions. |
| `sector` | Critical infrastructure sector key (`sectors.SECTOR_KEYS`). |

`mention_count`, `first_seen` and `last_seen` are maintained by `pipeline.link_entities` (and by the code that
removes links, which decrements the count). Entities with no mentions and no links are removed by housekeeping
and by `manage.py reextract`. `verdict` is `""` until enriched, then `malicious`, `suspicious`, `clean` or
`unknown`.

### `item_entities`

Which entities an item mentions. Unique on `(item_id, entity_id)`.

| `origin` | Produced by |
|---|---|
| `regex` | IOC, CVE and technique patterns in the extractor, and scammer identifiers |
| `kb` | Knowledge base matches (families, actors), scam types, brands and sectors |
| `heuristic` | A new family name found by pattern ("Zorblax ransomware"); scores lower than a known family and only trends once two sources name it |
| `feed` | Structured indicators and family tags supplied by the feed |
| `llm` | Proposed by the AI summary; shown with an *AI* badge |

`manage.py reextract` deletes and rebuilds the `regex`, `kb` and `heuristic` links and keeps `feed` and `llm` ones.

### `item_geo`

The countries (and Indonesian provinces, ISO 3166-2 in `region`) an item is *about*: victims or the place where
something happened. Attacker origin and hosting location are deliberately not stored here. `origin` is `text`
or `feed`.

### `entity_links`

Relationships between entities found by providers (`hash → family`, `ip → domain`). Unique on
`(src_id, dst_id, provider)`. `relation` is `attributed-to`, `related`, `exploits`…; `provider` decides whether
the link may be shared (`sharing.REDISTRIBUTABLE_PROVIDERS`).

### `enrichments`

One row per entity and provider with that provider's last answer (`verdict`, `score`, `summary`, `permalink`,
`data` with tags and family labels). Unique on `(entity_id, provider)`. Provider details only leave JATMP when
`api_share_provider_details` is on.

### `insights`

AI output that is not attached to an item or entity: `kind` `digest` (executive summary, structured fields in
`data`) or `answer` (Q&A, deleted after 90 days).

## Users and access

| Table | Notes |
|---|---|
| `users` | `role` is `viewer`, `analyst` or `admin` (`auth.ROLES`, ordered). Single-user mode uses a built-in local user (`auth.LOCAL_USER`) that cannot log in. `session_version` is bumped by `auth.end_other_sessions()`; cookies with another version are rejected. `notif_read_at` is the notification read watermark. |
| `api_keys` | `prefix` (public part), `secret_hash` (SHA-256 of the secret, never the secret), `scopes` (`read`, `export`, `write`), `expires_at`, `revoked_at`, `last_used_*`. |
| `watchlist` | Entities a user watches (`entity.watched` webhook, watchlist page). |
| `audit_log` | Who did what (`audit(db, user, action, detail, request)`), with the client IP. |
| `corrections` | Analyst corrections (0.13): `kind` (`unlink`, `false_positive`, `verdict`, `not_scam`), `item_id` / `entity_id`, `value` (the verdict), `reason`, who and when, `active` until undone (`undone_at`, `undone_by`), and in `data` what it changed (removed links with their origin, the previous verdict) for the undo and the quality report. See [Corrections and quality](how-it-works/corrections.md). |

## Operations

| Table | Notes |
|---|---|
| `collector_runs` | One row per job run. `job` is `source:<id>`, `backfill:<id>`, `enrichment`, `cve_intel`, `geotag`, `fraudtag`, `rescore`…; `status` is `queued`, `running`, `ok`, `error`, `skipped` or `aborted`; `batch_id` groups the runs of one manual action (`collect-…`, `backfill-…`); `progress_*` and `phase` are copied from the in-memory progress when the run finishes. Deleted after 30 days. |
| `notifications` | `user_id` None = everyone; `key` de-duplicates (the same key is not written twice); `link` is a same-origin path. |
| `webhooks`, `webhook_deliveries` | Hooks store a `salt`, not a secret: the signing key is derived from the install secret. Deliveries are `pending`, `ok` or `failed`, with `attempts` and `next_attempt_at` for the back-off. |

## Settings

`settings` is a key–value table (`key`, JSON `value`). Every key is declared in `settings.SCHEMA` as
`(default, env var, label, kind, group)`:

- `settings.get(key)` returns the environment variable when one is set (the UI then shows the field as locked),
  else the stored value, else the default. Values are cached for 5 seconds.
- `kind` is `text`, `int`, `bool`, `secret` or `select:a,b,c`. `int` values are clamped by `INT_BOUNDS` when
  saved from the UI.
- Values of kind `secret` are stored as `enc:v1:<Fernet token>`. The key is derived from `secret_key` in
  `data/config.json`, so a database without its `config.json` cannot decrypt them (they then read as empty).
- Keys that are not in `SCHEMA` are internal state: rules versions (`fraud_version`, `geo_version`,
  `sector_version`, `content_version`, `dedup_version`, `digest_version`), `netguard_seeded`, provider daily budgets, the builtin
  sources already offered.

`data/config.json` (not in the database) holds what must exist before the database does: `installed`, `mode`
(`single` or `multi`), `app_name`, `secret_key` (session signing, webhook signatures, settings encryption) and
`database_url`.
