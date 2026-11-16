# Changelog

All notable changes to JATMP. Upgrade steps per version are in [docs/upgrading.md](docs/upgrading.md).

## 0.10.0

- **Two dashboards.** The sidebar now opens with *Dashboard → Cyber threats* (the former dashboard) and
  *Dashboard → Scams & fraud*, a full dashboard of its own: scam reports over time stacked by scam type, a globe of
  the most targeted countries or provinces, KPI tiles with sparklines (reports, largest loss, scam types, brands,
  identifiers), trending scam types, impersonated brands, the latest scammer identifiers, charts by scam type, by
  kind of brand, by sector and by source, recent and highest-scoring reports. The scam pages moved from tabs into
  the sidebar under *Intelligence → Scams & fraud* (Scam reports, Scam types, Impersonated brands, Scammer
  identifiers), next to the cyber pages.
- **Dashboard period**: 7 or 15 days, 30 days, 3 or 6 months, or 1 year, on both dashboards; every tile, table,
  chart, the radar and the globe follow it, and the choice is remembered. Charts switch to weekly bars above 90 days.
  Periods that reach past the live collectors show a note that older days come from the historical backfill, that
  not every source can be backfilled, how many backfilled items the period holds, and (for admins) a link to the
  Backfill page.
- **Critical infrastructure sectors**: every item is tagged with the critical information infrastructure sectors of
  Indonesia's Perpres 82/2022 it
  is about (government administration, energy & mineral resources, transportation, finance, health, ICT, food,
  defence), from the organisations and services it names as targets, or from the sector a feed states
  (ransomware.live, OTX industries). Shown as a *Critical infrastructure sectors* chart on both dashboards (click a bar for its
  items), as chips on items, as a filter on the scam reports list and as `sectors` in the REST API. Existing items
  are tagged once in the background after the upgrade (`python manage.py sectortag`).
- **Executive summary** instead of the long AI digest: a one-line headline, an overall threat level, three or four
  key points and up to three actions for today, asked from the model as JSON and shown with the platform's own
  components (no more stray markdown rules or LaTeX such as `$\le$`). The data it gets now includes scam types and
  sectors. Older digests still display as text.
- **Backfill page**: *Start backfill* and *Stop* sit under the description instead of jumping around in the page
  header while a backfill reports progress. *Stop* only shows while a backfill runs, hides itself once the
  backfill stops, and cancels the queued sources right away; the status reads *Stopping after the current page*
  until the source being crawled finishes its page.
- **Faster scam and blocklist processing**: indicators of an item are looked up and created in one query per type
  instead of one per indicator, and blocklist verdicts are recorded in bulk (a ScamSniffer day with 500 domains went
  from about 2,000 queries to a handful, which matters most for its backfill back to 2022); the scam-type spread
  counts are computed once per type and day per batch; *Re-analyse items* loads items in chunks and skips the
  database work for items that are not about a scam before or after (about 40% faster on a 2,300-item test copy).
- Scam detection: vendor listicles ("Top 10 Best … Tools [Ranked & Scored]") only count their title, so a list of
  fraud-detection products is no longer filed as a scam report. Stored items are re-analysed once after the upgrade.
- Fix: the scam overview's brand list styled the sidebar's logo row too (shared class name).
- **Documentation site**: the `docs/` pages also build a searchable MkDocs (Material) site with light and dark
  themes, published to GitHub Pages from `main` (`.github/workflows/docs.yml`, strict: broken links and anchors
  fail the build). The Markdown still reads on GitHub; see [Development](docs/development.md#documentation-site).
  Screenshots of the dashboards, scam pages and backfill page are updated.
- API: `/api/stats/*` take periods up to 365 days; `scope=fraud` limits trending, trending timelines, sources and
  sectors to scam reports; new `/api/stats/fraud/overview`, `/fraud/kpi_series` and `/fraud/timeline`; timelines
  return `step` (1 = daily, 7 = weekly).

## 0.9.2

- Fix: switching the AI settings from Off or a local runtime to a cloud provider kept the previous preset's server
  address and model (Ollama's `http://localhost:11434` and `llama3.1`), so calls to the provider failed. Both the
  form and the server now replace values that belong to another vendor's preset; values you typed yourself are
  kept. Re-save the AI settings if you configured a cloud provider this way.
- Gemini suggestions follow Google's current free tier: `gemini-3.8-flash` (default), `gemini-3.5-flash-lite`,
  `gemini-3.6-flash`, `gemini-4-hydrogen`. The 2.5 models are retired on 1 December 2026.

## 0.9.1

- **15 Indonesian general news sections** for the National view: Detik News, CNN Indonesia Nasional and Ekonomi,
  CNBC Indonesia News, Antara Terkini and Hukum, Liputan6 News, Republika News, Okezone News, Sindonews Nasional,
  Jawa Pos Nasional, iNews, JPNN, Katadata and BBC News Indonesia. Breaches, attacks on public services, *judol* and
  digital fraud are often reported there rather than in the tech sections.
- New RSS topic filter **`cyber`** for general news: only unambiguous cyber and digital-fraud terms count, plus scam
  reports, so "tabung gas bocor", "modus penyelundupan" or a hijacked bus no longer pass as they would with the
  `security` filter.
- **New built-in sources join automatically** on start-up, with a notification. JATMP remembers which built-in
  sources it has offered, so a source you deleted does not come back. The first start after upgrading adds every
  missing built-in source once (as *Add new built-in sources* did); the button and `manage.py seed-sources` still
  add every missing one.
- Checked and not added: Tribunnews, Bisnis and Tirto refuse automated clients; Kumparan, IDN Times, Suara,
  Merdeka and Beritasatu publish no feed; DailySocial's feed stopped in July 2026.

## 0.9.0

- **Telegram collector** (`app/collectors/telegram.py`): public channels through their web preview
  (`t.me/s/<channel>`), no account needed, with links, forwarded-from names, file names and view counts, and a
  backfill of up to 3,000 posts per run. Optional MTProto through Telethon (`requirements-telegram.txt`, api_id /
  api_hash under Settings → Social, `python manage.py telegram-login` once) for channels without a preview and
  deeper history; both produce the same item ids. Built in: vx-underground (enabled), The Hacker News,
  BleepingComputer and CVE Notify (disabled). Channels run by threat actors are left to the analyst.
- **Scams & fraud section** (`app/processing/fraud.py`, `/fraud`): every item is also checked as a possible scam
  report, on the same pipeline and entity graph. New entity types: scam type (19 types in English and Bahasa
  Indonesia, from *investasi bodong* and *pinjol ilegal* to APK wedding invitations, QRIS fraud and crypto
  drainers), impersonated brand (about 70 Indonesian and global banks, e-wallets, marketplaces, couriers,
  government bodies and platforms), and scammer identifiers (phone numbers, bank accounts, e-wallets, crypto
  wallets).
- **Fraud score** (0–100, explained like the severity): scam type, losses converted to rupiah, victim count,
  impersonated brand, published identifiers, an official warning or arrest, and spread velocity (reports of the
  same scam type doubling week on week). Shown on the item page, in the preview, in the feed and the API.
- **Pages**: overview (KPIs, scam types this week against last week with the malware and brands seen alongside,
  most impersonated brands, recent and top reports, latest identifiers, fraud sources), scam reports, scam types,
  impersonated brands and scammer identifiers, all with the International / National switch.
- **UU PDP data minimisation**: identifiers only from scam reports and only where the text marks them as the
  scammer's; official and victims' numbers and account holder names are skipped; phone numbers, accounts and
  e-wallets unseen for a year are deleted; identifiers never leave through the API, feeds, STIX / TAXII, webhooks
  or MISP. Extraction can be turned off.
- **Fraud sources** (topic *scam & fraud*): FBI IC3 announcements, CekFakta.com and Liputan6 Cek Fakta (new RSS
  topic filter `fraud`), and ScamSniffer's crypto phishing blocklist as a new collector (one item per day, domains
  marked malicious on arrival so they spend no enrichment quota, backfill to 2022). Any source can get the topic.
- REST API v1 items carry a `fraud` object; scam types and brands appear in the relationship graph and weigh into
  item correlation (a shared scammer account or wallet is strong evidence).
- `manage.py fraudtag` and *Re-analyse items*; a one-off analysis of existing items after the upgrade.
- README: the dashboard screenshot now stops at the KPI tiles.

## 0.8.3

- Threat radar icons: a bug for malware families, a broken shield for CVEs and a hooded hacker for threat actors,
  instead of circles, diamonds and triangles. The same icons appear in the legend and on the filter buttons.

## 0.8.2

- **Dashboard rework.** Top row: the threat radar next to a globe. Below it, five KPI tiles in one row (new:
  *Threat actors*, with a sparkline), the AI digest (only when an LLM is configured), a lower collection-volume
  chart, *Trending malware*, *Trending CVEs* and *Trending threat actors* side by side (each scrolls on its own),
  the trend-over-time chart, three breakdowns, and *Notable recent items* next to *Items per source* and
  *IOC verdicts*. *Most-mentioned families* is gone.
- **Threat radar** shows trending CVEs and threat actors as well as malware families, one shape and colour per
  type (circle, diamond, triangle); buttons in the card head hide or show each type, and a dashed ring marks
  entries first seen this week.
- **Globe** (`static/js/globe.js`) replaces the dashboard map and the *Most targeted countries* card: the top 10
  target countries (provinces in the National view) pulse on a globe that turns from one to the next and shows a
  callout with the count and the families and actors named. Drag to turn it, hover for a country's count, click
  to open the feed, use the numbered buttons to jump to a target, zoom with + / −. It reuses the Natural Earth
  outlines of the flat maps (no new data, no library) and stays still with *prefers-reduced-motion*.
- **Trend over time** has a dropdown for malware families, CVEs or threat actors
  (`/api/stats/trending_timeline?type=`).
- **New breakdowns**: *CVEs by exploitation risk* (in CISA KEV, EPSS 10%+, CVSS critical / high / lower; CVEs not
  yet rated are counted under the chart) and *Threat actors by type* (nation-state, ransomware, extortion,
  cybercrime). Actors in the built-in knowledge base are classified; others can get a `category` in
  `data/knowledge_extra.json`. `/api/stats/categories` takes `type=malware|cve|actor`.
- **CVSS and EPSS explained**: hovering or focusing the CVSS, EPSS and priority headers (CVE list, dashboard,
  CVE pages) opens a short explanation.
- **Geography page**: the map and list cards have the same height and the lists scroll inside them; *Most
  targeted* now lists every target country instead of the top 10.

## 0.8.1

- **More Indonesian sources**: Seraphim News (RSS, security-only, so no topic filter) and two Indonesian X
  accounts, secgron (Teguh Aprianto, Ethical Hacker Indonesia) and Id_SIRTII (Id-SIRTII/CC under BSSN), disabled
  by default like the other optional X accounts. Indonesian X accounts carry country and language, so they count
  for the National view. Add them with *Add new built-in sources* under Settings → Sources.
- Not added, after checking: bssn.go.id answers automated clients with 403, Tempo's feed sits behind a Cloudflare
  challenge, Kompas forbids automated collection in its robots.txt, and cyberthreat.id is offline. No Indonesian
  security account on Bluesky posts regularly.

## 0.8.0

- **Geo attribution** per item (`app/processing/geo.py`, `app/gazetteer.py`): target countries from place names,
  demonyms, Indonesian provinces, cities, regencies, institutions and domains, leak-site victim countries and the
  countries OTX and ransomware.live supply; attacker countries ("Russian hackers", "China-nexus", "attributed to",
  "peretas asal") are recognised and left out. Stored in the new `item_geo` table, kept apart from the source
  country (`items.src_country`, `sources.country`) and the hosting country of IPs (`entities.country`).
- **International / National (ID) switch** in the top bar for the dashboard, Feed, Malware, Actors, CVEs, IOCs,
  statistics and the report builder (new *Scope* option); remembered for the session.
- **Geography page** with a world map of target countries and an Indonesian province map (Natural Earth, public
  domain, pre-projected so no map library is needed; `static/js/geomap.js`), families and actors per country,
  hosting countries, source countries and languages. A map card on the dashboard follows the switch.
- **Offline GeoIP** for IP indicators (`app/geoip.py`): DB-IP Lite or MaxMind GeoLite2 in `data/geoip/`, downloaded
  on request or monthly; otherwise the country comes from IPinfo, VirusTotal, AbuseIPDB or OTX. Fixes OTX country
  names being cut to two letters.
- **Bahasa Indonesia**: language detection, Indonesian severity terms (synonyms counted once), Indonesian word order
  for new family names, Indonesian news and government domains excluded from indicators.
- **Indonesian news sources**: nine technology feeds with a new RSS *security* topic filter; sources have a country
  and language (Settings → Sources → Edit).
- Feed filters `country`, `province`, `src_country`, `lang`; target chips on feed rows, item pages and previews;
  hosting-country chips and filter on the IOC table; REST API v1 items carry `geo` and accept `country`,
  `province` and `region`, IP indicators carry `country`; `GET /api/stats/geo`.
- `manage.py geotag` and `geoip-update`, *Re-run geography* and *Download GeoIP database* buttons, a one-off
  geo-tagging job after the upgrade.
- Fix: columns added by the start-up migration now get their default on existing rows, and indexes declared on
  them are created.

## 0.7.0

- **Historical backfill** (Manage → Backfill): per-source reach and method, presets and custom ranges, estimates
  (exact for WordPress sites), background run one source at a time with progress, stop and a summary
  notification. Methods: WordPress REST API or Internet Archive snapshots for RSS, cursor paging for Bluesky,
  Mastodon, OTX and MISP, full lists for ransomware.live country / group sources, 7 days for ThreatFox; X,
  urlscan and ANY.RUN explain why they cannot.
- Items carry an **origin** (live / backfill), shown as a *history* badge and in the API. History does not count
  as trending, moves an entity's first-seen date back instead of marking it new, and is not enriched unless
  enabled.
- **Retention tiers**: full text for 180 days (configurable), then title, link, entities, severity and a snippet;
  deletion is off by default. Bulky copies of the text in raw provider data are dropped on ingest.
  `manage.py slim` and `vacuum`.
- **Full-text search** with SQLite FTS5 (word-prefix matching, safe against FTS syntax in user input) for the
  feed, the global search and `/api/v1/items?q=`.
- **PostgreSQL option**: `postgres` compose profile, `requirements-postgres.txt`, `manage.py copy-db` to move a
  SQLite install, string values trimmed to column length before writing, storage statistics for both engines.
- Fix: a collector run and a backfill (or two manual runs) storing the same entry at the same moment no longer
  fail the run on the unique constraint; the write is retried and the duplicate skipped.

## 0.6.0

- **Relationship graph** on item and entity pages (`GET /api/items/<id>/graph`, `/api/entities/<id>/graph`):
  entities, enrichment links and correlated items, coloured by type and verdict, with preview on click, open on
  double-click, drag, zoom, keyboard focus and a "Show more" step. Built-in force-directed SVG renderer
  (`static/js/graph.js`), so no graph library is vendored.
- **On-demand infrastructure context**: Shodan (host API or keyless InternetDB), Censys Platform v3, CrowdSec
  CTI, Pulsedive, Hybrid Analysis and IPinfo behind a *Context lookup* button on indicator pages, with an
  *Infrastructure context* card (ports, services, hostnames, known CVEs, reputation, sandbox) and an ASN / country
  badge stored for geography features. Optional automatic lookup when an indicator turns malicious; daily budget
  per provider; test buttons.
- **STIX 2.1 export** (`/api/v1/stix/...`, *⇩ STIX* buttons) and a **read-only TAXII 2.1 server** (`/taxii2/`)
  with *indicators* and *reports* collections, `added_after`, paging, `match[type]` / `match[id]`, manifests and
  TAXII error messages; API keys also work as HTTP Basic passwords for TAXII clients. Everything passes the
  sharing rules (TLP, non-redistributable sources).

## 0.5.0

- **New providers.** MalwareBazaar (hash → family, tags), URLhaus (URL / host / payload status), GreyNoise
  Community (mass scanner vs benign service, used to cut false positives in the consensus) and AbuseIPDB
  (confidence score). MalwareBazaar and URLhaus use the existing abuse.ch Auth-Key. Every provider has a
  *Test connection* button under Settings → Threat-intel APIs, using account or status endpoints where
  available so no lookup quota is spent.
- **REST API v1 and API keys.** `/api/v1/items`, `/entities`, `/iocs`, `/trending` with cursor pagination and
  `since`; API keys with scopes, expiry, revocation, per-key rate limit and audit entries (Profile → API keys,
  admin overview on the admin page); offline reference at `/api/v1/docs` and `/api/v1/openapi.json`.
- **IOC export feeds** in CSV, JSON and plain text (blocklists), filtered by type, verdict, family, age and
  confidence.
- **Webhooks** with HMAC-signed generic JSON or Slack / Discord / Teams formats, four events, test button,
  secret rotation, retry with back-off, delivery log and an SSRF guard.
- **Sharing rules.** TLP per item (from OTX / MISP) and per source, a maximum TLP for everything outbound,
  per-source "share outside JATMP" (ANY.RUN and ransomware.live off by default) and provider details kept
  in-house unless enabled.
- **Dark web tier 1.** ransomware.live collector (recent, per group, per country; PRO key or the personal-use
  API) and a *Deep dive* button: leak-site victims, countries, sectors, exploited CVEs and tools for ransomware
  families and actors, Hudson Rock infostealer statistics for domains.
- **MISP pull and push**: events as a source, *Send to MISP* for items and families / actors, optional auto-push
  above a severity threshold, no echo of MISP-sourced items, duplicate pushes link to the existing event.
- Fix: API error responses now keep `WWW-Authenticate` and `Retry-After` headers.

## 0.4.0

- **Unified tables.** IOC, Malware, Threat actor and CVE lists now use the Feed's table design (generic
  `.data-table`): bold primary column, secondary line, related-entity chips, the same period filter including
  *1 year* and *All time*, Reset and pagination (the entity lists used to stop at 300 rows). Headers stay
  visible while scrolling; a table wider than its card scrolls horizontally instead.
- **Side preview.** A click on a title in the Feed, IOC, Malware, Actor or CVE tables, in the dashboard
  widgets or on detail pages opens a slide-over preview served by `GET /items/{id}/preview` and
  `GET /entities/{id}/preview` (partial HTML, same auth as the pages). Keyboard navigation (↑ / ↓, j / k, Esc),
  focus trap, a shareable `?preview=` URL, *Full page* in a new tab and a full-screen sheet on phones.
- **Job status and progress.** *Collect now* queues one run per source under a batch id and shows
  "Collecting… 12/50 sources · 8 new" with a progress bar; *Enrich now* and the new *Refresh CVE intel* show
  per-indicator / per-CVE progress. Each button shows "Last … · Next …" from the scheduler and stays disabled
  (and refuses a second run server-side) while its job runs. `GET /api/jobs/status`; the page polls every
  60 s, or every 2.5 s while something runs. Runs interrupted by a restart are marked *aborted*.
- **Notification center.** Bell with unread count in the top bar on every page: collection batch summaries,
  sources that start failing (on the transition, not on every failed run), failed enrichment runs, the
  VirusTotal quota being reached, the AI digest being ready and re-scoring finished. A new notification also
  shows as a toast. `GET /api/notifications`, `POST /api/notifications/read`; kept for 30 days.
- **CVE and actor widgets.** *Trending CVEs* (KEV badge, CVSS, EPSS, risk-weighted priority, co-mentioned
  families and actors) and *Trending threat actors* (growth, linked families and CVEs) replace the chip list on
  the dashboard. CVE pages get a *Vulnerability intel* card and the CVE list gained CVSS / EPSS columns.
- **CVE intel job** (`app/intel/cve.py`): CISA KEV (cached on disk for 12 h), FIRST EPSS and NVD CVSS every
  6 hours; the NVD is throttled to its public rate limit and skipped for the rest of a run when it keeps
  failing. New settings: *CVE context* (on by default) and an optional NVD API key. `manage.py cve-intel`.
- Fix: "All time" on the Feed was lost when sorting or paging.

## 0.3.0

- **Severity rewritten** (`app/processing/severity.py`). Grouped signals replace the flat keyword sum, with
  title weighting, dampeners for patch notes, roundups and non-incident news, a cap for routine leak-site
  victim postings, entity signals and a stored breakdown that the item page displays. `manage.py rescore` and
  a button under Settings → General re-score existing items.
- **Extraction.** Additional defang styles (`[:]`, `[://]`, `\.`, `(dot)`, `fxp`); hashes embedded in URLs
  and tracking IDs are skipped, as are version numbers that resemble IP addresses; a much larger benign-domain
  list; a denylist of legitimate tools for the new-family heuristic.
- **Enrichment.** Provider consensus (a lone OTX pulse hit is suspicious, not malicious; OTX whitelist means
  clean); lookups that all failed are retried after six hours instead of being marked done; *unknown*
  indicators are re-checked after three days; confirmed verdicts raise the severity of the items that mention
  the indicator; family attribution ignores ambiguous tokens; OTX family searches only accept pulses that name
  the family; fewer secondary urlscan IPs are created.
- **Correlation.** Related items are ranked by evidence strength (type weight divided by log mentions, with an
  other-source bonus) and the shared entities are listed.
- **Feed** is a table with sortable Severity, Title, Source and Time headers; the separate sort buttons are
  gone. Dashboard KPI tiles keep the icon link only.
- **AI settings** reduced to Off / Local / Cloud, vendor and model, with presets for six local runtimes and ten
  cloud providers, a live model list and an advanced base-URL override. The classic `LLM_*` variables still
  work and are reflected in the new UI.
- **Report builder** (`/reports`): a *Threat Intel Findings* document with a period summary, written-up top
  findings, leading malware families (type, coverage, example hash), top indicators and an optional appendix,
  exported as PDF, Word, Markdown or CSV.
- Fix: modal popovers (source edit, severity breakdown) opened inside their card after the entrance animation.
- New dependencies: `python-docx` and `reportlab` for Word and PDF export.

## 0.2.1

- Sortable columns on the Malware, Threat actors, CVEs and IOCs tables; the feed can be sorted by time or
  severity; the IOC table shows where each indicator was seen; family and actor pages gained an Indicators card
  with a link to all related IOCs (`/iocs?entity=ID`).
- Dashboard: KPI tiles link to their detail pages, the radar explains placement with an axis key, "All
  families" is a button, and the items-per-source chart shows the top 12 with readable labels.
- Chrome: new radar logo, brand links home, back button, burger menu only on small screens, "Add source" moved
  above the table as a full-width panel, credits in the sidebar.

## 0.2.0

- Security: CSP with nonces, vendored Chart.js, no inline handlers, extra response headers, HSTS and Secure
  cookie switch, PBKDF2 600k with transparent upgrade, open-redirect hardening, source URL scheme checks,
  secret values no longer rendered into Settings, clamped numeric settings and query parameters.
- Bug fixes: `.env` was never loaded outside Docker; feed URLs with a `javascript:` scheme reached `<a href>`;
  HTML entities in feeds were dropped instead of decoded; future-dated items showed "in 3h"; deprecated
  `datetime.utcnow()` usage; `canonical_malware` rebuilt the knowledge table on every call; per-entry duplicate
  checks on ingest; N+1 queries on the watchlist; mention counts left stale after retention cleanup.
- UX: no horizontal overflow on phones, modal popovers for source edit and password reset, mobile sidebar with
  backdrop and Escape, a "Remove" checkbox for secrets, Reset buttons on filters, `/` focuses search, ARIA
  labels, skip link, focus rings, labelled inputs, grouped source list, radar blips fan out when scores tie,
  friendlier empty states.
- Tooling: pytest suite, ruff configuration, GitHub Actions CI, `.dockerignore`, Docker health check,
  `/healthz`.
