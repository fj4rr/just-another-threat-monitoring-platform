# Changelog

All notable changes to JATMP. Upgrade steps per version are in [docs/upgrading.md](docs/upgrading.md).

## Unreleased

**Changes**

- Feed filters now stay when you pick another one. They are kept for your session, so choosing a language after a
  severity keeps the severity, and the topbar search or a chip only changes the filter it names. **Clear filters**
  is the only thing that drops them; a chip under the filter bar removes a single entity, country or province.
- The left menu is tidier: Cyber threats, Scams & fraud and Feed stay on top, and Intelligence, Analysis and Manage
  are dropdowns (open when the current page is inside them, and they remember their state). The whole menu collapses
  to an icon rail with the arrow next to the logo.
- New **New threats** button on the Intelligence lists (Malware, Threat actors, CVEs, IOCs, Scam types and Impersonated
  brands): it keeps only what was first seen inside the chosen period and leaves your other filters alone.
- Every screenshot in the docs and the README is retaken for the new menu and layout.
- Higher minimum versions of optional and core dependencies: `anthropic` 2.8.0, `feedparser` 6.0.14,
  `python-docx` 1.2.0, `psycopg` 3.3.9 (PostgreSQL) and `telethon` 1.45.0 (Telegram MTProto). Run
  `pip install -r requirements.txt` again (and the PostgreSQL or Telegram file if you use them) when upgrading
  from source; the Docker image installs from the lock file as before.

**Fixes**

- The default urlscan.io source searched `verdicts.malicious:true`, a field free accounts may not search, so it
  failed with 403 Forbidden. It now searches `task.tags:malicious`, which every plan allows. An existing source
  keeps its saved query: edit it under Settings → Sources.
- Enrichment no longer fails with "UNIQUE constraint failed: entity_links" when the same indicator is linked twice
  in one run (for example listed by two OTX pulses). The link check now sees links added earlier in the batch.
- Enrichment no longer ends every run with "Enrichment failed: object of type 'datetime.datetime' has no len()".
  The family step reused the name of the stale-verdict list for a cutoff time, so the final summary broke.

**Documentation**

- *Using JATMP* describes the grouped, collapsible menu, the *New threats* button of the Intelligence lists (and
  its 30-day / 7-day fallback under *All time*) and how Feed filters stay until cleared (only the Feed keeps them;
  the other lists still have *Reset*). *Trends and correlation* points from the *new* badge to that button. *Collection* and *Configuration* give the new urlscan.io default query and why the old
  one failed on free accounts. *Scams and fraud* points at the new menu.
- The pages that 0.13.0 and 0.13.1 left out now describe them too. *How it works*: the overview's numbers table and
  key terms (corrections, error rate, precision and recall), enrichment (an analyst's verdict wins and keeps its
  date fresh), ingest (corrections respected at every step, distinctive spellings such as "RedLine" and "Cl0p",
  never a copy of itself), scoring (corrections re-score the item), sharing (corrected indicators in the feeds,
  `ioc.malicious` from an analyst verdict) and housekeeping (corrections kept by re-analysis and `reextract`, the
  self-copy repair, the quality gate before a rules change).
- User guide: the docs index lists *Corrections and quality*; *Maintenance commands* documents
  `manage.py quality` and its options; *Analysis* has a section on corrections and rule quality and the new
  indicator rules (public DNS resolvers, paste and file-sharing services); *Scams and fraud* lists the new scam
  phrases and how to mark an item *not a scam report*; *Reporting and AI* explains how Q&A picks and cites items.
- Developer pages: *Extending JATMP* adds the quality cases to the rules recipe, the indicator exclusion lists,
  topic filters and `severity.RULES_VERSION`; *Security* and *Data model* cover the corrections audit trail and
  the analyst verdict.

## 0.13.1

Rule tuning from the first quality report: every fix comes with the case that motivated it and counter-examples
that must not change (`tests/test_v0131.py`, and added to `tests/quality/`). Upgrade notes:
[docs/upgrading.md](docs/upgrading.md).

- **Indicators**: "server 91.92.243.10" is no longer mistaken for a version number; public DNS resolvers (`8.8.8.8`,
  `1.1.1.1`…) are no indicators; on paste, file-sharing and code-hosting services (Pastebin, GitHub, Google Drive,
  Dropbox, MEGA…) the URL of a paste or file is an indicator and the service's domain is not. A defanged GitHub or
  Drive payload URL used to be dropped.
- **Families**: a name that is also an everyday word counts without a qualifier when it is written in its own
  distinctive spelling ("RedLine", "Cl0p", "SafePay"); "redline" and "Safepay checkout" still don't.
- **Geography**: marketplaces and hosting are no targets ("sold on Russian forums", "hosted in the Netherlands",
  "a Dutch hosting provider", "server di Singapura").
- **Scams**: "mengaku dari Bea Cukai / polisi / bank…", fraudulent investment apps, fake QRIS stickers, SMS
  phishing and smishing messages, fake sellers and "jual beli <thing> online" are recognised.
- **Sectors**: fuel stations and fuel supply (SPBU) are energy.
- **Severity**: English service disruption (halted production, shut-down systems), the scale of a leak ("279
  million records"), data put up for sale, stolen credentials and telecoms as a sensitive sector; a roundup's or
  guide's title gets no headline bonus.
- **Quality on the seed set** (now 172 cases, with the counter-examples): families, indicators, scam, sectors and
  severity precision and recall 1.000; geography precision 1.000, recall 0.955 (a Dubai-based victim, a known miss).
  Before: families R 0.941, indicators P 0.889 / R 0.941, scam R 0.706, sectors R 0.929, geography P 0.900,
  severity P 0.875 / R 0.583. The rules were tuned on these cases, so read this as "the misses are fixed and the
  counter-examples hold", not as accuracy on live feeds; analysts' corrections will show that.

## 0.13.0

The rest of the product review's urgent items: analysts can correct the platform, the rules are measured, topic
filters work for every source kind, and Q&A finds items by meaning it already knows. Upgrade notes:
[docs/upgrading.md](docs/upgrading.md).

**Analyst corrections**

- Analysts and admins can mark an entity as wrong on one item (✕ on the item page), mark a family, actor or
  indicator as wrong / not a threat everywhere, set an analyst verdict that wins over the providers, and mark an
  item as not a scam report. Each correction asks for a reason, is logged with the analyst's name (and in the
  audit log), and can be undone.
- Corrections stay in force: re-extraction, AI extraction, the ThreatFox merge and new items skip removed links;
  the scam re-analysis keeps *not a scam report*; enrichment keeps an analyst verdict. Severity and the enrichment
  bonus follow.
- New **Corrections** page: the log with undo, the error rate analysts reported per area over 30 days, and the
  names corrected most often (rules worth tuning).

**Quality measurement**

- `python manage.py quality` reports precision, recall and F1 of the extractor (families and actors,
  indicators), the scam rules, sectors, target countries and severity on labelled cases in `tests/quality/`, with
  every case the rules get wrong. First measurement on the hand-written seed set: families P 1.000 / R 0.941,
  indicators 0.889 / 0.941, scam 1.000 / 0.706, sectors 1.000 / 0.929, geography 0.900 / 0.947, severity
  (notable) 0.875 / 0.583.
- The active corrections export as test cases (Corrections page, `--corrections FILE`); the report says how many
  analyst corrections the current rules would still repeat.
- CI fails when an area falls below `tests/quality/baseline.json` and shows the report in the job summary.

**Collection**

- Topic filters (`security`, `cyber`, `fraud`) work for every news and social source: Telegram, X, Mastodon and
  Bluesky gained the *Filter* field. The filter runs before storing, for scheduled runs and backfills, and the run
  message counts the entries it dropped.

**AI**

- Q&A finds items by the entities a question names (aliases included), by malware type and sector ("ransomware
  on hospitals" finds "LockBit hits a healthcare provider"), by the period it names, and by each word through the
  full-text index; copies count once. Answers cite their items as [n] links and list what they are based on.

**Fixes**

- An original article could be marked as a copy of itself, which hid it from the feed: the one-off dedup job of
  0.10.1 ran over copies that the first collector runs had already linked. `find_original` never returns the item
  itself now, and existing cases are repaired at start-up.

**Documentation**

- New page [Corrections and quality](docs/how-it-works/corrections.md); collection, AI, sources, using JATMP,
  development (release checklist: run the quality report), architecture and data model updated.

- *How it works* and the user guide pages (getting started, configuration, using JATMP, analysis, geography,
  integrations, reporting and AI, history and storage, maintenance, the docs index) are rewritten in plainer,
  more natural language, with the behaviour of 0.11 and 0.12 throughout: copies shown once, one counting rule,
  the severity rules version, verdicts that age, source health, the enrichment queue and quota panel, each
  provider at its own pace, redaction of personal data in cloud prompts, the daily schedule's time zone, and TLP
  on new sources. The overview's walkthrough now follows the article to its first verdict re-check.
- Fixes: *History and storage* said PostgreSQL search scans the text (it has its own full-text index since
  0.10.1); *Using JATMP* said only VirusTotal warns about its quota; the overview said severity is never
  re-analysed automatically; *Architecture* lacked the source-health and severity re-scoring jobs and the new
  `quota`, `redact` and `sourcehealth` modules.

## 0.12.0

Trust and coverage items from the product review of 2026-11. Upgrade notes: [docs/upgrading.md](docs/upgrading.md).

**Trust in the numbers**

- **One counting rule.** A story that several outlets carry counts once in every figure: KPI tiles and sparklines,
  timelines, malware / actor / sector / scam-type / brand breakdowns, target countries and provinces, entity
  mentions, scam report counts and the PDF / Word reports, as it already did in trend scores and the executive
  summary. Only per-outlet figures (*Items per source*, source country, language) count copies. The tile is now
  *Stories collected* and shows the item count including copies.
- **Severity rules version.** When the scoring rules change, stored items are re-scored once at start-up (keeping
  enrichment bonuses and AI assessments), so trends never compare items scored by different rules.
- **Verdicts that age.** Indicators store when their verdict was last given or confirmed and pages show "verdict
  as of …". Malicious and suspicious IPs, domains and URLs are looked up again after 30 days and the answer may
  lower the verdict (the items that mention them lose the bonus with it); after 60 days without confirmation they
  leave the IOC export feeds and TAXII, and STIX indicators carry `valid_until`. A blocklist that lists an
  indicator again keeps its verdict fresh. File hashes never age.

**Collection and enrichment**

- **Source health** on the Sources tab: last new item, items this week against the usual rate, the usual gap,
  how long a source has been failing, and *summary only* for feeds whose items carry little text. An hourly check
  notifies about sources that went quiet or have been failing for 24 hours.
- **Enrichment queue** on the IOC page and Settings → Enrichment: indicators waiting and the oldest, arrivals
  against capacity per day, re-checks and stale verdicts due, and how long each daily budget lasts at the current
  pace with the batch size that would spread it over the day.
- **Every provider at its own pace**: a run looks up its batch with one thread per provider, so it takes as long
  as the slowest provider instead of the sum of all of them. The per-provider gap no longer holds a lock while it
  waits, which made VirusTotal's 16-second gap stall every other provider.

**AI**

- **Personal data out of cloud prompts**: phone and e-wallet numbers, bank accounts, long ID numbers and e-mail
  addresses are replaced with consistent placeholders before a prompt goes to a cloud model (setting *Personal
  data in prompts*: cloud by default, always or never). IOCs, crypto wallets and amounts stay.

**Fixes**

- The dashboard, the AI settings and the docs still said the executive summary runs at 06:00 UTC; they now point
  at the schedule settings of 0.11.

## 0.11.0

Quick wins from a product review of the platform (trust in the numbers, operations). Upgrade notes:
[docs/upgrading.md](docs/upgrading.md).

**Trust in the numbers**

- **Copies are visible.** The feed lists each story once and says how many syndicated copies it hid; *Show copies*
  lists them with a *copy* badge. Item pages and previews say "Copy of *original*" on a copy and "Also carried by
  *N* other outlets" on the original.
- **Re-scoring no longer loses points.** *Re-score all items*, `manage.py rescore` and `manage.py reextract` keep
  the *indicator confirmed* bonus and the last AI assessment (the AI reason now stores the severity the model
  proposed, so it is applied again with the same +20 cap). Before, maintenance could drop a confirmed-malicious
  item below the webhook threshold.
- Running the AI analysis again on an item no longer adds its points a second time to the score, and a lower new
  assessment takes them away again; a *suspicious* indicator that turns *malicious* shows +12 in the breakdown
  (it showed +7 while the score rose by 12).

**Collection and enrichment**

- **ThreatFox** keeps the IOCs reported later in the day: items are keyed by the day ThreatFox first saw the IOCs
  (as in the backfill), and a later run adds new IOCs to that day's item, updates its count and scores it again.
- **Quota panel**: Settings → Enrichment and the IOC page show the lookups used today against each provider's daily
  budget. The "budget used up" notification now comes for every provider with a budget, not only VirusTotal.
- The auto-summary queue is rebuilt at start-up (live items of the last 24 hours with severity 40 or more and no
  summary), so a restart no longer drops the items waiting for an AI summary.

**Operations**

- **Time zone and times of the daily jobs**: Settings → General (or `JATMP_TIMEZONE`) sets the zone, the time of
  the AI executive summary and the time of housekeeping, and shows their next run. Defaults stay 06:00 and 03:30
  UTC.
- **TLP on new sources**: the *Add source* form asks for a TLP and says whether the source's items will be shared;
  Settings → Sharing counts the sources without one ("no TLP" counts as CLEAR and is shared).
- `tzdata` is now a dependency on every platform.

**Documentation**

- `tests/test_docs_numbers.py` checks the weights, thresholds, windows and defaults quoted in *How it works*
  against the code, and the release checklist has an "update How it works" step.

- New section **How it works** ([docs/how-it-works/](docs/how-it-works/index.md)) that explains every process
  behind the platform with the rules and numbers it uses: an overview that follows one article from the feed to
  the dashboard (with real scores from the code), the scheduler's day and where each number comes from; then
  [Collection](docs/how-it-works/collection.md), [Ingest and analysis](docs/how-it-works/processing.md),
  [Severity scoring](docs/how-it-works/scoring.md), [Enrichment and verdicts](docs/how-it-works/enrichment.md),
  [Trends and correlation](docs/how-it-works/trends.md), [AI processing](docs/how-it-works/ai.md),
  [Sharing and delivery](docs/how-it-works/sharing.md) and
  [Housekeeping and re-analysis](docs/how-it-works/housekeeping.md).
- Data model: syndicated copies are counted once by trend scores, scam spread and the executive summary, not by
  the dashboard item counts (the page said "statistics").

## 0.10.1

Fixes from a security, data-processing and efficiency audit. Upgrade notes: [docs/upgrading.md](docs/upgrading.md).

**Security**

- The REST endpoint for a single entity (`/api/v1/entities/{id}`) returned scammer phone numbers and bank accounts;
  identifiers now give 404 there too, like everywhere else they are never shared.
- The stylesheet cleaner (0.10) could backtrack exponentially on crafted text and hang a collector thread for
  hours. It now parses selectors without nested quantifiers and looks for rules from their declaration block, in
  linear time.
- **Outbound guard** for every request JATMP makes on its own (feeds, WordPress and Wayback backfill, RSS-Bridge,
  providers, CVE intel, the AI, MISP, GeoIP, webhooks): only public addresses unless a host is allow-listed, checked
  on every redirect hop, connecting to the checked address (no DNS rebinding), and bodies capped after
  decompression (no memory exhaustion by a huge feed or a gzip bomb; the GeoIP unpacking is capped too).
- CSV reports and the CSV IOC feed neutralise cells that a spreadsheet would run as a formula.
- AI output is bounded: at most +20 severity, shown as *AI assessment*; new families from a single news item are
  ignored until another source reports them; AI-proposed entities and tags carry an *AI* badge; tags are cleaned.
- Manual enrichment, context lookups, deep dives and AI summaries are limited per user and minute and run once per
  entity at a time; *Run now* on a source is ignored while that source runs.
- First-run setup from another machine requires a one-time token from the log or `data/setup-token`.
- API keys, the AI key and the Telegram session are stored encrypted (Fernet, key from `data/config.json`).
- Changing a password, an admin resetting it, or the new *Sign out other sessions* button ends the user's other
  sessions.
- `requirements.lock` pins every dependency (Docker and CI install with it), CI runs `pip-audit`, Dependabot is on.
- `/healthz` no longer reveals the version.

**Data processing**

- Scammer identifiers need a cue that names the scammer; a generic "hubungi nomor" next to a police station, branch
  office or complaint line is not one. Crypto wallets must pass their checksum, and "alamat"/"address" no longer
  count as a crypto cue.
- Weak scam phrases need a scam word nearby, and a malware article with one passing scam sentence is no longer a
  scam report. A brand that issues the warning is not counted as impersonated.
- "Rp 2,5 T" and "Rp 5 M" are read as trillions and billions of rupiah.
- Families and actors that are everyday words (Bitter, Patchwork, Pegasus, Oyster, Interlock…) need a qualifier;
  actors now follow the same rule. Demonyms and platform names ("the Indonesian ransomware gang", "Facebook
  malware") are no new family, a guessed family scores less than a known one, and it only trends once two sources
  name it. Intel-feed tags name families only on intel sources and never as everyday words.
- Family names from providers and the AI pass the extractor's filters; Indonesian patterns also run on mixed-
  language items.
- A sector needs more than one word in the title (unless the headline is about an attack on that one sector), and
  "bank", "rekening", "nasabah" in a scam report are the victim's bank, not an attacked finance sector.
- Syndicated copies of a story from other outlets are marked as such: trending, spread velocity and the executive
  summary count the story once.
- "critical" only scores next to a vulnerability ("critical flaw"), not in "critical infrastructure".
- Long entry ids (URLs with tracking parameters) are hashed instead of cut at 500 characters, so they no longer
  collide. Re-scoring passes each link's origin, so a heuristic family scores the same as at ingest.

**Efficiency**

- Indexes on `items.collected_at`, `items.severity` and the `entities` columns used for sorting and filtering.
- Item lists load their entities in one query per page instead of one per item.
- Trending lists are cached for 45 seconds and refreshed when new items arrive.
- AI auto-summaries run in a job of their own with a 5-minute limit instead of inside collector runs.
- *Re-score* and `manage.py reextract` work in chunks; `reextract` now also rebuilds sectors and intel-tag families.
- PostgreSQL gets a full-text index for search instead of scanning every item's text.
- Benign-domain checks look up each parent domain instead of scanning the whole list.

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
- Fix: stylesheet rules that some WordPress sites print into the post text (Malwarebytes' Kadence blocks) showed up
  as the item's text and snippet. They are now removed when items are collected, and a one-off job cleans the
  items stored before (only rules made of real selectors and `property: value;` declarations count, so code and
  JSON in articles stay).
- Scam detection: "fraud" as the name of a criminal charge ("pleaded guilty to wire fraud", bank, mail,
  securities, tax fraud…) no longer counts as a scam word, so an FBI agent stealing from seized crypto wallets is
  not filed as a crypto scam.
- **Documentation site**: the `docs/` pages also build a searchable MkDocs (Material) site with light and dark
  themes, published to GitHub Pages from `main` (`.github/workflows/docs.yml`, strict: broken links and anchors
  fail the build), where screenshots open full size on click. The Markdown still reads on GitHub; see
  [Development](docs/development.md#documentation-site).
  Every screenshot is retaken for 0.10, and the remaining "digest" labels (AI settings, report appendix,
  notifications) now say executive summary.
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
