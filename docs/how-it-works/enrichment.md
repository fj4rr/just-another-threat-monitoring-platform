# Enrichment and verdicts

[← How JATMP works](index.md)

This page explains how the indicators found in items get a verdict: which ones are looked up and when, which
providers are asked, how their answers are combined, how verdicts age, and what a verdict changes. It also covers
the CVE intel refresh, which does the same job for vulnerabilities. The code is in
`app/processing/enrichment.py`, `app/intel/clients.py`, `app/intel/quota.py` and `app/intel/cve.py`.

## The enrichment run

`jobs.run_enrichment` runs every **`enrichment_interval`** minutes (default 10, minimum 2; the first run is 2
minutes after start-up) and whenever someone clicks *Enrich now*. It does nothing if automatic enrichment is
switched off (Settings → Enrichment) or if no provider has an API key.

Each run only looks up a small, prioritised batch, because the free tiers of most providers allow just a few
hundred lookups a day.

### Which indicators a run picks

With the default `enrichment_batch` of **8**, a run fills its batch in this order:

| Tier | What it picks | In what order |
|---|---|---|
| 1. Fresh | Indicators that have **never been looked up** and are mentioned in an item **published in the last 14 days** | Highest severity of the items that mention them first, then the most mentioned, then the most recently seen |
| 2. Top-up (only if tier 1 has fewer than 8) | Other indicators that have never been looked up: those mentioned in live items, or linked through enrichment (for example a family's indicators pulled from OTX). Indicators that **only appear in backfilled items** are skipped unless `enrich_backfill` is on | Newest first |
| 3. Re-check (2 extra places) | Indicators seen in the last **21 days** whose last lookup **failed** more than **6 hours** ago, or came back **unknown** more than **3 days** ago | Most mentioned first, then the longest since the last check |
| 4. Aged verdicts (2 extra places) | *Malicious* or *suspicious* IPs, domains and URLs whose verdict is older than **`verdict_recheck_days`** (default 30) and that were mentioned in the last **90 days**; see [Verdicts that age](#verdicts-that-age) | Oldest verdict first |
| 5. Families (when *enrich families* is on) | Up to **2** of the top 5 trending malware families that haven't been enriched in the last 24 hours | By trend score |

So a single run handles up to 12 indicators (8 + 2 + 2) and 2 families. Indicators from curated blocklists never
wait in this queue: they are marked malicious as soon as they are stored (see
[Blocklist verdicts](processing.md#9-blocklist-verdicts)).

**Each provider works at its own pace.** A run first does all its lookups, with one thread per provider working
through the indicators that provider supports (`enrichment.prefetch`). The run therefore takes as long as its
slowest provider, rather than the time of all providers added together. The answers are then applied one
indicator at a time, and each one is saved as soon as it is done, so a run that fails half-way keeps what it
finished. The progress bar shows "lookups" first, then "indicators".

### The queue

The IOC page (for analysts and admins) and Settings → Enrichment show what the job has in front of it
(`enrichment.queue_status`):

- how many indicators from the last 14 days are still waiting for their first lookup, and how old the oldest is;
- how many new indicators arrive per day (averaged over 7 days), compared with what the job can handle per day
  (batch × runs per day: 8 × 144 = 1,152 with the defaults);
- how many re-checks and aged verdicts are due.

If more indicators arrive than the job can look up, a note says so.

For each provider with a daily budget, the panel also shows how long the budget lasts at the current pace, and
which batch size would spread it over the whole day (`quota.pace`). For example, VirusTotal's 400 lookups a day
last about 8 hours at 8 indicators every 10 minutes. A batch of 2 would spread them across the day, at the cost of
a longer queue.

## Providers

Every provider with an API key is asked about every type of indicator it supports:

| Provider | Indicator types | Minimum gap between calls | Daily budget (default) |
|---|---|---|---|
| VirusTotal | IP, domain, URL, MD5, SHA-1, SHA-256 | 16 s (`vt_min_interval`; the free tier allows 4 a minute) | 400 (`vt_daily_budget`; the free tier allows 500) |
| AlienVault OTX | IP, domain, URL, MD5, SHA-1, SHA-256 | — | — |
| urlscan.io | domain, IP, URL, SHA-256 | 2 s | — |
| ANY.RUN TI Lookup | IP, domain, URL, MD5, SHA-1, SHA-256 | 3 s | — |
| MalwareBazaar (abuse.ch) | MD5, SHA-1, SHA-256 | 1 s | — |
| URLhaus (abuse.ch) | URL, domain, IP, MD5, SHA-256 | 1 s | — |
| GreyNoise | IP | 2 s | 40 (`greynoise_daily_budget`) |
| AbuseIPDB | IP | 1 s | 900 (`abuseipdb_daily_budget`; the free tier allows 1,000) |

How the limits work:

- **Gaps between calls** are enforced per provider. They keep JATMP within the free tiers' per-minute limits.
  While one provider waits for its gap, the others carry on. With VirusTotal configured, a full run of 12
  indicators still takes about 3 minutes, but the other providers finish their part in the meantime. The gaps
  are kept in memory, so right after a restart the first call to each provider doesn't wait.
- **Daily budgets** are counted per provider and per calendar day on the server (UTC in the Docker image), and
  they survive restarts. Once a provider's budget is used up, its lookups fail with "daily budget exhausted",
  the other providers keep working, and the indicator is tried again 6 hours later. You get one notification per
  provider and day when that happens, for every provider with a budget, including the context providers.
- **The quota panel** under Settings → Enrichment shows, for every configured provider with a budget, how many
  lookups have been used today out of the limit. Analysts and admins see the same figures at the top of the IOC
  page.
- **A provider error** (quota, timeout, HTTP error) never stops the run. It is logged, and the other providers'
  answers are still used.

### What a provider's answer contains

Each provider returns its own verdict (`malicious`, `suspicious`, `clean` or `unknown`), a score, a one-line
summary, a link to its page, tags, malware family labels, related indicators, and some raw data. JATMP stores one
record per indicator and provider (a later lookup replaces it), and shows them all on the indicator's page.

A few providers need special handling before their answers are combined:

- **OTX** says *malicious* when an indicator appears in 3 or more pulses, or in any pulse that names a family;
  *suspicious* for 1–2 pulses; and *clean* when OTX itself lists the indicator as whitelisted or a known false
  positive (CDNs and big-tech infrastructure, for example).
- **urlscan.io** says *malicious* when any of up to 20 scans of the indicator was judged malicious, and
  *unknown* otherwise.
- **GreyNoise** says *clean* for known benign business services ("RIOT") and benign scanners. Its classification
  is also shown on the indicator as a badge ("mass scanner", "benign service").

## Consensus

All the answers from one lookup are combined into the indicator's **verdict** (`_consensus`):

1. Start from the indicator's current verdict (or from nothing, when an aged verdict is being re-checked).
2. **OTX on its own is weak evidence.** An OTX *malicious* without a family name and from fewer than 5 pulses
   counts as *suspicious*.
3. **GreyNoise filters out noise.** If GreyNoise says an IP is benign, the *malicious* and *suspicious* answers of
   the noisier providers (OTX, AbuseIPDB, urlscan.io) are ignored. Scanners and CDNs turn up in their reports all
   the time.
4. **The strongest remaining verdict wins:** malicious beats suspicious, which beats clean, which beats unknown.
   One provider saying *malicious* is enough.
5. If GreyNoise said benign and no strong provider (VirusTotal, abuse.ch, ANY.RUN) said *malicious* or
   *suspicious*, the verdict is **clean**.

Because the first step starts from the current verdict, a verdict normally only goes up. A later lookup where
every provider says *unknown* won't turn a *malicious* indicator back. There are two ways down: step 5 (a
GreyNoise *benign* answer turns *suspicious* or *unknown* into *clean*), and the re-check of an aged verdict
described next.

| Result of the lookup | Stored verdict | Next lookup |
|---|---|---|
| At least one provider answered | The consensus (*unknown* if they all said so) | If *unknown*: again after 3 days, as long as the indicator was mentioned in the last 21 days; otherwise not automatically |
| Every provider that was asked failed | Unchanged (empty for a first lookup) | After 6 hours |
| No provider supports the type, or none answered | *unknown* | As for *unknown* |

*Enrich now* on an indicator's page looks it up again whenever you like (limited per user and per minute, and
only one lookup per indicator at a time).

### Verdicts that age

IPs, domains and URLs change hands. Last year's command-and-control server might host a small online shop today.
So every indicator records when its verdict was last given or confirmed, and its page shows "verdict as of
*date*".

| Step | Rule | Setting |
|---|---|---|
| Re-check | A *malicious* or *suspicious* IP, domain or URL whose verdict is older than **30 days** and that was mentioned in the last 90 days is looked up again (tier 4 above). The new answer **replaces** the old verdict, even when it is lower. The items that mention the indicator then get the bonus of their strongest remaining indicator, or none | `verdict_recheck_days` (0 = never) |
| Leave the feeds | Once the verdict is older than **60 days** without being confirmed again, the indicator is left out of the IOC export feeds (txt, csv, json) and TAXII. STIX indicators carry `valid_until` = verdict date + 60 days. The pages and the REST API still list it: the pages mark it *aged*, and the API includes its `verdict_at` | `verdict_feed_days` (0 = keep it in the feeds) |
| Confirmed again | Any lookup that gets an answer, or a blocklist that lists the indicator again (ScamSniffer, for example), resets the verdict date to today | — |

File hashes never age: a file is always the same file.

## What a verdict changes

When a lookup finishes:

| Effect | When |
|---|---|
| **Family attribution.** Up to 5 family labels per provider (such as `trojan.lumma/lummastealer` or `Win32/Formbook`) are matched to a known family, skipping generic words (trojan, generic, win32, agent, android…), legitimate tools and platforms. The indicator is linked to the family as `attributed-to`, so a hash posted on Bluesky connects to every article about that family | Always |
| **Related indicators.** Up to 8 per provider (a domain's IPs, a URL's host) are created and linked as `related` | Always |
| **Severity goes up.** Every item that mentions the indicator gets +12 (*malicious*) or +5 (*suspicious*), replacing any earlier *indicator confirmed* reason; see [Severity scoring](scoring.md#after-ingest) | The verdict went up |
| **Severity goes down.** Each item that mentions the indicator gets the bonus of its strongest remaining indicator, or loses the bonus | The verdict went down (an aged verdict re-checked) |
| **Webhook** `ioc.malicious` | The verdict turned *malicious*, and the indicator may be shared |
| **Context lookup** (Shodan, Censys…) | The verdict turned *malicious* and *run context lookups when an indicator turns malicious* is on |
| **Hosting country** of an IP: taken from the offline GeoIP database first, otherwise from IPinfo, Censys, Shodan, VirusTotal, AbuseIPDB, CrowdSec or OTX, in that order | IP indicators |

## Family enrichment

For a trending malware family (tier 5 above, or *Enrich* on a family's page), JATMP looks for fresh indicators:

- **OTX pulse search** for the family's name. Short or ambiguous names such as "Play" are searched as
  `"Play" ransomware`. OTX's search is fuzzy, so only pulses that really name the family in their title, tags or
  family list are used. Up to 40 indicators from each of the first 5 pulses are linked to the family.
- **ANY.RUN TI Lookup** for `threatName:"<family>"` over the last 14 days: the sandbox tasks and up to 40 related
  IOCs.

These indicators are new and have never been looked up, so later runs pick them up in tier 2.

## Context lookups

*Context lookup* on an IP, domain or hash asks the infrastructure providers (Shodan or its keyless InternetDB,
Censys, CrowdSec CTI, Pulsedive, Hybrid Analysis and IPinfo) about open ports, services, network owner,
reputation and sandbox results. They are never part of the scheduled run, because their free tiers are small.
Each provider has its own daily budget (`context_daily_budget`, default 100), and manual lookups are limited per
user and per minute. The answers are stored like any other enrichment, so their verdicts count towards the
consensus too.

## CVE intel

CVEs are enriched by a separate job, `jobs.run_cve_intel`, every **6 hours** (the first run is 3 minutes after
start-up) and whenever someone clicks *Refresh CVE intel*. Switching the setting off only stops the scheduled
run; you can still refresh by hand.

1. **Pick** up to **60** CVEs mentioned in the last **30 days** that haven't been checked in the last
   **24 hours**: never-checked ones first, then the most recently mentioned.
2. **CISA KEV.** The catalogue is downloaded and cached for 12 hours (`data/cache/cisa_kev.json`). A CVE in the
   catalogue gets its KEV entry (date added, due date, known ransomware use, vendor, product). A CVE that isn't in
   it gets an empty entry, so a CVE removed from KEV loses its badge. If the catalogue can't be downloaded, the
   existing KEV data is kept.
3. **FIRST EPSS.** One request per 80 CVEs gives the probability of exploitation within the next 30 days and its
   percentile.
4. **NVD CVSS.** One request per CVE, but only when its CVSS score is missing or more than **7 days** old. Without
   an NVD key, that is at most 10 per run, 6.5 seconds apart; with a key, 50 per run, 0.8 seconds apart. Two
   failures in a row stop the NVD lookups for the rest of the run ("NVD unavailable, CVSS retried next run").
5. The results are stored on the CVE and saved every 10 CVEs.

KEV, EPSS and CVSS feed the CVE list, the *CVEs by exploitation risk* chart and the ranking of trending CVEs. See
[CVE priority](trends.md#cve-priority).
