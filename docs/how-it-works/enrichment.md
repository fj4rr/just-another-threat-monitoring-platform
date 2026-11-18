# Enrichment and verdicts

[← How JATMP works](index.md)

How indicators found in items get a verdict: which indicators are looked up and when, which providers are asked,
how their answers are combined, and what a verdict changes. The same page covers the CVE intel refresh, which
does the equivalent for vulnerabilities. Code: `app/processing/enrichment.py`, `app/intel/clients.py`,
`app/intel/cve.py`.

## The enrichment run

`jobs.run_enrichment` runs every **`enrichment_interval`** minutes (default 10, minimum 2; first run 2 minutes
after start-up) and on *Enrich now*. It does nothing when automatic enrichment is off (Settings → Enrichment) or
when no provider has a key. Each run looks up a small, prioritised batch, because free provider tiers allow only
a few hundred lookups a day.

### Which indicators a run picks

With the default `enrichment_batch` of **8**:

| Tier | Picks | Order |
|---|---|---|
| 1. Fresh | Indicators **never looked up**, mentioned in an item **published in the last 14 days** | Highest severity of the items that mention them, then most mentioned, then most recently seen |
| 2. Top-up (only when tier 1 has fewer than 8) | Other never-looked-up indicators: ones mentioned by live items, or linked by enrichment (a family's indicators pulled from OTX). Indicators that appear **only in backfilled items** are skipped unless `enrich_backfill` is on | Newest first |
| 3. Re-check (2 extra slots) | Indicators seen in the last **21 days** whose last lookup **failed** more than **6 hours** ago, or came back **unknown** more than **3 days** ago | Most mentioned, then longest since the last check |
| 4. Stale verdicts (2 extra slots) | *Malicious* or *suspicious* IPs, domains and URLs whose verdict is older than **`verdict_recheck_days`** (default 30) and that were mentioned in the last **90 days**; see [Verdicts that age](#verdicts-that-age) | Oldest verdict first |
| 5. Families (when *enrich families* is on) | Up to **2** of the top 5 trending malware families not enriched in the last 24 hours | Trend score |

So one run handles up to 8 + 2 + 2 indicators and 2 families. Indicators from curated blocklists never wait here:
they are marked malicious at ingest (see [Blocklist verdicts](processing.md#9-blocklist-verdicts)).

**Every provider at its own pace.** The lookups of a run happen first, with one thread per provider working
through the indicators it supports (`enrichment.prefetch`), so a run takes as long as its slowest provider instead
of the sum of all of them; then the answers are applied one indicator at a time, each committed as soon as it is
done (a run that fails half-way keeps what it finished). Progress shows "lookups", then "indicators".

### The queue

The IOC page (analysts and admins) and Settings → Enrichment show what the job has in front of it
(`enrichment.queue_status`): indicators from the last 14 days that were never looked up and the age of the oldest,
new indicators per day (7-day average) against the job's capacity per day (batch × runs per day: 8 × 144 = 1,152
with the defaults), re-checks due and stale verdicts. When more arrive than the job can look up, a note says so.
For every provider with a daily budget the panel also says how long the budget lasts at the current pace and which
batch size would spread it over the day (`quota.pace`): VirusTotal's 400 a day last about 8 hours at 8 indicators
every 10 minutes; a batch of 2 would spread them over the day, at the cost of a longer queue.

## Providers

Every provider with a key is asked about every indicator type it supports, one after another:

| Provider | Indicator types | Minimum gap between calls | Daily budget (default) |
|---|---|---|---|
| VirusTotal | IP, domain, URL, MD5, SHA-1, SHA-256 | 16 s (`vt_min_interval`; free tier is 4 per minute) | 400 (`vt_daily_budget`; free tier 500) |
| AlienVault OTX | IP, domain, URL, MD5, SHA-1, SHA-256 | — | — |
| urlscan.io | domain, IP, URL, SHA-256 | 2 s | — |
| ANY.RUN TI Lookup | IP, domain, URL, MD5, SHA-1, SHA-256 | 3 s | — |
| MalwareBazaar (abuse.ch) | MD5, SHA-1, SHA-256 | 1 s | — |
| URLhaus (abuse.ch) | URL, domain, IP, MD5, SHA-256 | 1 s | — |
| GreyNoise | IP | 2 s | 40 (`greynoise_daily_budget`) |
| AbuseIPDB | IP | 1 s | 900 (`abuseipdb_daily_budget`; free tier 1,000) |

- **Gaps** are enforced per provider across all threads (the calling thread waits; the wait of one provider no
  longer holds up the others). They keep JATMP inside the free tiers' per-minute limits; with VirusTotal
  configured, one run of 10 indicators still takes at least 2½ minutes, but the other providers finish theirs in
  the meantime.
- **Budgets** are counted per provider and calendar day of the server (UTC in the Docker image) in the settings table. When a budget is used up, that
  provider's lookups fail with "daily budget exhausted" and the others keep working; the failed indicator is
  retried 6 hours later. One notification per provider and day says when its budget is used up (every
  provider with a budget, including the context providers).
- **Quota panel.** Settings → Enrichment shows, for every configured provider with a budget, the lookups used
  today against the limit; analysts and admins see the same figures at the top of the IOC page.
- The gaps are kept in memory: right after a restart the first call to a provider does not wait.
- A **provider error** (quota, timeout, HTTP error) never stops the batch; it is logged and the next provider is
  asked.

### What a provider answer contains

Each provider returns a `LookupResult`: its own verdict (`malicious`, `suspicious`, `clean`, `unknown`), a score,
a one-line summary, a permalink, tags, malware family labels, related indicators and raw data. It is stored as
one `enrichments` row per indicator and provider (a later lookup replaces it), and shown on the indicator page.

Provider-specific rules applied before the consensus:

- **OTX** says *malicious* for an indicator in 3 or more pulses, or in any pulse that names a family; *suspicious*
  for 1–2 pulses; *clean* when OTX itself lists it as whitelisted or a known false positive (CDNs, big-tech
  infrastructure).
- **urlscan.io** says *malicious* when any of up to 20 scans of it has a malicious verdict, else *unknown*.
- **GreyNoise** says *clean* for benign business services ("RIOT") and benign scanners; its classification is
  kept on the indicator as a badge ("mass scanner", "benign service").

## Consensus

The provider answers of one lookup are combined into the indicator's **verdict** (`_consensus`):

1. Start from the indicator's current verdict (from nothing when a stale verdict is re-checked).
2. **OTX alone is weak evidence:** an OTX *malicious* without a family label and with fewer than 5 pulses counts
   as *suspicious*.
3. **GreyNoise filters noise:** if GreyNoise says the IP is benign, *malicious* and *suspicious* answers from the
   noisy providers (OTX, AbuseIPDB, urlscan.io) are ignored. Scanners and CDNs end up in their reports all the
   time.
4. **The strongest remaining verdict wins:** malicious > suspicious > clean > unknown. One provider saying
   *malicious* is enough.
5. If GreyNoise said benign and no strong provider (VirusTotal, abuse.ch, ANY.RUN) said *malicious* or
   *suspicious*, the verdict is **clean**.

Because step 1 starts from the current verdict, a verdict normally only rises: a later lookup where every
provider says *unknown* does not turn a *malicious* indicator back. Two ways lead down: step 5 (a GreyNoise
*benign* answer turns *suspicious* or *unknown* into *clean*), and the re-check of a stale verdict below.

### Verdicts that age

IPs, domains and URLs change owners: last year's command-and-control address may host a shop today. Since 0.12
every indicator stores when its verdict was last given or confirmed (`verdict_at`; older rows use `enriched_at`),
and pages show "verdict as of *date*".

| Step | Rule | Setting |
|---|---|---|
| Re-check | A *malicious* or *suspicious* IP, domain or URL whose verdict is older than **30 days** and that was mentioned in the last 90 days is looked up again (tier 4 above). The answer **replaces** the verdict, also when it is lower; the items that mention it then get the bonus of their strongest remaining indicator, or none | `verdict_recheck_days` (0 = never) |
| Leave the feeds | Once the verdict is older than **60 days** and was not confirmed again, the indicator is left out of the IOC export feeds (txt, csv, json) and TAXII; STIX indicators carry `valid_until` = verdict date + 60 days. Pages and the REST list still show it, marked *aged* | `verdict_feed_days` (0 = keep) |
| Confirmed again | Any lookup with an answer, or a blocklist that lists the indicator again (ScamSniffer), sets the verdict date to today | — |

File hashes never age: a file stays what it is.

| Outcome of the lookup | Stored verdict | Next lookup |
|---|---|---|
| At least one provider answered | The consensus (*unknown* if they all said so) | *unknown*: re-checked after 3 days while it is still being mentioned (21 days); otherwise never automatically |
| Every provider that was asked failed | Unchanged (empty for a first lookup) | After 6 hours |
| No provider supports the type, or none answered | *unknown* | As *unknown* |

*Enrich now* on an indicator page looks it up again at any time (limited per user and minute; one lookup per
indicator at a time).

## What a verdict changes

When a lookup finishes:

| Effect | When |
|---|---|
| **Family attribution.** Up to 5 family labels per provider (`trojan.lumma/lummastealer`, `Win32/Formbook`) are mapped to a known family; generic words (trojan, generic, win32, agent, android…), legitimate tools and platforms are skipped. The indicator gets an `attributed-to` link to the family, so a hash posted on Bluesky connects to every article about that family | Always |
| **Related indicators.** Up to 8 per provider (a domain's IPs, a URL's host) are created and linked as `related` | Always |
| **Severity feedback.** Every item that mentions the indicator gets +12 (*malicious*) or +5 (*suspicious*), replacing an earlier *indicator confirmed* reason; see [Severity scoring](scoring.md#after-ingest) | The verdict rose |
| **Severity feedback down.** Each item that mentions the indicator gets the bonus of its strongest remaining indicator (or loses it) | The verdict fell (a stale verdict re-checked) |
| **Webhook** `ioc.malicious` | The verdict turned *malicious*, and the indicator may be shared |
| **Context lookup** (Shodan, Censys…) queued | The verdict turned *malicious* and *run context lookups when an indicator turns malicious* is on |
| **Hosting country** of an IP: the offline GeoIP database first, then the country reported by IPinfo, Censys, Shodan, VirusTotal, AbuseIPDB, CrowdSec or OTX, in that order | IP indicators |

## Family enrichment

For a trending malware family (tier 4 above, or *Enrich* on a family page) JATMP pulls fresh indicators:

- **OTX pulse search** for the family name (short or ambiguous names such as "Play" are searched as
  `"Play" ransomware`). Only pulses that actually name the family in their name, tags or family list are kept,
  because OTX's full-text search is fuzzy. Up to 40 indicators from each of the first 5 pulses are linked to the
  family (relation `indicator`).
- **ANY.RUN TI Lookup** for `threatName:"<family>"` over 14 days: the sandbox tasks and up to 40 related IOCs.

The pulled indicators are new, never-looked-up entities, so later enrichment runs pick them up in tier 2.

## Context lookups

*Context lookup* on an IP, domain or hash asks the infrastructure providers — Shodan (or the keyless InternetDB),
Censys, CrowdSec CTI, Pulsedive, Hybrid Analysis, IPinfo — for open ports, services, ASN, reputation and sandbox
results. They are never part of the scheduled batch (free tiers are small); each provider has its own daily
budget (`context_daily_budget`, default 100), and manual lookups are limited per user and minute. The answers
are stored like any enrichment, so their verdicts take part in the consensus too.

## CVE intel

CVEs are enriched by a separate job, `jobs.run_cve_intel`, every **6 hours** (first run 3 minutes after start-up)
and on *Refresh CVE intel*. Turning the setting off only stops the scheduled run.

1. **Pick** up to **60** CVEs mentioned in the last **30 days** that were not checked in the last **24 hours**:
   never-checked first, then the most recently mentioned.
2. **CISA KEV.** The catalogue is downloaded once and cached for 12 hours (`data/cache/cisa_kev.json`). A CVE in
   it gets the KEV entry (date added, due date, known ransomware use, vendor, product); a CVE not in it gets an
   empty entry, so a CVE removed from KEV loses its badge. If the catalogue cannot be loaded, existing KEV data is
   kept.
3. **FIRST EPSS.** One request per 80 CVEs: the probability of exploitation in the next 30 days and its
   percentile.
4. **NVD CVSS.** One request per CVE, only when its CVSS is missing or older than **7 days**: at most 10 per run,
   6.5 s apart, without an NVD key; 50 per run, 0.8 s apart, with one. Two failures in a row stop NVD lookups for
   the rest of the run ("NVD unavailable, CVSS retried next run").
5. The results are stored in the CVE entity's `meta` and committed every 10 CVEs.

KEV, EPSS and CVSS feed the CVE list, the *CVEs by exploitation risk* chart and the ranking of trending CVEs; see
[CVE priority](trends.md#cve-priority).
