# How JATMP works

[← Documentation index](../README.md)

This section explains what JATMP does behind the scenes. Every automatic process is described in the order it
happens, together with the rules and numbers it uses.

It is written for three kinds of readers:

- **Analysts** who want to know where a score, a verdict or a trend comes from before they rely on it.
- **Administrators** who tune sources, quotas and schedules.
- **Anyone** who wants to check that the platform behaves the way they expect.

If you are looking for the code structure, see [Architecture](../architecture.md); for the tables and columns,
see [Data model](../data-model.md). These pages describe *behaviour*.

Everything here is rule-based and deterministic: the same input always gives the same result, and every score
lists its reasons on the item page. The optional AI features can add to those results, but only within fixed
limits, and they never replace them (see [AI processing](ai.md)).

## The five stages

Every piece of information in JATMP goes through the same five stages.

```
 ┌────────────┐   ┌───────────────────┐   ┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
 │ 1 Collect  │──▶│ 2 Ingest &        │──▶│ 3 Enrich     │──▶│ 4 Aggregate      │──▶│ 5 Share &        │
 │            │   │   analyse         │   │              │   │                  │   │   maintain       │
 │ feeds,     │   │ dedup, clean,     │   │ intel        │   │ trends, CVE      │   │ API, STIX/TAXII, │
 │ social,    │   │ extract entities, │   │ providers,   │   │ risk, correlation│   │ webhooks, MISP;  │
 │ intel APIs │   │ severity, fraud,  │   │ consensus    │   │ dashboards,      │   │ retention,       │
 │            │   │ sectors, geography│   │ verdicts     │   │ reports, AI      │   │ re-analysis      │
 └────────────┘   └───────────────────┘   └──────────────┘   └──────────────────┘   └──────────────────┘
  per source,       same transaction as     every 10 min,      on every page view    every 30 s (webhooks),
  every 30–180 min  the collection          8 indicators       (cached 45 s)         daily (housekeeping)
```

| Stage | What happens | When | Read more |
|---|---|---|---|
| **1. Collect** | Each enabled source fetches whatever its provider currently lists | On the source's own interval (at least every 5 minutes); also on *Collect now* and during a *Backfill* | [Collection](collection.md) |
| **2. Ingest and analyse** | New entries are de-duplicated, cleaned, searched for entities, scored for severity and fraud, tagged with sectors and geography, and stored | Straight away, inside the collection run | [Ingest and analysis](processing.md), [Severity scoring](scoring.md), [Scams and fraud](../fraud.md) |
| **3. Enrich** | Indicators are looked up on the intel providers you configured, and their answers are combined into one verdict | Every 10 minutes, 8 indicators at a time (the defaults) | [Enrichment and verdicts](enrichment.md) |
| **4. Aggregate** | Trend scores, CVE risk, correlations, statistics and AI summaries are calculated from the stored items | Whenever a page is opened (trend lists are cached for 45 seconds); CVE intel every 6 hours; the AI summary once a day | [Trends and correlation](trends.md), [AI processing](ai.md) |
| **5. Share and maintain** | Webhooks, MISP pushes and the APIs deliver whatever may leave; housekeeping trims and removes old data; re-analysis jobs apply new rules to stored items | Webhooks every 30 seconds; housekeeping once a day; re-analysis after an upgrade | [Sharing and delivery](sharing.md), [Housekeeping and re-analysis](housekeeping.md) |

All five stages run inside **one process**: the web application with its built-in scheduler (see
[Architecture](../architecture.md#the-big-picture)). There is no queue between the stages, so by the time a
collection run finishes, every item it found has been fully analysed.

## Follow one article through JATMP

The easiest way to understand the platform is to follow a single item from start to finish. The article below is
made up, but every number in this walkthrough was produced by running its text through JATMP's own code.

> **LockBit ransomware exploits Citrix zero-day to hit Indonesian hospitals**
>
> Researchers say a new LockBit campaign is actively exploited in the wild against hospitals in Jakarta and
> Surabaya. The flaw, CVE-2026-31337, allows remote code execution on unpatched appliances. The operators used
> the T1190 technique. Indicators: 185.220.101[.]54, update-citrix[.]net,
> hxxps://update-citrix[.]net/payload.exe. Rumah sakit di Jakarta mengalami gangguan layanan.

### Collection (t = 0)

The outlet's RSS source comes up on its schedule. JATMP downloads the feed (up to 10 MB), reads up to 500
entries, applies the source's topic filter if it has one, and passes the newest 100 to the pipeline.
→ [Collection](collection.md)

### Ingest (a few milliseconds later)

Still inside the same run, the article goes through these steps:

1. **Is it new?** JATMP hasn't stored this entry from this source before, so it carries on.
2. **Clean-up.** HTML, scripts and any stray stylesheet text are removed. The link is kept because it starts
   with `https://`.
3. **Is it a syndicated copy?** A fingerprint of the normalised title is compared with articles from other
   sources over the last four days. Nothing matches, so this item is the original.
4. **Entities.** The extractor finds six:

    | Type | Value | Origin | Why it counts |
    |---|---|---|---|
    | malware | LockBit (ransomware) | `kb` | It is in the knowledge base |
    | cve | CVE-2026-31337 | `regex` | Matches the CVE pattern |
    | technique | T1190 | `regex` | Matches the ATT&CK id pattern |
    | ip | 185.220.101.54 | `regex` | A public IPv4 address, written defanged |
    | domain | update-citrix.net | `regex` | Written defanged (`[.]`). News is read in *strict* mode, where only defanged hosts count |
    | url | https://update-citrix.net/payload.exe | `regex` | Restored from `hxxps://…[.]…` |

5. **Severity.** The points add up to 132, which is capped at **100**. They come from: zero-day in the title
   (30 × 1.5 = 45), "exploited in the wild" as the runner-up in the same group (15), remote code execution (14),
   ransomware in the title (18), an active campaign (10), a sensitive sector as runner-up (4), a known family
   (10), one CVE (5), three indicators (8) and an ATT&CK technique (3). → [Severity scoring](scoring.md)
6. **Fraud.** The text describes no scam, so the fraud score is 0. The item is not a scam report.
7. **Sectors.** "hospitals" in the title and *rumah sakit* in the body make it a **health** sector item.
8. **Geography.** The language is English. "Indonesian" in the title plus Jakarta and Surabaya in the body make
   **Indonesia** the target country (score 8.25), with the provinces **DKI Jakarta** and **Jawa Timur**.
9. **Links.** All seven entities (the six above plus the sector) are linked to the item, and each entity's
   mention count and first-seen / last-seen dates are updated.

### Right after the commit (under a second)

The trend cache is cleared, so the dashboard includes the item the next time someone opens it. A severity of 100
is above the default webhook threshold of 70, so an `item.high_severity` event is queued for every webhook that
subscribes to it. If MISP auto-push is on, a push job is queued too, and if AI auto-summaries are on, the item
joins the summary queue.

### Enrichment (within 10 minutes)

None of the three indicators has been looked up yet, and this item has the highest severity in the queue, so
they are among the next ones checked. Each configured provider answers. Suppose VirusTotal reports the IP as
malicious: the combined verdict becomes `malicious`, every item that mentions the IP gets
*+12 indicator confirmed malicious* (this one is already at 100), and an `ioc.malicious` webhook event is queued.
The IP's page shows "verdict as of" today's date. → [Enrichment and verdicts](enrichment.md)

### CVE intel (within 6 hours)

CVE-2026-31337 is looked up in CISA KEV, FIRST EPSS and the NVD. If it turns out to be in KEV, its trend score on
the dashboard is doubled. → [Trends and correlation](trends.md#cve-priority)

### Every time someone opens the dashboard

LockBit's trend score counts this article as one story. If five outlets syndicate it, it still counts once: the
feed shows it a single time, and the item page lists the other outlets that carried it. The *National (ID)* view includes the item because it targets
Indonesia.

### 30 seconds later

The webhook delivery job sends the queued events. → [Sharing and delivery](sharing.md)

### 30 days later

If the IP has been mentioned in the last 90 days, JATMP looks it up again, because addresses change hands. If the providers
no longer flag it, the verdict goes down and the bonus is taken off the items that mention it. If nobody
confirms it within 60 days, it drops out of the IOC export feeds. → [Verdicts that age](enrichment.md#verdicts-that-age)

### 180 days later

The nightly housekeeping slims the item. The title, link, entities, scores and a 400-character snippet are kept;
the full text is removed. → [Housekeeping and re-analysis](housekeeping.md)

## A day on the scheduler

These are the default timings. Most can be changed under Settings. The two daily jobs run at a local time in the
time zone you choose under Settings → General; the defaults are UTC.

| When | Job | What it does |
|---|---|---|
| 5 s, 8 s, 11 s … after start-up | First run of each source | Sources start at 5 s + 3 s × source id, so they don't all hit the network at once |
| 15 s after start-up | `run_content_cleanup` | Cleans stored text again if the cleaning rules changed (otherwise does nothing) |
| 20 s after start-up | `run_geotag` | Re-tags geography if the rules changed |
| 30 s after start-up | `run_dedup` | Fingerprints stored articles if the dedup rules changed |
| 40 s after start-up | `run_fraudtag` | Re-runs the scam analysis if the rules changed |
| 60 s after start-up | `run_sectortag` | Re-tags sectors if the rules changed |
| 90 s after start-up | `run_rescore_if_outdated` | Re-scores stored items if the severity rules changed |
| 2 min after start-up, then every 10 min | `run_enrichment` | Looks up 8 indicators, plus re-checks, aged verdicts and 2 trending families when enabled; each provider works at its own pace |
| 3 min after start-up, then every 6 h | `run_cve_intel` | Fetches KEV, EPSS and CVSS for up to 60 recently mentioned CVEs |
| 15 min after start-up, then hourly | `run_source_health` | Warns about sources that went quiet or keep failing |
| Every 30 s | `run_webhooks` | Delivers up to 50 webhook events that are due |
| Every 30–180 min, per source | `run_source` | Collects and ingests one source |
| 03:30 daily (`housekeeping_time`) | `run_housekeeping` | Removes old runs, notifications and deliveries; slims old items; deletes them if you enabled that; prunes scammer identifiers |
| 06:00 daily (`digest_time`) | `run_digest` | Writes the AI executive summary (when an AI model is configured and the summary is on) |
| 04:00 UTC on the 5th of each month | `run_geoip_update` | Refreshes the offline GeoIP database (when auto-update is on) |
| 2 s after new items arrive | `run_auto_summaries` | Writes AI summaries for new items with severity ≥ 40 (when enabled), 10 per run |

Two scheduler rules apply to every job. A job that is still running when its next turn comes is not started a
second time, and runs that were missed while the process was busy or stopped are merged into one (as long as
they are no more than 10 minutes late). All jobs share a pool of 10 threads.

## Where each number comes from

| What you see | How it is calculated | Read more |
|---|---|---|
| **Severity** (0–100) on an item | Rules applied to the title and text, plus the entities found, when the item is stored. It rises by +12 / +5 when an indicator is later confirmed malicious or suspicious, and by up to +20 from the AI | [Severity scoring](scoring.md) |
| **Fraud score** (0–100) | The scam analysis, when the item is stored. 0 means "not a scam report" | [Scams and fraud](../fraud.md#fraud-score) |
| **Verdict** on an indicator, and its date | The combined answer of the enrichment providers, with the date it was last given or confirmed | [Enrichment and verdicts](enrichment.md#consensus) |
| **Trend score**, *new*, growth | How often something was mentioned in the period compared with the period before, weighted by how many sources and source types reported it | [Trends and correlation](trends.md#trend-score) |
| **CVE priority**, KEV / EPSS / CVSS | The CVE intel refresh, combined with the trend score | [Trends and correlation](trends.md#cve-priority) |
| **Related items** and their score | The entities two items share, weighted by type and rarity | [Trends and correlation](trends.md#correlation) |
| **Target countries** and provinces | Place names, nationalities, institutions and data from the feed, when the item is stored | [Ingest and analysis](processing.md#10-geography) |
| **Sectors** | Sector vocabulary in the title and body, when the item is stored | [Ingest and analysis](processing.md#7-critical-infrastructure-sectors) |
| **"Copy of …"**, and story counts | Fingerprints compared across sources when the item is stored | [Ingest and analysis](processing.md#3-cross-source-duplicates) |
| **Source health** (quiet, failing, summary only) | Each source's recent items and run history, checked every hour | [Collection](collection.md#source-health) |
| **Enrichment queue** and quotas | Indicators waiting for a lookup, and today's use of each provider's daily budget | [Enrichment and verdicts](enrichment.md#the-queue) |
| **Job progress bars** and notifications | The run records of each job and the progress of whatever is running now | [Collection](collection.md#runs-batches-and-progress) |

## Key terms

| Term | Meaning |
|---|---|
| **Source** | One configured feed, account, channel or intel query, with its own collector type, interval and sharing rules |
| **Item** | One stored article, post, pulse, scan or analysis. Every item belongs to exactly one source |
| **Story** | An original item together with its syndicated copies. Dashboards count stories, so a story carried by five outlets counts once |
| **Entity** | Anything JATMP tracks across items: a malware family, threat actor, CVE, ATT&CK technique, indicator, scam type, brand, scammer identifier or sector. Each one is unique by its type and normalised value |
| **Link** | A record that says "this item mentions this entity", together with how it was found (its *origin*): `regex`, `kb`, `heuristic`, `feed` or `llm` |
| **Indicator (IOC)** | An entity of type `ip`, `domain`, `url`, `md5`, `sha1` or `sha256` |
| **Verdict** | JATMP's combined opinion on an indicator: `malicious`, `suspicious`, `clean` or `unknown`, or empty if it hasn't been checked successfully yet. It always comes with the date it was last given or confirmed |
| **Run** | One execution of a job, recorded with its status |
| **Batch** | The runs started by one manual action (*Collect now*, *Backfill*). They share one progress bar and one summary notification |
| **Live / backfill** | Whether an item was collected as it appeared, or fetched from history later |
| **Original / copy** | When another outlet publishes the same article within four days, the later one is a *copy* of the first |
| **Slimmed** | An item older than the full-text retention period. Its text is cut to a snippet; everything else stays |
| **Rules version** | A number in the code that goes up whenever detection or scoring rules change. When it differs from the version stored in the database, a one-off job re-analyses the stored items |

## What JATMP does not do

Knowing the limits helps you read the results correctly.

- **It only reads what the source delivers.** For RSS, that is the text inside the feed entry; JATMP does not
  open the article page. Feeds that only carry a short summary produce fewer entities, and the Sources tab marks
  them as *summary only*.
- **It never visits leak sites or criminal infrastructure.** Leak-site victims come from the ransomware.live
  aggregator, and indicators are looked up on intel providers rather than contacted directly.
- **It never looks up scammer identifiers anywhere.** Bank accounts and wallets get links so an analyst can check
  them by hand.
- **It doesn't use machine learning.** Detection is based on rules, vocabularies and a knowledge base. A language
  model only runs if you configure the optional AI, and what it can change is limited.
- **It doesn't re-run entity extraction on its own.** When a new version changes the scoring, fraud, sector,
  geography or cleaning rules, stored items are re-analysed automatically once. Changes to entity extraction only
  reach old items when you run `manage.py reextract` (see
  [Housekeeping and re-analysis](housekeeping.md#re-analysis-of-stored-items)).

## Pages in this section

| Page | What it covers |
|---|---|
| [Collection](collection.md) | Scheduling, what each collector fetches, topic filters, run results and notifications, source health, manual batches, backfill |
| [Ingest and analysis](processing.md) | The ten ingest steps: duplicates, cleaning, syndicated copies, entity extraction, severity, fraud, sectors, linking, blocklists, geography |
| [Severity scoring](scoring.md) | Every signal and its weight, entity points, dampeners, later adjustments, worked examples, re-scoring |
| [Enrichment and verdicts](enrichment.md) | Which indicators are looked up and when, the queue and quotas, providers, the consensus rules, verdicts that age, family links, CVE intel |
| [Trends and correlation](trends.md) | Counting rules, periods and baselines, the trend score, CVE priority, related items, the graph |
| [AI processing](ai.md) | Item summaries and their safeguards, the auto-summary queue, briefs, the executive summary, questions, personal data |
| [Sharing and delivery](sharing.md) | TLP, redistribution and personal-data rules, aged indicators, webhooks (events, signing, retries), MISP push |
| [Housekeeping and re-analysis](housekeeping.md) | The nightly clean-up, retention, identifier pruning, versioned re-analysis, restarts |
| [Corrections and quality](corrections.md) | Analyst corrections and why they stick, the Corrections page, the quality report and its CI gate |
