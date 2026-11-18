# How JATMP works

[← Documentation index](../README.md)

This section explains what JATMP does behind the screens: every automatic process, in the order it happens, with
the rules and numbers it uses. It is written for analysts who want to know where a score or a verdict comes from,
for administrators who tune sources and quotas, and for anyone who wants to check that the platform behaves the way
they expect. Developers will find the code structure in [Architecture](../architecture.md) and the tables in
[Data model](../data-model.md); these pages describe *behaviour*.

Everything described here is rule-based and deterministic. The same input gives the same result, and every score
shows its reasons on the item page. The optional AI features add to these results within fixed limits; they never
replace them (see [AI processing](ai.md)).

## The five stages

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
  every 30–180 min  the collection          8 indicators       (cached 45 s)         nightly (housekeeping)
```

| Stage | What happens | When | Details |
|---|---|---|---|
| **1. Collect** | One job per enabled source fetches what the provider currently lists | Every `interval_minutes` per source (minimum 5); *Collect now*; *Backfill* | [Collection](collection.md) |
| **2. Ingest and analyse** | New entries are de-duplicated, cleaned, scanned for entities, scored for severity and fraud, tagged with sectors and geography, and stored | Immediately, inside the collection run | [Ingest and analysis](processing.md), [Severity scoring](scoring.md), [Scams and fraud](../fraud.md) |
| **3. Enrich** | Indicators are looked up on the configured intel providers; the answers become one verdict | Every 10 minutes, 8 indicators per run (defaults) | [Enrichment and verdicts](enrichment.md) |
| **4. Aggregate** | Trend scores, CVE risk, correlation, statistics and the AI summaries are computed from the stored items | When a page is opened (trends cached 45 s); CVE intel every 6 h; AI digest daily | [Trends and correlation](trends.md), [AI processing](ai.md) |
| **5. Share and maintain** | Webhooks, MISP pushes and the APIs deliver what may leave; housekeeping slims and deletes old data; re-analysis jobs apply new rules to stored items | Webhooks every 30 s; housekeeping daily (03:30 UTC by default); re-analysis after upgrades | [Sharing and delivery](sharing.md), [Housekeeping and re-analysis](housekeeping.md) |

All five stages run in **one process** (the web application and its scheduler, see
[Architecture](../architecture.md#the-big-picture)). There is no queue between them: an item is fully analysed
by the time the collection run that found it finishes.

## Follow one article through JATMP

The fastest way to understand the platform is to follow a single item. The example below is a made-up article,
but every number in it was produced by running the text through JATMP's own code.

> **LockBit ransomware exploits Citrix zero-day to hit Indonesian hospitals**
>
> Researchers say a new LockBit campaign is actively exploited in the wild against hospitals in Jakarta and
> Surabaya. The flaw, CVE-2026-31337, allows remote code execution on unpatched appliances. The operators used
> the T1190 technique. Indicators: 185.220.101[.]54, update-citrix[.]net,
> hxxps://update-citrix[.]net/payload.exe. Rumah sakit di Jakarta mengalami gangguan layanan.

**t = 0 — collection.** The RSS job of the outlet runs on its interval. It downloads the feed (at most 10 MB),
parses up to 500 entries, applies the source's topic filter if it has one, and hands the newest 100 to the
pipeline as `RawItem`s. → [Collection](collection.md)

**t + a few ms — ingest.** Inside the same run:

1. *Is it new?* The pair (source, external id) is not in the database yet, so the entry is stored.
2. *Clean-up.* HTML, scripts and stray stylesheet text are removed; the link is kept because it is `https://`.
3. *Syndicated copy?* A fingerprint of the normalised title is compared with articles from other sources of the
   last four days. No match, so this item is an original.
4. *Entities.* The extractor finds:

    | Type | Value | Origin | Why |
    |---|---|---|---|
    | malware | LockBit (ransomware) | `kb` | In the knowledge base |
    | cve | CVE-2026-31337 | `regex` | CVE pattern |
    | technique | T1190 | `regex` | ATT&CK id pattern |
    | ip | 185.220.101.54 | `regex` | Public IPv4, written defanged |
    | domain | update-citrix.net | `regex` | Written defanged (`[.]`) — news is read in *strict* mode, so only defanged hosts count |
    | url | https://update-citrix.net/payload.exe | `regex` | Refanged from `hxxps://…[.]…` |

5. *Severity.* The raw sum is 132, capped at **100**: zero-day in the title (30 × 1.5 = 45), exploited in the
   wild as runner-up in the same group (15), remote code execution (14), ransomware in the title (18), active
   campaign (10), sensitive sector as runner-up (4), a known family (10), one CVE (5), three indicators (8),
   ATT&CK technique (3). → [Severity scoring](scoring.md)
6. *Fraud.* No scam type is described, so the fraud score is 0 and the item is not a scam report.
7. *Sectors.* "hospitals" in the title and *rumah sakit* in the body → **health**.
8. *Geography.* Language `en`. "Indonesian" in the title, Jakarta and Surabaya in the body → target country
   **Indonesia** (score 8.25) with provinces **DKI Jakarta** and **Jawa Timur**.
9. *Links.* Seven entities (six above plus the sector) are linked to the item; each entity's mention counter
   and first / last seen dates are updated.

**t + < 1 s — after the commit.** The trending cache is cleared, so the dashboard counts the item on the next
page view. Severity 100 is above the default webhook threshold (70), so an `item.high_severity` event is queued
for every webhook that subscribed to it; if MISP auto-push is on, a push job is queued; if AI auto-summaries are
on, the item joins the summary queue.

**t + up to 10 min — enrichment.** The three indicators have never been looked up and the item has the highest
severity in the queue, so they are among the next eight. Each configured provider answers; say VirusTotal
reports the IP as malicious. The consensus verdict becomes `malicious`, every item that mentions the IP gets
*+12 indicator confirmed malicious* (this one is already at 100), and an `ioc.malicious` webhook event is queued.
→ [Enrichment and verdicts](enrichment.md)

**t + up to 6 h — CVE intel.** CVE-2026-31337 is looked up in CISA KEV, FIRST EPSS and the NVD. If it is in KEV,
its trend score on the dashboard is doubled. → [Trends and correlation](trends.md#cve-priority)

**Every page view.** LockBit's trend score for the period counts this item once (and once only, even if five
outlets syndicate the story). The *Indonesia* view includes it because it targets Indonesia.

**After 30 s.** The webhook delivery job sends the queued events. → [Sharing and delivery](sharing.md)

**After 180 days.** The nightly housekeeping slims the item: title, link, entities, scores and a 400-character
snippet stay; the full text goes. → [Housekeeping and re-analysis](housekeeping.md)

## A day on the scheduler

All times are UTC; the two daily jobs follow the schedule time zone when one is set (Settings → General). Intervals are the defaults; most can be changed under Settings.

| When | Job | What it does |
|---|---|---|
| Start + 5 s, + 8 s, + 11 s … | First run of each source | Sources start 5 s + 3 s × source id after start-up, so they do not all hit the network at once |
| Start + 15 s | `run_content_cleanup` | Cleans stored text if the cleaning rules changed (no-op when up to date) |
| Start + 20 s | `run_geotag` | Re-tags geography if the rules changed |
| Start + 30 s | `run_dedup` | Fingerprints stored articles if the dedup rules changed |
| Start + 40 s | `run_fraudtag` | Re-runs the scam analysis if the rules changed |
| Start + 60 s | `run_sectortag` | Re-tags sectors if the rules changed |
| Start + 2 min, then every 10 min | `run_enrichment` | Looks up 8 indicators (plus re-checks and 2 trending families when enabled) |
| Start + 3 min, then every 6 h | `run_cve_intel` | KEV, EPSS and CVSS for up to 60 recently mentioned CVEs |
| Every 30 s | `run_webhooks` | Delivers up to 50 due webhook events |
| Every 30–180 min per source | `run_source` | Collects and ingests one source |
| 03:30 daily (`housekeeping_time`) | `run_housekeeping` | Old runs, notifications and deliveries; slimming; deletion (if enabled); identifier pruning |
| 06:00 daily (`digest_time`) | `run_digest` | AI executive summary (when an LLM is configured and the digest is on) |
| 04:00 on the 5th of each month | `run_geoip_update` | Refreshes the offline GeoIP database (when auto-update is on) |
| 2 s after new items | `run_auto_summaries` | AI summaries of new items with severity ≥ 40 (when enabled), 10 per run |

Two scheduler settings apply to every job: a job that is still running when its next run is due is not started
twice (`max_instances = 1`), and runs that were missed while the process was busy or down collapse into one
(`coalesce`, with a grace time of 10 minutes). All jobs share a pool of 10 threads.

## Where each number comes from

| You see | It is computed by | Read more |
|---|---|---|
| **Severity** (0–100) on an item | Rules on the title and text, plus the entities found, at ingest; +12 / +5 when an indicator is later confirmed; up to +20 from the AI | [Severity scoring](scoring.md) |
| **Fraud score** (0–100) | The scam analysis at ingest; 0 means "not a scam report" | [Scams and fraud](../fraud.md#fraud-score) |
| **Verdict** on an indicator | The consensus of the enrichment providers' answers | [Enrichment and verdicts](enrichment.md#consensus) |
| **Trend score**, *new*, growth | Mention rate in the period against the baseline before it, weighted by sources and source types | [Trends and correlation](trends.md#trend-score) |
| **CVE priority**, KEV / EPSS / CVSS | CVE intel refresh, combined with the trend score | [Trends and correlation](trends.md#cve-priority) |
| **Related items** and their score | Shared entities, weighted by type and rarity | [Trends and correlation](trends.md#correlation) |
| **Target countries**, provinces | Place names, demonyms, institutions and feed data at ingest | [Ingest and analysis](processing.md#10-geography) |
| **Sectors** | Sector vocabulary in title and body at ingest | [Ingest and analysis](processing.md#7-critical-infrastructure-sectors) |
| **"Copy of" / one story counted once** | Cross-source fingerprints at ingest | [Ingest and analysis](processing.md#3-cross-source-duplicates) |
| **Job progress bars** and notifications | `CollectorRun` rows and the in-memory progress of each run | [Collection](collection.md#runs-batches-and-progress) |

## Key terms

| Term | Meaning |
|---|---|
| **Source** | One configured feed, account, channel or intel query, with its own collector kind, interval and sharing rules |
| **Item** | One stored article, post, pulse, scan or analysis. Every item belongs to one source |
| **Entity** | Anything tracked across items: a malware family, actor, CVE, technique, indicator, scam type, brand, scammer identifier or sector. Unique by type and normalised value |
| **Link** (`item_entities`) | "This item mentions this entity", with the *origin* of the finding: `regex`, `kb`, `heuristic`, `feed` or `llm` |
| **Indicator / IOC** | An entity of type `ip`, `domain`, `url`, `md5`, `sha1` or `sha256` |
| **Verdict** | JATMP's combined opinion on an indicator: `malicious`, `suspicious`, `clean`, `unknown`, or empty when never (successfully) checked |
| **Run** | One execution of a job, stored as a `CollectorRun` row with a status |
| **Batch** | The runs started by one manual action (*Collect now*, *Backfill*), shown as one progress bar and summarised in one notification |
| **Live / backfill** | Whether an item was collected as it appeared or crawled from history later |
| **Original / copy** | An article syndicated by another outlet within four days is a *copy* (`dup_of`) of the first one; statistics count the story once |
| **Slimmed** | An item past the full-text retention period: the text is cut to a snippet, everything else stays |
| **Rules version** | A number in the code that changes when detection rules change; when it differs from the stored one, a one-off job re-analyses stored items |

## What JATMP does not do

Knowing the boundaries helps reading the results correctly:

- **It reads what the source delivers.** For RSS that is the text in the feed entry; JATMP does not open the
  article page. Short feed summaries therefore give fewer entities than full-text feeds.
- **It does not visit leak sites or criminal infrastructure.** Leak-site victims come from the ransomware.live
  aggregator; indicators are looked up on intel providers, never contacted.
- **It does not look up scammer identifiers anywhere.** Bank accounts and wallets get links for an analyst to
  check by hand.
- **It does not machine-learn.** Detection is rules, vocabularies and a knowledge base; a model only runs when you
  configure the optional AI, and its output is bounded.
- **It does not re-analyse old items by itself when you change a setting.** Rule changes that ship with a new
  version re-analyse stored items once; extraction and severity changes need *Re-score all items* or
  `manage.py reextract` (see [Housekeeping and re-analysis](housekeeping.md#re-analysis-of-stored-items)).

## Pages in this section

| Page | What it covers |
|---|---|
| [Collection](collection.md) | Scheduling, what one run of each collector fetches, topic filters, run outcomes and notifications, manual batches, backfill |
| [Ingest and analysis](processing.md) | The ten ingest steps: duplicates, cleaning, syndication, entity extraction, severity, fraud, sectors, linking, blocklists, geography |
| [Severity scoring](scoring.md) | Every signal group and weight, entity points, dampeners, later adjustments, worked examples |
| [Enrichment and verdicts](enrichment.md) | Which indicators are looked up when, providers and quotas, the consensus rules, re-checks, family links, CVE intel |
| [Trends and correlation](trends.md) | Trend score, baselines and periods, CVE priority and risk buckets, related items, the graph, the National view |
| [AI processing](ai.md) | Item summaries and their guardrails, the auto-summary queue, the executive summary, briefs and Q&A |
| [Sharing and delivery](sharing.md) | TLP and redistribution rules, webhooks (events, signing, retries), MISP push, what never leaves |
| [Housekeeping and re-analysis](housekeeping.md) | The nightly clean-up, retention tiers, personal-data pruning, versioned re-analysis, restarts |
