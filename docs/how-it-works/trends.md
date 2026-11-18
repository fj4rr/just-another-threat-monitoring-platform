# Trends and correlation

[← How JATMP works](index.md)

How the dashboards turn stored items into trend scores, CVE priorities, breakdowns and related items. None of this
is stored: it is computed from the items when a page is opened (trend lists are cached for 45 seconds). Code:
`app/processing/trends.py`, `app/processing/graph.py`, `app/intel/cve.py`.

## Counting rules

Three rules decide what a number on the dashboards counts:

- **Publication date.** Periods are measured on `published_at`, so backfilled history lands in the period it was
  published in, not the day it was collected.
- **Region.** In the *National (ID)* view every count is limited to items that target Indonesia or come from an
  Indonesian outlet without another target (see [The National view](processing.md#the-national-indonesia-view)).
- **Stories or items.** Trend scores, the scam *spreading* check and the AI executive summary count a syndicated
  article and its copies **once** (`count(distinct coalesce(dup_of, id))`, see
  [Cross-source duplicates](processing.md#3-cross-source-duplicates)). The KPI tiles, the timeline and the
  breakdown charts count **items**, so a story carried by three outlets counts three times there.

## Periods and baselines

| Period | Chart buckets | Trend baseline |
|---|---|---|
| 7, 15 or 30 days | One per day | The 30 days before the period |
| 3 months (90 days) | One per day | The 90 days before the period |
| 6 months, 1 year | One per week (first day of each 7-day block) | As long as the period |

The baseline is `max(30, period)` days immediately before the period. Live collectors only cover the recent past,
so the long periods (and their baselines) are only meaningful after a [backfill](collection.md#backfill); the
dashboards say so when sources have gaps.

## Trend score

Families, actors and CVEs on the threat radar, in the *Trending* tables and in the AI digest are ranked by a
**trend score**. For one entity, with a period of `W` days and a baseline of `B` days:

| Input | Meaning |
|---|---|
| `r` | Stories mentioning it in the period |
| `b` | Stories mentioning it in the baseline |
| `s` | Distinct sources of those stories in the period (originals only; at least 1) |
| `c` | Distinct source **types** (news, social, intel) in the period (at least 1) |

```
growth = (r / W + 0.1) / (b / B + 0.1)
score  = r × √min(growth, 10) × (1 + 0.25 × (s − 1)) × (1 + 0.2 × (c − 1))
```

- **Volume** (`r`) is the base: something mentioned once does not trend, however new.
- **Growth** compares daily rates. The `+ 0.1` keeps a first mention from producing an infinite growth; the
  square root and the cap at 10 keep a sudden spike from drowning steady, widely covered threats.
- **Spread** rewards independent confirmation: each extra source adds 25%, each extra source type 20%.

| Example (7-day period, 30-day baseline) | r | b | s | c | growth | score |
|---|---|---|---|---|---|---|
| A family that suddenly appears in news and on Bluesky | 6 | 3 | 4 | 2 | 4.79 | **27.56** |
| A family that is always in the news at this rate | 6 | 26 | 4 | 2 | 0.99 | **12.54** |
| A single blog post twice about a new name | 2 | 0 | 1 | 1 | 3.86 | **3.93** |
| An outbreak covered everywhere | 20 | 0 | 8 | 3 | 29.57 (capped at 10) | **243.5** |

Further rules:

- An entity with no story in the period is not listed.
- A malware name that was **only ever found by the "*Name* ransomware" pattern** (origin `heuristic`) is only
  listed once **two sources** name it in the period, so a single misread headline cannot trend.
- An entity whose `first_seen` falls inside the period gets the **new** badge.
- Actors are grouped by kind (nation-state, ransomware, extortion, cybercrime, unclassified) from the knowledge
  base, or from a `category` in `data/knowledge_extra.json`.

Trend lists are cached in memory for **45 seconds** per combination of type, period, region and length, and the
cache is cleared whenever a collection run stores new items.

## CVE priority

Chatter alone is a poor guide to which vulnerability to patch first, so trending CVEs are re-ranked by
exploitation risk:

```
priority = trend score × (2 if in CISA KEV) × (1 + EPSS) × (0.5 + CVSS / 10)
```

A CVE without a CVSS score is multiplied by 1 for that part. The dashboard takes the 60 CVEs with the highest
trend score, sorts them by priority, shows the top 8 and lists the families and actors mentioned alongside each.

Example: two CVEs with the same trend score of 10. One is in KEV with EPSS 0.6 and CVSS 9.8 → 10 × 2 × 1.6 × 1.48
= **47.4**. The other is not in KEV, has EPSS 0.01 and CVSS 5.3 → 10 × 1 × 1.01 × 1.03 = **10.4**.

### CVEs by exploitation risk

The chart puts each CVE mentioned in the period in the **first** bucket it qualifies for:

| Bucket | Condition |
|---|---|
| In CISA KEV | Listed in the catalogue |
| EPSS 10%+ | EPSS score ≥ 0.10 |
| CVSS critical | CVSS ≥ 9 |
| CVSS high | CVSS 7 – 8.9 |
| CVSS medium / low | Any other CVSS score |
| Low EPSS, no CVSS | Looked up, but neither of the above (counted under the chart) |
| Not looked up yet | No CVE intel yet (counted under the chart) |

The data comes from the [CVE intel refresh](enrichment.md#cve-intel).

## Correlation

The *Related items* list on an item page ranks other items by the **strength of the evidence they share**, not by
how many entities they share.

Each shared entity contributes

```
weight(type) / log2(2 + mention_count)
```

so a rare entity counts more than one that is mentioned everywhere:

| Type | Weight | | Type | Weight |
|---|---|---|---|---|
| sha256, sha1, md5 | 6.0 | | crypto wallet | 6.0 |
| url | 5.0 | | bank account, e-wallet | 5.0 |
| domain | 4.0 | | phone | 4.0 |
| ip | 3.0 | | brand | 1.0 |
| malware, actor | 2.5 | | scam type | 0.5 |
| cve | 1.5 | | sector | 0.2 |
| technique | 0.5 | | | |

The item's score is the sum over its shared entities, then multiplied by **1.3** if it comes from another source
**type** (a news article and a Bluesky post), or **1.15** if from another source of the same type. Matches through
an indicator are flagged as *strong*. The top 15 are shown.

To stay fast, entities mentioned in more than 400 items do not *find* candidates (they still add weight to
candidates found through rarer entities), and at most the 4,000 most recent links are read.

## Relationship graph

The graph on an item page is assembled from:

1. the item, in the centre;
2. its entities (indicators with a bad verdict first), at most 45% of the nodes;
3. what enrichment linked them to (a hash's family, a domain's IPs, a family's OTX indicators), at most 25% of
   the nodes;
4. the top related items from the correlation above, with edges to the entities they share.

On an entity page: the entity, its enrichment links, the families, actors and CVEs most often mentioned with it,
and the 10 highest-severity items that mention it. The graph starts at **60 nodes**; *Show more* raises the limit
to 150. When something was left out the graph says so.

## Other breakdowns

| Widget | Computed as |
|---|---|
| KPI tiles | Items in the period against the period before; families and actors first seen in the period; indicators seen in the period and how many are malicious |
| Sparklines | Items, and distinct families, indicators, CVEs and actors mentioned, per day (per week above 90 days) |
| Timeline | Items per day (or week) and source type |
| Threat actors by type | Items mentioning an actor, per actor kind |
| Critical infrastructure sectors | Items per sector, all eight sectors listed |
| Sources | Items per source |
| Indicators by type / verdict | Indicators last seen in the period, split into malicious, suspicious and other |
| Geography and the globe | `item_geo` targets of the items in the period (top 10 on the globe) |
| Scam & fraud dashboard | The same rules over items with `fraud_score > 0`; *spreading* means at least 5 reports this week and twice as many as the week before |
