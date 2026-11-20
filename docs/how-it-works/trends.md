# Trends and correlation

[← How JATMP works](index.md)

This page explains how the dashboards turn stored items into trend scores, CVE priorities, breakdowns and lists of
related items. None of these figures are stored: they are calculated from the items whenever a page is opened
(trend lists are cached for 45 seconds). The code is in `app/processing/trends.py`, `app/processing/graph.py` and
`app/intel/cve.py`.

## Counting rules

Three rules decide what a number on the dashboards actually counts.

**Stories, not copies.** When several outlets publish the same article, the original and its copies count as one
story (see [Cross-source duplicates](processing.md#3-cross-source-duplicates)). This rule applies everywhere JATMP
counts how much was reported:

- the KPI tiles and their sparklines, and the timelines;
- the breakdown charts (malware and actor types, sectors, scam types, brands);
- target countries and provinces;
- mention counts in the entity lists;
- trend scores and the scam *spreading* check;
- the AI executive summary and the PDF / Word reports.

The *Stories collected* tile also shows the number of items, copies included, when the two differ.

**Per-outlet figures count items.** *Items per source*, source countries and languages describe what each outlet
published, so there a copy counts for the outlet that carried it.

**Dates and regions.** Periods are measured by publication date, so backfilled history lands in the period it was
published in, not the day it was collected. In the *National (ID)* view, every figure only includes items that
target Indonesia, or that come from an Indonesian outlet without naming another target (see
[The National view](processing.md#the-national-indonesia-view)).

## Periods and baselines

| Period | Chart bars | Trend baseline |
|---|---|---|
| 7, 15 or 30 days | One per day | The 30 days before the period |
| 3 months (90 days) | One per day | The 90 days before the period |
| 6 months, 1 year | One per week (the first day of each 7-day block) | As long as the period itself |

In other words, the baseline is always the `max(30, period)` days immediately before the period. The live
collectors only cover the recent past, so the longer periods (and their baselines) only become meaningful after
a [backfill](collection.md#backfill). The dashboards tell you when some sources have gaps.

## Trend score

Malware families, threat actors and CVEs on the threat radar, in the *Trending* tables and in the AI summary are
ranked by a **trend score**. For one entity, with a period of `W` days and a baseline of `B` days, JATMP uses:

| Input | Meaning |
|---|---|
| `r` | Stories that mention it in the period |
| `b` | Stories that mention it in the baseline |
| `s` | How many different sources reported it in the period (originals only; at least 1) |
| `c` | How many different source **types** (news, social, intel) reported it in the period (at least 1) |

```
growth = (r / W + 0.1) / (b / B + 0.1)
score  = r × √min(growth, 10) × (1 + 0.25 × (s − 1)) × (1 + 0.2 × (c − 1))
```

Each part has a job:

- **Volume** (`r`) is the starting point. Something mentioned only once doesn't trend, however new it is.
- **Growth** compares the daily rate now with the daily rate before. The `+ 0.1` stops a first mention from
  producing infinite growth, and the square root and the cap at 10 stop a sudden spike from drowning out threats
  that are steady but widely covered.
- **Spread** rewards independent confirmation: each extra source adds 25%, and each extra source type adds 20%.
  Syndicated copies don't count as extra sources.

| Example (7-day period, 30-day baseline) | r | b | s | c | growth | score |
|---|---|---|---|---|---|---|
| A family that suddenly shows up in the news and on Bluesky | 6 | 3 | 4 | 2 | 4.79 | **27.56** |
| A family that is always in the news at this rate | 6 | 26 | 4 | 2 | 0.99 | **12.54** |
| A single blog that mentions a new name twice | 2 | 0 | 1 | 1 | 3.86 | **3.93** |
| An outbreak that everyone covers | 20 | 0 | 8 | 3 | 29.57 (capped at 10) | **243.5** |

A few more rules:

- An entity with no story in the period isn't listed at all.
- A malware name that was **only ever found by the "*Name* ransomware" pattern** only appears once **two
  sources** name it in the period, so a single misread headline can't make something trend.
- An entity first seen during the period gets the **new** badge. To list only such entities, use the
  *✦ New threats* button on the Intelligence lists (Malware, Threat actors, CVEs, IOCs, Scam types, Impersonated
  brands), which keeps the entries whose first-seen date falls in the chosen period; see
  [Using JATMP](../using-jatmp.md#tables-and-preview).
- Actors are grouped by type (nation-state, ransomware, extortion, cybercrime or unclassified), using the
  knowledge base or a `category` you set in `data/knowledge_extra.json`.

Trend lists are cached in memory for **45 seconds** for each combination of type, period, region and list
length. The cache is cleared whenever a collection run stores new items.

## CVE priority

Lots of chatter about a vulnerability doesn't necessarily mean it should be patched first. So trending CVEs are
re-ranked by how likely they are to be exploited:

```
priority = trend score × (2 if in CISA KEV) × (1 + EPSS) × (0.5 + CVSS / 10)
```

A CVE without a CVSS score is multiplied by 1 for that part. The dashboard takes the 60 CVEs with the highest
trend scores, sorts them by priority, shows the top 8, and lists the families and actors mentioned alongside
each one.

For example, take two CVEs that both have a trend score of 10. The first is in KEV, with an EPSS of 0.6 and a
CVSS of 9.8: 10 × 2 × 1.6 × 1.48 = **47.4**. The second isn't in KEV, with an EPSS of 0.01 and a CVSS of 5.3:
10 × 1 × 1.01 × 1.03 = **10.4**.

### CVEs by exploitation risk

This chart puts each CVE mentioned in the period into the **first** bucket it qualifies for:

| Bucket | Condition |
|---|---|
| In CISA KEV | It is in the catalogue |
| EPSS 10%+ | Its EPSS score is 0.10 or more |
| CVSS critical | CVSS 9 or more |
| CVSS high | CVSS 7 to 8.9 |
| CVSS medium / low | Any other CVSS score |
| Low EPSS, no CVSS | Looked up, but none of the above (counted below the chart) |
| Not looked up yet | No CVE intel yet (counted below the chart) |

The data comes from the [CVE intel refresh](enrichment.md#cve-intel).

## Correlation

The *Related items* list on an item's page ranks other items by **how strong the evidence they share is**, not
just by how many entities they have in common.

Each shared entity contributes:

```
weight(type) / log2(2 + mention_count)
```

so a rare entity counts for more than one that is mentioned everywhere.

| Type | Weight | | Type | Weight |
|---|---|---|---|---|
| sha256, sha1, md5 | 6.0 | | crypto wallet | 6.0 |
| url | 5.0 | | bank account, e-wallet | 5.0 |
| domain | 4.0 | | phone | 4.0 |
| ip | 3.0 | | brand | 1.0 |
| malware, actor | 2.5 | | scam type | 0.5 |
| cve | 1.5 | | sector | 0.2 |
| technique | 0.5 | | | |

An item's score is the sum over all the entities it shares. It is then multiplied by **1.3** if the item comes
from a different source **type** (a news article and a Bluesky post, say), or by **1.15** if it comes from a
different source of the same type. Matches through an indicator are flagged as *strong*. The top 15 are shown.

**Newsletters and round-ups.** A digest (Cisco Talos' *Threat Source*, weekly round-ups, podcasts) covers several
unrelated stories and repeats a "most prevalent files" list every issue, so what it shares with another item is
weak evidence. An item counts as a digest when its title or tags match the round-up pattern (*newsletter*, *threat
source*, *week in review*, *roundup*, *bulletin*, *in other news*, *weekly threat report*, *mingguan*…), when its
body carries newsletter boilerplate (*Welcome to this week's edition…*, *Upcoming events where you can find*;
Talos issue titles say nothing, so the title alone is not enough), or when its source has `"digest": true` in its config (`false` opts a
source out). Links through a digest are scored ×0.4, ×0.1 when both items are digests, never made between two
issues of the same source, and dropped when the score ends below 1. They carry a *digest* badge and are never
flagged *strong*. The flag is stored on the item (`items.is_digest`), set when it is collected and re-set after an
upgrade or `manage.py digesttag`.

**Co-mentions.** *Mentioned together with*, the indicators listed on a family's page and the chips on the lists count
the entities that appear in the same items, and they leave out digests entirely: a hash from a newsletter's weekly
*most prevalent files* list sits next to the family of another story, and that is no evidence the two belong
together. Even outside digests, being in the same article is not attribution (on this deployment's data, an
indicator and a family from the same article agreed with the provider's family only about a third of the time), so on
an indicator's page the card is called *Seen in the same items as*, and *Linked by enrichment* (what a provider
attributes) comes first.

To keep this fast, entities mentioned in more than 400 items aren't used to *find* candidates (although they
still add weight to candidates found through rarer entities), and at most the 4,000 most recent links are read.

## Relationship graph

The graph on an item's page is built from:

1. the item itself, in the centre;
2. its entities (indicators with a bad verdict first), taking up at most 45% of the nodes;
3. whatever enrichment linked them to (a hash's family, a domain's IPs, a family's OTX indicators), at most 25%
   of the nodes;
4. the top related items from the correlation above, with lines to the entities they share.

On an entity's page, the graph shows the entity, its enrichment links, the families, actors and CVEs most often
mentioned with it, and the 10 highest-severity items that mention it. The graph starts with up to **60 nodes**;
*Show more* raises the limit to 150. When something had to be left out, the graph says so.

**Reading the lines.** Under the graph, a second legend row shows each kind of line that appears in it, what it
means and *whose claim it is*. Hover an entry for the explanation; hovering a line in the graph shows its label and
the same claim.

| Line | Means | Claim |
|---|---|---|
| Solid, grey (*Mentions*) | The item names the entity: extracted from its text by the platform's rules, or listed by the source's own indicator feed | automatic |
| Dashed, green (*Provider link*) | A threat-intel provider (OTX, urlscan, MalwareBazaar…) states the relation, such as an indicator attributed to a family | provider's claim |
| Solid, blue (*Also mentions*) | Another item names the same entity: not proof that the two items describe the same activity | needs validation |
| Dotted (*Mentioned together*) | Two entities named in the same items: not attribution | needs validation |

*Needs validation* marks relations that come from co-occurrence only. An analyst can remove a wrong link with
**Correct** ([Analyst corrections](corrections.md)). Newsletters and round-ups are left out of both kinds.

## Other figures

| Widget | What it shows |
|---|---|
| KPI tiles | Stories in the period compared with the period before; families and actors first seen in the period; indicators seen in the period, and how many of them are malicious |
| Sparklines | Stories, plus the number of different families, indicators, CVEs and actors mentioned, per day (per week for periods over 90 days) |
| Timeline | Stories per day (or week), split by source type |
| Threat actors by type | Stories that mention an actor, per type of actor |
| Critical infrastructure sectors | Stories per sector, with all eight sectors listed |
| Items per source | Items per source, copies included |
| Indicators by type and verdict | Indicators last seen in the period, split into malicious, suspicious and the rest |
| Geography and the globe | Target countries of the stories in the period (top 10 on the globe); source countries and languages count items |
| Scam & fraud dashboard | The same rules, applied to scam reports (items with a fraud score above 0). *Spreading* means at least 5 reports this week and twice as many as the week before |
