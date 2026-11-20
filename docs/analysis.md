# Analysis

[← Documentation index](README.md)

This page gives an overview of how JATMP turns collected items into entities, scores, verdicts, correlations and
trends. The exact rules, weights and formulas are in [How it works](how-it-works/index.md), especially
[Severity scoring](how-it-works/scoring.md), [Enrichment and verdicts](how-it-works/enrichment.md) and
[Trends and correlation](how-it-works/trends.md).

## Entity extraction

Every item is searched for malware families (about 150, plus their aliases), threat actors (about 45), CVEs,
ATT&CK techniques and indicators (IPs, domains, URLs, and MD5, SHA-1 and SHA-256 hashes).

Defanged indicators are understood in all their usual forms (`hxxp`, `[.]`, `[:]`, `[://]`, `\.`, `(dot)`).
Families that aren't in the knowledge base yet are picked up from phrases such as "PipeMagic backdoor", but
legitimate tools that attackers misuse (ConnectWise, AnyDesk, PsExec and others) are never mistaken for
families. Family names that are also everyday words ("Play", "Hook") need a qualifier such as "ransomware",
unless they are written in the family's own spelling ("RedLine", "Cl0p").

JATMP also ignores hashes that are part of a URL, version numbers that look like IP addresses, public DNS
resolvers such as `8.8.8.8` and `1.1.1.1`, and about 200 vendor, media and platform domains. Paste, file-sharing
and code-hosting services (Pastebin, GitHub, Google Drive, Dropbox, MEGA and others) are handled carefully: the
service's own domain is never an indicator, but the URL of a specific paste or file on it is.

## Severity

Every item gets a score from 0 to 100 that explains itself: the item page shows the full breakdown.

The signals are grouped (exploitation, impact, threat class, activity) so that synonyms aren't counted twice.
Within a group, the strongest term counts in full and the runner-up at half weight, and terms in the title count
1.5 times as much as terms in the body. Patch notes, round-ups, guides and routine leak-site victim postings are
scored down. When an indicator is later confirmed malicious, the items that mention it are scored up.

When a new version changes the scoring rules, every stored item is re-scored once after the upgrade, so old and
new items are always judged the same way. Re-scoring keeps the points that enrichment and the AI added.

## Cross-source enrichment

Indicators found in news and social posts are looked up on whichever of these providers you have keys for:
VirusTotal, OTX, urlscan, ANY.RUN, MalwareBazaar (hashes), URLhaus (URLs, hosts, payloads), GreyNoise and
AbuseIPDB (IPs). Each provider works at its own pace, so a slow one doesn't hold up the others.

The answers are combined into a single verdict:

- Any provider reporting *malicious* wins.
- Infrastructure that OTX whitelists is marked clean.
- A lone mention in an OTX pulse is treated as suspicious rather than malicious.
- GreyNoise acts as a false-positive filter. An IP it knows as a benign business service or benign scanner is
  marked clean, unless a strong provider (VirusTotal, abuse.ch, ANY.RUN) says otherwise. Mass scanners get a
  "mass scanner" badge, because their activity is opportunistic rather than targeted.

Failed lookups are retried after six hours, and *unknown* results are checked again after three days. When a
provider identifies a family (for example, a hash on Bluesky identified as Lumma Stealer), the indicator is
linked to that family, so it connects to every article about it. For trending families, JATMP also pulls fresh
indicators from OTX and ANY.RUN, using only pulses that actually name the family.

**Verdicts age.** IPs, domains and URLs change owners, so every verdict carries the date it was last confirmed.
A malicious or suspicious one that is still being mentioned is checked again after 30 days, and the new answer
can lower it. If it isn't confirmed within 60 days, the indicator drops out of the IOC export feeds. File hashes
never age.

The IOC page and Settings → Enrichment show how many indicators are waiting to be looked up and how much of each
provider's daily budget is left.

An analyst can also set an indicator's verdict by hand. That verdict wins over the providers until it is undone
(see below).

## Corrections and rule quality

No set of rules is perfect, so analysts and admins can correct JATMP's mistakes, and the corrections stick:

- **✕ next to an entity** on an item page removes it from that item ("Pegasus" in an article about a musical).
- **✎ Correct** on an entity page removes a family or actor everywhere, marks an indicator as *not a threat*, or
  sets an analyst verdict (*malicious*, *suspicious* or *clean*).
- **Not a scam report**, in the fraud-score popover of an item, takes the item out of the scam section.

Each correction asks for a reason and records who made it. Re-extraction, the AI and rule changes don't bring the
mistake back, and the affected items are re-scored. The *Corrections* page lists every correction with an undo
button, the error rate analysts reported per area over the last 30 days, and the names corrected most often,
which usually point at a rule worth tuning.

The rules themselves are measured too. `python manage.py quality` reports the precision and recall of the
extractor, the scam rules, sectors, target countries and severity on a set of labelled cases, and CI fails when a
change makes any area worse. Analysts' corrections can be exported as test cases, so the report also says how many
of the mistakes analysts found the current rules would still make. Details are in
[Corrections and quality](how-it-works/corrections.md).

## Relationship graph

Item and entity pages show an interactive graph: the item, its entities, whatever enrichment linked them to (a
hash to its family, an indicator pulled from OTX), and other items that share them. Nodes are coloured by type
and verdict. Click a node to preview it, double-click to open it, drag and zoom to explore, or use the keyboard
(Tab, Enter, O). The graph is drawn by a small built-in SVG renderer rather than a third-party library. It starts
with up to 60 nodes, and *Show more* raises that to 150.

A second row in the legend explains each kind of line in the graph and whose claim it is: *Mentions* (automatic),
*Provider link* (a provider's claim), and *Also mentions* and *Mentioned together*, which are marked *needs
validation* because they only come from appearing in the same items. Hover a legend entry or a line for the
explanation; see [Reading the lines](how-it-works/trends.md#relationship-graph).

## Infrastructure context, on demand

*Context lookup* on an IP, domain or hash asks Shodan (open ports, host names, known CVEs), Censys (services,
network owner), CrowdSec CTI (reputation, behaviour), Pulsedive (risk, threats), Hybrid Analysis (sandbox verdict
and family) and IPinfo (network owner and country, used for the geography features), as far as you have keys for
them.

Their free tiers are small, so these lookups never run in the background unless you switch on *run context
lookups when an indicator turns malicious*. Shodan InternetDB and IPinfo can be used without a key once keyless
lookups are allowed.

## Correlation

The item page ranks related items by how strong the evidence they share is. A shared hash, URL or domain counts
for far more than a shared CVE, rare entities count for more than frequently mentioned ones, and items from
another source or source type get a bonus. Newsletters and round-ups, which name many unrelated things in one
issue, count for much less and are marked *digest*. Entity pages show coverage per source, the entities mentioned
alongside it (leaving newsletters out), related indicators, and enrichment results. On an indicator's page the
provider links (*Linked by enrichment*) come first, and the co-mentions are called *Seen in the same items as*,
because appearing in the same report is not attribution. See [Correlation](how-it-works/trends.md#correlation).

## Trends

The dashboard scores each family, CVE and threat actor by how often it was mentioned in the chosen period
compared with a baseline before it (30 days, or as long as the period when that is longer), weighted by how many
sources and source types cover it. A story that several outlets carry counts once.

The results appear on the threat radar (one icon per type), in a chart over time, and in the *Trending malware*,
*Trending CVEs* and *Trending threat actors* tables, which also list the families, actors and CVEs mentioned
alongside each entry.

Two breakdowns put the period in context:

- **CVEs by exploitation risk** places each CVE in the first bucket it qualifies for: in CISA KEV, EPSS of 10% or
  more, CVSS critical (9+), high (7 to 8.9), or lower. CVEs with no CVSS score and a low EPSS, or not looked up
  yet, are counted below the chart.
- **Threat actors by type** counts stories per kind of actor: nation-state, ransomware, extortion (data theft and
  extortion crews such as ShinyHunters or Scattered Spider) and cybercrime. Actors from the built-in knowledge
  base are already classified; others are *unclassified* unless `data/knowledge_extra.json` gives them a
  `category`.

## Critical infrastructure sectors

Each item is tagged with the critical information infrastructure sectors it concerns, as defined by Indonesia's
Perpres 82/2022 (*Infrastruktur Informasi Vital*): government administration, energy & mineral resources,
transportation, finance, health, ICT, food, and defence.

The rules (`app/processing/sectors.py`, in English and Bahasa Indonesia) look for the organisations and services
of each sector as targets or affected parties: *rumah sakit* and hospitals, banks and e-wallets, airlines and
*bandara*, telecom operators and data centres, ministries, *pemda* and `.go.id` sites, refineries and PLN, the
military and TNI.

A sector counts when the title names it or the body names it at least twice. Newsletters and round-ups only count
their title, and look-alikes are excluded (MITRE's *defense evasion*, the hacktivist *IT Army*). A sector stated by
the feed (the ransomware.live victim sector, OTX industries) counts on its own. An item gets at most three
sectors.

Sectors are entities like any other (of type `sector`). They appear as chips, filter the feed (click a bar in a
*Critical infrastructure sectors* chart) and the scam report list, and are exported as `sectors` in the REST API.
They carry almost no weight in correlation. When the rules change, stored items are re-tagged once;
`python manage.py sectortag` does it by hand.

## Vulnerability context

Every six hours, the CVEs mentioned in the last 30 days are looked up in the CISA Known Exploited Vulnerabilities
catalogue, FIRST EPSS and the NVD (CVSS score, vector and description). None of these needs a key; an optional
NVD key just makes the CVSS lookups faster.

Trending CVEs are ranked by exploitation risk as well as by how much they are discussed:
trend score × 2 if in KEV × (1 + EPSS) × (0.5 + CVSS/10). The CVE list can be sorted by CVSS or EPSS.

CVSS rates how much damage a flaw allows if it is exploited (0 to 10). EPSS is the probability that it will be
exploited in the wild within the next 30 days. Hovering over either column header shows the same explanation.

## A note on severity

The severity score is a triage aid, not a vulnerability rating. The item page shows how each score was built.
Enrichment raises it when an indicator is confirmed malicious (and lowers it again if that verdict is later
withdrawn), the AI can raise it by a limited amount during analysis, and an analyst's correction re-scores the
item from the entities that remain.
