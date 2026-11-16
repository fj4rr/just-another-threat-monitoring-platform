# Analysis

[← Documentation index](README.md)

How JATMP turns collected items into entities, scores, verdicts, correlations and trends.

## Entity extraction

Each item is scanned for malware families (about 150 families plus aliases), threat actors
(about 45), CVEs, ATT&CK techniques and indicators (IPs, domains, URLs, MD5/SHA1/SHA256). Defanged indicators
are understood in their common forms (`hxxp`, `[.]`, `[:]`, `[://]`, `\.`, `(dot)`). Families that are not in
the knowledge base yet are picked up from phrases such as "PipeMagic backdoor", while legitimate tools that
attackers abuse (ConnectWise, AnyDesk, PsExec and others) are never promoted to families. Hashes that are part
of a URL, version numbers that look like IP addresses and roughly 200 vendor, media and platform domains are
ignored.

## Severity

Every item receives an explainable score from 0 to 100. Signals are grouped (exploitation,
impact, threat class, activity) so that synonyms are not counted twice; the strongest term in a group counts in
full and the runner-up at half weight. Matches in the title weigh 1.5 times more than matches in the body.
Patch notes, roundups and guides, and routine leak-site victim postings are damped, and an indicator that is
later confirmed malicious raises the score of the items that mention it. The item page shows the full
breakdown.

## Cross-source enrichment

Indicators found in news and social posts are looked up on VirusTotal, OTX,
urlscan, ANY.RUN, MalwareBazaar (hashes), URLhaus (URLs, hosts, payloads), GreyNoise and AbuseIPDB (IPs),
whichever have keys. The verdicts are combined into a consensus: any provider reporting *malicious* wins,
infrastructure that OTX whitelists is marked clean, and a lone OTX pulse mention is treated as suspicious rather
than malicious. GreyNoise works as a false-positive filter: an IP it knows as a benign business service or
benign scanner is marked clean unless a strong provider (VirusTotal, abuse.ch, ANY.RUN) says otherwise, and
mass scanners get a "mass scanner" badge (opportunistic, not targeted). Lookups that failed are retried after six hours, *unknown* results are re-checked after three
days, and families attributed by a provider (a hash on Bluesky identified as Lumma Stealer, for example) are
linked back so the indicator connects to the articles about that family. Indicators for trending families are
pulled from OTX and ANY.RUN, accepting only pulses that actually name the family.

## Relationship graph

Item and entity pages draw an interactive graph: the item, its entities, what
enrichment linked them to (a hash to its family, an indicator pulled from OTX) and other items that share them.
Nodes are coloured by type and by verdict; click one to preview it, double-click to open it, drag, zoom, and use
the keyboard (Tab, Enter, O). It is drawn by a small built-in SVG renderer, not a third-party library, and capped
at 60 nodes with a "Show more" step up to 150.

## Infrastructure context, on demand

"Context lookup" on an IP, domain or hash asks Shodan (open ports,
hostnames, known CVEs), Censys (services, ASN), CrowdSec CTI (reputation, behaviours), Pulsedive (risk, threats),
Hybrid Analysis (sandbox verdict and family) and IPinfo (ASN and country, kept for the geography features), as
far as keys are configured. Free tiers are small, so these never run in the background batch unless "run context
lookups when an indicator turns malicious" is switched on; Shodan InternetDB and IPinfo can be used without a key
once keyless lookups are allowed.

## Correlation

The item page ranks related items by the strength of the evidence they share: a common hash,
URL or domain weighs far more than a common CVE, rare entities more than frequently mentioned ones, and items
from another source or source type receive a bonus. Entity pages show coverage per source, co-occurring
entities, related indicators and enrichment results.

## Trends

The dashboard scores each family by its recent mention rate against a 30-day baseline, weighted by
how many sources and source types cover it, and shows the result as a radar, timelines and tables. The same
score drives the *Trending CVEs* and *Trending threat actors* widgets, which also list the families, actors
and CVEs mentioned alongside each entry.

## Vulnerability context

Every six hours, CVEs mentioned in the last 30 days are looked up in the CISA Known
Exploited Vulnerabilities catalog, FIRST EPSS and the NVD (CVSS score, vector and description). None of these
needs a key; an optional NVD key only makes the CVSS lookups faster. Trending CVEs are ranked by exploitation
risk as well as chatter (trend score × 2 when in KEV × (1 + EPSS) × (0.5 + CVSS/10)), and the CVE list can be
sorted by CVSS or EPSS.

## A note on severity

The severity score is a triage heuristic, not a vulnerability rating. The item page shows how a score was
built, enrichment raises it when an indicator is confirmed malicious, and the LLM can raise it during
analysis.
