# Ingest and analysis

[← How JATMP works](index.md)

What happens to each entry a collector returns, from "is it new?" to a stored, scored, linked and geo-tagged item.
All of it happens inside the collection run, in one database transaction per batch (`pipeline.ingest_committed`),
so an item never appears half-analysed.

## The ten steps

For every `RawItem` in a batch, `pipeline.ingest()` runs these steps in this order:

| # | Step | Result stored on the item | Code |
|---|---|---|---|
| 1 | [Skip known entries](#1-new-or-already-stored) | — | `ingest` |
| 2 | [Clean and limit](#2-cleaning-and-limits) | `title`, `content`, `url`, `tags`, `raw`, `tlp`, `published_at` | `strip_html`, `safe_url`, `_slim_raw` |
| 3 | [Cross-source duplicates](#3-cross-source-duplicates) | `fingerprint`, `dup_of` | `fingerprint`, `find_original` |
| 4 | [Entity extraction](#4-entity-extraction) | (entities, linked in step 8) | `extractor.extract_all`, `tag_families` |
| 5 | [Severity](#5-severity) | `severity`, `severity_detail` | `severity.score_item` |
| 6 | [Scam and fraud analysis](#6-scam-and-fraud-analysis) | `fraud_score`, `fraud_detail`, `fraud_loss_idr`, `fraud_victims` | `fraud.apply` |
| 7 | [Critical infrastructure sectors](#7-critical-infrastructure-sectors) | (sector entities) | `sectors.apply` |
| 8 | [Link entities](#8-linking-entities) | `item_entities` rows; entity counters | `link_entities` |
| 9 | [Blocklist verdicts](#9-blocklist-verdicts) | `enrichments` rows, entity `verdict` | `mark_listed` |
| 10 | [Geography](#10-geography) | `lang`, `src_country`, `item_geo` rows | `geo.tag_item` |

The order matters in two places:

- **Severity (5) is scored before the fraud and sector entities (6, 7) exist.** Scam types, brands, identifiers
  and sectors never add severity points; a scam report gets its own fraud score instead. The two scores are
  deliberately independent.
- **Sectors (7) run after fraud (6)** because a scam report about a bank is usually not an attack on the finance
  sector (see the rule below).

After the batch, the transaction is committed and the trending cache is cleared. If another run stored one of the
same entries in the meantime (a scheduled run and a backfill of the same source, for instance), the unique
constraint on (source, external id) fires; the batch is rolled back and retried, up to three times, and the retry
skips what the other run stored.

## 1. New or already stored?

The dedup key is **(source, external id)**. The external id is the provider's id of the entry (RSS GUID, post URI,
pulse id), falling back to the URL and then the title. Ids longer than 500 characters (URLs with tracking
parameters) keep their first 434 characters plus `#sha256:<hash of the whole id>`, so two long ids that only
differ at the end never collide.

All ids of the batch are checked with one query per 500 ids. An id that repeats inside the same batch is stored
once.

The same story published by **another** source is not a duplicate at this step; it is stored, and step 3 decides
whether it is a copy.

## 2. Cleaning and limits

Feed content is untrusted input. Before anything else looks at it:

| Field | Treatment |
|---|---|
| `content` | For `article`s: `<script>` and `<style>` blocks and all tags removed, HTML entities decoded, stylesheet rules printed into the text by some blog plugins removed, whitespace collapsed. Posts, pulses and scans are already text. Cut at **50,000** characters |
| `url` | Kept only if it starts with `http://` or `https://` and contains no line breaks (so a `javascript:` link can never reach a page). Max 2,000 characters |
| `title`, `author` | Cut at 1,000 and 250 characters |
| `tags` | At most 50, each at most 80 characters |
| `published_at` | The provider's date; missing → now; **in the future → now** (clocks drift and some feeds post-date entries) |
| `raw` | Provider metadata kept small: string values longer than 2,000 characters, or equal to the content, are dropped |
| `tlp` | The entry's own TLP if the feed gives one (OTX, MISP), normalised to CLEAR / GREEN / AMBER / RED |
| `origin` | `live` for scheduled and manual collection, `backfill` for history |

The cleaning patterns are written to run in linear time on hostile input: every article passes through them, and
a regular expression that backtracks would hold a scheduler thread that cannot be killed.

## 3. Cross-source duplicates

News is syndicated: the same wire story appears on five Indonesian portals within hours. Counting it five times
would make anything in it look like it is trending. So every **article** gets a fingerprint:

1. Take the title and remove an outlet suffix such as " - ANTARA News" or " | Republika Online".
2. Lower-case it and keep only the words.
3. If the title has fewer than 5 words ("Weekly update"), add up to 30 words from the first 400 characters of the
   text.
4. Fewer than 6 words in total → no fingerprint (too little to compare).
5. Otherwise hash the words (BLAKE2b).

Then JATMP looks for an article from **another source** with the same fingerprint published within **4 days**
before or after. If there is one, the new item becomes a copy: `dup_of` points at the **original** (the earliest,
and never at another copy). Items in the same batch are checked against each other as well.

Copies are stored like any other item. The feed hides them unless *Show copies* is ticked (the page says how
many it left out), a *copy* badge marks them where they are listed, and the item page and preview say
"Copy of *original*" on a copy and "Also carried by *N* other outlets" on the original. Trend scores, the scam
*spreading* check and the AI executive summary count `coalesce(dup_of, id)`, so the story counts once there; item
counts on the dashboard tiles and charts include copies (see
[Counting rules](trends.md#counting-rules)). Posts, pulses and scans are not fingerprinted.

## 4. Entity extraction

The text that is scanned is `title + content + tags`. Extraction has four parts.

### Indicators, CVEs and techniques (`origin = regex`)

First the text is **refanged**: `hxxp(s)` → `http(s)`, `fxp` → `ftp`, `[.]` `(.)` `{.}` `[dot]` `(dot)` `\.` →
`.`, `[:]` → `:`, `[://]` → `://`, `[/]` → `/`, `[at]` → `@`.

| Type | Pattern | Rejected when |
|---|---|---|
| `cve` | `CVE-YYYY-NNNN…` | — |
| `technique` | `T1xxx` or `T1xxx.yyy` | — |
| `sha256`, `sha1`, `md5` | 64 / 40 / 32 hex characters | It is part of a longer hash already found; it has fewer than 6 distinct characters (`000000…`); it sits in a URL path or parameter (preceded by `/ = # - _` or followed by `/ - _`); an MD5 / SHA-1 sits in a token with `utm_`, `token=`, `session`, `/commit/`, `/blob/`… |
| `ip` | IPv4 | Not a public address (private, loopback, reserved, multicast, link-local); preceded by *version, build, release, firmware, v, Chrome, Windows, kernel…* (a version number); followed by `.digit` (`1.2.3.4.5`); preceded by `.` |
| `url` | `http(s)://…` | Its host is a benign domain; in strict mode, it was not written defanged |
| `domain` | host names with a 2–24 letter TLD | It is benign (or a parent of it is); its "TLD" is a file extension (`.exe`, `.zip`, `.php`, `.json`…); it is an IP; in strict mode, it was neither defanged nor the host of a kept URL |

**Strict mode.** News and social sources (every category except `intel`) are read in strict mode: a domain or
URL only counts when the author **defanged** it (or it is the host of a defanged URL). Ordinary links in prose —
the vendor's blog, a reference — are almost never indicators, while a researcher who writes `evil[.]com` means
it. Intel sources are read without strict mode, because everything they publish is meant as an indicator. IPs and
hashes are taken in both modes.

**Benign domains.** About 200 domains are never indicators: platforms, search, social networks, link shorteners,
security media and vendors, standards bodies and Indonesian media, banks and government sites (for example
`bleepingcomputer.com`, `cisa.gov`, `t.me`, `detik.com`, `bssn.go.id`). A subdomain of a benign domain is benign too.

### Known families and actors (`origin = kb`)

The knowledge base (`app/knowledge.py`, plus your additions in `data/knowledge_extra.json`) holds about 150
malware families and 45 threat actors with their aliases, compiled into word-boundary patterns. Every match
becomes an entity with the canonical name and the family's category (ransomware, stealer, loader…). Names that are
everyday words or four letters or shorter ("Play", "Fog", "Hook", "Conti") only count next to a qualifier: "Play
ransomware", "the Fog group", "malware called Hook". Ambiguous actor names likewise need a qualifier such as
*APT*, *group* or *threat actor* within two words ("Bitter APT").

### New family names (`origin = heuristic`)

Families that are not in the knowledge base yet are what matters most for spotting new campaigns, so the
extractor also looks for **a name next to a malware noun**:

- English: "*Zorblax* ransomware", "the *PipeMagic* backdoor" (nouns: ransomware, infostealer, stealer, loader,
  botnet, backdoor, trojan, wiper, rootkit, malware, spyware, dropper, keylogger, RAT).
- Indonesian word order (run when the text is Indonesian or the language is unclear): "ransomware *Brain Cipher*",
  "malware bernama *Lumma*", "trojan perbankan *Mamont*".

Precision rules, all of which must pass:

1. A single token (multi-word families belong in the knowledge base); no hyphen.
2. In a title-case headline ("WhiteArmor Ransomware Demands…") the name must be CamelCase or mix letters and
   digits; in prose, a capitalised word is enough unless it starts the sentence.
3. Not a generic word (*new, Android, Russian, sophisticated, AI…*), a legitimate tool that attackers abuse
   (*AnyDesk, ConnectWise, PsExec, Mimikatz…*), a platform (*Facebook, Telegram, Shopee…*), a country or
   demonym, or a short all-caps acronym.
4. Not a name already found in the same text.

A name that turns out to be a known alias is mapped to the knowledge-base family instead. A heuristic family
**scores less** than a known one (6 severity points instead of 10) and only **trends once two sources name it**.

### What the feed delivers (`origin = feed`)

- **Structured indicators** a collector attaches (OTX pulse indicators, urlscan scan URLs, ThreatFox IOCs, MISP
  attributes, ScamSniffer domains) are added as they are.
- **Tags of intel sources** that name a known family (OTX `malware_families`, ThreatFox family names) become
  family entities. Tags of news and social sources are free-form and ignored here; a tag of 3 characters or less
  or an everyday word is never a family.

All findings are then de-duplicated by (type, value).

## 5. Severity

The text and the entities from step 4 give the item its 0–100 severity and the list of reasons shown on the item
page. The rules, weights and dampeners are on their own page: [Severity scoring](scoring.md).

## 6. Scam and fraud analysis

The same text is read a second time as a possible scam report: scam types, impersonated brands, reported losses
and victims, scammer identifiers (only from items that are about a scam, and only where the sentence marks them
as the scammer's), and the fraud score. **A fraud score above 0 is the definition of a scam report** everywhere
in JATMP. The scam type counts for "spreading" are computed once per scam type and day for the whole batch.
Rules and points: [Scams and fraud](../fraud.md).

## 7. Critical infrastructure sectors

Each sector (government administration, energy & mineral resources, transportation, finance, health, ICT, food,
defence; Perpres 82/2022) has an English and Indonesian vocabulary of the organisations and services in it. Points
per sector:

| Signal | Points |
|---|---|
| Each match in the title | 2 |
| Each match in the body (first 20,000 characters) | 1, at most 4 per sector |
| The feed states the sector (ransomware.live victim sector, OTX industries) | 3 |

A sector is tagged when it reaches **2 points**, with these exceptions:

- **A title word alone** (no body match, not from the feed) needs 3 points, unless the title names exactly one
  sector and describes an attack on it ("Serangan ransomware lumpuhkan layanan rumah sakit"). "Hospital food
  vendor hit by phishing" is not a health-sector item.
- **Scam reports and finance.** When the item is a scam report, *finance* only counts if the feed says so or the
  text describes an attack (breach, hack, *dibobol*, leak…). Most scams mention a bank as the payment channel.
- **Round-ups and newsletters** are judged on their title only.

At most **3** sectors per item, strongest first. Sectors are entities of type `sector` with origin `kb`.

## 8. Linking entities

All findings of steps 4, 6 and 7 are linked to the item:

1. The existing entities are looked up with **one query per entity type** (per 500 values); the missing ones are
   created in one flush. A blocklist item with 500 domains costs two queries, not 500.
2. A new IP entity gets its **hosting country** from the offline GeoIP database right away, when one is
   installed.
3. One `item_entities` row per entity, with the origin of the finding (`regex`, `kb`, `heuristic`, `feed`).
4. The entity's `mention_count` goes up by one; `first_seen` / `last_seen` move to the item's **publication**
   date if it is earlier / later (so a backfill can move `first_seen` back in time); a missing category is filled
   in.

## 9. Blocklist verdicts

Some sources are curated blocklists: everything on them is malicious by definition (ScamSniffer's drainer
domains). Their items carry `listed_by` in `raw`. For those, every structured indicator gets an enrichment row
from that "provider" with verdict `malicious`, and indicators that were never enriched get the verdict
`malicious` at once. They skip the enrichment queue and spend no provider quota.

## 10. Geography

### Language and source country

The language is decided by counting common words in the first 4,000 characters: with at least 6 words, it is
`id` when there are at least 3 Indonesian stop words and 20% more than English ones, `en` when there are at least
3 English stop words and no fewer than Indonesian ones, else empty (and then the source's configured language is
used). The **source country** is the source's configured country, or Indonesia for an Indonesian-language item.

### Target countries and provinces

Target countries are where the victims are or the activity takes place. Points per country:

| Signal | Points |
|---|---|
| Country name in the title | 2 |
| Country name in the body | 1 for the first mention, 0.5 for the 2nd to 5th, then nothing |
| … when it is a demonym ("Indonesian", "Russian") | × 0.75 |
| … with a target cue in front ("against", "in", "targeting", "di", "menyerang"…) | × 1.5 |
| Indonesian province, city, regency or institution (BSSN, OJK, Pertamina…) | Indonesia +3 in the title, +2 in the body; the province +2 / +1 |
| Ambiguous Indonesian place after *Kota*, *Kabupaten*, *Pemkot*… ("Kota Malang") | as above |
| Weak Indonesian acronyms (BCA, KPU…) | Only counted in Indonesian text, or when Indonesia already has 1.5 points |
| `.go.id`, `.co.id`, `.ac.id` domains in the text | Indonesia +2 each, at most +4 |
| Leak-site postings in the form `victim.com (GB)` | That country +3 |
| Countries the feed states (ransomware.live victim country, OTX targeted countries) | +10 each |

A country is a target with **1.5 points or more** (feed countries always), at most **4** per item; provinces need
1 point, at most 4, and only when Indonesia is a target.

**Attackers are not targets.** A country named as the actor's origin is set aside: "Russian hackers",
"China-nexus", "Iran-linked", "attributed to North Korea", "peretas asal Rusia". "Latin America" is not the US.
Names that only make sense in Indonesian text are ignored elsewhere. An ALL-CAPS headline is title-cased first so
proper nouns are recognised.

Each target is stored as an `item_geo` row (country, province if any, score, origin `text` or `feed`). The
*hosting* country of IP indicators is a different relation, stored on the entity (GeoIP at creation, providers at
enrichment) and never counted as a target.

### The National (Indonesia) view

The *National (ID)* switch keeps the items that **target Indonesia**, plus items from **Indonesian outlets that
name no other target country**. Everything else is international. The same condition is applied by every list,
chart, statistic, report and the IOC table.
