# Ingest and analysis

[← How JATMP works](index.md)

This page follows each entry a collector returns, from the question "have we seen this before?" to a stored item
that is scored, linked to its entities and tagged with its geography. All of it happens inside the collection run,
in one database transaction per batch (`pipeline.ingest_committed`), so you never see an item that is only half
analysed.

The entries arrive here already filtered: if the source has a topic filter, the entries it dropped never reach the
pipeline (see [Topic filters](collection.md#topic-filters)). Analysts' corrections are respected throughout, so a
link an analyst removed or an item marked *not a scam report* stays that way (see
[Corrections and quality](corrections.md#why-a-correction-sticks)).

## The ten steps

For every entry in a batch, `pipeline.ingest()` runs these steps in order:

| # | Step | What it stores on the item | Code |
|---|---|---|---|
| 1 | [Skip entries already stored](#1-new-or-already-stored) | — | `ingest` |
| 2 | [Clean the text and apply limits](#2-cleaning-and-limits) | Title, text, link, tags, provider data, TLP, publication date | `strip_html`, `safe_url`, `_slim_raw` |
| 3 | [Spot copies from other outlets](#3-cross-source-duplicates) | Fingerprint, and which item it copies | `fingerprint`, `find_original` |
| 4 | [Extract entities](#4-entity-extraction) | (the entities, linked in step 8) | `extractor.extract_all`, `tag_families` |
| 5 | [Score severity](#5-severity) | Severity and its reasons | `severity.score_item` |
| 6 | [Analyse for scams and fraud](#6-scam-and-fraud-analysis) | Fraud score, reasons, losses, victims | `fraud.apply` |
| 7 | [Tag critical infrastructure sectors](#7-critical-infrastructure-sectors) | (sector entities) | `sectors.apply` |
| 8 | [Link the entities](#8-linking-entities) | One link per entity; entity counters | `link_entities` |
| 9 | [Record blocklist verdicts](#9-blocklist-verdicts) | Enrichment records and verdicts | `mark_listed` |
| 10 | [Work out the geography](#10-geography) | Language, source country, target countries and provinces | `geo.tag_item` |

The order matters in two places:

- **Severity (step 5) is scored before the fraud and sector entities exist (steps 6 and 7).** Scam types,
  brands, scammer identifiers and sectors therefore never add severity points. A scam report gets its own fraud
  score instead, and the two scores stay independent on purpose.
- **Sectors (step 7) come after fraud (step 6),** because a scam that mentions a bank is usually not an attack on
  the finance sector (see the rule below).

Once the whole batch is processed, the transaction is committed and the trend cache is cleared. Occasionally
another run stores one of the same entries at the same moment (a scheduled run and a backfill of the same
source, for example). The database's uniqueness check then fails, so JATMP rolls the batch back and tries again,
up to three times, skipping whatever the other run already stored.

## 1. New or already stored?

An entry is identified by its **source and external id**. The external id is the provider's own id for the entry
(an RSS GUID, a post URI, a pulse id), or failing that its URL, or failing that its title. Ids longer than 500
characters (URLs with tracking parameters, typically) keep their first 434 characters followed by
`#sha256:<hash of the whole id>`, so two long ids that only differ at the end never get mixed up.

The ids of a whole batch are checked with one database query per 500 ids. If the same id appears twice in one
batch, it is stored once.

**Entries that grow.** ThreatFox is a special case: it delivers one entry per malware family and day, and new
IOCs for that day keep arriving. When such an entry is already stored, its new indicators are added to the
existing item, its title is updated with the new count, and it is scored again (keeping any enrichment bonus and
AI assessment). Every other kind of known entry is simply skipped.

The same story published by **another** source is not a duplicate at this step. It is stored, and step 3 decides
whether it is a copy.

## 2. Cleaning and limits

Feed content comes from outside, so it is treated as untrusted. Before anything else reads it:

| Field | What happens |
|---|---|
| Text | For articles, `<script>` and `<style>` blocks and all HTML tags are removed, HTML entities are decoded, stylesheet rules that some blog plugins print into the text are removed, and whitespace is tidied up. Posts, pulses and scans are already plain text. The text is cut at **50,000** characters |
| Link | Only kept if it starts with `http://` or `https://` and contains no line breaks, so a `javascript:` link can never reach a page. Up to 2,000 characters |
| Title, author | Cut at 1,000 and 250 characters |
| Tags | At most 50, each up to 80 characters |
| Publication date | Taken from the provider. If it is missing, JATMP uses the current time. If it is **in the future**, JATMP also uses the current time (clocks drift, and some feeds post-date entries) |
| Provider data | Kept small: text values over 2,000 characters, or identical to the item's text, are dropped |
| TLP | The entry's own TLP if the feed gives one (OTX, MISP), normalised to CLEAR, GREEN, AMBER or RED |
| Origin | `live` for scheduled and manual collection, `backfill` for history |

The cleaning patterns are written to run in linear time, even on hostile input. Every article passes through
them, and a pattern that got stuck backtracking would tie up a scheduler thread that can't be stopped.

## 3. Cross-source duplicates

News gets syndicated: the same wire story can appear on five Indonesian news sites within a few hours. If each
copy counted separately, everything in that story would look as if it were trending. So JATMP gives every
**article** a fingerprint:

1. Take the title and remove an outlet suffix such as " - ANTARA News" or " | Republika Online".
2. Lower-case it and keep only the words.
3. If the title has fewer than 5 words (for example "Weekly update"), add up to 30 words from the first 400
   characters of the text.
4. If there are still fewer than 6 words, give up: there is too little to compare.
5. Otherwise, hash the words.

JATMP then looks for an article from **another source** with the same fingerprint, published within **4 days**
before or after this one. If it finds one, the new item becomes a **copy** that points to the **original**: the
earliest item, never another copy, and never the item itself. Items in the same batch are compared with each other
as well.

Copies are stored like any other item, and you can see them in the interface:

- The feed lists each story once and says how many copies it hid; tick *Show copies* to list them, marked with a
  *copy* badge.
- The item page and the preview say "Copy of *original*" on a copy, and "Also carried by *N* other outlets" on
  the original.

Every count of stories (the dashboards, trend scores, the scam *spreading* check, the executive summary and the
reports) counts a story and its copies **once**. Only per-outlet figures, such as *Items per source*, count each
copy for the outlet that published it. See [Counting rules](trends.md#counting-rules). Posts, pulses and scans
are not fingerprinted.

## 4. Entity extraction

JATMP scans the title, the text and the tags together. Extraction has four parts.

### Indicators, CVEs and techniques (origin `regex`)

First, the text is **refanged**: the usual ways of writing indicators safely are turned back into the real
thing. `hxxp(s)` becomes `http(s)`, `fxp` becomes `ftp`, `[.]` `(.)` `{.}` `[dot]` `(dot)` and `\.` become `.`,
`[:]` becomes `:`, `[://]` becomes `://`, `[/]` becomes `/`, and `[at]` becomes `@`.

| Type | Pattern | Rejected when |
|---|---|---|
| `cve` | `CVE-YYYY-NNNN…` | — |
| `technique` | `T1xxx` or `T1xxx.yyy` | — |
| `sha256`, `sha1`, `md5` | 64, 40 or 32 hex characters | It is part of a longer hash that was already found; it has fewer than 6 different characters (`000000…`); it sits inside a URL (right after `/ = # - _` or right before `/ - _`); or an MD5 / SHA-1 sits in a token containing `utm_`, `token=`, `session`, `/commit/`, `/blob/` and the like |
| `ip` | IPv4 address | It isn't public (private, loopback, reserved, multicast, link-local); it is a well-known public DNS resolver (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`…); it follows the word *version, build, release, firmware, v, Chrome, Windows, kernel* and the like (so it is really a version number; "server 91.92.243.10" is not); it is followed by `.digit` (as in `1.2.3.4.5`); or it comes right after a `.` |
| `url` | `http(s)://…` | Its host is a benign domain; it is just the front page of a paste or file-sharing service; or, in strict mode, it wasn't written defanged |
| `domain` | Host names with a 2–24 letter top-level domain | It, or a domain above it, is benign; its "top-level domain" is really a file extension (`.exe`, `.zip`, `.php`, `.json`…); it is an IP; or, in strict mode, it was neither defanged nor the host of a URL that was kept |

**Strict mode.** News and social sources (every category except `intel`) are read in strict mode, where a domain
or URL only counts if the author **defanged** it (or it is the host of a defanged URL). Ordinary links in an
article, such as the vendor's blog or a reference, are almost never indicators. When a researcher writes
`evil[.]com`, on the other hand, they mean it. Intel sources are read without strict mode, because everything
they publish is meant as an indicator. IPs and hashes are picked up in both modes.

**Benign domains.** About 200 domains are never treated as indicators: platforms, search engines, social
networks, link shorteners, security media and vendors, standards bodies, and Indonesian media, banks and
government sites (for example `bleepingcomputer.com`, `cisa.gov`, `t.me`, `detik.com`, `bssn.go.id`). Their
subdomains are benign too.

**Abused hosting services.** Paste, file-sharing and code-hosting services (Pastebin, GitHub and its raw content,
Google Drive, Dropbox, MEGA, Discord's CDN, transfer.sh and about 20 more) are legitimate, so their domain is never
an indicator. A URL on them that points somewhere (a paste, a release asset, a shared file) is one: in an item that
quotes `hxxps://pastebin[.]com/raw/abcd1234`, the URL is kept and `pastebin.com` is not.

### Known families and actors (origin `kb`)

The knowledge base (`app/knowledge.py`, plus any additions you make in `data/knowledge_extra.json`) holds about
150 malware families and 45 threat actors, with their aliases. Every match becomes an entity with the official
name and the family's category (ransomware, stealer, loader and so on).

Some names are also everyday words, or are four letters or shorter ("Play", "Fog", "Hook", "Conti"). These only
count next to a qualifier: "Play ransomware", "the Fog group", "malware called Hook". The exception is a name
written in its own distinctive spelling, with a capital in the middle or a digit inside the word ("RedLine",
"Cl0p", "SafePay"): that spelling is no everyday word, so it counts on its own, while "redline" or "Safepay
checkout" still don't. Ambiguous actor names likewise need a word such as *APT*, *group* or *threat actor* within
two words of the name ("Bitter APT").

### New family names (origin `heuristic`)

Families that aren't in the knowledge base yet are exactly the ones that matter for spotting new campaigns. So
the extractor also looks for **a name right next to a malware noun**:

- In English: "*Zorblax* ransomware", "the *PipeMagic* backdoor". The nouns are ransomware, infostealer,
  stealer, loader, botnet, backdoor, trojan, wiper, rootkit, malware, spyware, dropper, keylogger and RAT.
- In Indonesian, where the noun comes first: "ransomware *Brain Cipher*", "malware bernama *Lumma*", "trojan
  perbankan *Mamont*". These patterns run when the text is in Indonesian or its language is unclear.

To keep false positives down, a candidate must pass every one of these checks:

1. It is a single word, without a hyphen. (Multi-word family names belong in the knowledge base.)
2. In a headline written in title case ("WhiteArmor Ransomware Demands…"), the name must be CamelCase or mix
   letters and digits. In ordinary sentences, a capitalised word is enough, unless it starts the sentence.
3. It isn't a generic word (*new, Android, Russian, sophisticated, AI…*), a legitimate tool that attackers misuse
   (*AnyDesk, ConnectWise, PsExec, Mimikatz…*), a platform (*Facebook, Telegram, Shopee…*), a country or
   nationality, or a short all-capitals acronym.
4. It wasn't already found in the same text.

If the name turns out to be a known alias, it is mapped to the knowledge-base family instead. A heuristic
family **scores less** than a known one (6 severity points instead of 10), and it only **trends once two sources
name it**.

### What the feed delivers (origin `feed`)

- **Structured indicators** that a collector attaches (OTX pulse indicators, urlscan scan URLs, ThreatFox IOCs,
  MISP attributes, ScamSniffer domains) are added exactly as delivered.
- **Tags on intel sources** that name a known family (OTX's malware families, ThreatFox family names) become
  family entities. Tags on news and social sources are free-form and are ignored here. A tag of three
  characters or fewer, or an everyday word, is never treated as a family.

Finally, all findings are de-duplicated by type and value.

## 5. Severity

The text and the entities from step 4 give the item its severity from 0 to 100, along with the list of reasons
shown on the item page. The rules, weights and dampeners have their own page: [Severity scoring](scoring.md).

## 6. Scam and fraud analysis

The same text is then read a second time, as a possible scam report. JATMP looks for scam types, impersonated
brands, reported losses and victims, and scammer identifiers. Identifiers are only taken from items that are
about a scam, and only where the sentence makes clear they belong to the scammer. The result is the fraud score.
**A fraud score above 0 is what makes an item a scam report**, everywhere in JATMP. To keep this fast, the
"spreading" counts for each scam type are worked out once per scam type and day for the whole batch.
If an analyst has marked the item *not a scam report*, the analysis is skipped and the fraud score stays 0, also
when the scam rules change and stored items are re-analysed. The rules and points are on
[Scams and fraud](../fraud.md).

## 7. Critical infrastructure sectors

Each sector defined by Perpres 82/2022 (government administration, energy & mineral resources, transportation,
finance, health, ICT, food, defence) has an English and Indonesian vocabulary describing the organisations and
services in it. Each sector collects points:

| Signal | Points |
|---|---|
| Each match in the title | 2 |
| Each match in the body (first 20,000 characters) | 1, up to 4 per sector |
| The feed states the sector (ransomware.live victim sector, OTX industries) | 3 |

A sector is tagged when it reaches **2 points**, with three exceptions:

- **One word in the title, and nothing else.** If there is no match in the body and the feed doesn't state the
  sector, a title word needs 3 points, unless the title names exactly one sector and describes an attack on it
  ("Serangan ransomware lumpuhkan layanan rumah sakit"). "Hospital food vendor hit by phishing" is therefore not
  a health-sector item.
- **Scams and finance.** For a scam report, *finance* only counts if the feed says so or the text describes an
  attack (a breach, a hack, *dibobol*, a leak and so on). Most scams only mention a bank as the way money was
  paid.
- **Round-ups and newsletters** are judged on their title alone.

An item gets at most **3** sectors, strongest first. Sectors are stored as entities of type `sector`.

## 8. Linking entities

Everything found in steps 4, 6 and 7 is now linked to the item:

1. Existing entities are looked up with **one query per entity type** (per 500 values), and the missing ones are
   created together. A blocklist item with 500 domains therefore costs two queries, not 500.
2. A new IP gets its **hosting country** from the offline GeoIP database straight away, if one is installed.
3. Each entity gets one link to the item, recording how it was found (`regex`, `kb`, `heuristic`, `feed`).
   Links that an analyst removed are skipped: the entity on this item for *wrong entity here*, and on every item
   for *wrong entity everywhere* or *not a threat*. The same check applies when entities are re-extracted, added
   by the AI or merged into a ThreatFox item.
4. The entity's mention count goes up by one. Its first-seen and last-seen dates move to the item's
   **publication** date if that is earlier or later (so a backfill can move first-seen back in time). If the
   entity had no category yet, it gets one.

## 9. Blocklist verdicts

Some sources are curated blocklists, where everything listed is malicious by definition (ScamSniffer's
wallet-drainer domains, for example). Their items carry a "listed by" marker. Every structured indicator on such
an item gets an enrichment record from that list with the verdict `malicious`, and indicators that were never
looked up get the verdict `malicious` straight away. They skip the enrichment queue and use no provider quota.
When the list names an indicator again on a later day, its verdict date is refreshed, so the verdict doesn't
age (see [Verdicts that age](enrichment.md#verdicts-that-age)).

## 10. Geography

### Language and source country

The language is decided by counting common words in the first 4,000 characters. With at least 6 words, the text
is `id` (Indonesian) if it has at least 3 Indonesian common words and 20% more of them than English ones, and
`en` if it has at least 3 English common words and no fewer than Indonesian ones. Otherwise the language is left
empty and the source's configured language is used instead.

The **source country** is the country configured for the source, or Indonesia for an item written in Indonesian.

### Target countries and provinces

Target countries are where the victims are or where the activity takes place. Each country collects points:

| Signal | Points |
|---|---|
| The country's name in the title | 2 |
| The country's name in the body | 1 for the first mention, 0.5 for the 2nd to 5th, then nothing |
| … when it is a nationality ("Indonesian", "Russian") | × 0.75 |
| … when a target word comes right before it ("against", "in", "targeting", "di", "menyerang"…) | × 1.5 |
| An Indonesian province, city, regency or institution (BSSN, OJK, Pertamina…) | Indonesia gets +3 in the title or +2 in the body; the province gets +2 or +1 |
| An ambiguous Indonesian place name after *Kota*, *Kabupaten*, *Pemkot* and the like ("Kota Malang") | As above |
| Weak Indonesian acronyms (BCA, KPU…) | Only count in Indonesian text, or when Indonesia already has 1.5 points |
| `.go.id`, `.co.id` and `.ac.id` domains in the text | Indonesia gets +2 for each, up to +4 |
| Leak-site postings in the form `victim.com (GB)` | That country gets +3 |
| Countries stated by the feed (ransomware.live victim country, OTX targeted countries) | +10 each |

A country becomes a target with **1.5 points or more** (countries stated by the feed always qualify), up to **4**
per item. Provinces need 1 point, up to 4, and only count when Indonesia is a target.

**Attackers are not targets.** When a country is named as the origin of the attacker, it is set aside: "Russian
hackers", "China-nexus", "Iran-linked", "attributed to North Korea", "peretas asal Rusia". Neither are the places
where criminals trade or servers sit (0.13.1): "sold on Russian forums", "Chinese-language marketplaces", "hosted in
the Netherlands", "a Dutch hosting provider", "server di Singapura". Likewise, "Latin America" doesn't mean the US. Names that only make sense in Indonesian text are ignored elsewhere, and a headline
written in capitals is converted to title case first so that names can be recognised.

Each target is stored with its country, its province if any, its score, and whether it came from the text or the
feed. The *hosting* country of an IP is a different thing. It is stored on the indicator itself (from GeoIP when
the indicator is created, and from the providers during enrichment) and never counts as a target.

### The National (Indonesia) view

The *National (ID)* switch keeps the items that **target Indonesia**, plus items from **Indonesian outlets that
name no other target country**. Everything else counts as international. Every list, chart, statistic, report
and the IOC table apply the same condition.
