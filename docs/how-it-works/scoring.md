# Severity scoring

[← How JATMP works](index.md)

Every item gets a **severity from 0 to 100** when it is stored, together with the list of reasons that produced
it (click the score on the item page). This page lists every rule. The code is `app/processing/severity.py`.

Severity is a **triage heuristic**: "how urgently should an analyst read this?" It is not a CVSS score and not a
probability. Scam reports have a separate [fraud score](../fraud.md#fraud-score); the two never add up.

## How the score is built

```
severity = text signals            (4 groups, strongest term + half the runner-up per group)
         + entity signals          (family, actor, CVEs, indicators, techniques)
         + structured-intel base   (pulses, analyses, scans)
         × dampeners               (patch note ×0.7, round-up / non-incident ×0.5)
         → cap for routine leak-site posts (35)
         → rounded, clamped to 0–100
```

Later, two things can raise a stored score: an indicator confirmed malicious by enrichment, and the AI assessment.
See [After ingest](#after-ingest).

## Text signals

The title and the first 20,000 characters of the text (plus the tags) are matched against four **signal groups**.
Inside a group, terms are synonyms of a kind of evidence, so they must not add up:

- **Only the strongest term of a group counts in full; the runner-up counts at half weight;** the rest are
  ignored.
- A term that matches **in the title counts 1.5 times** (headlines name the subject; bodies mention everything
  in passing).
- An English term and its Indonesian equivalent share a label and count once.
- Between groups, contributions add up.

### Exploitation

| Signal | Points | Matches, for example |
|---|---|---|
| zero-day | 30 | zero-day, 0-day |
| exploited in the wild | 30 | actively exploited, in the wild, under active attack, mass exploitation, *sedang / aktif dieksploitasi* |
| listed in CISA KEV | 28 | KEV, known exploited vulnerability |
| public exploit code | 18 | PoC released, exploit code published |
| exploitation mentioned | 10 | exploit, exploited, exploiting, *eksploitasi* |

If the strongest exploitation term is worth **18 or more** (after the title bonus), the item counts as
*actively exploited*: the patch-note damper below is then not applied, because an exploited bug being patched is
still urgent.

### Impact

| Signal | Points | Matches, for example |
|---|---|---|
| remote code execution | 14 | RCE, unauthenticated attacker, pre-auth, *eksekusi kode jarak jauh* |
| destructive / wiper | 14 | wiper, destructive malware, data-destroying |
| critical / CVSS ≥ 9 | 12 | CVSS 9.8, "critical flaw", "rated critical", *celah kritis* — not "critical infrastructure" |
| authentication bypass | 12 | auth bypass, bypasses authentication |
| service disruption | 10 | *layanan lumpuh*, *sistem lumpuh*, *data terenkripsi* |
| privilege escalation | 6 | privilege escalation, LPE, EoP |
| high severity | 6 | high-severity |

### Threat class

| Signal | Points | Matches, for example |
|---|---|---|
| supply-chain | 16 | supply chain, trojanised installer, malicious npm / PyPI package or browser extension, *rantai pasok* |
| ransomware | 12 | ransomware, double extortion, *uang tebusan* |
| spyware / zero-click | 12 | zero-click, spyware, mercenary, commercial surveillance, *penyadapan* |
| backdoor / implant | 9 | backdoor, rootkit, bootkit, implant, web shell, *pintu belakang* |
| botnet / worm | 9 | botnet, worm, wormable, self-propagating |
| breach / exfiltration | 8 | data breach, exfiltration, leaked data, *kebocoran data, diretas, dibobol, dijual di dark web* |
| stealer | 7 | infostealer, credential theft, keylogger, *pencurian kredensial* |
| phishing / social engineering | 6 | phishing, smishing, BEC, ClickFix, malvertising, *penipuan, modus, mengatasnamakan, APK palsu* |
| website defacement / injection | 6 | *deface*, *judi online*, *situs disusupi* |

### Activity

| Signal | Points | Matches, for example |
|---|---|---|
| active campaign | 10 | campaign, "deployed ransomware", *kampanye, serangan siber, diserang* |
| new malware / variant | 8 | new … variant / stealer / family, previously undocumented, novel, *malware baru* |
| state-sponsored / APT | 8 | APT, state-sponsored, nation-state, espionage, *didukung negara, spionase* |
| wide scale | 6 | widespread, millions of, worldwide, *jutaan, seluruh dunia* |
| targeting described | 5 | targets, targeted, *menargetkan, menyasar, mengincar* |
| sensitive sector | 5 | critical infrastructure, healthcare, hospital, government, SCADA, *pemerintah, rumah sakit, layanan publik* |

## Entity signals

What the extractor found adds evidence of its own, once per kind:

| Signal | Points |
|---|---|
| A **known** malware family (knowledge base, feed, provider) | 10 |
| Only an **unknown** family named by the "*Name* ransomware" pattern | 6 |
| A known threat actor | 8 |
| CVEs | 5 for one, +2 for each further CVE, at most 11 |
| Indicators (IPs, domains, URLs, hashes) | 8, or 12 with five or more |
| ATT&CK technique ids | 3 |
| Item kind `pulse` or `analysis` / `scan` (structured intel) | 6 / 4 |

Scam types, brands, scammer identifiers and sectors add **no** severity points (see
[the order of the ingest steps](processing.md#the-ten-steps)).

## Dampeners and caps

Applied after everything above has been added, in this order. They look at the **title** only (except the
leak-site cap):

| Rule | Effect | Triggered by |
|---|---|---|
| Patch / advisory | × 0.7 | "fixes", "patches", "Patch Tuesday", "security update", "addresses", "hotfix", *tambal, pembaruan keamanan*… — unless the item is actively exploited (see above) |
| Round-up, guide or non-incident | × 0.5 | "week in review", "roundup", "top 10", "how to", "what is", webinar, podcast, survey, "announces", funding, acquisition, training, tips; outages, pricing, lawsuits, GDPR; *cara mengatasi, begini cara, kenali, apa itu, seminar, peluncuran, promo, diskon* |
| Routine leak-site posting | capped at **35** | A `post` whose text says a group "added / claims / listed … victims / leak site"; ransomware trackers post hundreds of these a day |

Both multipliers can apply to the same item (× 0.35). The result is rounded and kept between 0 and 100. The cut is
listed among the reasons with negative points, so the breakdown always adds up to the score (up to rounding).

## Worked examples

These were produced by running the text through `score_item`.

**1. An exploited zero-day.** *"LockBit ransomware exploits Citrix zero-day to hit Indonesian hospitals"*, body
about an actively exploited RCE, one CVE, one technique and three defanged indicators:

| Reason | Points | How |
|---|---|---|
| zero-day | 45 | 30, in the title × 1.5; strongest of *exploitation* |
| exploited in the wild | 15 | 30 × 0.5 as runner-up of *exploitation* |
| remote code execution | 14 | strongest of *impact* |
| ransomware | 18 | 12, in the title × 1.5; strongest of *threat class* |
| active campaign | 10 | strongest of *activity* |
| sensitive sector | 4 | 5 × 1.5 (hospitals, in the title) × 0.5 as runner-up |
| known malware family | 10 | LockBit |
| 1 CVE(s) | 5 | |
| 3 indicator(s) | 8 | |
| ATT&CK techniques | 3 | |
| **Total** | **132 → 100** | clamped |

**2. A patch note.** *"Microsoft fixes critical Exchange flaw in Patch Tuesday update"*, body mentions one CVE
and remote code execution:

| Reason | Points | How |
|---|---|---|
| critical / CVSS ≥ 9 | 18 | 12, in the title × 1.5; strongest of *impact* |
| remote code execution | 7 | 14 × 0.5 as runner-up of *impact* |
| 1 CVE(s) | 5 | |
| patch / advisory only | −9 | (18 + 7 + 5) × 0.7 = 21; no exploitation signal, so the damper applies |
| **Total** | **21** | |

Had the body added "exploited in the wild", the item would have scored **65** with no damper: exploited in the
wild 30, exploitation mentioned 5 (10 × 0.5 as runner-up, from the word "exploited"), then 18 + 7 + 5 as before.

**3. A scam warning.** *"Waspada penipuan APK undangan pernikahan mengatasnamakan BRI, korban rugi Rp 1,2
miliar"*: severity **9** (*penipuan* in the title, phishing / social engineering 6 × 1.5). The same item has a
**fraud score of 83** (malicious APK lure 28, also impersonation 4, impersonates BRI 10, losses Rp 1.2 billion
15, 120 victims 10, scammer identifiers 8, police warning 8). This is intended: as a cyber threat it is minor; as
a scam report it is serious, and it ranks high on the scam & fraud dashboard.

## After ingest

| Event | Effect on the stored score | Reason shown |
|---|---|---|
| An indicator of the item turns **malicious** in enrichment | +12 | *indicator confirmed malicious (ip)* |
| An indicator turns **suspicious** | +5 (and +7 more if it later turns malicious) | *indicator confirmed suspicious (…)* |
| The AI summary rates the item higher than its score | Raised toward the model's number, **at most +20**; never lowered | *AI assessment (capped)*, with an *AI* badge |

Only one *indicator confirmed* reason is kept per item, for the strongest verdict; several malicious indicators
do not add +12 each. The AI reason is likewise replaced, not added, when an item is summarised again. Both
adjustments are capped at 100.

### Recomputing scores

Scores are not recomputed automatically when the rules change in a new version (unlike fraud, sectors and
geography). Two tools do it:

| Tool | Recomputes from | Keeps the enrichment bonus | Keeps the AI points |
|---|---|---|---|
| *Re-score all items* (Settings), `manage.py rescore` | The stored text and the entities already linked (with their origins); no re-extraction, no network | Yes | No |
| `manage.py reextract` | A fresh extraction of the stored text; rebuilds the `regex`, `kb` and `heuristic` links and the scam and sector analysis | No | No |

Slimmed items (past the full-text retention) are re-scored on their snippet, so their score may drop. See
[Housekeeping and re-analysis](housekeeping.md).

## Reading a score

| Range | Typical content |
|---|---|
| 80–100 | Exploited zero-days, supply-chain compromises, ransomware campaigns with indicators |
| 50–79 | Active campaigns, new malware with indicators, critical vulnerabilities, significant breaches |
| 20–49 | Breach and malware news without technical detail, structured intel without strong text signals, patched critical bugs |
| 0–19 | Round-ups, guides, product news, scam warnings (see their fraud score), routine leak-site postings |

Webhooks use **70** as the default threshold for "high severity", and AI auto-summaries only run from **40**.
