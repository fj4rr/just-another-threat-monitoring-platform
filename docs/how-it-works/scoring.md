# Severity scoring

[← How JATMP works](index.md)

Every item gets a **severity from 0 to 100** when it is stored, together with the list of reasons behind it. You
can see the breakdown by clicking the score on the item page. This page lists every rule; the code is in
`app/processing/severity.py`.

Severity is a **triage aid**. It answers the question "how urgently should an analyst read this?" It is not a
CVSS score and not a probability. Scam reports have their own [fraud score](../fraud.md#fraud-score), and the two
are never added together.

## How the score is built

```
severity = text signals            (4 groups: the strongest term, plus half the runner-up, in each group)
         + entity signals          (family, actor, CVEs, indicators, techniques)
         + structured-intel base   (pulses, analyses, scans)
         × dampeners               (patch note ×0.7, round-up / non-incident ×0.5)
         → cap for routine leak-site posts (35)
         → rounded, kept between 0 and 100
```

After that, two things can still raise a stored score: an indicator that enrichment confirms as malicious, and
the AI assessment. See [After ingest](#after-ingest).

## Text signals

The title, the first 20,000 characters of the text, and the tags are matched against four **signal groups**.
The terms within one group are different ways of saying the same kind of thing, so they must not all add up:

- **Only the strongest term in a group counts in full. The runner-up counts at half weight,** and anything
  after that is ignored.
- A term that appears **in the title counts 1.5 times**, because headlines name the real subject while the body
  mentions everything in passing.
- An English term and its Indonesian equivalent share a label and count once.
- The contributions of the different groups are added together.

### Exploitation

| Signal | Points | Examples of what matches |
|---|---|---|
| zero-day | 30 | zero-day, 0-day |
| exploited in the wild | 30 | actively exploited, in the wild, under active attack, mass exploitation, *sedang / aktif dieksploitasi* |
| listed in CISA KEV | 28 | KEV, known exploited vulnerability |
| public exploit code | 18 | PoC released, exploit code published |
| exploitation mentioned | 10 | exploit, exploited, exploiting, *eksploitasi* |

When the strongest exploitation term is worth **18 points or more** (including the title bonus), the item counts
as *actively exploited*. The patch-note dampener below then no longer applies, because a bug that is being
exploited is still urgent even when a patch is available.

### Impact

| Signal | Points | Examples of what matches |
|---|---|---|
| remote code execution | 14 | RCE, unauthenticated attacker, pre-auth, *eksekusi kode jarak jauh* |
| destructive / wiper | 14 | wiper, destructive malware, data-destroying |
| critical / CVSS ≥ 9 | 12 | CVSS 9.8, "critical flaw", "rated critical", *celah kritis* (but not "critical infrastructure") |
| authentication bypass | 12 | auth bypass, bypasses authentication |
| service disruption | 10 | *layanan lumpuh*, *sistem lumpuh*, *data terenkripsi* |
| privilege escalation | 6 | privilege escalation, LPE, EoP |
| high severity | 6 | high-severity |

### Threat class

| Signal | Points | Examples of what matches |
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

| Signal | Points | Examples of what matches |
|---|---|---|
| active campaign | 10 | campaign, "deployed ransomware", *kampanye, serangan siber, diserang* |
| new malware / variant | 8 | new … variant / stealer / family, previously undocumented, novel, *malware baru* |
| state-sponsored / APT | 8 | APT, state-sponsored, nation-state, espionage, *didukung negara, spionase* |
| wide scale | 6 | widespread, millions of, worldwide, *jutaan, seluruh dunia* |
| targeting described | 5 | targets, targeted, *menargetkan, menyasar, mengincar* |
| sensitive sector | 5 | critical infrastructure, healthcare, hospital, government, SCADA, *pemerintah, rumah sakit, layanan publik* |

## Entity signals

The entities the extractor found are evidence in their own right. Each kind counts once:

| Signal | Points |
|---|---|
| A **known** malware family (from the knowledge base, a feed or a provider) | 10 |
| Only an **unknown** family, found by the "*Name* ransomware" pattern | 6 |
| A known threat actor | 8 |
| CVEs | 5 for the first, +2 for each additional CVE, up to 11 |
| Indicators (IPs, domains, URLs, hashes) | 8, or 12 with five or more |
| ATT&CK technique ids | 3 |
| The item is a `pulse` or `analysis` / a `scan` (structured intel) | 6 / 4 |

Scam types, brands, scammer identifiers and sectors add **no** severity points (see
[the order of the ingest steps](processing.md#the-ten-steps)).

## Dampeners and caps

These are applied after everything above has been added up, in this order. Apart from the leak-site cap, they
only look at the **title**:

| Rule | Effect | Triggered by |
|---|---|---|
| Patch or advisory | × 0.7 | "fixes", "patches", "Patch Tuesday", "security update", "addresses", "hotfix", *tambal, pembaruan keamanan*… — unless the item is actively exploited (see above) |
| Round-up, guide or non-incident | × 0.5 | "week in review", "roundup", "top 10", "how to", "what is", webinar, podcast, survey, "announces", funding, acquisition, training, tips; outages, pricing, lawsuits, GDPR; *cara mengatasi, begini cara, kenali, apa itu, seminar, peluncuran, promo, diskon* |
| Routine leak-site posting | capped at **35** | A post saying a group "added / claims / listed … victims / leak site". Ransomware trackers publish hundreds of these every day |

Both multipliers can apply to the same item (× 0.35 in total). The result is rounded and kept between 0 and 100.
Each reduction appears in the breakdown as a reason with negative points, so the reasons always add up to the
score (allowing for rounding).

## Worked examples

All three were calculated by running the text through `score_item`.

**1. An exploited zero-day.** *"LockBit ransomware exploits Citrix zero-day to hit Indonesian hospitals"*, with a
body describing an actively exploited RCE, one CVE, one technique and three defanged indicators:

| Reason | Points | How |
|---|---|---|
| zero-day | 45 | 30, in the title × 1.5; the strongest *exploitation* term |
| exploited in the wild | 15 | 30 × 0.5 as the runner-up in *exploitation* |
| remote code execution | 14 | The strongest *impact* term |
| ransomware | 18 | 12, in the title × 1.5; the strongest *threat class* term |
| active campaign | 10 | The strongest *activity* term |
| sensitive sector | 4 | 5 × 1.5 (hospitals, in the title) × 0.5 as the runner-up |
| known malware family | 10 | LockBit |
| 1 CVE(s) | 5 | |
| 3 indicator(s) | 8 | |
| ATT&CK techniques | 3 | |
| **Total** | **132 → 100** | Capped |

**2. A patch note.** *"Microsoft fixes critical Exchange flaw in Patch Tuesday update"*, with a body mentioning
one CVE and remote code execution:

| Reason | Points | How |
|---|---|---|
| critical / CVSS ≥ 9 | 18 | 12, in the title × 1.5; the strongest *impact* term |
| remote code execution | 7 | 14 × 0.5 as the runner-up in *impact* |
| 1 CVE(s) | 5 | |
| patch / advisory only | −9 | (18 + 7 + 5) × 0.7 = 21. There is no exploitation signal, so the dampener applies |
| **Total** | **21** | |

If the body had also said "exploited in the wild", the item would have scored **65** with no dampener:
exploited in the wild 30, exploitation mentioned 5 (10 × 0.5 as the runner-up, from the word "exploited"), and
then 18 + 7 + 5 as before.

**3. A scam warning.** *"Waspada penipuan APK undangan pernikahan mengatasnamakan BRI, korban rugi Rp 1,2
miliar"* scores a severity of only **9** (*penipuan* in the title: phishing / social engineering, 6 × 1.5). The
same item has a **fraud score of 83**: malicious APK lure 28, also impersonation 4, impersonates BRI 10, losses of
Rp 1.2 billion 15, 120 victims 10, scammer identifiers 8, and a police warning 8. That is intended. As a cyber
threat it is minor, but as a scam report it is serious, and it ranks high on the scam & fraud dashboard.

## After ingest

| Event | Effect on the stored score | Reason shown |
|---|---|---|
| One of the item's indicators turns **malicious** in enrichment | +12 | *indicator confirmed malicious (ip)* |
| One of the item's indicators turns **suspicious** | +5. If it later turns malicious, the score rises by another 7 and the reason shows +12 | *indicator confirmed suspicious (…)* |
| A malicious or suspicious indicator is re-checked and its verdict goes down | The item keeps the bonus of its strongest remaining indicator, or loses it | Updated, or removed |
| The AI rates the item higher than the rule-based score | The score is raised towards the AI's number, by **at most +20**. It never goes below the rule-based score | *AI assessment (capped)*, with an *AI* badge |

Each item keeps only one *indicator confirmed* reason, for its strongest verdict, so several malicious indicators
don't add +12 each. The AI assessment is replaced rather than added to when an item is analysed again: its old
points are taken off first, so a lower new assessment can remove them. Both adjustments are capped at 100.

### Recomputing scores

When the terms, weights or dampeners change in a new version, the rules version (`severity.RULES_VERSION`) goes
up, and every stored item is re-scored once, about 90 seconds after the new version first starts
(`jobs.run_rescore_if_outdated`). That way old and new items are scored by the same rules before the trends
compare them. You can also re-score by hand:

| Tool | What it starts from | Keeps the enrichment bonus | Keeps the AI assessment |
|---|---|---|---|
| *Re-score all items* (Settings), `manage.py rescore` | The stored text and the entities already linked (with how they were found). Nothing is re-extracted and no network calls are made | Yes | Yes |
| `manage.py reextract` | A fresh extraction of the stored text, which rebuilds the `regex`, `kb` and `heuristic` links and the scam and sector analysis | Yes | Yes |

In every case, the points that don't come from the text are added back afterwards (`severity.carry_over`): the
*indicator confirmed* bonus for the strongest verdict among the item's indicators today, and the last *AI
assessment*. The AI assessment remembers the severity the model proposed, so it is applied again to the new
score with the same cap. If the new score already reaches the model's number, it adds nothing. AI assessments
stored before version 0.11 don't have a proposed severity, so they keep their original points.

Slimmed items (past the full-text retention period) are re-scored from their snippet, so their score may drop.
See [Housekeeping and re-analysis](housekeeping.md).

## Reading a score

| Range | Typical content |
|---|---|
| 80–100 | Exploited zero-days, supply-chain compromises, ransomware campaigns with indicators |
| 50–79 | Active campaigns, new malware with indicators, critical vulnerabilities, significant breaches |
| 20–49 | Breach and malware news without technical detail, structured intel without strong text signals, patched critical bugs |
| 0–19 | Round-ups, guides, product news, scam warnings (check their fraud score), routine leak-site postings |

Webhooks use **70** as the default threshold for a "high severity" item, and AI auto-summaries only run from **40**
upwards.
