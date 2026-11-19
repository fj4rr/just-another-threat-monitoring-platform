# Corrections and quality

[← How it works](index.md)

Every rule-based system makes mistakes. This page covers how analysts correct JATMP's mistakes, how those
corrections stay in force, and how the detection rules are measured so a rule change can be judged by its effect.
Code: `app/corrections.py` and `app/quality.py`.

## Analyst corrections

Analysts and admins can correct four things. Each correction asks for a reason, is recorded with the analyst's
name, and can be undone.

| Correction | Where | What it does |
|---|---|---|
| **Wrong entity here** | ✕ next to an entity on an item page | Removes that one link (a family, actor, CVE, sector, scam type, brand or indicator) and re-scores the item |
| **Wrong entity everywhere** / **Not a threat** | *✎ Correct* on an entity page | Removes the entity from every item, re-scores them, and stops it being linked again. An indicator also becomes *clean* |
| **Analyst verdict** | *✎ Correct* on an indicator page | Sets *malicious*, *suspicious* or *clean*. It wins over the providers: later lookups still store their answers, but they don't change the verdict. The items that mention the indicator get or lose the enrichment bonus with it |
| **Not a scam report** | The fraud-score popover on an item page | Sets the fraud score to 0 and removes the item's scam types, brands and identifiers |

### Why a correction sticks

A correction is not a one-off edit, because the jobs that rebuild things would bring the mistake back. Instead the
active corrections are consulted wherever that could happen:

| Job that could undo it | What stops it |
|---|---|
| Re-extraction (`manage.py reextract`), AI extraction, the ThreatFox merge, new items | `link_entities` skips links an analyst removed: one item's link for *wrong entity here*, every link for *wrong entity everywhere* |
| Scam re-analysis after an upgrade, *Re-analyse items* | The fraud analysis gives an item marked *not a scam report* a score of 0 |
| Enrichment and the re-check of stale verdicts | An analyst verdict is kept; its date is refreshed by each lookup, so it does not age out of the feeds while the indicator is still mentioned |
| *Re-score all items*, the severity rules version | Severity is computed from the links that remain |

The active corrections are cached in memory for at most 30 seconds and reloaded at once after a change.

### The Corrections page

*Corrections* (in the sidebar) lists every correction with who made it, when, why and its target, and has an
*Undo* button for each active one. Undoing restores what the correction changed: the removed links come back with
their original origin, an indicator gets its previous verdict back, a scam report is analysed again.

The page also shows two things for the last 30 days:

- **Error rate reported by analysts**: per area, the links analysts removed against all links made in the period,
  and the items marked *not a scam report* against all scam reports. It is a lower bound, since it counts only the
  mistakes someone noticed.
- **Most corrected**: the names corrected most often. A name that keeps coming back usually needs a rule change, for
  example an everyday word added to `COMMON_WORDS` in the knowledge base (see
  [Extending JATMP](../extending.md)).

Every correction is also written to the audit log (`correction_unlink`, `correction_verdict`…, and
`correction_undone`).

## Measuring the rules

`python manage.py quality` runs the real detection rules over labelled cases and reports, per area:

- **precision**: of what JATMP found, how much was right (low precision means false alarms);
- **recall**: of what was really there, how much JATMP found (low recall means misses);
- **F1**, the balance of the two, and every case the rules got wrong.

| Area | Rule | A case says | Counted per |
|---|---|---|---|
| `families` | The extractor's families and actors | Every family and actor the text names | Name |
| `indicators` | The extractor's IPs, domains, URLs and hashes | Every indicator an analyst would act on (not benign platforms, private addresses, versions or file names) | Value |
| `scam` | The scam rules | Whether the item is a scam report | Item |
| `sectors` | Critical infrastructure sectors | The sectors that are targets | Sector |
| `geography` | Target countries | The countries that are targets (not the attacker's origin or the hosting country) | Country |
| `severity` | Severity | Whether the item belongs among the notable items (severity **30** or more) | Item |

The cases live in `tests/quality/<area>.jsonl`, one JSON object per line. The first set (0.13) was written by hand
from real headlines and from the traps the rules were tuned on: everyday words that are also family names, defanged
indicators, smuggling "modus" next to scam "modus", hosting countries. It is small and deliberately hard, so read
its numbers as a trend line, not as how JATMP does on your feeds.

### Corrections become test cases

*Export as test cases* on the Corrections page (or `GET /api/corrections/export.jsonl`) turns the active
corrections into cases:

- *Not a scam report* is a complete label, so it joins the `scam` area.
- *Wrong entity here* and *wrong entity everywhere* only say what must **not** be found on those items. They are
  reported apart: **analyst corrections the rules still repeat: 7 of 23**. A rule change that brings that number
  down fixes mistakes analysts actually met.

```bash
python manage.py quality --corrections jatmp-corrections.jsonl
```

Good cases from the export can be copied into `tests/quality/` so they guard every later release.

### The quality gate in CI

`tests/quality/baseline.json` holds the precision and recall of each area when they were last recorded.
`tests/test_quality.py` fails the build when an area falls below it, and lists the cases the rules now get wrong.
CI also adds the report to the job summary. When a rule change improves an area, record the new numbers with
`python manage.py quality --update-baseline` and mention them in the changelog ("fraud recall went from 0.706 to
0.82").
