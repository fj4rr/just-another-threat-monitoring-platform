# Maintenance commands

[← Documentation index](README.md)

`manage.py` runs jobs and maintenance tasks from the command line. Many of them also have a button in the
interface, noted below. Most of these jobs also run on their own schedule; see
[A day on the scheduler](how-it-works/index.md#a-day-on-the-scheduler).

```bash
python manage.py collect          # run every collector now (or only some: collect 1 5 7)
python manage.py enrich           # run one enrichment batch
python manage.py cve-intel        # refresh CISA KEV, EPSS and CVSS for recently mentioned CVEs
python manage.py digest           # write the AI executive summary now
python manage.py reextract        # extract the entities of every item again
python manage.py ioc-clean        # dry run: IP / SHA-1 indicators the extractor now rejects; add --apply to remove them
python manage.py rescore          # recalculate severity with the current rules (also a button in Settings → General)
python manage.py seed-sources     # add new built-in sources to an existing install (also a button in Settings)
python manage.py slim             # apply the retention tier now (trim the text of old items)
python manage.py geotag           # re-run the geography (targets, provinces, language, source country)
python manage.py geoip-update     # download the offline GeoIP database and locate IP indicators
python manage.py fraudtag         # re-run the scam & fraud analysis on every item (also a button on the fraud pages)
python manage.py sectortag        # detect the critical infrastructure sectors of every item again
python manage.py digesttag        # flag the newsletters and round-ups again (after changing a source's "digest" setting)
python manage.py quality          # precision and recall of the detection rules on the cases in tests/quality/
python manage.py telegram-login   # sign in to Telegram once for MTProto (optional; needs requirements-telegram.txt)
python manage.py vacuum           # give freed disk space back after deleting a lot of data
python manage.py copy-db postgresql+psycopg://jatmp:secret@localhost:5432/jatmp   # copy everything into an empty database
python manage.py create-user alice analyst
```

Re-scoring and re-extraction keep the points that don't come from the text (the enrichment bonus and the last AI
assessment), so they never drop a confirmed item below a threshold. They also keep analysts' corrections: a link an
analyst removed is not added back. After an upgrade that changes the scoring, fraud, sector or geography rules, the
matching re-analysis runs on its own; changes to entity extraction need `reextract`, and the upgrade notes say
when. See [Housekeeping and re-analysis](how-it-works/housekeeping.md#re-analysis-of-stored-items).

## The quality report

`python manage.py quality` runs the detection rules over the labelled cases in `tests/quality/` and prints the
precision, recall and F1 of each area (families and actors, indicators, scam reports, sectors, target countries,
severity), followed by the cases the rules got wrong. Options:

| Option | What it does |
|---|---|
| `--corrections FILE` | Adds an export of the analysts' corrections (*Export as test cases* on the Corrections page) and reports how many of them the current rules would still repeat |
| `--summary` | Prints the numbers without the list of wrong cases |
| `--json` | Prints the result as JSON |
| `--check` | Exits with an error when an area falls below `tests/quality/baseline.json` (what CI does) |
| `--update-baseline` | Records the current numbers as the new baseline (only without `--corrections`) |

What the areas measure and how to read the numbers is explained in
[Corrections and quality](how-it-works/corrections.md#measuring-the-rules).
