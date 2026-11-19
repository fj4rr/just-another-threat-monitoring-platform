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
python manage.py rescore          # recalculate severity with the current rules (also a button in Settings → General)
python manage.py seed-sources     # add new built-in sources to an existing install (also a button in Settings)
python manage.py slim             # apply the retention tier now (trim the text of old items)
python manage.py geotag           # re-run the geography (targets, provinces, language, source country)
python manage.py geoip-update     # download the offline GeoIP database and locate IP indicators
python manage.py fraudtag         # re-run the scam & fraud analysis on every item (also a button on the fraud pages)
python manage.py sectortag        # detect the critical infrastructure sectors of every item again
python manage.py telegram-login   # sign in to Telegram once for MTProto (optional; needs requirements-telegram.txt)
python manage.py vacuum           # give freed disk space back after deleting a lot of data
python manage.py copy-db postgresql+psycopg://jatmp:secret@localhost:5432/jatmp   # copy everything into an empty database
python manage.py create-user alice analyst
```

Re-scoring and re-extraction keep the points that don't come from the text (the enrichment bonus and the last AI
assessment), so they never drop a confirmed item below a threshold. After an upgrade that changes the scoring,
fraud, sector or geography rules, the matching re-analysis runs on its own; see
[Housekeeping and re-analysis](how-it-works/housekeeping.md#re-analysis-of-stored-items).
