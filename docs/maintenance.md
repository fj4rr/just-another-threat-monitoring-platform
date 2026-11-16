# Maintenance commands

[← Documentation index](README.md)

`manage.py` runs jobs and housekeeping from the command line. Several commands also have a button in the UI.

```bash
python manage.py collect          # run every collector now (or a subset: collect 1 5 7)
python manage.py enrich           # run one enrichment batch
python manage.py cve-intel        # refresh CISA KEV / EPSS / CVSS for recently mentioned CVEs
python manage.py digest           # generate the AI digest now
python manage.py reextract        # re-extract entities on every item
python manage.py rescore          # recompute severity with the current rules (also a button in Settings → General)
python manage.py seed-sources     # add new built-in sources to an existing install (also a button in Settings)
python manage.py slim             # apply the retention tier now (trim the text of old items)
python manage.py geotag           # re-run geo attribution (targets, provinces, language, source country)
python manage.py geoip-update     # download the offline GeoIP database and locate IP indicators
python manage.py vacuum           # give freed space back to the disk
python manage.py copy-db postgresql+psycopg://jatmp:secret@localhost:5432/jatmp   # copy into an empty database
python manage.py create-user alice analyst
```
