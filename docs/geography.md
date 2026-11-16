# Geography and Indonesia

[← Documentation index](README.md)

Where each item's targets, reporting and infrastructure are, the International / National (Indonesia) view, and Bahasa Indonesia support.

## Three kinds of location

Three relations are kept apart so that hosting countries never inflate the target map:

- *Target countries* (and, for Indonesia, the province): where the victims are or the activity takes place. They
  come from place names and demonyms in the text, the 38 Indonesian provinces with their cities and regencies
  (an ambiguous name such as Malang or Palu only counts after *Kota*, *Kabupaten*, *Pemkot*...), Indonesian
  institutions and companies (BSSN, Komdigi, BPJS, OJK, Pertamina...), `.go.id` / `.co.id` / `.ac.id` domains,
  the victim country of leak-site postings and the targeted countries OTX and ransomware.live supply. A country
  that describes the *attacker* is not a target: "Russian hackers", "China-nexus", "Iran-linked", "attributed to
  North Korea", "peretas asal Rusia".
- *Source country*: the outlet's country (set per source), or Indonesia for items written in Indonesian.
- *Hosting country* of IP indicators: from an offline GeoIP database when one is installed (DB-IP Lite, or MaxMind
  GeoLite2 with a key), otherwise from the enrichment providers (IPinfo, VirusTotal, AbuseIPDB, OTX...).

## Geography page

The **Geography** page shows target countries on a world map and Indonesian provinces on a province map (both
link to the matching feed), the families and actors named per country, hosting countries, source countries and
languages. The maps are drawn from public-domain Natural Earth outlines that ship with JATMP, so nothing is
loaded from outside. Item pages and previews list the targets, source country and language; the feed and the
REST API filter by `country`, `province`, `src_country` and `lang`. The map and list cards share a height and the
lists scroll, so every target country and province is listed.

On the dashboard, a globe shows the top 10 target countries (or provinces in the National view) of the last 30
days, built from the same outlines; see [the dashboard](using-jatmp.md#dashboard).

## International / National (ID)

The switch in the top bar limits the dashboard, every list, the statistics,
the report builder and the IOC table to Indonesia: items that target Indonesia, plus items from Indonesian outlets
that do not name another target country. The choice is remembered for the session.

## Bahasa Indonesia

Language is detected per item. The severity rules know Indonesian terms (*kebocoran data*,
*diretas*, *peretasan*, *penipuan*, *phising*, *dieksploitasi*, *uang tebusan*, *judi online*...) and count an
English term and its Indonesian synonym once; awareness pieces (*tips*, *cara*, *kenali*) are damped like
English guides. The extractor recognises the Indonesian word order for new families ("ransomware Brain Cipher",
"trojan perbankan Mamont"), and Indonesian news and government domains are never indicators.
