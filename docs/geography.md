# Geography and Indonesia

[← Documentation index](README.md)

This page explains where each item's targets, reporting and infrastructure are located, how the International /
National (Indonesia) view works, and how JATMP handles Bahasa Indonesia. The exact scoring rules are in
[Ingest and analysis](how-it-works/processing.md#10-geography).

## Three kinds of location

JATMP keeps three kinds of location apart, so that hosting countries never inflate the map of targets.

**Target countries** (and, for Indonesia, the province) are where the victims are or where the activity takes
place. They come from:

- place names and nationalities in the text;
- the 38 Indonesian provinces with their cities and regencies (an ambiguous name such as Malang or Palu only
  counts after *Kota*, *Kabupaten*, *Pemkot* and the like);
- Indonesian institutions and companies (BSSN, Komdigi, BPJS, OJK, Pertamina…);
- `.go.id`, `.co.id` and `.ac.id` domains;
- the victim country of leak-site postings, and the targeted countries that OTX and ransomware.live provide.

A country that describes the *attacker* is not a target: "Russian hackers", "China-nexus", "Iran-linked",
"attributed to North Korea", "peretas asal Rusia". Nor is a marketplace or a hosting location: "sold on Russian
forums", "hosted in the Netherlands", "a Dutch hosting provider". Cities outside Indonesia are not recognised, so
"a Dubai-based exchange" names no country.

**Source country** is the outlet's country (set per source), or Indonesia for items written in Indonesian.

**Hosting country** of an IP indicator comes from an offline GeoIP database when one is installed (DB-IP Lite,
or MaxMind GeoLite2 with a key). Otherwise it comes from the enrichment providers (IPinfo, VirusTotal, AbuseIPDB,
OTX and others).

## Geography page

The **Geography** page shows target countries on a world map and Indonesian provinces on a province map, both
linking to the matching feed. It also lists the families and actors named for each country, as well as hosting
countries, source countries and languages. Target countries count stories, so a story carried by several
outlets counts once; source countries and languages count each outlet's items.

The maps are drawn from public-domain Natural Earth outlines that ship with JATMP, so nothing is loaded from
outside. The map and list cards are the same height, and the lists scroll, so every target country and province
is listed.

Item pages and previews show the targets, source country and language. The feed and the REST API can filter by
`country`, `province`, `src_country` and `lang`.

On the dashboard, a globe shows the top 10 target countries of the selected period (or provinces in the National
view), built from the same outlines; see [the dashboard](using-jatmp.md#dashboards).

## International / National (ID)

The switch in the top bar limits the dashboard, every list, the statistics, the report builder and the IOC table
to Indonesia. In the National view you see items that target Indonesia, plus items from Indonesian outlets that
don't name another target country. Your choice is remembered for the session.

## Bahasa Indonesia

The language of each item is detected automatically.

- **Severity.** The scoring rules know Indonesian terms (*kebocoran data*, *diretas*, *peretasan*, *penipuan*,
  *phising*, *dieksploitasi*, *uang tebusan*, *judi online*…) and count an English term and its Indonesian
  equivalent once. Awareness pieces (*tips*, *cara*, *kenali*) are scored down, just like English guides.
- **Extraction.** The extractor understands the Indonesian word order for new families ("ransomware Brain
  Cipher", "trojan perbankan Mamont").
- **Indicators.** Indonesian news and government domains are never treated as indicators.
