# Sources

[← Documentation index](README.md)

What JATMP collects out of the box. Every source can be edited, disabled or removed under **Settings → Sources**, and any RSS / Atom feed, Bluesky or Mastodon account, X account or threat-intel query can be added there. On an existing install, **Add new built-in sources** (or `python manage.py seed-sources`) adds sources introduced by newer versions.

## Built-in sources

| Source type | Included out of the box |
|---|---|
| **News (RSS)** | The Hacker News, Cyber Security News, BleepingComputer, SecurityWeek, The Record, Dark Reading, The DFIR Report, Unit 42, Malwarebytes Labs, SANS ISC, Krebs on Security, Cisco Talos, Securelist, Microsoft Security. Any other RSS or Atom feed can be added from the UI. |
| **Indonesian news** (RSS, Bahasa Indonesia) | Detik Inet, CNN Indonesia Teknologi, CNBC Indonesia Tech, Antara Tekno, Liputan6 Tekno, Republika Tekno, Okezone Techno, Sindonews Tekno, Jawa Pos Teknologi. These are general technology sections, so a *security* topic filter keeps only entries about breaches, hacking, fraud, malware and the like (English and Indonesian terms). The filter can be set on any RSS source. Seraphim News, a security-only outlet (CVE analysis, data breaches, ransomware), is collected unfiltered. BSSN, Kompas and Tempo are not included: their sites refuse automated clients or forbid automated collection. |
| **Bluesky** (public API, no key) | vx-underground, Marcus Hutchins, MalwareHunterTeam, Kevin Beaumont, Catalin Cimpanu, Will Thomas (BushidoToken), Zack Whittaker, Lorenzo Franceschi-Bicchierai, Dan Goodin, Karsten Hahn, hasherezade, Silas Cutler, Shadowserver, The DFIR Report, ESET Research, Cisco Talos, SentinelLABS, GreyNoise, Huntress, Ransomware.live |
| **Mastodon** (public API, no key) | Marcus Hutchins, Brian Krebs, Brad Duncan (malware-traffic), SANS ISC, Proofpoint Threat Insight, Thomas Roccia, ffforward, Matt Taggart, Kevin Beaumont |
| **X / Twitter** (API v2 bearer token or an RSS bridge) | Enabled: vxunderground, MalwareTechBlog, malwrhunterteam. Available but disabled by default so the API quota is not spent unintentionally: GossiTheDog, cyb3rops, 1ZRR4H, BushidoToken, TheDFIRReport, Unit42_Intel, abuse_ch, malware_traffic, ESETresearch, MsftSecIntel, executemalware, pr0xylife, g0njxa, Max_Mal_, RedDrip7, fr0gger_, StopMalvertisin, ViriBack, Fox_threatintel, FalconFeedsio, H4ckManac, anyrun_app, ffforward. Indonesian, also disabled by default: secgron (Teguh Aprianto, Ethical Hacker Indonesia), Id_SIRTII (Id-SIRTII/CC, BSSN) |
| **Threat-intel collectors** | OTX subscribed pulses and searches, urlscan.io searches, ANY.RUN TI Lookup queries, the latest ThreatFox IOCs, MISP events, ransomware.live leak-site victims (recent, per group or per country; disabled by default, see [Dark web (tier 1)](integrations.md#dark-web-tier-1)) |

API keys for the threat-intel collectors and X are set under Settings → Threat-intel APIs or through
environment variables; see [Configuration](configuration.md). How far back each source can be crawled is shown
on the backfill page; see [History and storage](history-and-storage.md).

## Account verification

The Bluesky and Mastodon accounts listed above were verified active on 12 November 2026, with three
exceptions: `vxunderground.bsky.social` has no posts yet, and Marcus Hutchins and MalwareHunterTeam rarely
post on Bluesky (their main activity is on X; Marcus Hutchins is also on Mastodon). X handles cannot be
verified without an API token.
