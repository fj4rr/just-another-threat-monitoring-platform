# Sources

[← Documentation index](README.md)

What JATMP collects out of the box. Every source can be edited, disabled or removed under **Settings → Sources**, and any RSS / Atom feed, Bluesky or Mastodon account, X account, public Telegram channel or threat-intel query can be added there. On an existing install, **Add new built-in sources** (or `python manage.py seed-sources`) adds sources introduced by newer versions.

## Built-in sources

| Source type | Included out of the box |
|---|---|
| **News (RSS)** | The Hacker News, Cyber Security News, BleepingComputer, SecurityWeek, The Record, Dark Reading, The DFIR Report, Unit 42, Malwarebytes Labs, SANS ISC, Krebs on Security, Cisco Talos, Securelist, Microsoft Security. Any other RSS or Atom feed can be added from the UI. |
| **Indonesian news** (RSS, Bahasa Indonesia) | Detik Inet, CNN Indonesia Teknologi, CNBC Indonesia Tech, Antara Tekno, Liputan6 Tekno, Republika Tekno, Okezone Techno, Sindonews Tekno, Jawa Pos Teknologi. These are general technology sections, so a *security* topic filter keeps only entries about breaches, hacking, fraud, malware and the like (English and Indonesian terms). The filter can be set on any RSS source. Seraphim News, a security-only outlet (CVE analysis, data breaches, ransomware), is collected unfiltered. BSSN, Kompas and Tempo are not included: their sites refuse automated clients or forbid automated collection. |
| **Bluesky** (public API, no key) | vx-underground, Marcus Hutchins, MalwareHunterTeam, Kevin Beaumont, Catalin Cimpanu, Will Thomas (BushidoToken), Zack Whittaker, Lorenzo Franceschi-Bicchierai, Dan Goodin, Karsten Hahn, hasherezade, Silas Cutler, Shadowserver, The DFIR Report, ESET Research, Cisco Talos, SentinelLABS, GreyNoise, Huntress, Ransomware.live |
| **Mastodon** (public API, no key) | Marcus Hutchins, Brian Krebs, Brad Duncan (malware-traffic), SANS ISC, Proofpoint Threat Insight, Thomas Roccia, ffforward, Matt Taggart, Kevin Beaumont |
| **X / Twitter** (API v2 bearer token or an RSS bridge) | Enabled: vxunderground, MalwareTechBlog, malwrhunterteam. Available but disabled by default so the API quota is not spent unintentionally: GossiTheDog, cyb3rops, 1ZRR4H, BushidoToken, TheDFIRReport, Unit42_Intel, abuse_ch, malware_traffic, ESETresearch, MsftSecIntel, executemalware, pr0xylife, g0njxa, Max_Mal_, RedDrip7, fr0gger_, StopMalvertisin, ViriBack, Fox_threatintel, FalconFeedsio, H4ckManac, anyrun_app, ffforward. Indonesian, also disabled by default: secgron (Teguh Aprianto, Ethical Hacker Indonesia), Id_SIRTII (Id-SIRTII/CC, BSSN) |
| **Telegram** (public web preview, no account) | Enabled: vx-underground. Disabled by default (they repeat the RSS feeds or post a lot): The Hacker News, BleepingComputer, CVE Notify. See [Telegram](#telegram) |
| **Scam & fraud** | FBI IC3 public service announcements, CekFakta.com and Liputan6 Cek Fakta (fact-checkers, filtered to scam reports), ScamSniffer crypto phishing domains. See [Scam and fraud sources](#scam-and-fraud-sources) |
| **Threat-intel collectors** | OTX subscribed pulses and searches, urlscan.io searches, ANY.RUN TI Lookup queries, the latest ThreatFox IOCs, MISP events, ransomware.live leak-site victims (recent, per group or per country; disabled by default, see [Dark web (tier 1)](integrations.md#dark-web-tier-1)) |

API keys for the threat-intel collectors and X are set under Settings → Threat-intel APIs or through
environment variables; see [Configuration](configuration.md). How far back each source can be crawled is shown
on the backfill page; see [History and storage](history-and-storage.md).

## Topic filters

Any RSS source can carry a topic filter (*Filter* in the source's Edit dialog):

- `security` keeps only entries about breaches, hacking, fraud, malware and the like (English and Indonesian terms).
  Used for the general technology sections of Indonesian outlets.
- `fraud` keeps only entries about a scam (the scam-type rules of the [fraud analysis](fraud.md)). Used for
  fact-checkers, whose feeds are mostly political hoaxes.

Separately, a source can have the **topic** *scam & fraud* (also in the Edit dialog). It then shows on the fraud
overview, and a single scam word is enough to file one of its entries under *Other scam*.

## Telegram

Add a source of kind *Telegram public channel* with the channel's username or `t.me` link. By default JATMP reads
the channel's public web preview (`https://t.me/s/<channel>`), which needs no account: 20 posts per page, older
pages for a backfill (up to 3,000 posts per run). Posts keep their links, forwarded-from name, attached file names
and view count; posts without text (a bare photo or sticker) are skipped.

Channels that turned the web preview off, or a deeper backfill, need MTProto:

1. `pip install -r requirements-telegram.txt` (Telethon).
2. Create an application at [my.telegram.org](https://my.telegram.org) and enter its api_id and api_hash under
   Settings → Social (or `TELEGRAM_API_ID` / `TELEGRAM_API_HASH`).
3. Run `python manage.py telegram-login` once. It asks for the phone number, the login code and the two-step
   password if set, and stores the session string (`telegram_session`).

From then on Telegram sources use MTProto automatically; set *Via* to `web` or `mtproto` on a source to force one.
Both ways produce the same item ids, so switching never duplicates posts. Only public channels are read: JATMP
does not join channels, read private groups or post. Use a separate Telegram account, because the session string
gives full access to it.

Channels run by threat actors (hacktivist groups, leak and fraud markets) are not built in: they are renamed or
banned often, and following one is an analyst's decision. Add them like any other channel.

## Scam and fraud sources

| Source | What it adds |
|---|---|
| FBI IC3 public service announcements | US fraud warnings (election, investment, impersonation scams) |
| CekFakta.com, Liputan6 Cek Fakta | Indonesian fact-checks about scams (fake bank accounts, *bansos* links, job offers), filtered with the `fraud` topic filter |
| ScamSniffer crypto phishing domains | One item per day of newly listed wallet-drainer and fake-airdrop domains (GPL-3.0 list, published a week late). The domains are marked malicious on arrival, so they do not use enrichment quota. Backfill reaches back to May 2022 |

Scam reports also come from the news, social and Telegram sources. See [Scams and fraud](fraud.md).

## Account verification

The Bluesky and Mastodon accounts listed above were verified active on 12 November 2026, with three
exceptions: `vxunderground.bsky.social` has no posts yet, and Marcus Hutchins and MalwareHunterTeam rarely
post on Bluesky (their main activity is on X; Marcus Hutchins is also on Mastodon). X handles cannot be
verified without an API token. The Telegram channels and the scam & fraud sources were verified on 16 November
2026.
