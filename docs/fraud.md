# Scams and fraud

[← Documentation index](README.md)

Since 0.9 JATMP reads every collected item a second time as a possible scam report. Scam reports get their own
section (**Scams & fraud** in the menu) but stay on the same pipeline and entity graph as everything else, so a
wedding-invitation APK scam links to the Android banking trojan it installs, a crypto drainer report to its phishing
domains, and an infostealer campaign to the account takeovers that follow. The International / National (ID)
switch applies here too.

## What is detected

| | How |
|---|---|
| **Scam type** | A fixed taxonomy in English and Bahasa Indonesia: investment scam (incl. *investasi bodong*, robot trading, pig butchering), illegal online loan (*pinjol ilegal*), job / task scam, romance scam, sextortion, malicious APK lure (wedding invitations, traffic tickets, bills), courier / package lure, impersonation, phishing, OTP theft / account takeover, online gambling (*judol*), fake shop, prize / giveaway (incl. fake *bansos*), crypto scam / drainer, tech support / refund scam, BEC / invoice fraud, QRIS / QR code fraud, deepfake scam, and *Other scam*. Typical phrases include fraudulent investment apps, callers who *mengaku dari*
Bea Cukai, the police, a bank or the tax office, SMS phishing and smishing messages, fake payment or delivery
pages, fake QRIS stickers, and fake sellers or *jual beli … online* fraud. Tools and policies against scams (*aplikasi anti-scam*, an anti-fraud team) are no scam word. Strong phrases count on their own; weaker ones ("phishing", "APK", "deepfake", "mengatasnamakan") only next to a scam word (within about 200 characters, or a scam word in the title), and outside fraud sources one passing scam word is not enough. An article whose title says nothing about a scam must show the scam in more than one place, so a malware write-up with one sentence about "scammers using fake delivery notices" stays out. Newsletters and weekly round-ups are judged on their title only. |
| **Impersonated brand** | About 70 banks, e-wallets, marketplaces, couriers, telecoms, utilities, government bodies, platforms and crypto exchanges, Indonesian first (BCA, BRI, Bank Mandiri, BNI, DANA, OVO, GoPay, Shopee, J&T, PLN, OJK, BPJS, DJP, Bea Cukai…). A brand counts when it appears next to an impersonation cue ("mengatasnamakan BCA", "fake PayPal"). A brand that speaks or acts ("Shopee warns customers…", "BCA mengimbau nasabah", "kata pihak OJK", "Coinbase blocks $4.7 million in transfers to scammers", "BRI Ajak…", a headline "Indodax: …") is not the one impersonated, unless the text says so right next to the name ("fake Shopee websites"). A brand's own advisory that names no case ("nasabah diimbau berhati-hati saat menerima komunikasi yang mengatasnamakan BRI", with no victim, perpetrator, loss or circulating fake) talks about impersonation in general and names no brand. A plain scam word only counts right next to the name ("phishing BCA", "penipuan berkedok hadiah BRI"), not a sentence away. Platforms and government bodies need the cue right next to them, because they are usually the channel ("lewat WhatsApp") or the one issuing the warning ("FBI warns…"). Ambiguous words are matched carefully: *dana* (funds) is not DANA, *mandiri* (independent) is not Bank Mandiri. |
| **Impersonated person** | Public figures whose name or face a scam borrows: deepfake giveaways and investment ads ("Deepfake Elon Musk", "an AI-generated deepfake of Elon Musk"), *mencatut nama Menteri Keuangan Sri Mulyani*, fake accounts of officials. They are brands of the type *person* (same lists, filters, chips and graph). A list of about 45 often-borrowed names (Elon Musk, Donald Trump, Prabowo Subianto, Sri Mulyani, Raffi Ahmad…) counts next to an impersonation cue or in a sentence about a deepfake; other names only count right after an office or calling ("mencatut nama Bupati Bandung Dadang Supriatna", "posing as billionaire …"). A name without one is left alone, because it may belong to a private person. |
| **Scammer identifiers** | Phone numbers (Indonesian mobile numbers normalised to `+628…`), bank accounts (with the bank when it is named), e-wallet numbers and crypto wallets (BTC, ETH, TRON; Bitcoin and TRON addresses must pass their Base58Check or bech32 checksum, so an invoice number is no wallet). See the rules below. |
| **Losses and victims** | The largest loss a report states (headline forms such as "Rp 2,5 T" and "Rp 5 M" included), converted to rupiah (dollar amounts at the rate set under Settings → Scam & fraud), and the largest victim count ("1.200 korban", "ratusan korban", "thousands of victims"). Amounts only count next to a loss word, so prices and fees are ignored, and money that was saved, frozen or returned is not a loss. |

## Fraud score

Each scam report gets a **fraud score** from 0 to 100, separate from the threat severity and explained the same way
(click the score on the item page, or see the side preview):

| Part | Points |
|---|---|
| Scam type (the strongest one) | 10–28, e.g. malicious APK lure 28, investment scam 26, OTP theft 24, phishing 18, online gambling 12 |
| More scam types in the same report | +4 each, up to +8 |
| Impersonated bank, e-wallet or government body / person / other brand | +10 / +8 / +6 |
| Reported losses | +5 below Rp 100 million, up to +30 from Rp 1 trillion |
| Reported victims | +5 from 10, up to +20 from 10,000 |
| Scammer identifiers published | +8 |
| Official warning or law enforcement (OJK, Satgas PASTI, IASC, police, FBI / IC3, FTC, BSSN, arrests) | +8 |
| Spreading: at least 5 reports of the same scam type this week and twice as many as the week before | +8 |

## Scammer identifiers and personal data (UU PDP)

Phone numbers and bank accounts are personal data under Indonesia's Personal Data Protection Law (UU PDP, Law
27/2022). JATMP keeps as little as it can:

- Identifiers are taken **only from items that are about a scam**, and only where the sentence marks them as the
  scammer's (*nomor penipu*, *pelaku menghubungi dari*, *transfer ke rekening*, "texts from"…). A plain "hubungi
  nomor" or "contact" is not enough when the same sentence names an institution (*Polres*, *kantor cabang*,
  *layanan pengaduan*, OJK…): "Hubungi Polres Jakarta Selatan di nomor 0812…" is the police's number.
- Numbers the text marks as **official** (call centre, hotline, *resmi*) or as the **victim's** (*nomor milik
  korban*) are skipped.
- **Account holder names are never stored**, only the number (and the bank).
- Phone numbers, bank accounts and e-wallets that no item has mentioned for a year are **deleted** by the nightly
  housekeeping (`fraud_identifier_days`; crypto wallets are not personal data and stay).
- Identifiers **never leave JATMP**: they are left out of the REST API, the IOC feeds, STIX / TAXII, webhooks
  (also for watched identifiers) and MISP pushes.
- Item text sent to a **cloud** AI model has phone numbers, bank accounts, e-wallets, e-mail addresses and long ID
  numbers replaced with placeholders first, whether or not they were extracted (setting *Personal data in
  prompts*, Settings → AI).
- Extraction can be turned off entirely (*Extract scammer phone numbers…* under Settings → Scam & fraud).

Bank accounts link to [cekrekening.id](https://cekrekening.id/home) and wallets to a block explorer so an analyst can
look them up by hand; JATMP does not query them (cekrekening.id sits behind a CAPTCHA).

## Dashboard

*Dashboard → Scams & fraud* (`/fraud`) works like the cyber threats dashboard, with the same period switch
(7 days to 1 year) and International / National view:

- **Scam reports over time**, stacked by the five most reported scam types of the period, and a **globe** of the
  most targeted countries (provinces in the National view); click one for its scam reports.
- **Tiles** with sparklines: scam reports against the period before, the largest reported loss (and victim count),
  scam types reported (and how many are spreading this week), brands impersonated and scammer identifiers.
- **Trending scam types** (the period against the one before, with the malware and brands seen alongside and a
  *spreading* badge), **most impersonated brands** and the **latest scammer identifiers**.
- Charts of reports **by scam type**, **by kind of impersonated brand** (banks, e-wallets, couriers, government…),
  **by sector** ([critical infrastructure sectors](analysis.md#critical-infrastructure-sectors)) and **per source**.
- **Recent scam reports**, the **highest fraud scores** and the fraud sources with their status.

## Pages

**Scam reports** are the second feed: *Feed → Scams & fraud* (`/feed/scams`, a tab next to *Cyber threats* on the
Feed page). It lists every scam report, filterable by scam type, brand, sector, minimum fraud score, period and
text (and by target country or province when opened from the globe), sortable by fraud score, loss, victims and
time. The old address `/fraud/items` forwards there with its filters.

The other pages are in the menu's *Intelligence* dropdown, in its scams part:

- **Scam types** and **Brands & people** (impersonated brands and people, with a *Type* filter): the usual entity tables (mentions, sources, trend, first / last seen)
  with the malware and brands or scam types seen alongside.
- **Scammer identifiers**: phone numbers, bank accounts, e-wallets and wallets with the scam types and brands they
  appeared with, where they were seen, and a *Copy* button.

Scam types and brands also appear as chips in the feed, on item pages and in the relationship graph.

## Sources

Scam reports come from every source, and a few are added for this section (topic *scam & fraud*, see
[Sources](sources.md#scam-and-fraud-sources)): FBI IC3 public service announcements, CekFakta.com and Liputan6
Cek Fakta (filtered to scam reports), and ScamSniffer's crypto phishing blocklist. Any source can be given the topic
*scam & fraud* under Settings → Sources → Edit; such sources show on the overview, and a single scam word is
enough there to file an entry under *Other scam*.

Not included, after checking: OJK and Komdigi reject automated clients, turnbackhoax.id was down, OpenPhish forbids
fetching its feed in robots.txt, PhishTank no longer registers new users, the FTC has no feed, Chainabuse needs a
key, and Reddit's r/Scams is mostly victims' own posts (personal data).

## Re-running the analysis

Existing items are analysed once in the background after an upgrade, and again whenever the rules change. To run it
by hand: *Re-analyse items* on the dashboard or under Settings → Scam & fraud, or `python manage.py fraudtag`.
Re-analysis loads items in chunks and only touches the database for items that are, or were, about a scam, so it
runs in about the time it takes to read the items.

## When the analysis is wrong

If an item isn't really about a scam, an analyst or admin can open the fraud-score popover on the item page and
choose **Not a scam report**, with a reason. The fraud score drops to 0, the item's scam types, brands and
identifiers are removed, and it leaves the scam section. The correction stays in force when the analysis is run
again, and it can be undone on the *Corrections* page. A wrong brand or scam type on a real scam report can be
removed with the ✕ next to it. See [Corrections and quality](how-it-works/corrections.md).

## Processing

Collection and analysis are built to stay cheap as the blocklists grow: the indicators of an item are looked up and
created with one query per indicator type (a ScamSniffer day with hundreds of domains costs a handful of queries),
blocklist verdicts are written in bulk instead of waiting for the enrichment providers, and the spread velocity of a
scam type is counted once per type and day for a whole collection batch. Fact-check feeds are filtered to scam
reports before anything is stored.
