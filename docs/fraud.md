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
| **Scam type** | A fixed taxonomy in English and Bahasa Indonesia: investment scam (incl. *investasi bodong*, robot trading, pig butchering), illegal online loan (*pinjol ilegal*), job / task scam, romance scam, sextortion, malicious APK lure (wedding invitations, traffic tickets, bills), courier / package lure, impersonation, phishing, OTP theft / account takeover, online gambling (*judol*), fake shop, prize / giveaway (incl. fake *bansos*), crypto scam / drainer, tech support / refund scam, BEC / invoice fraud, QRIS / QR code fraud, deepfake scam, and *Other scam*. Strong phrases count on their own; weaker ones ("phishing", "APK", "deepfake", "mengatasnamakan") only when the item also uses a scam word, so ordinary malware reporting stays out. Newsletters and weekly round-ups are judged on their title only. |
| **Impersonated brand** | About 70 banks, e-wallets, marketplaces, couriers, telecoms, utilities, government bodies, platforms and crypto exchanges, Indonesian first (BCA, BRI, Bank Mandiri, BNI, DANA, OVO, GoPay, Shopee, J&T, PLN, OJK, BPJS, DJP, Bea Cukai…). A brand counts when it appears next to an impersonation cue ("mengatasnamakan BCA", "fake PayPal") or in the title of a scam report. Platforms and government bodies need the cue right next to them, because they are usually the channel ("lewat WhatsApp") or the one issuing the warning ("FBI warns…"). Ambiguous words are matched carefully: *dana* (funds) is not DANA, *mandiri* (independent) is not Bank Mandiri. |
| **Scammer identifiers** | Phone numbers (Indonesian mobile numbers normalised to `+628…`), bank accounts (with the bank when it is named), e-wallet numbers and crypto wallets (BTC, ETH, TRON). See the rules below. |
| **Losses and victims** | The largest loss a report states, converted to rupiah (dollar amounts at the rate set under Settings → Scam & fraud), and the largest victim count ("1.200 korban", "ratusan korban", "thousands of victims"). Amounts only count next to a loss word, so prices and fees are ignored, and money that was saved, frozen or returned is not a loss. |

## Fraud score

Each scam report gets a **fraud score** from 0 to 100, separate from the threat severity and explained the same way
(click the score on the item page, or see the side preview):

| Part | Points |
|---|---|
| Scam type (the strongest one) | 10–28, e.g. malicious APK lure 28, investment scam 26, OTP theft 24, phishing 18, online gambling 12 |
| More scam types in the same report | +4 each, up to +8 |
| Impersonated bank, e-wallet or government body / other brand | +10 / +6 |
| Reported losses | +5 below Rp 100 million, up to +30 from Rp 1 trillion |
| Reported victims | +5 from 10, up to +20 from 10,000 |
| Scammer identifiers published | +8 |
| Official warning or law enforcement (OJK, Satgas PASTI, IASC, police, FBI / IC3, FTC, BSSN, arrests) | +8 |
| Spreading: at least 5 reports of the same scam type this week and twice as many as the week before | +8 |

## Scammer identifiers and personal data (UU PDP)

Phone numbers and bank accounts are personal data under Indonesia's Personal Data Protection Law (UU PDP, Law
27/2022). JATMP keeps as little as it can:

- Identifiers are taken **only from items that are about a scam**, and only where the sentence marks them as the
  scammer's (*nomor penipu*, *pelaku menghubungi dari*, *transfer ke rekening*, "texts from"…).
- Numbers the text marks as **official** (call centre, hotline, *resmi*) or as the **victim's** (*nomor milik
  korban*) are skipped.
- **Account holder names are never stored**, only the number (and the bank).
- Phone numbers, bank accounts and e-wallets that no item has mentioned for a year are **deleted** by the nightly
  housekeeping (`fraud_identifier_days`; crypto wallets are not personal data and stay).
- Identifiers **never leave JATMP**: they are left out of the REST API, the IOC feeds, STIX / TAXII, webhooks
  (also for watched identifiers) and MISP pushes.
- Extraction can be turned off entirely (*Extract scammer phone numbers…* under Settings → Scam & fraud).

Bank accounts link to [cekrekening.id](https://cekrekening.id/home) and wallets to a block explorer so an analyst can
look them up by hand; JATMP does not query them (cekrekening.id sits behind a CAPTCHA).

## Pages

- **Overview**: scam reports this week, the largest reported loss and victim count, brands impersonated and
  identifiers in the last 30 days, a scam-type table with this week against last week (and the malware and brands
  seen with each type), the most impersonated brands, recent and highest-scoring reports, the latest identifiers and
  the fraud sources with their status.
- **Scam reports**: every scam report, filterable by scam type, brand, minimum fraud score, period and text,
  sortable by fraud score, loss, victims and time.
- **Scam types** and **Impersonated brands**: the usual entity tables (mentions, sources, trend, first / last seen)
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
by hand: *Re-analyse items* on the overview or under Settings → Scam & fraud, or `python manage.py fraudtag`.
