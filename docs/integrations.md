# Sharing and integrations

[← Documentation index](README.md)

This page explains how other tools read data out of JATMP, how JATMP pushes data out, and the rules that decide
what may leave. The rules themselves are described step by step in
[Sharing and delivery](how-it-works/sharing.md).

## REST API v1

The REST API lives under `/api/v1/…`, with a reference at `/api/v1/docs` that works offline. Its read-only
endpoints cover items, entities, indicators and trends, with cursor pagination and `since` filters, so SIEMs,
TIPs and scripts can poll for what is new.

To authenticate, create a personal API key under **Profile → API keys** and send it as
`Authorization: Bearer jatmp_…`. Each key has scopes (`read`, `export`), an expiry date and its own rate limit,
and can be revoked at any time. JATMP only stores a hash of the key. Browser sessions work too.

Items that are scam reports include a `fraud` object (`score`, `loss_idr`, `victims`, `scam_types`, `brands`,
plus `detail` on single items). Indicators include `verdict_at`, the date their verdict was last given or
confirmed. Scammer identifiers (phone numbers, bank accounts, e-wallets and crypto wallets) are never part of
the API, the feeds, STIX / TAXII, webhooks or MISP pushes; see [Scams and fraud](fraud.md).

## IOC export feeds

`/api/v1/feeds/iocs.csv`, `.json` and `.txt` export indicators. You can filter them by type, verdict (*malicious*
by default), family, age, and a confidence from 0 to 100 that grows with the number of providers that agree. The
`.txt` feed has one value per line, so it works as a firewall or proxy blocklist (a Palo Alto EDL or a FortiGate
threat feed, for example).

IPs, domains and URLs whose malicious verdict hasn't been confirmed for 60 days are left out of the feeds, so a
blocklist built from them doesn't keep blocking addresses that have changed hands. See
[Verdicts that age](how-it-works/enrichment.md#verdicts-that-age).

## STIX 2.1 and TAXII 2.1

`/api/v1/stix/bundle`, `/stix/items/<id>` and `/stix/entities/<id>` export reports, malware, intrusion sets,
vulnerabilities, attack patterns and indicators (with STIX patterns, `indicates` relationships and TLP markings).
The *⇩ STIX* button on item and entity pages downloads the same thing. IP, domain and URL indicators carry a
`valid_until` date based on when their verdict was last confirmed.

A read-only TAXII 2.1 server at `/taxii2/` offers two collections, *indicators* and *reports*, with
`added_after`, pagination and `match[type]`, so OpenCTI, MISP, Sentinel or Splunk can subscribe. TAXII clients
authenticate with an API key, either as a Bearer token or as the HTTP Basic password. Object ids stay the same
for each installation, so consumers update objects rather than duplicating them.

## Webhooks

Webhooks are set up under Settings → Webhooks. You can subscribe to four events: a new high-severity item, a
watched entity being mentioned, an indicator turning malicious, and a job failing.

Generic receivers get signed JSON (`X-JATMP-Signature: sha256=HMAC(secret, "<timestamp>.<body>")`), while Slack,
Discord and Teams get ready-made messages. Failed deliveries are retried with increasing delays, and every
delivery is listed with its status.

## MISP, both ways

**From MISP:** a *MISP events* source pulls events in. Attributes become indicators, galaxy clusters become actors
and families, and the event's TLP is kept.

**To MISP:** *Send to MISP* on item, family and actor pages creates an event with TLP and family tags and the
indicators as attributes. New items above a severity threshold can also be pushed automatically. Events that came
from MISP are never pushed back.

## Sharing rules

Everything above goes through the same set of rules:

- **TLP.** Every item has a TLP: its own (from OTX or MISP), or its source's, or CLEAR if neither is set. Only
  items up to the configured maximum (TLP:GREEN by default) leave JATMP. When you add a source, the form asks
  for its TLP and tells you whether its items will be shared.
- **Redistribution.** Sources can be marked "not shared". ANY.RUN and ransomware.live are not shared by default,
  because of their terms.
- **Provider details** stay inside JATMP unless an admin enables them. JATMP's own verdict is always shared.

## Dark web (tier 1)

JATMP only uses clearnet aggregators. It never visits leak sites or forums, never logs in anywhere, never solves
CAPTCHAs, and never downloads leaked data.

**Deep dive** on a ransomware family or actor page asks ransomware.live for the group's leak-site victims (count,
countries, sectors, recent victims, the CVEs it exploits, and its tools) and links the CVEs. On a domain page, it
asks Hudson Rock how many employees and users of that domain were infected by infostealers (counts only, never
credentials).

ransomware.live's keyless API is for personal use only, so organisations should add the free PRO key. That is
why the ransomware.live sources start out disabled.
