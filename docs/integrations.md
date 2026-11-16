# Sharing and integrations

[← Documentation index](README.md)

How other tools read data out of JATMP, how JATMP pushes data out, and the rules that decide what may leave.

## REST API v1

`/api/v1/…`, with a reference at `/api/v1/docs` that is served offline. Read-only endpoints for items,
entities, indicators and trends with cursor pagination and `since` filters, so SIEMs, TIPs and scripts can poll
incrementally. Authentication is a personal API key (`Authorization: Bearer jatmp_…`) created under **Profile →
API keys** with scopes (`read`, `export`), an expiry, a per-key rate limit and revocation; only a hash of the key
is stored. Browser sessions work too.

Items that are scam reports carry a `fraud` object (`score`, `loss_idr`, `victims`, `scam_types`, `brands`, and
`detail` on single items). Scammer identifiers (phone numbers, bank accounts, e-wallets, crypto wallets) are never
part of the API, the feeds, STIX / TAXII, webhooks or MISP pushes; see [Scams and fraud](fraud.md).

## IOC export feeds

`/api/v1/feeds/iocs.csv`, `.json` and `.txt`, filtered by type, verdict (default
*malicious*), family, age and a 0–100 confidence that grows with the number of providers agreeing. The `.txt`
feed has one value per line and works as a firewall or proxy blocklist (for example a Palo Alto EDL or a
FortiGate threat feed).

## STIX 2.1 and TAXII 2.1

`/api/v1/stix/bundle`, `/stix/items/<id>` and `/stix/entities/<id>` export
reports, malware, intrusion sets, vulnerabilities, attack patterns and indicators (STIX patterns, `indicates`
relationships, TLP markings); the *⇩ STIX* button on item and entity pages downloads the same. A read-only
TAXII 2.1 server at `/taxii2/` offers two collections, *indicators* and *reports*, with `added_after`,
pagination and `match[type]`, so OpenCTI, MISP, Sentinel or Splunk can subscribe. TAXII clients authenticate with
an API key as Bearer token or as the HTTP Basic password. Object ids are stable per install, so consumers update
objects instead of duplicating them.

## Webhooks

Configured under Settings → Webhooks. Events: new high-severity item, watched entity mentioned, indicator turned malicious,
job failed. Generic receivers get signed JSON (`X-JATMP-Signature: sha256=HMAC(secret, "<timestamp>.<body>")`);
Slack, Discord and Teams get ready-made messages. Deliveries retry with back-off and are listed with their status.

## MISP, both ways

A *MISP events* source pulls events (attributes become indicators, galaxy clusters become
actors and families, the event TLP is kept). *Send to MISP* on item and family / actor pages creates an event with
TLP and family tags and the indicators as attributes, and new items above a severity threshold can be pushed
automatically. Events that came from MISP are never pushed back.

## Sharing rules

Everything above goes through one set of rules: items carry a TLP (their own, from OTX or
MISP, or their source's), and only items up to the configured maximum (default TLP:GREEN) leave JATMP. Sources
can be marked "not shared" (ANY.RUN and ransomware.live are by default, because of their terms), and
third-party provider details stay in-house unless an admin enables them; JATMP's own verdict is always shared.

## Dark web (tier 1)

Clearnet aggregators only: JATMP never visits leak sites or forums, logs in anywhere, solves CAPTCHAs or
downloads leaked data. **Deep dive** on a ransomware family or actor page asks ransomware.live for the group's
leak-site victims (count, countries, sectors, recent victims, CVEs it exploits, tools) and links the CVEs. On a
domain page it asks Hudson Rock how many employees and users of that domain were infected by infostealers
(counts only, never credentials). ransomware.live's keyless API is for personal use only, so organisations
should add the free PRO key; the ransomware.live sources are seeded disabled for that reason.
