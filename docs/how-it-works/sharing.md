# Sharing and delivery

[← How JATMP works](index.md)

This page explains the rules that decide what may leave JATMP, and how webhooks and MISP pushes are produced and
delivered. The interfaces themselves (REST API, IOC feeds, STIX / TAXII, MISP) are described in
[Sharing and integrations](../integrations.md). The code is in `app/sharing.py`, `app/webhooks.py` and
`app/intel/misp.py`.

## One gate for everything that leaves

The REST API, the IOC feeds, STIX bundles and TAXII collections, webhooks and MISP pushes all ask the same module,
`app/sharing.py`, whether an item or indicator may leave. It applies three independent checks, and all three must
pass.

### 1. TLP

Every item has an **effective TLP**, worked out in this order:

1. the item's own TLP, if the feed provided one (OTX pulses, MISP events);
2. otherwise, the TLP of its source (set under Settings → Sources);
3. otherwise, **CLEAR**.

Values are normalised, so `tlp:amber` becomes AMBER, WHITE becomes CLEAR and AMBER+STRICT becomes AMBER. An item
may be shared when its effective TLP is **at or below** the `api_max_tlp` setting (**GREEN** by default). With
the default, AMBER and RED items never leave JATMP.

Because a source without a TLP counts as CLEAR, its items are shared. To make that a deliberate choice, the
*Add source* form asks for a TLP and tells you whether the source's items will be shared, and Settings → Sharing
shows how many sources have no TLP set.

### 2. Redistribution

Some providers' terms don't allow their data to be passed on, so each source has a "share outside JATMP" flag:

| Flag | Meaning |
|---|---|
| Not set | The default for the source type: everything is shared except **ANY.RUN** (provider terms) and **ransomware.live** (victim names stay in-house) |
| On / off | Set by an admin, overriding the default |

Items from a source that may not be redistributed are never shared, whatever their TLP.

**Provider details**, meaning the answers from VirusTotal, ANY.RUN and the other enrichment providers (summaries,
scores, raw data), only leave when an admin switches on `api_share_provider_details`. JATMP's **own** combined
verdict can always be shared.

### 3. Personal data

Scammer identifiers (phone numbers, bank accounts, e-wallets and crypto wallets) **never** leave JATMP. They are
excluded from the API (asking for one by its id returns 404), the IOC feeds, STIX / TAXII, webhooks (even when
someone watches one) and MISP pushes. See
[Scams and fraud](../fraud.md#scammer-identifiers-and-personal-data-uu-pdp).

### When can an indicator be shared?

An indicator can be shared when **at least one shareable item mentions it**, or when it was linked by a provider
whose data may be passed on (OTX, ThreatFox, MalwareBazaar, URLhaus, MISP). For example, an IP that only ever
appeared in an ANY.RUN task or an AMBER pulse is not exported, but the same IP mentioned in a public news article
is.

On top of that, the IOC export feeds and TAXII leave out IPs, domains and URLs whose *malicious* or
*suspicious* verdict is older than `verdict_feed_days` (60 by default) and hasn't been confirmed since. That way a
blocklist built from JATMP doesn't keep blocking addresses that have changed hands. See
[Verdicts that age](enrichment.md#verdicts-that-age).

## Webhooks

### Events

| Event | Sent when | What it contains |
|---|---|---|
| `item.high_severity` | A collection run stores an item with a severity of **at least `webhook_min_severity`** (default 70) | The item: id, title, URL, severity, source and source type, TLP, publication time, up to 10 families / actors / CVEs, and a link into JATMP when `public_base_url` is set |
| `entity.watched` | A new item mentions an entity that **any** user is watching (scammer identifiers excepted) | The item, plus the watched entity |
| `ioc.malicious` | An indicator's verdict turns *malicious* during enrichment | The indicator, with a link to it |
| `job.failed` | Any **error** notification is created: a source starts failing or has been failing for a day, an enrichment run fails, or the AI summary or a MISP push fails | The notification's title and text |

Item events are only sent for **shareable** items, and only during **live** collection: backfills send none.
When ThreatFox adds new IOCs to an item it already stored, no new event is sent. A manual collection batch with
failures produces a *warning* notification rather than an error, so it doesn't trigger `job.failed`. The
failure notifications of scheduled runs do.

### From event to delivery

1. **Queue.** For every enabled webhook subscribed to the event, a delivery is saved as `pending`, with the
   payload `{"event", "created_at", "data"}`. Item events are queued right after the collection run has stored
   its items; the indicator event is queued in the same transaction as the new verdict.
2. **Deliver.** `run_webhooks` runs every **30 seconds** and sends up to **50** due deliveries, oldest first,
   saving the result after each one.
3. **Format.** *Generic* webhooks receive the payload as JSON. *Slack*, *Discord* and *Teams* webhooks receive a
   ready-made message: a title, a line with source, severity and entities, and an *Open* link.
4. **Sign.** Every request carries `X-JATMP-Event`, `X-JATMP-Delivery` (the delivery id), `X-JATMP-Timestamp` and
   `X-JATMP-Signature: sha256=<HMAC-SHA256(secret, "<timestamp>.<body>")>`. The secret is derived from the
   installation's secret key and the webhook's salt, so it is never stored in the database.
5. **Send.** The request has a 10-second timeout, doesn't follow redirects, and goes through the outbound guard:
   private and loopback addresses are refused unless *allow private webhook targets* is on, and the connection is
   made to the address that was checked (so the name can't be switched to a different address in between).
6. **Retry.** A 2xx response marks the delivery `ok`. Anything else is retried after **1 minute, 5 minutes,
   30 minutes and 2 hours**. If the fifth attempt also fails, the delivery is marked `failed`. Each webhook shows
   its last status.

Deliveries older than 30 days are deleted by the nightly housekeeping.

### Checking a webhook on the receiving side

Recalculate `HMAC-SHA256(secret, timestamp + "." + raw_body)` and compare it with the signature, using a
constant-time comparison. Reject requests whose timestamp is more than a few minutes old, to prevent replays, and
use `X-JATMP-Delivery` to ignore a delivery you have already processed: a retry after a timeout can arrive twice.

## MISP push

| How | What is pushed |
|---|---|
| *Send to MISP* on an item | One event for the item: its title, TLP and family tags, with its indicators as attributes |
| *Send to MISP* on a family or actor page | One event for the entity, with its indicators |
| Auto-push | After each live collection run, every new item with a severity of at least `misp_autopush_min_severity` (0 = off) |

An item is refused if it came **from** MISP (it is never pushed back), or if the sharing rules don't allow it. An
item that has already been pushed isn't pushed again (the event is recorded on the item). Auto-push runs as its
own job after the collection run, and a failure creates an error notification (at most one a day).

## Requests JATMP makes on its own

Everything above is data JATMP *publishes*. JATMP also *requests* data: feeds, intel providers, CVE intel, the AI
and GeoIP updates. All of those requests go through the outbound guard (`netguard`): only public addresses
(unless a host is on the private allow-list), every redirect checked, the connection made to the address that
was checked, and responses capped at 20 MB after decompression. Each request only *sends* what the lookup needs:
an indicator to an intel provider, a CVE id to EPSS and the NVD, and, only when a cloud AI is configured, the
prompts described in [AI processing](ai.md#what-leaves-your-network), with personal data replaced.
