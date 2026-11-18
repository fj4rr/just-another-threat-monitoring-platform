# Sharing and delivery

[← How JATMP works](index.md)

The rules that decide what may leave JATMP, and how webhooks and MISP pushes are produced and delivered. The
interfaces themselves (REST API, IOC feeds, STIX / TAXII, MISP) are described in
[Sharing and integrations](../integrations.md). Code: `app/sharing.py`, `app/webhooks.py`, `app/intel/misp.py`.

## One gate for everything outbound

The REST API, the IOC feeds, STIX bundles and TAXII collections, webhooks and MISP pushes all ask the same module,
`app/sharing.py`, whether an item or indicator may leave. There are three independent checks.

### 1. TLP

Every item has an **effective TLP**:

1. its own TLP, when the feed gave one (OTX pulses, MISP events);
2. otherwise its source's TLP (set under Settings → Sources);
3. otherwise **CLEAR**.

Values are normalised (`tlp:amber` → AMBER, WHITE → CLEAR, AMBER+STRICT → AMBER). An item is shareable when its
effective TLP is **at or below** the `api_max_tlp` setting (default **GREEN**). With the default, AMBER and RED
items stay inside JATMP.

### 2. Redistribution

Some providers' terms forbid passing their data on. A source has a `redistribute` flag:

| Flag | Meaning |
|---|---|
| Not set | Default for the kind: every kind is shared except **ANY.RUN** (provider terms) and **ransomware.live** (victim names stay in-house) |
| On / off | Set by an admin; overrides the default |

Items from a source that may not be redistributed are never shared, whatever their TLP.

**Provider details** — the enrichment answers of VirusTotal, ANY.RUN and the others (summaries, scores, raw data)
— only leave when an admin turns on `api_share_provider_details`. JATMP's **own** consensus verdict is always
shareable.

### 3. Personal data

Scammer identifiers (phone numbers, bank accounts, e-wallets, crypto wallets) **never** leave: they are excluded
from the API (a request for one by id returns 404), the IOC feeds, STIX / TAXII, webhooks (also when someone
watches one) and MISP pushes. See [Scams and fraud](../fraud.md#scammer-identifiers-and-personal-data-uu-pdp).

### When is an indicator shareable?

An indicator is shareable when **at least one shareable item mentions it**, or when it was linked by a provider
whose data may be redistributed (OTX, ThreatFox, MalwareBazaar, URLhaus, MISP). An IP that only ever appeared in
an ANY.RUN task or an AMBER pulse is not exported; the same IP mentioned in a public news article is.

## Webhooks

### Events

| Event | Produced when | Payload |
|---|---|---|
| `item.high_severity` | A collection run stores an item with severity **≥ `webhook_min_severity`** (default 70) | The item: id, title, URL, severity, source and source type, TLP, publication time, up to 10 families / actors / CVEs, and a link into JATMP when `public_base_url` is set |
| `entity.watched` | A new item mentions an entity that **any** user watches (scammer identifiers excepted) | The item, plus the watched entity |
| `ioc.malicious` | An indicator's verdict turns *malicious* in enrichment | The indicator and a link to it |
| `job.failed` | Any **error** notification is created: a source starts failing, an enrichment run fails, the AI summary or a MISP push fails | The notification's title and text |

Item events are only produced for **shareable** items and for **live** collection: backfills produce none. A
manual collection batch with failures produces a *warning* notification, not an error, so it does not fire
`job.failed`; the per-source failure notification of scheduled runs does.

### From event to delivery

1. **Emit.** For every enabled webhook subscribed to the event, a `webhook_deliveries` row is written with status
   `pending` and the payload `{"event", "created_at", "data"}`. Item events are written right after the
   collection run has stored its items; the indicator event in the same transaction as the new verdict.
2. **Deliver.** `run_webhooks` runs every **30 seconds** and sends up to **50** due deliveries, oldest first,
   committing after each one.
3. **Format.** *Generic* hooks get the payload as JSON. *Slack*, *Discord* and *Teams* hooks get a ready-made
   message (title, a detail line with source, severity and entities, and an *Open* link).
4. **Sign.** Every request carries `X-JATMP-Event`, `X-JATMP-Delivery` (the delivery id), `X-JATMP-Timestamp` and
   `X-JATMP-Signature: sha256=<HMAC-SHA256(secret, "<timestamp>.<body>")>`. The secret is derived from the install
   secret and the hook's salt, so it is not stored in the database.
5. **Send** with a 10-second timeout, **no redirects**, through the outbound guard: private and loopback
   addresses are refused unless *allow private webhook targets* is on, and the connection goes to the address
   that was checked (no DNS rebinding between check and send).
6. **Retry.** A 2xx response marks the delivery `ok`. Anything else is retried after **1 minute, 5 minutes,
   30 minutes and 2 hours**; the fifth failure marks it `failed`. The hook shows its last status.

Deliveries older than 30 days are deleted by the nightly housekeeping.

### Verifying a webhook on the receiving side

Recompute `HMAC-SHA256(secret, timestamp + "." + raw_body)` and compare it to the signature in constant time.
Reject requests whose timestamp is more than a few minutes old to prevent replays, and use `X-JATMP-Delivery` to
ignore a delivery you already processed (a retry after a timeout can arrive twice).

## MISP push

| Way | What is pushed |
|---|---|
| *Send to MISP* on an item | One event for the item: title, TLP and family tags, its indicators as attributes |
| *Send to MISP* on a family or actor page | One event for the entity with its indicators |
| Auto-push | After each live collection run, every new item with severity **≥ `misp_autopush_min_severity`** (0 = off) |

An item is refused when it came **from** MISP (never pushed back), or when the sharing rules forbid it. An item
that was already pushed is not pushed again (the event is recorded in the item's `raw`). Auto-push runs as its own
job after the collection run; a failure creates an error notification (at most one per day).

## Outbound requests JATMP makes on its own

Everything above is data JATMP *publishes*. JATMP also *requests* data — feeds, providers, CVE intel, the AI,
GeoIP updates. Each of those requests goes through `netguard`: public addresses only (unless a host is put on the
private allow-list), every redirect hop checked, the connection made to the checked address, and response bodies
capped at 20 MB after decompression. What each request *sends* is limited to what the lookup needs: an indicator
value to an intel provider, a CVE id to EPSS and the NVD, and — only with a cloud AI configured — the prompts
described in [AI processing](ai.md#what-leaves-your-network).
