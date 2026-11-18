# Security

[← Documentation index](README.md)

- **Content-Security-Policy.** Scripts load only from the application's origin plus a per-request nonce for the
  few inline blocks; there are no inline event handlers, and Chart.js is vendored under `app/static/js/vendor`.
  `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP and
  `Cache-Control: no-store` are set on every page.
- **Untrusted feed content.** HTML is stripped and entities are decoded on ingest. Item URLs are kept only when
  they use `http(s)`, so a feed cannot smuggle a `javascript:` link into the UI. Markdown returned by the LLM is
  rendered with raw HTML disabled. The text cleaners avoid nested quantifiers and are tested against hostile
  input, so one crafted article cannot hang a collector thread (regular-expression denial of service).
- **Outbound requests.** Feeds, intel providers, the AI, MISP and the GeoIP download only reach public addresses.
  The check runs on every redirect hop, and the connection goes to the address that was checked, so a DNS
  rebinding name cannot swap in `127.0.0.1` afterwards. Private hosts that JATMP should reach (an internal MISP, a
  self-hosted RSS-Bridge) are listed under Settings → Sharing → *Private hosts JATMP may contact*; a local AI
  server is added there when you save the AI tab in local mode. Response bodies are capped after decompression
  (20 MB by default), so a huge feed or a gzip bomb is refused instead of filling the memory.
- **AI output is advisory.** Article text is attacker-controlled, and so is whatever a model reads out of it. The
  AI summary may raise an item's severity by at most 20 points, listed as *AI assessment* in the breakdown; it may
  link known families and actors, but a new family only when another source already reported it; AI-proposed
  entities and tags carry an *AI* badge.
- **Exports.** CSV reports and the CSV IOC feed prefix text cells that start with `=`, `+`, `-` or `@` with an
  apostrophe, so a feed title cannot run as a spreadsheet formula.
- **Manual lookups.** Enrichment, context lookups, deep dives and AI summaries started from the UI are limited per
  user and minute and run once per entity at a time; *Run now* on a source does nothing while that source runs.
- **Sessions and authentication.** Signed cookie sessions (`SameSite=Lax`, `HttpOnly`), CSRF synchroniser
  tokens on every POST, PBKDF2-HMAC-SHA256 with 600k iterations (older hashes are upgraded on login), a
  15-minute lockout after five failed logins per username and IP, open-redirect-safe `next` handling and a
  session reset on login. Changing a password (or *Sign out other sessions* on the profile page) ends every other
  session of that user; an admin resetting a password ends that user's sessions.
- **First-run setup.** Before installation the wizard is open, and whoever finishes it becomes the admin. From the
  machine itself that needs nothing; from any other address (another host, a Docker port mapping) the wizard also
  asks for a one-time setup token, printed in the log at start-up and stored in `data/setup-token` until the
  install is done.
- **Settings hygiene.** Secret values are never sent back to the browser (only "configured" or "not set"),
  numeric settings are clamped so the VirusTotal throttle cannot be disabled by accident, and source URLs must
  be `http(s)`.
- **Outbound API.** API keys are 256-bit random secrets of which only a SHA-256 is stored; they carry scopes,
  expire, can be revoked by their owner or an admin, and are rate limited per key. Key creation, revocation and
  feed downloads are written to the audit log. Bearer requests need no CSRF token; every cookie-authenticated
  POST still does.
- **Webhooks.** Targets must resolve to public addresses (checked when saved and again before each delivery;
  redirects are not followed) unless an admin allows private ones. Signing secrets are derived from the session
  secret and a per-hook salt, so the database holds nothing that could forge a signature.
- **GeoIP download.** The offline GeoIP database is fetched from download.db-ip.com (or download.maxmind.com with
  a license key) only when an admin asks for it or the monthly refresh is switched on; a download that is not a
  valid database is discarded. IP lookups themselves never leave the host.
- **Sharing.** TLP and per-source redistribution flags gate the API, exports, webhooks and MISP pushes (see
  [Sharing and integrations](integrations.md#sharing-rules)).
- API keys entered in the UI (provider keys, the AI key, the Telegram session) are stored **encrypted** in the
  local database (Fernet, with a key derived from the secret in `data/config.json`). A copy of the database alone
  does not reveal them; **back up `data/config.json` together with the database**, or the keys have to be entered
  again. On shared hosts prefer environment variables, which lock the corresponding fields. `data/config.json`
  holds the session secret and is written with mode `0600`.
- **Dependencies.** `requirements.lock` pins every package; Docker and CI install with it, CI runs `pip-audit`
  against it, and Dependabot proposes updates weekly.
- `/healthz` (unauthenticated) reports liveness only, not the version.
- When exposing the platform beyond localhost, run it behind a TLS-terminating reverse proxy and set
  `JATMP_SECURE_COOKIES=1`.

## Personal data in scam reports

Scam reports can contain phone numbers and bank accounts. JATMP takes them only from scam reports and only where the
text marks them as the scammer's, skips official and victims' numbers, never stores account holder names, deletes
them after a year without mentions, and never shares them through the API, feeds, STIX / TAXII, webhooks or MISP.
Details in [Scams and fraud](fraud.md#scammer-identifiers-and-personal-data-uu-pdp).

Prompts to a **cloud** AI model have phone numbers, bank accounts, e-wallets, e-mail addresses and long ID numbers
replaced with placeholders first (*Personal data in prompts* under Settings → AI); see
[AI processing](how-it-works/ai.md#what-leaves-your-network).

## Telegram session

The optional MTProto session string (`telegram_session`) gives full access to the Telegram account it was created
with. It is stored like the other secrets (never shown in the UI, never logged); prefer `TELEGRAM_SESSION` in the
environment on shared hosts, use a separate account, and end the session from Telegram's *Active sessions* list if
the database leaks. The web-preview mode needs no account at all.
