# Security

[← Documentation index](README.md)

- **Content-Security-Policy.** Scripts load only from the application's origin plus a per-request nonce for the
  few inline blocks; there are no inline event handlers, and Chart.js is vendored under `app/static/js/vendor`.
  `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP and
  `Cache-Control: no-store` are set on every page.
- **Untrusted feed content.** HTML is stripped and entities are decoded on ingest. Item URLs are kept only when
  they use `http(s)`, so a feed cannot smuggle a `javascript:` link into the UI. Markdown returned by the LLM is
  rendered with raw HTML disabled.
- **Sessions and authentication.** Signed cookie sessions (`SameSite=Lax`, `HttpOnly`), CSRF synchroniser
  tokens on every POST, PBKDF2-HMAC-SHA256 with 600k iterations (older hashes are upgraded on login), a
  15-minute lockout after five failed logins per username and IP, open-redirect-safe `next` handling and a
  session reset on login.
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
- API keys entered in the UI are stored in the local database. On shared hosts prefer environment variables,
  which lock the corresponding fields. `data/config.json` holds the session secret and is written with mode
  `0600`.
- When exposing the platform beyond localhost, run it behind a TLS-terminating reverse proxy and set
  `JATMP_SECURE_COOKIES=1`.
