# Known limitations

[← Documentation index](README.md)

What JATMP 1.0 does not do, or does only in part, so you can plan around it. Most of these are on the roadmap;
issues and pull requests are welcome.

## Scale

- **One process.** The web server, the scheduler and every collector run in a single Python process with one
  web worker, because the scheduler lives in-process (running more workers makes collectors run twice). With
  SQLite there is one writer at a time; long backfills and many sources compete for it. PostgreSQL helps with
  writes ([History and storage](history-and-storage.md#postgresql)) but the single process stays.
- **No published load figures.** There are no run-time or queue-length metrics yet beyond the job status, the
  source health view and the enrichment queue on the IOC page, and no tested ceiling for sources or items per day.
  The default set (about 80 enabled sources) runs on a small host.
- **Enrichment throughput follows your API quotas.** With free tiers, a few hundred to about 1,400 indicators a
  day are looked up; busy intel feeds bring in more, so older indicators wait. See
  [Enrichment and verdicts](how-it-works/enrichment.md).

## Collection

- **Feed text only.** RSS items are analysed from what the feed carries; JATMP does not open the article page.
  Outlets that publish only a short summary yield fewer entities and lower scores. The source health view shows
  which sources are summary-only.
- **X needs an API token** (or an RSS bridge), and the free API tier is small. Instagram, TikTok and dark web
  forums and markets (beyond the tier-1 ransomware leak sites and infostealer statistics) are not collected.
- **Provider terms apply.** Some free APIs are for personal use only (ransomware.live without its PRO key). See
  [Third-party notices](https://github.com/fj4rr/just-another-threat-monitoring-platform/blob/main/THIRD_PARTY_NOTICES.md).

## Analysis

- **Rule-based detection.** Entities, severity, scam types, sectors and geography come from rules and a knowledge
  base, not a trained model. The quality report measures them on a hand-written set of about 170 cases; those
  numbers are what the rules were tuned on, not accuracy on live data. Analyst corrections are the real signal:
  report wrong or missed detections with the *Wrong or missed detection* issue form.
- **Geography** recognises countries, nationalities and Indonesian provinces, cities and regencies. Cities outside
  Indonesia are not recognised ([Geography](geography.md)).
- **Languages:** the rules are written for English and Bahasa Indonesia. Items in other languages are collected,
  but their keywords and scam phrases are not recognised (indicators and CVEs still are).

## AI

- **Q&A finds items by words**, through the full-text index plus the entities, malware categories and sectors a
  question names, not by meaning (no embeddings). A question in different words from the articles can miss them. Answers cite the items they
  used ([Reporting and AI](reporting-and-ai.md)).
- **AI output is advisory** and bounded by design (at most +20 severity, no new family on its own); see
  [Security](security.md).

## Sharing and users

- **Watched-entity webhooks are not per user.** When any user watches an entity, every webhook subscribed to
  `entity.watched` fires for it, so one user's watchlist reaches channels set up by others. Keep that event to
  channels the whole team shares.
- **No single sign-on.** Multi-user mode has local accounts with three roles (admin, analyst, viewer); there is no
  LDAP, SAML or OIDC, and no two-factor login. Put a reverse proxy with its own authentication in front if you
  need either.
- **The REST API is read-only** (the `write` scope is reserved).
