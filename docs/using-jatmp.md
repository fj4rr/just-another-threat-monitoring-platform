# Using JATMP

[← Documentation index](README.md)

Install modes and roles, the dashboard, the shared table design and side preview, job status and notifications.

## Install modes and roles

JATMP installs in **single-user** mode (no login) or **multi-user** mode with admin, analyst and viewer roles,
user management, job status and an audit log. Users keep a personal watchlist, and the interface offers a dark
and a light theme, a `/` shortcut for search, a phone layout, retention tiers and a Docker image
with a health check.

## Dashboards

The sidebar starts with two dashboards: **Cyber threats** (`/`) and **Scams & fraud** (`/fraud`, see
[Scams and fraud](fraud.md#dashboard)). The detail pages sit under *Intelligence*: Malware, Threat actors, CVEs and
IOCs for cyber threats; Scam reports, Scam types, Impersonated brands and Scammer identifiers for scams.

**Period.** Both dashboards cover 7 days by default; the switch under the title picks 15 days, 30 days, 3 months,
6 months or 1 year, and everything on the page follows it (tiles, tables, charts, radar, globe). The choice is
remembered for your session. Charts use weekly bars above 90 days. The live collectors only see what sources list
right now, so older days hold only what was backfilled; for periods beyond 7 days (or older than the install) the
dashboard says so, counts the backfilled items in the period and links admins to the Backfill page, where each
source shows how far back it can reach ([History and storage](history-and-storage.md#backfill)).

The cyber threats dashboard, from top to bottom:

- **Threat radar** and **globe**. The radar shows trending malware families (bug icon), CVEs (broken shield) and threat
  actors (hooded hacker): the closer to the centre, the higher the trend score; the larger, the more mentions; a
  dashed ring marks entries first seen in the period. The buttons in the card head hide or show a type. The globe
  shows the top 10 target countries of the period (Indonesian provinces in the National view). It turns
  from one to the next and shows each one's count and the families and actors named there. Drag it to turn it,
  hover a country for its count, click one to open its feed, or use the numbered buttons, + / − and ⟲. Pointing
  at the globe pauses the tour, and ▶ / ❚❚ starts or stops it.
- **KPI tiles**: items collected, IOCs seen, active malware families, threat actors and CVEs discussed in the
  period, each against the period before and with a sparkline.
- **Executive summary**, only when an LLM is configured ([Reporting and AI](reporting-and-ai.md#ai-optional)).
- **Collection volume** per day (or week) and source type.
- **Trending malware**, **Trending CVEs** and **Trending threat actors**, each scrolling on its own. Hover the
  CVSS, EPSS and priority headers for what they mean.
- **Top 5 trending over time**, with a dropdown for families, CVEs or actors, next to **Sectors (IIV)**: items per
  vital information infrastructure sector ([Analysis](analysis.md#sectors-iiv)); click a bar for its items.
- **Malware by type**, **CVEs by exploitation risk** and **Threat actors by type**.
- **Notable recent items** (severity 30 and up), next to **Items per source** and **IOC verdicts**.

## Tables and preview

The Feed, IOC, Malware, Threat actor and CVE lists share one table design: sortable
headers that stay visible while scrolling, a bold primary column with a secondary line and a row of related
entities, the same period filter (24 hours to 1 year, or all time), a Reset button and pagination. Clicking a
title opens a **side preview** with the essentials (severity breakdown, AI summary, indicators and their
verdicts, provider results, related items); ↑ / ↓ (or j / k) move to the previous or next row, Esc closes it,
*Full page* opens the detail page in a new tab and the URL (`?preview=item:12`) can be shared. Ctrl / Cmd /
middle-click still open the page itself.

## Job status and notifications

Under *Collect now* and *Enrich now* the dashboard shows when each job last
ran and when it runs next, and a live progress bar while it runs ("Collecting… 12/50 sources · 8 new"); the
button stays disabled until the run finishes. The bell in the top bar collects the results: one summary per
manual collection ("Collected 42 new items from 50 sources, 2 errors"), sources that start failing, failed
enrichment runs, the VirusTotal daily quota being used up and the AI executive summary being ready. Notifications are kept
for 30 days.
