# Using JATMP

[← Documentation index](README.md)

Install modes and roles, the shared table design and side preview, job status and notifications.

## Install modes and roles

JATMP installs in **single-user** mode (no login) or **multi-user** mode with admin, analyst and viewer roles,
user management, job status and an audit log. Users keep a personal watchlist, and the interface offers a dark
and a light theme, a `/` shortcut for search, a phone layout, retention tiers and a Docker image
with a health check.

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
enrichment runs, the VirusTotal daily quota being used up and the AI digest being ready. Notifications are kept
for 30 days.
