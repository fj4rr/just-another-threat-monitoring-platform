# Using JATMP

[← Documentation index](README.md)

This page is a tour of the interface: install modes and roles, the dashboards, the tables and side preview, job
status, and notifications.

## Install modes and roles

JATMP installs in one of two modes:

- **Single-user**: no login, one built-in user.
- **Multi-user**: logins with three roles (admin, analyst and viewer), user management, job status and an audit
  log.

In both modes, users keep a personal watchlist, and the interface has a dark and a light theme, a `/` shortcut
for search, and a layout that works on a phone. The Docker image comes with a health check.

## Dashboards

The sidebar starts with two dashboards: **Cyber threats** (`/`) and **Scams & fraud** (`/fraud`, see
[Scams and fraud](fraud.md#dashboard)). The detail pages are under *Intelligence*: Malware, Threat actors, CVEs
and IOCs for cyber threats; and Scam reports, Scam types, Impersonated brands and Scammer identifiers for scams.

### Period

Both dashboards show the last 7 days by default. The switch under the title lets you pick 15 days, 30 days,
3 months, 6 months or 1 year, and everything on the page follows it: tiles, tables, charts, the radar and the
globe. Your choice is remembered for the session, and charts switch to weekly bars for periods over 90 days.

The live collectors only see what sources list right now, so older days only contain what was backfilled. For
periods longer than 7 days (or reaching back before you installed JATMP), the dashboard tells you so, shows how
many backfilled items the period contains, and links admins to the Backfill page, where each source shows how
far back it can go ([History and storage](history-and-storage.md#backfill)).

### What's on the cyber threats dashboard

From top to bottom:

- **Threat radar and globe.** The radar shows trending malware families (bug icon), CVEs (broken shield) and
  threat actors (hooded figure). The closer an entry is to the centre, the higher its trend score; the larger
  it is, the more it was mentioned. A dashed ring marks entries first seen in the period, and the buttons in the
  card header hide or show each type.
  The globe shows the top 10 target countries of the period (Indonesian provinces in the National view). It
  turns from one to the next, showing each one's count and the families and actors named there. Drag it to turn
  it, hover over a country to see its count, click one to open its feed, or use the numbered buttons, + / − and
  ⟲. Pointing at the globe pauses the tour; ▶ / ❚❚ starts or stops it.
- **KPI tiles.** Stories collected, IOCs seen, active malware families, threat actors and CVEs discussed in the
  period, each compared with the period before and with a sparkline. A story that several outlets carry counts
  once; the *Stories collected* tile also shows the item count including copies.
- **Executive summary**, if an AI model is configured ([Reporting and AI](reporting-and-ai.md#ai-optional)).
- **Collection volume** per day (or week) and source type.
- **Trending malware**, **Trending CVEs** and **Trending threat actors**, each scrolling on its own. Hover over the
  CVSS, EPSS and priority column headers to see what they mean.
- **Top 5 trending over time**, with a dropdown for families, CVEs or actors, next to **Critical infrastructure
  sectors**, which shows stories per sector ([Analysis](analysis.md#critical-infrastructure-sectors)). Click a
  bar to see its items.
- **Malware by type**, **CVEs by exploitation risk** and **Threat actors by type**.
- **Notable recent items** (severity 30 and above), next to **Items per source** and **IOC verdicts**.

Every chart and list counts stories the same way. Only *Items per source* counts each outlet's copies, because it
describes what each outlet published. The details are in
[Counting rules](how-it-works/trends.md#counting-rules).

## Tables and preview

The Feed, IOC, Malware, Threat actor and CVE lists all share one table design: sortable headers that stay visible
while you scroll, a bold main column with a second line and a row of related entities, the same period filter
(24 hours to 1 year, or all time), a Reset button, and pagination.

Clicking a title opens a **side preview** with the essentials: the severity breakdown, the AI summary, indicators
and their verdicts (with the date of each verdict), provider results and related items. Use ↑ / ↓ (or j / k) to
move to the previous or next row, and Esc to close it. *Full page* opens the detail page in a new tab, and you can
share the URL (`?preview=item:12`) with a colleague. Ctrl-click, Cmd-click or a middle click still open the page
itself.

**Copies.** When several outlets carry the same article, the first one is the original and the others are
*copies*. The Feed lists each story once and tells you how many copies it left out; tick *Show copies* to list
them too, marked with a *copy* badge. On an item's page and in its preview, a copy says "Copy of …", and the
original says "Also carried by *N* other outlets".

**Indicator verdicts.** Every verdict shows the date it was last given or confirmed ("verdict as of …"). An IP,
domain or URL whose malicious verdict hasn't been confirmed for 60 days is marked *aged* and left out of the
export feeds until a provider confirms it again (see
[Verdicts that age](how-it-works/enrichment.md#verdicts-that-age)).

## Sources and enrichment at a glance

- **Source health.** On the Sources tab (Settings → Sources), each source shows when it last brought in a new
  item, how many it brought this week compared with usual, how long it has been failing, and whether its feed
  only carries short summaries. Sources that need attention are listed above the table. See
  [Source health](how-it-works/collection.md#source-health).
- **Enrichment queue and quotas.** The IOC page (for analysts and admins) and Settings → Enrichment show how many
  indicators are waiting to be looked up, whether the job is keeping up, and how much of each provider's daily
  budget has been used. See [The queue](how-it-works/enrichment.md#the-queue).

## Job status and notifications

Under *Collect now* and *Enrich now*, the dashboard shows when each job last ran and when it runs next. While a
job is running, you see a live progress bar ("Collecting… 12/50 sources · 8 new"), and the button stays disabled
until the run finishes.

The bell in the top bar collects the results:

- one summary per manual collection ("Collected 42 new items from 50 sources, 2 errors");
- sources that start failing, have been failing for a day, or have gone quiet;
- failed enrichment runs;
- a provider's daily quota being used up;
- the AI executive summary being ready.

Notifications are kept for 30 days.
