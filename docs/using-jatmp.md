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

The menu on the left starts with the two dashboards, **Cyber threats** (`/`) and **Scams & fraud** (`/fraud`, see
[Scams and fraud](fraud.md#dashboard)), followed by the **Feed**, which has the same two sides: **Cyber threats** (`/feed`, every item) and **Scams &
fraud** (`/feed/scams`, the scam reports). Both are in the Feed dropdown and as tabs on the Feed page. Everything
else is grouped in three dropdowns:

| Group | Pages |
|---|---|
| **Intelligence** | Malware, Threat actors, CVEs and IOCs for cyber threats; Scam types, Brands & people (impersonated brands and people) and Scammer identifiers for scams |
| **Analysis** | Geography, Watchlist, Reports, Corrections, AI insights |
| **Manage** | Settings, Backfill, and Admin in multi-user mode |

A group opens by itself when the page you are on belongs to it, and otherwise remembers whether you left it open
or closed. On a wider screen, the arrow next to the logo collapses the whole menu to a narrow rail of icons: hover
over an icon to see its name, or click a group's icon to expand the menu with that group open. Both choices are
remembered in your browser.

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
(24 hours to 1 year, or all time), a button to clear the filters, and pagination.

**New threats.** The Malware, Threat actors, CVEs and IOCs lists, and the Scam types and Impersonated brands lists,
have a *✦ New threats* button next to the filters. It keeps only the entries **first seen** within the chosen
period, so you can see what has just appeared rather than what is always in the news. When the period is *All
time*, it uses the last 30 days (7 days on the IOC list). Your other filters stay as they are, and clicking the
button again (*New threats ✕*) or *Reset* shows everything.

**Feed filters stay until you clear them.** On the Feed, the filters you pick are kept for your session. Choosing
a language after a minimum severity keeps the severity, and coming back to the Feed later shows the same view.
The search box in the top bar and the entity chips only change the filter they name. Filters that a link set (an
entity, a target country or province, a reporting country) appear as chips under the filter bar; click the ✕ on
one to drop just that filter. **Clear filters** drops them all and starts over. The other lists keep their
filters in the URL and have a *Reset* button.

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
  budget has been used. On the IOC page this is the *Enrichment* panel above the filters; click it to open the
  details. *Run enrichment batch* starts a run straight away, and *Copy visible* copies the indicators shown in the
  table, one per line. See [The queue](how-it-works/enrichment.md#the-queue).

## Correcting JATMP

Analysts and admins can fix the platform's mistakes, and the fix stays in force:

- **✕ next to an entity** on an item page removes it from that item ("Pegasus" in an article about a musical).
- **✎ Correct** on an entity page marks a family or actor as a wrong entity everywhere, an indicator as not a
  threat, or sets an analyst verdict (*malicious*, *suspicious*, *clean*) that wins over the providers.
- **Not a scam report** in the fraud-score popover of an item.

Each asks for a reason. The *Corrections* page lists them all with who, when and why, can undo any of them, and
shows which names are corrected most often (rules worth tuning). Details in
[Corrections and quality](how-it-works/corrections.md).

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
