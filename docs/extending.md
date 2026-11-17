# Extending JATMP

[← Documentation index](README.md)

Recipes for the changes developers make most often. Each one names the files to touch, the code to write, the
rules to keep and the tests to add. Read [Architecture](architecture.md) first for how the pieces fit together,
and [Development](development.md) for setting up, testing and releasing.

## Add a collector (a new kind of source)

A collector turns one provider into `RawItem`s. It does not touch the database: storing, extraction, scoring and
linking happen in the pipeline.

1. Create `app/collectors/<name>.py`:

    ```python
    from __future__ import annotations

    from .. import settings
    from ..processing.pipeline import RawItem
    from .base import Collector, SkipCollector, parse_dt


    class ExampleCollector(Collector):
        """Latest reports from example.org. One sentence on what it collects and what it needs."""

        kind = "example"           # stored in Source.kind; never change it once released
        category = "intel"         # news | social | intel
        label = "Example reports"  # shown in the "Add source" form
        # config fields for the UI: (name, label, placeholder); values end up in Source.config
        fields = [("query", "Search query", "ransomware")]

        def fetch(self) -> list[RawItem]:
            key = settings.get("example_api_key")
            if not key:
                raise SkipCollector("Example API key not set (Settings → Threat-intel APIs)")
            with self.client(Authorization=f"Bearer {key}") as c:  # netguard client: SSRF guard, size cap
                r = c.get("https://api.example.org/v1/reports", params={"q": self.cfg.get("query", "")})
                r.raise_for_status()
                rows = r.json().get("data") or []
            return [RawItem(external_id=str(x["id"]), title=x.get("title", ""), url=x.get("url", ""),
                            content=x.get("summary", ""), published_at=parse_dt(x.get("created")),
                            kind="pulse", tags=x.get("tags") or []) for x in rows]
    ```

2. Register the class in `REGISTRY` in `app/collectors/__init__.py`. The settings page, the scheduler and
   `run_source` pick it up from there.
3. Optional: add a default source to `DEFAULT_SOURCES`. Existing installs get new built-in sources on the next
   start (`auto_seed_sources`), so only add sources that work without configuration, or add them disabled.
4. Optional: historical backfill. Override `backfill_capability()` and `backfill(since, until, progress)`, which
   yields pages (lists) of `RawItem`s newest first, calls `progress("page 3")` and stops at `until`/`since`. See
   `mastodon.py` for a small example and `rss.py` for WordPress and Internet Archive.

Rules:

- Always use `self.client(...)`, never `httpx` directly. Header keyword names use `_` for `-`.
- Raise `SkipCollector` for "cannot run, nothing is wrong" (missing key, disabled plan); let other errors raise:
  the run is marked as an error and the admin is notified once.
- `external_id` must be stable across runs, or every run stores duplicates.
- Put HTML into `content` only with `kind="article"` (it gets stripped); posts and pulses are plain text.
- Put structured indicators into `indicators` (`intel.make_ioc(value)` builds them) rather than into the text.
- Keep `raw` small: it is stored on every item.
- If the provider's terms forbid redistribution, add the kind to `sharing.NO_REDISTRIBUTE_KINDS`.

Tests: replace the HTTP client with a mock transport and assert on the `RawItem`s and on what `ingest` stores.

```python
def test_example_collector(installed, monkeypatch):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": 1, "title": "Zzexample LockBit", "created": "2026-11-01"}]})

    monkeypatch.setattr(Collector, "client", lambda self, **h: httpx.Client(transport=httpx.MockTransport(handler)))
    settings.set("example_api_key", "test")
    raws = REGISTRY["example"](Source(name="x", kind="example", category="intel", config={})).fetch()
    assert raws[0].external_id == "1"
```

## Add an enrichment provider

Providers answer "what do you know about this indicator?". They live in `app/intel/clients.py` (lookups that run
automatically), `app/intel/context.py` (on-demand infrastructure context) or `app/intel/darkweb.py` (deep dive).

```python
class Example:
    name = "example"                       # stored in enrichments.provider; never change it
    supports = {"ip", "domain"}             # indicator types it can look up

    def __init__(self):
        self.key = settings.get("example_api_key")
        if not self.key:
            raise NotConfigured("Example API key not set")   # the provider is then simply skipped

    def lookup(self, etype: str, value: str) -> LookupResult | None:
        if etype not in self.supports:
            return None
        if not _budget_ok(self.name, int(settings.get("example_daily_budget") or 0)):
            raise RuntimeError("Example daily budget exhausted")
        throttle.wait(self.name, 2)          # seconds between calls
        with _client({"X-Key": self.key}) as c:
            r = c.get(f"https://api.example.org/v1/{etype}/{value}")
        if r.status_code == 404:
            return LookupResult(self.name, "unknown", 0, "Not known to Example")
        r.raise_for_status()
        d = r.json()
        return LookupResult(self.name, verdict="malicious" if d.get("bad") else "unknown", score=d.get("score", 0),
                            summary=d.get("summary", ""), permalink=d.get("link", ""),
                            malware=d.get("families", []), tags=d.get("tags", []))

    def test(self) -> str:                   # "Test" button under Settings; avoid spending lookup quota
        with _client({"X-Key": self.key}) as c:
            c.get("https://api.example.org/v1/account").raise_for_status()
        return "Example reachable, key accepted"
```

Then:

1. Add it to `PROVIDER_CLASSES` in `app/processing/enrichment.py` (or `CONTEXT_CLASSES` in `intel/context.py`).
   The *Test* buttons on the settings page find providers by `name` in those lists.
2. Add its settings (`example_api_key`, a budget) to `settings.SCHEMA`, see [below](#add-a-setting).
3. If its verdicts are noisy (it lists scanners and CDNs), add the name to `NOISY_PROVIDERS` so a GreyNoise
   "benign" answer overrides it in `_consensus`.
4. If its relationships may be shared, add the name to `sharing.REDISTRIBUTABLE_PROVIDERS`.
5. Document the key in [Configuration](configuration.md).

`malware` labels are mapped to known families by `enrichment.resolve_family`; unknown labels are ignored on
purpose, so a strange provider label never creates a family.

## Add a setting

Add one line to `SCHEMA` in `app/settings.py`:

```python
"example_daily_budget": (500, "EXAMPLE_DAILY_BUDGET", "Example lookups per day", "int", "enrichment"),
#                        default  env var (or "")    label in the UI            kind   group (= settings tab)
```

- The field appears on its tab automatically (`settings.html` renders every `SCHEMA` entry of the tab's group).
  A new group also needs a tab in the list at the top of `settings.html`.
- Kinds: `text`, `int` (add bounds to `INT_BOUNDS`), `bool`, `secret` (never sent to the browser, stored
  encrypted), `select:a,b,c`.
- An environment variable, when set, wins and locks the field.
- Read it with `settings.get("key")`. Values are cached for 5 seconds per process.

## Change detection rules

Rules are data in Python modules. After changing them, update the tests that pin their behaviour and decide how
stored items catch up.

| What | Where | Stored items catch up through |
|---|---|---|
| Malware families, actors, aliases | `MALWARE`, `ACTORS` in `app/knowledge.py` (or `data/knowledge_extra.json` without code, see [Configuration](configuration.md#extending-the-knowledge-base)) | `manage.py reextract` |
| Names that are everyday words | `COMMON_WORDS` / `AMBIGUOUS` in `knowledge.py`: these need a qualifier ("Pegasus spyware", "Bitter APT"), `QUALIFIERS` / `ACTOR_QUALIFIERS` list the qualifiers | `manage.py reextract` |
| Words that are never a new family | `GENERIC_WORDS`, `LEGIT_TOOLS`, `PLATFORM_WORDS`, `ID_GENERIC_WORDS` in `processing/extractor.py` (country names and demonyms come from the gazetteer) | `manage.py reextract` |
| Severity terms and weights | `GROUPS` and `ID_TERMS` in `processing/severity.py`, dampeners `PATCH_RE`, `META_RE`, `NOISE_RE` | *Re-score all items* / `manage.py rescore` |
| Scam types | `SCAM_TYPES` in `processing/fraud.py`: `(key, name, weight, strong pattern, weak pattern)` | bump `fraud.RULES_VERSION` |
| Brands, identifier cues, losses | `BRANDS`, `SCAMMER_SPECIFIC`, `SCAMMER_CUE`, `INSTITUTION_CUE`, `OFFICIAL_CUE`, `VICTIM_CUE`, `RE_RUPIAH` / `RE_DOLLAR` in `fraud.py` | bump `fraud.RULES_VERSION` |
| Sectors | `SECTORS`, `FEED_SECTORS`, `ATTACK_CUE` in `processing/sectors.py` | bump `sectors.RULES_VERSION` |
| Countries, provinces, places | `app/gazetteer.py`, detection in `processing/geo.py` | bump `geo.GEO_VERSION` |
| Text cleaning | `strip_html` / `strip_css` in `processing/pipeline.py` | bump `jobs.CONTENT_VERSION` |

Rules for patterns:

- **Linear time only.** Every article goes through these regular expressions in a scheduler thread that cannot
  be killed. Never nest unbounded quantifiers (`(a+)+`, `(x(?:y)?)+(?:\s*(x)+)*`), never let two adjacent parts
  match the same text, bound repetitions (`{0,40}`), and add a timing test with a hostile input when a pattern
  is complex (see `test_strip_css_is_linear`).
- English and Indonesian forms of one signal share a label, so they count once.
- Prefer false negatives to false positives in the fraud section: a wrong scammer phone number is personal data
  stored without reason.
- Write the reason a pattern exists as a comment next to it, with the example that motivated it.

## Re-analyse stored items after a rules change

For the rules in the table above with a version constant, bumping the constant is enough: the matching
start-up job re-analyses every stored item once. For a new kind of analysis, add a job following the same
pattern in `app/jobs.py`:

```python
EXAMPLE_VERSION = 1  # 1 (0.11): what changed, in a few words


def run_example(force: bool = False) -> str:
    if not force and int(settings.get("example_version") or 0) >= EXAMPLE_VERSION:
        return "example is up to date"
    db = SessionLocal()
    try:
        ids = [i for (i,) in db.execute(select(Item.id).order_by(Item.id))]
        for n in range(0, len(ids), 500):          # chunks: bounded memory, short write transactions
            for item in db.execute(select(Item).where(Item.id.in_(ids[n:n + 500]))).unique().scalars():
                ...                                   # recompute and store
            db.commit()
            db.expunge_all()
        settings.set("example_version", EXAMPLE_VERSION)
        return f"updated {len(ids)} item(s)"
    except Exception as e:
        db.rollback()
        log.warning("example failed: %s", e)
        return f"error: {e}"
    finally:
        db.close()
```

Schedule it once in `jobs.start()` (`scheduler.add_job(run_example, "date", run_date=_now() + timedelta(seconds=…),
id="example", replace_existing=True)`), mention it in [Upgrading](upgrading.md), and, if users may want to run it
again, add a `manage.py` command and a button. Jobs that need progress in the UI create a `CollectorRun`
(`_start_run` / `_finish`).

## Add a page

1. Add a route to the matching router in `app/routers/` (pages in `pages.py`, scam pages in `fraud_pages.py`,
   admin pages in `admin.py`):

    ```python
    @router.get("/examples")
    def examples(request: Request, days: int = 30, user: User = Depends(current_user), db: Session = Depends(get_db)):
        days = _clamp(days, 0, 3650)                              # clamp every number from the query string
        rows = db.execute(select(Item).options(with_links())     # with_links() when the template reads entity_links
                          .order_by(Item.published_at.desc()).limit(50)).unique().scalars().all()
        return render(request, "examples.html", {"user": user, "rows": rows, "days": days})
    ```

2. Create `app/templates/examples.html` extending `base.html`; reuse the macros in `_macros.html` (`chip`, `sev`,
   `verdict`, `fraud_score`…). Inline scripts need `nonce="{{ nonce }}"`; behaviour goes through `data-*`
   attributes or `static/js/app.js`, never `onclick`.
3. Add the link to the sidebar in `base.html` if it is a top-level page.
4. Use `require("analyst")` or `require("admin")` instead of `current_user` when the page changes data or shows
   admin information.

## Add a UI action or JSON endpoint

Actions the UI calls with `data-post` live in `app/routers/api.py`:

```python
@router.post("/examples/{item_id}/refresh", dependencies=[Depends(verify_csrf)])
def example_refresh(item_id: int, request: Request, user: User = Depends(require("analyst")),
                    db: Session = Depends(get_db)):
    item = db.get(Item, item_id)
    if not item:
        raise HTTPException(404, "item not found")
    throttle.check(f"{user.id}:example_refresh", 6)     # when it calls a provider or the AI
    ...
    audit(db, user, "example_refresh", str(item.id), request)
    db.commit()
    return {"ok": True, "message": "refreshed"}          # shown as a toast
```

- Every non-GET route needs `verify_csrf`.
- Work that takes more than a second or two goes into a job (`jobs.run_now(func, *args)`, or a queued
  `CollectorRun` so the UI shows progress), not into the request.
- Wrap provider calls that must not run twice at once in `with throttle.exclusive(f"example:{id}"): …`.

## Extend the REST API

The versioned API is `app/routers/api_v1.py`. It is read-only and has its own authentication:

- Use `Depends(principal("read"))` (or `"export"` for bulk feeds) instead of `current_user`.
- Filter with `sharing.shareable_item_clause()` / `sharing.shareable_entity_clause()` and check single objects with
  `sharing.item_shareable()`; return 404 (not 403) for objects that may not be shared.
- Never return entities of `fraud.IDENT_TYPES`, in lists, in single-object endpoints or nested in other objects.
- Page with `cursor` (the last id) and `limit`, return `next_cursor`.
- CSV output goes through `csvsafe.writer`.
- The endpoint appears in the offline docs at `/api/v1/docs` automatically; give it a `summary` and describe the
  query parameters, then mention it in [Sharing and integrations](integrations.md).

## Add a column or a table

1. Declare it in `app/models.py`. Give new columns a `default` (scalar defaults are applied to existing rows when
   the column is added), and `index=True` when it is filtered or sorted on.
2. Restart: `init_db()` creates new tables, adds new columns and creates declared indexes on existing tables.
3. Never rename or drop a column in a release, and never add a `NOT NULL` column without a default. If existing
   rows need a computed value, add a versioned one-off job (see above).
4. Check the column with PostgreSQL in mind: declared string lengths are enforced there (the `before_flush` hook
   trims, but a key that gets trimmed may collide).
5. If the data is copied between engines, check `app/dbcopy.py`.
6. Describe it in [Data model](data-model.md) and the upgrade notes.

## Make outbound requests

Use `netguard.client(...)` or one of the existing helpers (`Collector.client`, `intel.clients._client`). Choose
`max_bytes` for large downloads, `follow_redirects=False` when a redirect would be wrong (webhooks, MISP), and
`allow_private=` only where an admin explicitly configured a private target. Tests replace these helpers with an
`httpx.MockTransport` client; never let a test reach the internet.

## Security checklist for a change

- Untrusted input: feed text, provider answers, AI output, query strings, form fields, uploaded settings. Validate
  and bound it; never build SQL, FTS queries, shell commands or HTML from it without escaping.
- Templates auto-escape; never mark untrusted text `|safe`. Markdown goes through the `md` filter (raw HTML off).
- Links from feeds go through `safe_url` / `safe_href`.
- New outbound data paths respect `sharing.py` and leave scammer identifiers out.
- New outbound requests use `netguard`.
- New regular expressions are linear.
- New secrets are `secret` settings, never logged and never sent to the browser.
- Admin-only data and actions check `require("admin")`; changing actions write to the audit log.
