# Development

[← Documentation index](README.md)

How to set up a development environment, run JATMP locally without touching real data, write and run tests,
manage dependencies, and release a version. How the code is organised is in [Architecture](architecture.md),
the tables in [Data model](data-model.md), and recipes for common changes in [Extending JATMP](extending.md).

## Set up

Requirements: Python 3.11 or 3.12, git. Docker is optional (only to test the image).

```bash
git clone https://github.com/fj4rr/just-another-threat-monitoring-platform.git
```
```bash
cd just-another-threat-monitoring-platform
```
```bash
python -m venv .venv
```

Activate the virtual environment (`source .venv/bin/activate`, or `.venv\Scripts\activate` on Windows), then
install the pinned dependencies and the development tools:

```bash
pip install -r requirements-dev.txt -c requirements.lock
```

Optional extras: `requirements-postgres.txt` (PostgreSQL driver), `requirements-telegram.txt` (MTProto),
`requirements-docs.txt` (documentation site).

## Run locally

```bash
python run.py
```

This serves on <http://127.0.0.1:8000> and starts the scheduler, which collects from every enabled source.
Useful variations:

- **Throw-away data.** `JATMP_DATA_DIR` decides where `config.json` and the SQLite database live. Point it at an
  empty folder to get a fresh install (the setup wizard opens) without touching `data/`:

    ```bash
    JATMP_DATA_DIR=/tmp/jatmp-dev python run.py --port 8001
    ```

    On Windows PowerShell set `$env:JATMP_DATA_DIR` first. Uncheck *Add default sources* in the wizard if you
    do not want collectors to start fetching.
- **Auto-reload.** `python run.py --reload` restarts on code changes. The scheduler restarts with it, so
  scheduled runs may start again after each save.
- **No collectors.** To look at pages without network traffic, install without default sources, or disable the
  sources under Settings → Sources.
- **Seeding test data.** Import the app with the same `JATMP_DATA_DIR` in a script and call
  `pipeline.ingest(db, source, [RawItem(...)])` inside `db.session_scope()`; the pages show the result at once.
- **A local AI.** Run Ollama and choose *Local – Ollama* under Settings → AI. Saving the AI tab in local mode
  adds the host to the outbound allow-list.

The interactive API reference is at `/api/v1/docs` once you are signed in.

## Conventions

- **Python 3.11+**, `from __future__ import annotations` at the top of modules, type hints on public functions.
- **Lint:** `ruff check .` must pass (rules in `pyproject.toml`: pycodestyle, pyflakes, isort, bugbear, pyupgrade,
  bandit, naming, comprehensions, simplify, ruff). Line length is 120. Fix findings instead of silencing them; a
  `# noqa: XXX` needs a reason in the same comment.
- **Comments explain why**, not what: the incident, the false positive or the provider quirk behind a rule. Rules
  that came from an audit or an issue name it ("audit 2026-11 D-1").
- **Times** are naive UTC from `models.utcnow()`.
- **The UI and the docs are in English.** Indonesian appears in detection patterns and in names.
- **No new dependency** without a reason: the app runs on small hosts and offline. Front-end code stays
  build-free; third-party JavaScript is vendored under `static/js/vendor/`.
- **Security rules** for every change are listed at the end of [Extending JATMP](extending.md#security-checklist-for-a-change).

## Tests

```bash
pytest
```
```bash
pytest tests/test_v0101.py -k identifiers      # one file, tests matching a name
```
```bash
pytest -x --lf                                 # stop at the first failure, rerun what failed last time
```

How the suite works:

- `tests/conftest.py` sets `JATMP_DATA_DIR` to a fresh temporary folder **before** importing `app`, and removes
  provider keys from the environment, so tests never see your data or your keys.
- Fixtures:

    | Fixture | Gives you |
    |---|---|
    | `installed` | A single-user install with the default sources, once per session |
    | `client` | A `TestClient` for the app without the lifespan (no scheduler, no collectors) |
    | `multi_user_mode` | Switches the install to multi-user for one test and provides an admin (`admin` / password in the fixture) |
    | `_fresh_caches` (autouse) | Clears the trending cache and the manual-action throttles before each test |

- **One database for the whole session.** Tests add data with names that do not collide (`Zz…`, `zz-…`
  prefixes) and assert on their own rows rather than on totals.
- **No network.** Replace HTTP clients with `httpx.MockTransport`: monkeypatch `Collector.client`,
  `intel.clients._client`, `intel.context._client`, `intel.darkweb._client`, or pass `http=` where a function
  accepts one (`cve.refresh`, `webhooks.deliver_pending`). Tests of `netguard` itself use a local
  `ThreadingHTTPServer`.
- **CSRF in tests.** Read the token from a page (`<meta name="csrf-token">`) and send it as `X-CSRF-Token` or
  `csrf_token`; see the `_csrf` helper in the test files.
- **Files per release.** New behaviour goes into the file of the release that introduces it
  (`test_v0101.py`…); core behaviour lives in `test_app.py`, `test_extractor.py`, `test_scoring_and_reports.py`
  and `test_security_units.py`.
- **Numbers in the docs.** `tests/test_docs_numbers.py` reads the weights, thresholds, windows and defaults that
  the *How it works* pages quote and compares them with the constants in the code. A change on one side only
  fails the build; fix the page or the code, and add a check when a page quotes a new number that matters.
- **What to test.** For a detection rule: the case that motivated it, the false positive it must not produce,
  and an existing true positive that must still match. For a security fix: the attack. For a regular expression
  that is not trivial: a timing test with hostile input.

GitHub Actions (`.github/workflows/ci.yml`) runs on every push and pull request:

| Job | What |
|---|---|
| `test` | `ruff check .` and `pytest` on Python 3.11 and 3.12, dependencies from `requirements.lock` |
| `audit` | `pip-audit` against `requirements.lock` (known vulnerabilities fail the build) |
| `docker` | Builds the image |

`.github/workflows/docs.yml` builds and publishes the documentation site.

## Dependencies

- `requirements.txt` lists direct dependencies with compatible ranges (`>=x,<y`). It is what `pyproject.toml`
  reads.
- `requirements.lock` pins every package, direct and transitive, for all platforms. Docker and CI install with
  `-c requirements.lock`.
- Dependabot (`.github/dependabot.yml`) proposes updates weekly; merge them when CI is green.

To add or update a dependency, edit `requirements.txt`, then regenerate the lock with [uv](https://docs.astral.sh/uv/)
and check it:

```bash
uv pip compile requirements.txt --universal --python-version 3.11 -o requirements.lock --no-header --upgrade
```
```bash
pip-audit -r requirements.lock
```
```bash
pip install -r requirements-dev.txt -c requirements.lock && pytest
```

Drop `--upgrade` to change only what the edit requires. Keep upper bounds loose enough that a security fix can be
installed (a bound below the fixed version makes `pip-audit` fail).

## Documentation site

The pages under `docs/` are plain Markdown that reads on GitHub and also builds a MkDocs (Material) site, published
to GitHub Pages by `.github/workflows/docs.yml` on every push to `main` that touches the docs.

```bash
pip install -r requirements-docs.txt
```
```bash
mkdocs serve                  # http://127.0.0.1:8000 with live reload
```
```bash
mkdocs build --strict         # what CI runs: broken links and anchors fail the build
```

Navigation is in `mkdocs.yml`; add a new page there and to the index in `docs/README.md`. `scripts/mkdocs_hooks.py`
renders the root `CHANGELOG.md` as the changelog page and rewrites the links that only make sense on GitHub
(`../CHANGELOG.md`, `../README.md`, the "← Documentation index" back links). Screenshots live in
`docs/screenshots/`; retake them when a page changes visibly (see [Screenshots](screenshots.md)).

Which page to update:

| Change | Page |
|---|---|
| New source kind or default source | [Sources](sources.md) |
| New provider, key or environment variable | [Configuration](configuration.md) |
| Detection, scoring, enrichment | [Analysis](analysis.md), [Scams and fraud](fraud.md), [Geography](geography.md) |
| API, feeds, webhooks, MISP | [Sharing and integrations](integrations.md) |
| Anything security-relevant | [Security](security.md) |
| New table or column | [Data model](data-model.md) |
| New module, job or flow | [Architecture](architecture.md) |
| Anything an admin must do after upgrading | [Upgrading](upgrading.md) |

## Release checklist

1. Bump the version in `app/__init__.py` (`__version__`, shown in the UI and the API docs) and in
   `pyproject.toml`.
2. Rules changed? Bump the matching version constant so stored items are re-analysed once (see
   [Background jobs](architecture.md#background-jobs)).
3. Add a section to `CHANGELOG.md` (what changed, from the user's point of view) and to `docs/upgrading.md` (what
   an admin has to do or should expect: new columns, one-off jobs, new dependencies, changed defaults).
4. Update **How it works** (`docs/how-it-works/`) for every changed rule, weight, threshold, interval or job, and
   the checks in `tests/test_docs_numbers.py` when a quoted number moved or a new one was added.
5. Run `ruff check .`, `pytest`, `pip-audit -r requirements.lock` and `mkdocs build --strict`.
6. Try the upgrade path: copy a `data/` folder from the previous version, start the new version on the copy
   (`JATMP_DATA_DIR`), and check the start-up log and the one-off jobs.
7. Commit, push, and check that CI is green.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Every page redirects to `/setup` | `JATMP_DATA_DIR` points at a folder without an installed `config.json` |
| A source fails with `blocked: … resolves to a private or local address` | The outbound guard; add the host under Settings → Sharing → *Private hosts JATMP may contact* |
| Stored API keys read as empty | The database was moved without its `data/config.json` (the key that decrypts them) |
| `database is locked` on SQLite | A long write transaction; commit in chunks, or use PostgreSQL for heavy backfills |
| Collectors run twice | More than one worker or process is serving the app |
| A test passes alone and fails in the suite | It depends on totals or on data another test added; assert on your own rows |
