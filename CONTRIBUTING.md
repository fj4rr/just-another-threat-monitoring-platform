# Contributing to JATMP

Thanks for helping. Bug reports, false positives and misses of the detection rules, new sources, docs fixes and
pull requests are all welcome.

## Before you start

- **Security problems** go through the private channel in [SECURITY.md](SECURITY.md), never a public issue.
- **Bugs and ideas:** open an issue with the templates. For a wrong or missed detection, paste the item's title
  and the sentence that matters, and say what JATMP found and what it should have found.
- **Larger changes** (a new source kind, a new provider, a schema change): open an issue first so the approach can
  be agreed before you write the code.

By contributing you agree that your work is released under the project's [MIT License](LICENSE) and that you
follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

The full guide is [docs/development.md](docs/development.md): setting up, running on throw-away data
(`JATMP_DATA_DIR`), the test fixtures and the conventions. The short version:

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt -c requirements.lock
ruff check .
pytest
```

Recipes for common changes (a collector, a provider, a setting, a detection rule, a page) are in
[docs/extending.md](docs/extending.md), which ends with a security checklist for every change.

## Pull requests

- Keep a pull request to one change, and explain the *why* in its description.
- `ruff check .` and `pytest` must pass; CI also runs `pip-audit` and builds the Docker image.
- Add tests: for a rule, the case that motivated it, the false positive it must not produce and a true positive
  that must still match (and a case in `tests/quality/` when it affects precision or recall); for a security
  fix, the attack.
- Update the docs page your change affects (the table in [docs/development.md](docs/development.md#documentation-site)
  says which) and, for anything user-visible, add a line under *Unreleased* in [CHANGELOG.md](CHANGELOG.md).
- A number quoted in *How it works* that you change must change on the page too; `tests/test_docs_numbers.py`
  checks it.
- The interface and the docs are in English. No new dependency without a reason, and no front-end build step.
- Do not commit data, API keys, `.env` or anything under `data/`.
