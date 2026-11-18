"""The "How it works" pages quote the platform's numbers: weights, thresholds, windows, defaults. This test reads
them back and compares them with the constants in the code, so a change on one side without the other fails CI
(PM review 2026-11, item 21). When a check fails, update the page or the code, whichever is wrong; when a page
gains a new number worth guarding, add it to CHECKS.

Each check is (page, regex, expected): the regex must match at least once, and every match must equal
``expected`` (a tuple when the regex has several groups).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app import jobs, settings, sourcehealth
from app.processing import enrichment, pipeline, severity

DOCS = Path(__file__).resolve().parent.parent / "docs" / "how-it-works"


def _default(key: str):
    return settings.SCHEMA[key][0]


CHECKS = [
    # severity feedback after ingest
    ("scoring.md", r"turns \*\*malicious\*\* in enrichment \| \+(\d+)", severity.VERDICT_BONUS["malicious"]),
    ("scoring.md", r"turns \*\*suspicious\*\* \| \+(\d+)", severity.VERDICT_BONUS["suspicious"]),
    ("enrichment.md", r"gets \+(\d+) \(\*malicious\*\) or \+(\d+) \(\*suspicious\*\)",
     (severity.VERDICT_BONUS["malicious"], severity.VERDICT_BONUS["suspicious"])),
    ("index.md", r"\+(\d+) / \+(\d+) when an indicator is later confirmed",
     (severity.VERDICT_BONUS["malicious"], severity.VERDICT_BONUS["suspicious"])),
    ("*", r"\*\*at most \+(\d+)\*\*", severity.LLM_SEVERITY_MAX),  # the AI cap is always quoted in bold
    ("index.md", r"up to \+(\d+) from the AI", severity.LLM_SEVERITY_MAX),
    # AI auto-summaries
    ("index.md", r"severity ≥ (\d+) \(when enabled\), (\d+) per run",
     (jobs.AUTO_SUMMARY_MIN_SEVERITY, jobs.AUTO_SUMMARY_MAX_PER_RUN)),
    ("ai.md", r"summarises up to \*\*(\d+)\*\* items per run, skipping items with severity \*\*below (\d+)\*\*",
     (jobs.AUTO_SUMMARY_MAX_PER_RUN, jobs.AUTO_SUMMARY_MIN_SEVERITY)),
    ("ai.md", r"in-memory queue of at most (\d+) ids", jobs._summary_queue.maxlen),
    ("ai.md", r"collected in the last \*\*(\d+) hours\*\*", jobs.AUTO_SUMMARY_REQUEUE_HOURS),
    ("scoring.md", r"AI auto-summaries only run from \*\*(\d+)\*\*", jobs.AUTO_SUMMARY_MIN_SEVERITY),
    # webhooks
    ("scoring.md", r"Webhooks use \*\*(\d+)\*\* as the default threshold", _default("webhook_min_severity")),
    ("sharing.md", r"`webhook_min_severity`\*\* \(default (\d+)\)", _default("webhook_min_severity")),
    # enrichment pacing, budgets and windows
    ("enrichment.md", r"(\d+) s \(`vt_min_interval`", _default("vt_min_interval")),
    ("enrichment.md", r"(\d+) \(`vt_daily_budget`", _default("vt_daily_budget")),
    ("enrichment.md", r"(\d+) \(`greynoise_daily_budget`\)", _default("greynoise_daily_budget")),
    ("enrichment.md", r"(\d+) \(`abuseipdb_daily_budget`", _default("abuseipdb_daily_budget")),
    ("enrichment.md", r"\(default (\d+), minimum 2", _default("enrichment_interval")),
    ("enrichment.md", r"default `enrichment_batch` of \*\*(\d+)\*\*", _default("enrichment_batch")),
    ("index.md", r"then every (\d+) min \| `run_enrichment` \| Looks up (\d+) indicators",
     (_default("enrichment_interval"), _default("enrichment_batch"))),
    ("enrichment.md", r"published in the last (\d+) days\*\*", enrichment.FRESH_WINDOW.days),
    ("enrichment.md", r"seen in the last \*\*(\d+) days\*\* whose last lookup \*\*failed\*\* more than \*\*(\d+) "
                      r"hours\*\* ago, or came back \*\*unknown\*\* more than \*\*(\d+) days\*\*",
     (enrichment.RECHECK_MAX_AGE.days, int(enrichment.RECHECK_ERROR_AFTER.total_seconds() // 3600),
      enrichment.RECHECK_UNKNOWN_AFTER.days)),
    # verdicts that age (0.12)
    ("enrichment.md", r"older than \*\*`verdict_recheck_days`\*\* \(default (\d+)\) and that were mentioned in the "
                      r"last \*\*(\d+) days\*\*", (_default("verdict_recheck_days"), enrichment.STALE_RECHECK_SEEN.days)),
    ("enrichment.md", r"whose verdict is older than \*\*(\d+) days\*\* and that was mentioned in the last (\d+) days",
     (_default("verdict_recheck_days"), enrichment.STALE_RECHECK_SEEN.days)),
    ("enrichment.md", r"Once the verdict is older than \*\*(\d+) days\*\*", _default("verdict_feed_days")),
    ("enrichment.md", r"`valid_until` = verdict date \+ (\d+) days", _default("verdict_feed_days")),
    ("sharing.md", r"`verdict_feed_days` \((\d+) by default\)", _default("verdict_feed_days")),
    # source health (0.12)
    ("collection.md", r"fewer than \*\*(\d+)\*\* characters", sourcehealth.SUMMARY_ONLY_CHARS),
    ("collection.md", r"no new item for \*\*(\d+)\*\* times its usual gap, and at least (\d+) hours",
     (sourcehealth.QUIET_FACTOR, int(sourcehealth.QUIET_MIN.total_seconds() // 3600))),
    ("collection.md", r"\*\*failing for (\d+) hours\*\*", int(sourcehealth.FAILING_ALERT.total_seconds() // 3600)),
    ("collection.md", r"weekly average of the (\d+) weeks before", sourcehealth.BASELINE_WEEKS),
    ("collection.md", r"needs at least (\d+) such gaps", sourcehealth.MIN_GAPS),
    # enrichment capacity (0.12)
    ("enrichment.md", r"batch × runs per day: (\d+) × (\d+) =",
     (_default("enrichment_batch"), 1440 // _default("enrichment_interval"))),
    # cross-source dedup
    ("processing.md", r"published within \*\*(\d+) days\*\*", pipeline.DUP_WINDOW.days),
    # daily schedule defaults
    ("housekeeping.md", r"`run_housekeeping` runs every day at \*\*(\d\d:\d\d)\*\*", _default("housekeeping_time")),
    ("index.md", r"(\d\d:\d\d) daily \(`housekeeping_time`\)", _default("housekeeping_time")),
    ("ai.md", r"`run_digest` runs daily at \*\*(\d\d:\d\d)\*\*", _default("digest_time")),
    ("index.md", r"(\d\d:\d\d) daily \(`digest_time`\)", _default("digest_time")),
]


def _pages(name: str) -> list[Path]:
    return sorted(DOCS.glob("*.md")) if name == "*" else [DOCS / name]


def _norm(value):
    return tuple(str(v) for v in value) if isinstance(value, tuple) else str(value)


@pytest.mark.parametrize("page,pattern,expected", CHECKS, ids=[f"{c[0]}:{c[1][:40]}" for c in CHECKS])
def test_how_it_works_numbers_match_the_code(page, pattern, expected):
    found = []
    for path in _pages(page):
        text = re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))  # a quoted phrase may wrap across lines
        found += [(path.name, m.groups() if len(m.groups()) > 1 else m.group(1)) for m in re.finditer(pattern, text)]
    assert found, f"{page}: the phrase {pattern!r} is gone; update the check or the page"
    wrong = [(name, got) for name, got in found if _norm(got) != _norm(expected)]
    assert not wrong, f"{page} quotes {wrong}, the code says {expected}"
