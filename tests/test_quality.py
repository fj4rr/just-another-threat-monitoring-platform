"""Quality gate (PM review 2026-11, item 18): the detection rules must not get worse on the labelled cases in
tests/quality. When a rule change improves an area, record it with ``python manage.py quality --update-baseline``
(and say so in the changelog); when it makes one worse, the build fails here with the cases it now gets wrong."""
import json

import pytest

from app import quality

FIELDS = {"families": ("expect",), "indicators": ("expect",), "scam": ("scam",), "sectors": ("expect",),
          "geography": ("expect",), "severity": ("notable",)}


@pytest.mark.parametrize("area", quality.AREAS)
def test_labelled_cases_are_well_formed(area):
    cases = quality.load(area)
    assert len(cases) >= 15, f"{area}: the seed set is too small to say anything"
    for c in cases:
        assert ("text" in c) or ("title" in c), c["id"]
        for f in FIELDS[area]:
            assert f in c, f"{c['id']} has no {f!r}"


def test_no_area_falls_below_the_baseline():
    base = quality.baseline()
    assert set(base) == set(quality.AREAS)
    res = quality.run()
    regs = quality.regressions(res, base)
    assert not regs, "\n".join(regs) + "\n\n" + quality.report_markdown(res, base, errors=20)


def test_scoring_counts_misses_and_false_alarms():
    r = quality.AreaResult("x", tp=8, fp=2, fn=4)
    assert (round(r.precision, 2), round(r.recall, 2)) == (0.8, 0.67)
    assert quality.AreaResult("y").precision == 1.0  # nothing predicted, nothing expected


def test_correction_cases_report_what_the_rules_still_repeat(tmp_path):
    p = tmp_path / "c.jsonl"
    p.write_text("\n".join(json.dumps(c) for c in [
        {"area": "families", "id": "c1", "text": "Pegasus, the winged horse, on stage", "reject": ["pegasus"]},
        {"area": "families", "id": "c2", "text": "LockBit claims the attack", "reject": ["lockbit"]},
        {"area": "scam", "id": "c3", "title": "Bank launches app", "body": "New features.", "scam": False},
    ]), encoding="utf-8")
    res = quality.run(extra=quality.load_extra(p))
    assert res["rejects"] == {"total": 2, "repeated": 1, "examples": [
        {"area": "families", "reject": "lockbit", "case": "c2"}]}
    scam = next(a for a in res["areas"] if a.area == "scam")
    assert scam.cases == len(quality.load("scam")) + 1  # a complete label joins the area
