"""How often the detection rules are right (PM review 2026-11, item 18).

Labelled cases live in ``tests/quality/<area>.jsonl``, one JSON object per line. Each case runs through the real
rules, and the report gives precision (of what JATMP found, how much was right), recall (of what was there, how
much JATMP found) and F1 per area, plus every miss and false alarm so a rule change can be judged by its effect.

======================  ===============================  ============================================  =========
area                    rule                             case fields                                   counted
======================  ===============================  ============================================  =========
``families``            extractor: families and actors   ``text``, ``expect`` (all names in the text)  names
``indicators``          extractor: IPs, domains, URLs,   ``text``, ``expect`` (all indicator values)    values
                        hashes
``scam``                fraud rules: is a scam report    ``title``, ``body``, ``scam`` (true / false)   items
``sectors``             critical infrastructure sectors  ``title``, ``body``, ``expect`` (sector keys)  sectors
``geography``           target countries                 ``title``, ``body``, ``expect`` (ISO-2 codes)  countries
``severity``            severity >= ``NOTABLE``          ``title``, ``body``, ``notable`` (true/false)  items
======================  ===============================  ============================================  =========

Analyst corrections (``app/corrections.py``) become cases too (``cases_from_corrections``): "this item is not a scam
report" is a complete label; "LockBit is wrong on this item" only says what must *not* be found (``reject``), so
those cases are reported apart as *corrections the rules still repeat*.

``python manage.py quality`` prints the report; CI fails when an area falls below ``tests/quality/baseline.json``.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

AREAS = ("families", "indicators", "scam", "sectors", "geography", "severity")
NOTABLE = 30  # the dashboard's "Notable recent items" (severity 30 or more)
DATA_DIR = Path(__file__).resolve().parent.parent / "tests" / "quality"
IOC = ("ip", "domain", "url", "md5", "sha1", "sha256")


# --------------------------------------------------------------------------- what the rules say about one case
def _text(c: dict) -> tuple[str, str]:
    if "text" in c:
        return "", c["text"]
    return c.get("title", ""), c.get("body", "")


def predict_families(c: dict) -> set[str]:
    from .processing.extractor import extract_all

    title, body = _text(c)
    return {e.display.lower() for e in extract_all(f"{title}\n{body}", strict=not c.get("intel"))
            if e.type in ("malware", "actor")}


def predict_indicators(c: dict) -> set[str]:
    from .processing.extractor import extract_all

    title, body = _text(c)
    return {e.value.lower() for e in extract_all(f"{title}\n{body}", strict=not c.get("intel")) if e.type in IOC}


def predict_scam(c: dict) -> bool:
    from .processing.fraud import scam_types

    title, body = _text(c)
    return bool(scam_types(title, body, c.get("topic", "")))


def predict_sectors(c: dict) -> set[str]:
    from .processing.sectors import detect

    title, body = _text(c)
    return set(detect(title, body, scam=bool(c.get("scam_item"))))


def predict_geography(c: dict) -> set[str]:
    from .processing.geo import analyse

    title, body = _text(c)
    return {cc for cc, _ in analyse(title, body).top()}


def predict_severity(c: dict) -> bool:
    from .processing.extractor import extract_all
    from .processing.severity import score_item

    title, body = _text(c)
    ents = extract_all(f"{title}\n{body}", strict=True)
    return score_item(title, body, ents, c.get("kind", "article"))[0] >= NOTABLE


PREDICT: dict[str, Callable[[dict], object]] = {
    "families": predict_families, "indicators": predict_indicators, "scam": predict_scam,
    "sectors": predict_sectors, "geography": predict_geography, "severity": predict_severity,
}
BINARY = {"scam": "scam", "severity": "notable"}  # area -> the case field holding the true label


# --------------------------------------------------------------------------- scoring
@dataclass
class AreaResult:
    area: str
    cases: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    errors: list[dict] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def as_dict(self) -> dict:
        return {"area": self.area, "cases": self.cases, "tp": self.tp, "fp": self.fp, "fn": self.fn,
                "precision": round(self.precision, 3), "recall": round(self.recall, 3), "f1": round(self.f1, 3)}


def _norm(values: Iterable[str]) -> set[str]:
    return {str(v).strip().lower() for v in values}


def evaluate(area: str, cases: list[dict]) -> AreaResult:
    res = AreaResult(area)
    predict = PREDICT[area]
    for c in cases:
        if "reject" in c:  # partial labels from corrections are reported by evaluate_rejects
            continue
        res.cases += 1
        got = predict(c)
        label = f'{c.get("id", "")} {(c.get("title") or c.get("text", ""))[:60]}'.strip()
        if area in BINARY:
            want = bool(c[BINARY[area]])
            res.tp += got and want
            res.fp += got and not want
            res.fn += want and not got
            if got != want:
                res.errors.append({"case": label, "missed" if want else "false alarm": area})
            continue
        want, got = _norm(c.get("expect") or []), _norm(got)
        res.tp += len(got & want)
        res.fp += len(got - want)
        res.fn += len(want - got)
        if got != want:
            err = {"case": label}
            if want - got:
                err["missed"] = sorted(want - got)
            if got - want:
                err["false alarm"] = sorted(got - want)
            res.errors.append(err)
    return res


def evaluate_rejects(cases: list[dict]) -> dict:
    """Correction cases ("X must not be found here"): how many the current rules would still get wrong."""
    total, repeated, examples = 0, 0, []
    for c in cases:
        if "reject" not in c or c.get("area") not in PREDICT:
            continue
        got = PREDICT[c["area"]](c)
        got = _norm(got) if isinstance(got, set) else ({"scam"} if got else set())
        for name in _norm(c["reject"]):
            total += 1
            if name in got:
                repeated += 1
                if len(examples) < 20:
                    examples.append({"area": c["area"], "reject": name, "case": c.get("id", "")})
    return {"total": total, "repeated": repeated, "examples": examples}


# --------------------------------------------------------------------------- data
def load(area: str, data_dir: Path | None = None) -> list[dict]:
    path = (data_dir or DATA_DIR) / f"{area}.jsonl"
    if not path.exists():
        return []
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if line and not line.startswith("//"):
            case = json.loads(line)
            case.setdefault("id", f"{area}:{n}")
            out.append(case)
    return out


def load_extra(path: Path) -> dict[str, list[dict]]:
    """Cases from an export of the corrections (or any JSON lines with an ``area`` field), by area."""
    by: dict[str, list[dict]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            c = json.loads(line)
            by.setdefault(c.get("area", ""), []).append(c)
    return by


def run(data_dir: Path | None = None, extra: dict[str, list[dict]] | None = None) -> dict:
    extra = extra or {}
    areas = [evaluate(a, load(a, data_dir) + [c for c in extra.get(a, []) if "reject" not in c]) for a in AREAS]
    rejects = evaluate_rejects([c for cases in extra.values() for c in cases])
    return {"areas": areas, "rejects": rejects}


def baseline(data_dir: Path | None = None) -> dict:
    path = (data_dir or DATA_DIR) / "baseline.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def report_markdown(result: dict, base: dict | None = None, errors: int = 10) -> str:
    base = base or {}
    lines = ["| Area | Cases | Precision | Recall | F1 | Baseline P / R |", "|---|---:|---:|---:|---:|---|"]
    for r in result["areas"]:
        b = base.get(r.area) or {}
        lines.append(f"| {r.area} | {r.cases} | {r.precision:.3f} | {r.recall:.3f} | {r.f1:.3f} | "
                     f"{b.get('precision', '-')} / {b.get('recall', '-')} |")
    rj = result["rejects"]
    if rj["total"]:
        lines += ["", f"Analyst corrections the rules still repeat: **{rj['repeated']} of {rj['total']}**"]
        lines += [f"- {e['area']}: `{e['reject']}` ({e['case']})" for e in rj["examples"]]
    if errors:
        for r in result["areas"]:
            if r.errors:
                lines += ["", f"**{r.area}**: {len(r.errors)} case(s) wrong"]
                lines += [f"- {json.dumps(e, ensure_ascii=False)}" for e in r.errors[:errors]]
    return "\n".join(lines)


def regressions(result: dict, base: dict, tolerance: float = 0.0005) -> list[str]:
    """Areas whose precision or recall fell below the baseline."""
    out = []
    for r in result["areas"]:
        b = base.get(r.area)
        if not b:
            continue
        for metric in ("precision", "recall"):
            if getattr(r, metric) + tolerance < float(b[metric]):
                out.append(f"{r.area} {metric} {getattr(r, metric):.3f} < baseline {b[metric]}")
    return out


# --------------------------------------------------------------------------- corrections -> cases
AREA_OF_TYPE = {"malware": "families", "actor": "families", "sector": "sectors",
                **dict.fromkeys(IOC, "indicators")}


def cases_from_corrections(db, limit_items: int = 20) -> list[str]:
    """The active corrections as JSON lines for ``manage.py quality --corrections``."""
    from sqlalchemy import select

    from .models import Correction, Item

    out = []

    def item_case(item_id: int, **fields) -> None:
        item = db.get(Item, item_id)
        if item is None:
            return
        out.append(json.dumps({"id": f"correction:{fields.pop('cid')}:{item_id}", "title": item.title or "",
                               "body": (item.content or "")[:20000], **fields}, ensure_ascii=False) + "\n")

    for c in db.execute(select(Correction).where(Correction.active).order_by(Correction.id)).scalars():
        d = c.data or {}
        if c.kind == "not_scam" and c.item_id:
            item_case(c.item_id, cid=c.id, area="scam", scam=False)
        elif c.kind in ("unlink", "false_positive") and d.get("type") in AREA_OF_TYPE:
            name = d.get("value") or d.get("entity", "")
            for iid, _origin in (d.get("links") or [])[:limit_items]:
                item_case(iid, cid=c.id, area=AREA_OF_TYPE[d["type"]], reject=[name])
    return out
