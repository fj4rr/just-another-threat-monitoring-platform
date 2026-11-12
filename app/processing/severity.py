"""Explainable severity scoring for collected items (0–100).

The score is built from independent signal groups so that synonyms are not double counted,
the title weighs more than the body, and content that is *about* threats without describing
active ones (patch notes, roundups, how-to guides) is damped. Every contribution is returned
as a reason so the UI can show *why* an item scored the way it did.

    score, reasons = score_item(title, body, entities, kind="article")

Design notes
* Within a group only the strongest matching term counts (``max``), between groups the
  contributions add up. Term weights are therefore comparable across groups.
* A term found in the title gets a 50 % bonus: headlines name the actual subject, bodies
  mention everything in passing.
* Dampeners are multiplicative and applied last, except that an *exploitation* signal
  (zero-day, in-the-wild, KEV) always cancels the patch-note dampener: an actively exploited
  bug being patched is still urgent.
* Routine victim postings from leak-site trackers are capped so they do not drown real
  campaign reporting in the "notable" lists.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Signal groups: (group label, [(regex, weight, short reason)]). Order is cosmetic.
GROUPS: list[tuple[str, list[tuple[str, int, str]]]] = [
    ("exploitation", [
        (r"\bzero[\s-]?days?\b|\b0[\s-]?days?\b", 30, "zero-day"),
        (r"actively exploited|exploited in the wild|in[\s-]the[\s-]wild|exploitation (?:observed|detected|confirmed|underway)|under active (?:attack|exploitation)|mass[\s-]exploitation", 30, "exploited in the wild"),
        (r"\bkev\b|known exploited vulnerabilit", 28, "listed in CISA KEV"),
        (r"\b(?:poc|proof[\s-]of[\s-]concept)\b.{0,40}\b(?:released|published|available|public)\b|exploit (?:code )?(?:released|published|available|public)", 18, "public exploit code"),
        (r"\bexploit(?:ed|ing|s)?\b", 10, "exploitation mentioned"),
    ]),
    ("impact", [
        (r"\bremote code execution\b|\brce\b|unauthenticated (?:attacker|remote|access)|pre[\s-]auth", 14, "remote code execution"),
        (r"\bcvss\s*(?:v?\d(?:\.\d)?\s*)?(?:score\s*)?(?:of\s*)?(?:9\.\d|9|10)(?:\.0)?\b|\bcritical\b", 12, "critical / CVSS ≥ 9"),
        (r"auth(?:entication)?[\s-]bypass|bypass(?:es|ed|ing)? (?:\w+ )?authentication", 12, "authentication bypass"),
        (r"\bwiper\b|destructive (?:malware|attack)|data[\s-]destroying", 14, "destructive / wiper"),
        (r"privilege escalation|\blpe\b|\beop\b", 6, "privilege escalation"),
        (r"\bhigh[\s-]severity\b", 6, "high severity"),
    ]),
    ("threat class", [
        (r"supply[\s-]chain|trojani[sz]ed (?:installer|update|package)|malicious (?:npm|pypi|nuget|vs ?code|browser) (?:package|extension)", 16, "supply-chain"),
        (r"\bransomware\b|double[\s-]extortion|data[\s-]extortion", 12, "ransomware"),
        (r"\bzero[\s-]click\b|\bspyware\b|mercenary|commercial surveillance", 12, "spyware / zero-click"),
        (r"\bbackdoor|\brootkit\b|\bbootkit\b|\bimplant\b|\bweb[\s-]?shell\b", 9, "backdoor / implant"),
        (r"\bbotnet\b|\bworm(?:s|able)?\b|self[\s-]propagating|self[\s-]spreading", 9, "botnet / worm"),
        (r"info[\s-]?stealer|\bstealer\b|credential (?:theft|harvest|stealing)|\bkeylogger\b", 7, "stealer"),
        (r"data breach|exfiltrat|\bleak(?:ed|s)?\b.{0,30}\b(?:data|records|credentials)\b|stolen data|\bbreached\b", 8, "breach / exfiltration"),
        (r"\bphishing\b|\bsmishing\b|\bvishing\b|business email compromise|\bbec\b|\bclickfix\b|\bmalvertis", 6, "phishing / social engineering"),
    ]),
    ("activity", [
        (r"\bcampaign\b|\bdeploy(?:s|ed|ing)?\b.{0,25}\b(?:malware|ransomware|backdoor|payload|loader|stealer|trojan)\b|\b(?:malware|ransomware|backdoor|payload|loader|stealer)\b.{0,25}\bdeployed\b", 10, "active campaign"),
        (r"\bnew\b.{0,30}\b(?:malware|variant|stealer|loader|botnet|ransomware|backdoor|rat|trojan|family|strain)\b|previously (?:unknown|undocumented|unseen)|\bnovel\b", 8, "new malware / variant"),
        (r"\btarget(?:s|ed|ing)\b", 5, "targeting described"),
        (r"\bwidespread\b|\bmillions? of\b|\bthousands of\b|\bworldwide\b|\bglobal(?:ly)?\b", 6, "wide scale"),
        (r"\bapt\b|state[\s-](?:sponsored|backed|linked|aligned)|nation[\s-]state|\bespionage\b", 8, "state-sponsored / APT"),
        (r"\bcritical infrastructure\b|\bhealthcare\b|\bhospital|\bgovernment\b|\benergy sector\b|\bics\b|\bscada\b|\bot\b network", 5, "sensitive sector"),
    ]),
]

# Title patterns that indicate the item is *about* a fix, not an attack.
PATCH_RE = re.compile(
    r"\b(?:fix(?:es|ed)?|patch(?:es|ed)?|patch tuesday|security updates?|releases? (?:security )?updates?|"
    r"addresses|resolves|plugs|closes|mitigates|update (?:addresses|fixes)|hotfix|out-of-band update)\b", re.I)
# Title patterns for meta / evergreen content: roundups, guides, opinion, marketing.
META_RE = re.compile(
    r"\b(?:week(?:ly)? in review|in review|roundup|round-up|recap|digest|top \d+|best (?:practices|of)|"
    r"how to|what is|why you|guide to|explained|webinar|podcast|episode|survey|report finds|study finds|"
    r"predictions|outlook \d{4}|year in review|the state of|interview|opinion|q&a|cheat ?sheet|"
    r"announc(?:es|ing)|partners? with|launches|acquires|acquisition|funding|raises \$|hiring|"
    r"certification|training|career)\b", re.I)
# Routine leak-site victim postings ("X ransomware group has added Y to its victims").
VICTIM_POST_RE = re.compile(r"\b(?:added|adds|claims?|listed|lists|posted)\b.{0,60}\b(?:victims?|leak site|dls)\b", re.I)
# Operational noise that is not a threat (install problems, outages, policy).
NOISE_RE = re.compile(r"\b(?:installation issues?|fails? to install|known issue|outage|bug fix|end of support|"
                      r"deprecat|price|pricing|lawsuit|fined|regulat|compliance|gdpr|privacy policy)\b", re.I)

_COMPILED = [(g, [(re.compile(p, re.I | re.S), w, r) for p, w, r in terms]) for g, terms in GROUPS]
IOC_TYPES = {"sha256", "sha1", "md5", "ip", "domain", "url"}
KIND_BASE = {"pulse": 6, "analysis": 6, "scan": 4}


@dataclass(frozen=True)
class Reason:
    label: str
    points: int

    def as_dict(self) -> dict:
        return {"label": self.label, "points": self.points}


def _title_bonus(title_l: str, pat: re.Pattern) -> bool:
    return bool(title_l) and bool(pat.search(title_l))


def score_item(title: str, body: str, entities, kind: str = "article") -> tuple[int, list[Reason]]:
    """Return (score, reasons). ``entities`` is any iterable of objects with ``.type`` and
    optionally ``.origin`` (Extracted from the extractor, or Entity rows)."""
    title_l = (title or "").lower()
    body_l = (body or "")[:20000].lower()
    text_l = f"{title_l}\n{body_l}"
    reasons: list[Reason] = []
    score = 0.0
    exploitation = False

    for group, terms in _COMPILED:
        hits: list[tuple[float, str]] = []
        for pat, weight, label in terms:
            if not pat.search(text_l):
                continue
            hits.append((weight * (1.5 if _title_bonus(title_l, pat) else 1.0), label))
        if not hits:
            continue
        hits.sort(reverse=True)
        # strongest term counts fully, the runner-up at half weight; the rest are synonyms
        if group == "exploitation" and hits[0][0] >= 18:
            exploitation = True
        score += hits[0][0]
        reasons.append(Reason(hits[0][1], round(hits[0][0])))
        if len(hits) > 1:
            score += hits[1][0] * 0.5
            reasons.append(Reason(hits[1][1], round(hits[1][0] * 0.5)))

    # ---- entity signals
    types: dict[str, int] = {}
    heuristic_family = False
    for e in entities or []:
        t = getattr(e, "type", "")
        types[t] = types.get(t, 0) + 1
        if t == "malware" and getattr(e, "origin", "") == "heuristic":
            heuristic_family = True
    if types.get("malware"):
        pts = 12 if heuristic_family else 10
        score += pts
        reasons.append(Reason("unknown family named" if heuristic_family else "known malware family", pts))
    if types.get("actor"):
        score += 8
        reasons.append(Reason("known threat actor", 8))
    n_cve = types.get("cve", 0)
    if n_cve:
        pts = min(5 + 2 * (n_cve - 1), 11)
        score += pts
        reasons.append(Reason(f"{n_cve} CVE(s)", pts))
    n_ioc = sum(types.get(t, 0) for t in IOC_TYPES)
    if n_ioc:
        pts = 8 + (4 if n_ioc >= 5 else 0)
        score += pts
        reasons.append(Reason(f"{n_ioc} indicator(s)", pts))
    if types.get("technique"):
        score += 3
        reasons.append(Reason("ATT&CK techniques", 3))
    if kind in KIND_BASE:
        score += KIND_BASE[kind]
        reasons.append(Reason(f"structured intel ({kind})", KIND_BASE[kind]))

    # ---- dampeners
    if not exploitation and PATCH_RE.search(title_l):
        before = score
        score *= 0.7
        reasons.append(Reason("patch / advisory only", round(score - before)))
    if META_RE.search(title_l) or NOISE_RE.search(title_l):
        before = score
        score *= 0.5
        reasons.append(Reason("roundup / guide / non-incident", round(score - before)))
    if kind == "post" and VICTIM_POST_RE.search(text_l) and score > 35:
        reasons.append(Reason("routine leak-site posting (capped)", round(35 - score)))
        score = 35.0

    final = int(max(0, min(100, round(score))))
    return final, reasons


def reasons_to_json(reasons: list[Reason]) -> list[dict]:
    return [r.as_dict() for r in reasons]
