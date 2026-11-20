"""Digest items: newsletters, weekly round-ups and podcasts that wrap several unrelated stories in one post.

Cisco Talos' "Threat Source" is the typical case: one issue covers a new CVE, a ransomware story, a scam
and the week's "most prevalent malware files" hashes, which recur issue after issue. Every entity such a post
mentions is *in the post*, not *about* it, so treating a shared hash or CVE as proof that two items describe
the same activity floods the correlation list with unrelated issues.

``is_digest`` is the single place that decides. A source can force it with ``config["digest"] = true`` (or
``false`` to opt out). Otherwise three signals are tried: the title and tags (round-up wording), a series name
in the tags, and boilerplate phrases in the body, because issue titles are often whimsical ("Never be afraid to
ask questions") and the tag is not always present.
"""
from __future__ import annotations

import re

from .fraud import ROUNDUP

# Round-up wording the fraud ROUNDUP pattern does not cover: bulletins, "in other news", headlines, briefings,
# "Week in Ransomware", "Weekly/Daily/Monthly <x>" and the Indonesian equivalents.
_TITLE = re.compile(
    r"\b(?:(?:risky|threatsday|weekly|daily|security news) bulletin|in other news|"
    r"(?:cyber ?security|security|cyber|daily|top|weekly) headlines|(?:threat(?: intelligence)?|daily|weekly) briefing|"
    r"week in (?:ransomware|breaches|cyber)|"
    r"(?:weekly|daily|monthly)\s+(?:cyber|threat|security|vulnerabilit\w*|intel\w*|news|report|wrap|update)|"
    r"(?:cyber|threat|security)\s+(?:weekly|daily|monthly)|mingguan|kilas (?:siber|keamanan)|ringkasan berita)\b",
    re.I)
# Words in the shared ROUNDUP pattern that make sense for sectors and scams but not here: "Contagious Interview" is a
# DPRK campaign (19 real reports in one deployment), "Lessons from 59 Linux Kernel Bug Reports" is one study, a
# webinar advert names a single topic, and "best known for" comes from the listicle alternative.
_NOT_DIGEST = ("interview", "lessons from", "webinar", "best known")
# Series names that show up in tags or author lines.
_SERIES = re.compile(r"\b(?:threat source|talos takes|week in (?:security|review)|stormcast|newsletter)\b", re.I)
# Boilerplate phrases from the body of newsletter issues.
_BODY = re.compile(
    r"welcome to (?:this|the|our) (?:week'?s|weekly|latest|monthly|daily)?\s*(?:edition|issue)|"
    r"(?:this|the) (?:week'?s )?(?:edition|issue) of (?:the |our )?[\w' -]{0,40}newsletter|"
    r"threat source newsletter|talos takes|upcoming events where you can find|the one big thing|"
    r"top security (?:news )?headlines of the week|unsubscribe from this newsletter|most prevalent malware files",
    re.I)


def is_digest(item) -> bool:
    forced = (getattr(item.source, "config", None) or {}).get("digest")
    if forced is not None:
        return bool(forced)
    head = " ".join([item.title or "", *[str(t) for t in (item.tags or [])]])
    if any(not m.group(0).lower().startswith(_NOT_DIGEST) for m in ROUNDUP.finditer(head)) \
            or _SERIES.search(head) or _TITLE.search(item.title or ""):
        return True
    return bool(_BODY.search(item.content or ""))
