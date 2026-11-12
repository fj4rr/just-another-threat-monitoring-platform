"""Thin clients for threat-intel providers, shared by collectors and enrichment."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..processing.extractor import Extracted


@dataclass
class LookupResult:
    provider: str
    verdict: str = "unknown"  # malicious | suspicious | clean | unknown
    score: float = 0.0  # 0..100
    summary: str = ""
    permalink: str = ""
    data: dict = field(default_factory=dict)
    malware: list[str] = field(default_factory=list)  # family labels the provider associates
    related: list[Extracted] = field(default_factory=list)  # related IOCs
    tags: list[str] = field(default_factory=list)


class NotConfigured(Exception):
    pass


def ioc_kind(value: str) -> str:
    """Guess IOC type of a raw indicator string from a feed."""
    import re

    v = value.strip()
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", v):
        return "ip"
    if re.match(r"https?://", v, re.I):
        return "url"
    if "." in v and " " not in v:
        return "domain"
    return ""


def make_ioc(value: str, kind: str | None = None) -> Extracted | None:
    kind = kind or ioc_kind(value)
    if not kind:
        return None
    v = value.strip()
    if kind == "ip":
        v = v.split(":")[0]
    if kind in ("md5", "sha1", "sha256", "domain"):
        v = v.lower()
    return Extracted(kind, v, v, origin="feed")
