"""Topic filters for every source kind (PM review 2026-11, item 10; moved here from the RSS collector).

A source's ``filter`` setting keeps only the entries about its topic. It used to exist for RSS feeds only; Telegram
channels, X, Mastodon and Bluesky accounts took everything. ``keep()`` is applied to every collector's entries
before they are stored (``Collector.keep``), for scheduled runs and backfills alike.

* ``security``: security-related entries of general technology feeds (English and Indonesian terms);
* ``cyber``: stricter, for general news sections and general channels (unambiguous cyber terms, or a scam report);
* ``fraud``: scam reports only (the scam & fraud rules decide).
"""
from __future__ import annotations

import re

from .pipeline import RawItem, strip_html

TOPICS = ("security", "cyber", "fraud")
TEXT_CHARS = 3000  # the start of the text is enough to tell the topic


# "filter: security" keeps only entries about security from general technology feeds (many Indonesian
# outlets publish one tech feed for gadgets, apps and cyber incidents alike). English and Indonesian terms.
SECURITY_RE = re.compile(
    r"\b(?:hack(?:ed|er|ers|ing)?|breach(?:ed|es)?|malware|ransomware|phish(?:ing)?|vulnerab\w*|exploit\w*|"
    r"cyber\w*|leak(?:ed|s)?|ddos|scam\w*|fraud\w*|spyware|botnet|trojan|zero[\s-]?day|cve-\d{4}|stealer|"
    r"backdoor|deface\w*|infostealer|data breach|"
    r"peretas|peretasan|diretas|meretas|retas|kebocoran|bocor|siber|penipuan|penipu|phising|pishing|"
    r"pembobolan|dibobol|membobol|pencurian data|data pribadi|pembajakan akun|dibajak|serangan (?:siber|ransomware|ddos)|"
    r"kejahatan digital|keamanan digital|modus|mengatasnamakan|judi online|judol|bssn|pdns|pusat data nasional|"
    r"skimming|social engineering|rekayasa sosial|kode otp|apk palsu|undangan pernikahan)\b", re.I)

# "filter: cyber" is the stricter version for general news sections (national, economy, law), where words that are
# fine in a tech section mean something else: "tabung gas bocor", "modus penyelundupan", "dibajak" (a hijacked bus).
# Only unambiguous cyber and digital-fraud terms count; scam reports are added by the fraud rules.
CYBER_RE = re.compile(
    r"\b(?:hack(?:ed|er|ers|ing)|malware|ransomware|phish(?:ing)?|cyber\w*|ddos|spyware|botnet|zero[\s-]?day|"
    r"cve-\d{4}|infostealer|data breach|deface\w*|"
    r"peretas|peretasan|diretas|meretas|siber|phising|pishing|serangan (?:siber|ransomware|ddos)|"
    r"(?:kebocoran|bocornya|pencurian|penjualan|jual beli) data(?: pribadi| pengguna| nasabah| pelanggan)?|"
    r"data (?:pribadi |pengguna |nasabah |pelanggan |warga )?(?:\w+ ){0,5}(?:bocor|diretas|dicuri|dijual)|"
    r"(?:akun|sistem|server|situs|website|aplikasi|rekening) (?:\w+ ){0,2}(?:dibobol|diretas|dibajak)|"
    r"pembobolan (?:rekening|akun|data|sistem|bank)|pembajakan akun|kejahatan (?:digital|siber)|keamanan digital|"
    r"penipuan (?:online|daring|digital|siber)|judi online|judi daring|judol|pinjol ilegal|investasi bodong|"
    r"anti-?scam|scam\w*|rekening penipu|kode otp|apk palsu|skimming|rekayasa sosial|social engineering|"
    r"bssn|pdns|pusat data nasional|id-sirtii|csirt)\b", re.I)


def _body(r: RawItem) -> str:
    return f"{strip_html(r.content)[:TEXT_CHARS]}\n{' '.join(r.tags)}"


def keep(raws: list[RawItem], topic: str | None) -> list[RawItem]:
    """The entries of ``raws`` about ``topic``; all of them when there is no (known) topic."""
    topic = str(topic or "").strip().lower()
    if topic not in TOPICS:
        return raws
    from .fraud import scam_types

    if topic == "fraud":  # fact-check and consumer-alert feeds: keep only entries about a scam
        return [r for r in raws if scam_types(r.title, _body(r))]
    if topic == "cyber":  # general news sections: unambiguous cyber terms, or a scam report
        return [r for r in raws if CYBER_RE.search(f"{r.title}\n{_body(r)}") or scam_types(r.title, _body(r))]
    return [r for r in raws if SECURITY_RE.search(f"{r.title}\n{_body(r)}")]
