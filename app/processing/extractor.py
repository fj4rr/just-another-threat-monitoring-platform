"""Entity extraction: IOCs (refanged), CVEs, ATT&CK techniques, malware families, actors."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .. import knowledge


@dataclass(frozen=True)
class Extracted:
    type: str
    value: str  # normalized
    display: str
    category: str = ""
    origin: str = "regex"


def refang(text: str) -> str:
    t = text
    t = re.sub(r"h[xX]{2}p(s?)", r"http\1", t)
    t = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", ".", t, flags=re.I)
    t = re.sub(r"\[\s*:\s*\]", ":", t)
    t = re.sub(r"\[\s*/\s*\]", "/", t)
    t = re.sub(r"\[at\]|\(at\)", "@", t, flags=re.I)
    return t


DEFANG_HINT = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|hxxp", re.I)

RE_CVE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
RE_TECH = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_URL = re.compile(r"\bhttps?://[^\s\"'<>\]\)]+", re.I)
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.I
)

# Domains that show up in articles constantly and are never IOCs.
BENIGN_DOMAINS = {
    "google.com", "github.com", "microsoft.com", "twitter.com", "x.com", "bsky.app",
    "bsky.social", "youtube.com", "linkedin.com", "facebook.com", "virustotal.com",
    "otx.alienvault.com", "urlscan.io", "any.run", "app.any.run", "medium.com",
    "thehackernews.com", "bleepingcomputer.com", "cybersecuritynews.com", "wikipedia.org",
    "apple.com", "amazon.com", "cloudflare.com", "mitre.org", "attack.mitre.org", "nvd.nist.gov",
    "cisa.gov", "t.co", "bit.ly", "feedburner.com", "feeds.feedburner.com", "wordpress.com",
    "gravatar.com", "w3.org", "schema.org", "abuse.ch", "bazaar.abuse.ch", "threatfox.abuse.ch",
    "securityweek.com", "darkreading.com", "therecord.media", "malwarebytes.com",
}
FILE_EXT_TLDS = {
    "exe", "dll", "zip", "rar", "js", "ps1", "bat", "vbs", "lnk", "msi", "iso", "png", "jpg",
    "gif", "pdf", "doc", "docx", "xls", "xlsx", "txt", "html", "php", "aspx", "py", "sh", "bin",
    "dat", "tmp", "log", "json", "xml", "jar", "apk", "dmg", "img", "hta", "cmd", "sys", "md",
}


def _public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast
                or addr.is_link_local or addr.is_unspecified)


def _benign_domain(d: str) -> bool:
    d = d.lower().strip(".")
    if d.rsplit(".", 1)[-1] in FILE_EXT_TLDS:
        return True
    return any(d == b or d.endswith("." + b) for b in BENIGN_DOMAINS)


def extract_iocs(text: str, *, strict: bool = True) -> list[Extracted]:
    """Extract IOCs. strict=True (news/social): only take domains/URLs that were defanged,
    because ordinary prose links are rarely IOCs. TI feeds pass strict=False."""
    out: dict[tuple[str, str], Extracted] = {}
    raw = text or ""
    defanged_tokens = set()
    if strict:
        for tok in re.findall(r"\S+", raw):
            if DEFANG_HINT.search(tok):
                defanged_tokens.add(refang(tok).strip(".,;:()[]<>\"'").lower())
    t = refang(raw)

    for m in RE_CVE.finditer(t):
        v = f"CVE-{m.group(1)}-{m.group(2)}".upper()
        out[("cve", v)] = Extracted("cve", v, v)
    for m in RE_TECH.finditer(t):
        v = m.group(0).upper()
        out[("technique", v)] = Extracted("technique", v, v)

    hashes = set()
    for rx, typ in ((RE_SHA256, "sha256"), (RE_SHA1, "sha1"), (RE_MD5, "md5")):
        for m in rx.finditer(t):
            h = m.group(0).lower()
            if any(h in x for x in hashes):
                continue
            if len(set(h)) < 6:  # 000000... style junk
                continue
            hashes.add(h)
            out[(typ, h)] = Extracted(typ, h, h)

    for m in RE_IPV4.finditer(t):
        ip = m.group(0)
        if _public_ip(ip):
            # skip version-number-ish matches like 1.2.3.4 in "version 1.2.3.4"
            pre = t[max(0, m.start() - 10): m.start()].lower()
            if "version" in pre or pre.endswith("v"):
                continue
            out[("ip", ip)] = Extracted("ip", ip, ip)

    url_domains = set()
    for m in RE_URL.finditer(t):
        u = m.group(0).rstrip(".,;:")
        host = re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split(":")[0].lower()
        if _benign_domain(host):
            continue
        if strict and not any(u.lower().startswith(tok) or tok.startswith(u.lower()) or host in tok
                              for tok in defanged_tokens):
            continue
        url_domains.add(host)
        out[("url", u)] = Extracted("url", u, u)

    for m in RE_DOMAIN.finditer(t):
        d = m.group(0).lower().strip(".")
        if _benign_domain(d) or RE_IPV4.fullmatch(d):
            continue
        if strict and not (any(d in tok for tok in defanged_tokens) or d in url_domains):
            continue
        out[("domain", d)] = Extracted("domain", d, d)
    return list(out.values())


def extract_known_entities(text: str) -> list[Extracted]:
    found: dict[tuple[str, str], Extracted] = {}
    if not text:
        return []
    for etype, name, cat, pat in knowledge.compiled_patterns():
        if (etype, name.lower()) in found:
            continue
        if pat.search(text):
            found[(etype, name.lower())] = Extracted(etype, name.lower(), name, cat, "kb")
    return list(found.values())


# "<Name> ransomware/stealer/…" – catches families that are not in the knowledge base yet,
# which is exactly what matters for spotting *new* campaigns.
RE_NEW_FAMILY = re.compile(
    r"\b([A-Z][A-Za-z0-9]{2,}(?:[\- ][A-Z][A-Za-z0-9]{1,})?)\s+"
    r"((?i:ransomware|infostealer|stealer|loader|botnet|backdoor|trojan|wiper|rootkit|malware|spyware|dropper|keylogger)|RAT)\b"
)
NOUN_CATEGORY = {
    "ransomware": "ransomware", "infostealer": "stealer", "stealer": "stealer", "keylogger": "stealer",
    "loader": "loader", "dropper": "loader", "rat": "rat", "botnet": "botnet", "backdoor": "backdoor",
    "trojan": "other", "wiper": "wiper", "rootkit": "rootkit", "malware": "other", "spyware": "spyware",
}
GENERIC_WORDS = {
    "the", "new", "a", "an", "this", "that", "android", "windows", "linux", "macos", "mac", "ios", "mobile",
    "banking", "chinese", "russian", "north", "korean", "iranian", "ai", "python", "go", "golang", "rust",
    "info", "data", "crypto", "open", "custom", "fake", "malicious", "remote", "novel", "sophisticated",
    "stealthy", "multi", "cross", "cloud", "web", "browser", "linux-based", "modular", "powerful", "evasive",
    "dangerous", "notorious", "several", "multiple", "other", "similar", "new-age", "commodity", "mac-based",
    "global", "major", "known", "unknown", "advanced", "dark", "javascript", "powershell", "npm", "pypi",
    "github", "chrome", "telegram", "discord", "iot", "ransom", "uefi", "firmware", "fileless", "kernel",
    "office", "excel", "word", "pdf", "zip", "lnk", "html", "svg", "the new", "as", "of", "and", "or", "with",
    "deploy", "deploys", "deliver", "delivers", "drop", "drops", "spread", "spreads", "push", "pushes",
    "use", "uses", "using", "via", "from", "new", "latest", "fresh", "updated", "free", "first", "second",
    "hackers", "attackers", "operators", "threat", "cyber", "state", "nation", "apt", "group", "gang",
    "agentic", "llm", "gpt", "chatgpt", "vibe-coded", "rogue", "russia", "china", "iran", "israel", "ukraine",
}


GENERIC_WORDS |= {
    "most", "more", "many", "some", "any", "all", "every", "each", "such", "through", "strong", "weak",
    "profile", "flash", "alert", "top", "best", "worst", "big", "small", "old", "early", "late", "recent",
    "byod", "arm64", "arm", "x64", "x86", "api", "sdk", "usb", "dns", "vpn", "smb", "rdp", "ssh", "http",
    "https", "sql", "xss", "csrf", "edr", "xdr", "siem", "soc", "mdr", "ics", "ot", "scada", "saas", "macos",
    "wallet", "credential", "password", "info-stealing", "wallet-stealing", "self-spreading", "how", "why",
    "what", "when", "where", "who", "which", "here", "there", "after", "before", "against", "behind",
    "inside", "into", "over", "under", "about", "like", "unlike", "new-found", "brand", "nasty", "sneaky",
    "silent", "hidden", "persistent", "rare", "unique", "massive", "huge", "widespread", "targeted",
    "linked", "related", "based", "driven", "powered", "built", "made", "named", "dubbed", "called",
    "detects", "blocks", "removes", "analysis", "report", "research", "campaign", "attack", "attacks",
    "russian-linked", "china-linked", "iran-linked", "pro-russian", "ransomware", "malware", "stealer",
    "worm", "project", "java", "spark", "bluesky", "mastodon", "websocket", "unidentified", "node", "nodejs",
    "packed", "inno", "generic", "sample", "samples", "script", "payload", "apk", "exe", "dll", "delphi",
    "electron", "installer", "setup", "crypter", "builder", "panel", "kit", "phishing", "commercial",
    "legit", "legitimate", "signed", "unsigned", "obfuscated", "encrypted", "unnamed", "undocumented",
    "linux", "unix", "esxi", "vmware", "android-based", "windows-based", "go-based", "rust-based",
}


def _sentence_start(text: str, pos: int) -> bool:
    before = text[:pos].rstrip(" \t\"'“‘(")
    return not before or before[-1] in ".!?:\n|—–-"


def extract_candidate_families(text: str, known: set[str]) -> list[Extracted]:
    """Proper-noun + malware-noun pattern. Precision rules:
    * single token only (multi-word families belong in the knowledge base);
    * in title-case text ("WhiteArmor Ransomware Demands…") the token must be CamelCase;
    * in prose ("…the Remus malware…") a capitalised word is enough, unless it starts the sentence."""
    out: dict[str, Extracted] = {}
    text = text or ""
    for m in RE_NEW_FAMILY.finditer(text):
        name, noun_raw = m.group(1).strip(), m.group(2)
        noun = noun_raw.lower()
        start = m.start(1)
        if " " in name:  # "The PipeMagic backdoor" -> keep the token next to the noun
            head, name = name.rsplit(" ", 1)
            start += len(head) + 1
        if "-" in name:
            continue
        low = name.lower()
        if low in GENERIC_WORDS or len(low) < 3 or low.isdigit():
            continue
        camel = bool(re.search(r"[a-z][A-Z]", name)) or bool(re.search(r"[A-Za-z]\d|\d[A-Za-z]", name))
        prose = noun_raw.islower() or noun_raw == "RAT"
        if not camel:
            if not prose or _sentence_start(text, start):
                continue
            if name.isupper() and len(name) <= 3:
                continue
        if not re.search(r"[aeiouy]", low) and not camel and len(low) < 4:
            continue
        if low in known or any(low in k or k in low for k in known):
            continue
        hit = knowledge.canonical_malware(low)  # "BlackBasta" / "AMOS" -> the known family
        if hit:
            out[hit[0].lower()] = Extracted("malware", hit[0].lower(), hit[0], hit[1], "kb")
            continue
        out[low] = Extracted("malware", low, name, NOUN_CATEGORY.get(noun, "other"), "heuristic")
    return list(out.values())


def extract_all(text: str, *, strict: bool = True) -> list[Extracted]:
    known = extract_known_entities(text)
    names = {e.value for e in known if e.type == "malware"} | {e.display.lower() for e in known}
    return known + extract_candidate_families(text, names) + extract_iocs(text, strict=strict)


SEVERITY_TERMS = {
    r"\bzero[\s-]?day\b|\b0[\s-]?day\b": 25,
    r"actively exploited|exploited in the wild|in-the-wild": 25,
    r"\bransomware\b": 15,
    r"critical|cvss\s*(?:score\s*)?(?:of\s*)?(?:9|10)": 15,
    r"supply[\s-]chain": 15,
    r"\bnew\b.{0,30}\b(malware|campaign|variant|stealer|loader|botnet|ransomware)\b": 10,
    r"\bcampaign\b": 8,
    r"\bbackdoor\b|\bwiper\b": 10,
    r"data breach|exfiltrat": 8,
    r"\bkev\b|known exploited": 15,
}


def severity_score(text: str, entities: list[Extracted]) -> int:
    t = (text or "").lower()
    score = 0
    for pat, w in SEVERITY_TERMS.items():
        if re.search(pat, t):
            score += w
    types = {e.type for e in entities}
    if "malware" in types:
        score += 10
    if "actor" in types:
        score += 8
    if types & {"sha256", "sha1", "md5", "ip", "domain", "url"}:
        score += 10
    if "cve" in types:
        score += 5
    return min(score, 100)
