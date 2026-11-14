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
    """Undo the usual defanging conventions: hxxp, [.], (.), {.}, [dot], \\., [:], [://], [at], fxp."""
    t = text
    t = re.sub(r"\bh[xX]{2}p(s?)\b", r"http\1", t)
    t = re.sub(r"\bh[xX]{2}ps?(?=\[)", lambda m: "https" if m.group(0).lower().endswith("s") else "http", t)
    t = re.sub(r"\bfxp(s?)://", r"ftp\1://", t, flags=re.I)
    t = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)|\{dot\}|\\\.", ".", t, flags=re.I)
    t = re.sub(r"\[\s*:\s*//\s*\]|\(\s*:\s*//\s*\)", "://", t)
    t = re.sub(r"\[\s*:\s*\]|\(\s*:\s*\)", ":", t)
    t = re.sub(r"\[\s*/\s*\]", "/", t)
    t = re.sub(r"\[at\]|\(at\)|\{at\}", "@", t, flags=re.I)
    return t


DEFANG_HINT = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\\\.|\[:\]|\[://\]|hxxp|fxp", re.I)

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
    # social / publishing platforms
    "infosec.exchange", "mastodon.social", "mastodon.online", "fosstodon.org", "reddit.com", "substack.com",
    "youtu.be", "instagram.com", "tiktok.com", "threads.net", "discord.com", "discord.gg", "t.me",
    "telegram.org", "slack.com", "zoom.us", "vimeo.com", "spotify.com", "apple.co", "goo.gl", "ow.ly",
    "buff.ly", "tinyurl.com", "lnkd.in", "mailchimp.com", "list-manage.com", "eventbrite.com",
    # press / security media
    "theregister.com", "zdnet.com", "wired.com", "arstechnica.com", "techcrunch.com", "reuters.com",
    "bloomberg.com", "nytimes.com", "bbc.com", "bbc.co.uk", "theguardian.com", "forbes.com", "cnn.com",
    "krebsonsecurity.com", "scmagazine.com", "scworld.com", "helpnetsecurity.com", "infosecurity-magazine.com",
    "cyberscoop.com", "thedfirreport.com", "isc.sans.edu", "sans.org", "sans.edu", "404media.co",
    # vendors / research blogs
    "paloaltonetworks.com", "unit42.paloaltonetworks.com", "crowdstrike.com", "sentinelone.com", "trendmicro.com",
    "kaspersky.com", "securelist.com", "talosintelligence.com", "mandiant.com", "cloud.google.com", "proofpoint.com",
    "eset.com", "welivesecurity.com", "sophos.com", "fortinet.com", "fortiguard.com", "checkpoint.com",
    "research.checkpoint.com", "zscaler.com", "elastic.co", "huntress.com", "rapid7.com", "tenable.com",
    "qualys.com", "greynoise.io", "shadowserver.org", "spamhaus.org", "recordedfuture.com", "intel471.com",
    "group-ib.com", "bitdefender.com", "avast.com", "mcafee.com", "symantec.com", "broadcom.com", "cisco.com",
    "ibm.com", "akamai.com", "netskope.com", "trellix.com", "withsecure.com", "f-secure.com", "cyble.com",
    "socradar.io", "cybereason.com", "secureworks.com", "arcticwolf.com", "dragos.com", "claroty.com",
    "silentpush.com", "censys.io", "shodan.io", "abuseipdb.com", "hybrid-analysis.com", "joesandbox.com",
    "tria.ge", "malshare.com", "malpedia.caad.fkie.fraunhofer.de", "exploit-db.com", "packetstormsecurity.com",
    # platforms & standards bodies
    "android.com", "mozilla.org", "chromium.org", "chrome.com", "oracle.com", "vmware.com", "ivanti.com",
    "citrix.com", "atlassian.com", "adobe.com", "sap.com", "zoho.com", "okta.com", "salesforce.com",
    "cve.org", "first.org", "nist.gov", "fbi.gov", "justice.gov", "ic3.gov", "ncsc.gov.uk", "europol.europa.eu",
    "enisa.europa.eu", "bsi.bund.de", "cert.org", "us-cert.gov", "ransomware.live", "ransomlook.io",
    "huggingface.co", "openai.com", "anthropic.com", "gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org",
    "docs.google.com", "drive.google.com", "play.google.com", "office.com", "live.com", "outlook.com",
    "gmail.com", "yahoo.com", "protonmail.com", "proton.me", "example.com", "example.net", "example.org",
    "localhost", "wp.com", "s.w.org", "jetpack.com", "i0.wp.com", "i1.wp.com", "i2.wp.com",
    # Indonesian media, government and platforms (0.8)
    "detik.com", "inet.detik.com", "kompas.com", "tekno.kompas.com", "cnnindonesia.com", "cnbcindonesia.com",
    "antaranews.com", "liputan6.com", "republika.co.id", "okezone.com", "sindonews.com", "jawapos.com",
    "tempo.co", "kumparan.com", "tribunnews.com", "kompas.id", "katadata.co.id", "bisnis.com", "idntimes.com",
    "bssn.go.id", "kominfo.go.id", "komdigi.go.id", "ojk.go.id", "bi.go.id", "polri.go.id", "kemkes.go.id",
    "id-sirtii.or.id", "cekrekening.id", "turnbackhoax.id", "tokopedia.com", "shopee.co.id", "bukalapak.com",
    "gojek.com", "traveloka.com", "klikbca.com", "bca.co.id", "bri.co.id", "bankmandiri.co.id", "bni.co.id",
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
            # hex inside a URL path / query (commit SHAs, tracking ids, CDN asset names) is not a sample hash
            pre = t[max(0, m.start() - 1): m.start()]
            if pre in ("/", "=", "#", "-", "_") or t[m.end(): m.end() + 1] in ("/", "-", "_"):
                continue
            token_head = t[max(0, m.start() - 120): m.start()].rsplit(None, 1)[-1] if m.start() and not t[m.start() - 1].isspace() else ""
            if typ in ("md5", "sha1") and re.search(r"(?:utm_|fbclid|gclid|token=|session|/commit/|/blob/|/tree/)", token_head, re.I):
                continue
            hashes.add(h)
            out[(typ, h)] = Extracted(typ, h, h)

    for m in RE_IPV4.finditer(t):
        ip = m.group(0)
        if _public_ip(ip):
            # skip version-number-ish matches: "version 1.2.3.4", "v1.2.3.4", "Chrome 131.0.6778.85", "1.2.3.4.5"
            pre = t[max(0, m.start() - 24): m.start()].lower()
            post = t[m.end(): m.end() + 2]
            if re.search(r"(?:version|versions|build|release|update|firmware|v|ver\.?|chrome|firefox|edge|safari|ios|android|kernel|openssl|php|java|python|node|windows|macos)\s*$", pre):
                continue
            if post.startswith(".") and post[1:2].isdigit():
                continue
            if m.start() > 0 and t[m.start() - 1] == ".":
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
    "use", "uses", "using", "via", "from", "latest", "fresh", "updated", "free", "first", "second",
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


# Legitimate software that is routinely *abused* and therefore appears next to malware nouns
# ("ConnectWise RAT", "AnyDesk remote access trojan…"); never a family of its own.
LEGIT_TOOLS = {
    "connectwise", "screenconnect", "anydesk", "teamviewer", "atera", "splashtop", "rustdesk", "ngrok",
    "psexec", "rclone", "megasync", "winscp", "putty", "7zip", "winrar", "chrome", "edge", "firefox", "safari",
    "office", "outlook", "onedrive", "sharepoint", "dropbox", "docker", "kubernetes", "vscode", "zoom", "slack",
    "teams", "whatsapp", "signal", "telegram", "cloudflare", "azure", "aws", "gcp", "okta", "microsoft", "google",
    "apple", "meta", "amazon", "linkedin", "github", "gitlab", "bitbucket", "jenkins", "ansible", "terraform",
    "vmware", "esxi", "citrix", "fortinet", "fortigate", "ivanti", "cisco", "paloalto", "sonicwall", "veeam",
    "adobe", "acrobat", "notepad", "winzip", "steam", "discord", "spotify", "netflix", "paypal", "stripe",
    "quickbooks", "salesforce", "zendesk", "servicenow", "jira", "confluence", "trello", "notion", "evernote",
    "cursor", "copilot", "chatgpt", "claude", "gemini", "ollama", "openai", "anthropic", "deepseek", "nvidia",
    "intel", "amd", "lenovo", "dell", "asus", "samsung", "huawei", "xiaomi", "oppo", "vivo", "sony", "lg",
    "ubuntu", "debian", "fedora", "redhat", "centos", "alpine", "arch", "kali", "parrot", "tails",
    "mimikatz", "metasploit", "bloodhound", "sharphound", "rubeus", "certify", "impacket", "nmap", "masscan",
    "wireshark", "procdump", "advanced", "process", "task", "regedit", "cmd", "wmic", "certutil", "bitsadmin",
    "mshta", "rundll32", "regsvr32", "msbuild", "installutil", "cscript", "wscript", "schtasks",
}


def _sentence_start(text: str, pos: int) -> bool:
    before = text[:pos].rstrip(" \t\"'“‘(")
    return not before or before[-1] in ".!?:\n|—–-"


# Indonesian word order puts the noun first: "ransomware LockBit", "malware bernama Lumma", "trojan perbankan Mamont".
RE_NEW_FAMILY_ID = re.compile(
    r"\b((?i:ransomware|malware|trojan|botnet|spyware|stealer|backdoor|wiper|loader))\s+"
    r"(?:(?i:bernama|berjenis|jenis|baru|perbankan|pencuri data)\s+)*([A-Z][A-Za-z0-9]{2,}(?: [A-Z][A-Za-z0-9]{2,})?)\b")
ID_GENERIC_WORDS = {
    "baru", "ini", "itu", "yang", "tersebut", "jenis", "bernama", "asal", "berbahaya", "palsu", "perbankan",
    "pencuri", "bank", "di", "dan", "untuk", "dengan", "dari", "pada", "kini", "juga", "telah", "sudah", "masih",
    "menyerang", "mengincar", "incar", "sasar", "menyasar", "ancam", "mengancam", "serang", "menginfeksi",
    "indonesia", "asing", "lokal", "android", "ios", "windows", "linux", "apk", "whatsapp", "telegram", "via",
    "lewat", "melalui", "bisa", "dapat", "akan", "mampu", "curi", "mencuri", "sebar", "menyebar", "tersebar",
    "kembali", "makin", "semakin", "ganas", "canggih", "pertama", "terbaru", "lama", "global",
}


def extract_candidate_families_id(text: str, known: set[str]) -> list[Extracted]:
    """Same idea as :func:`extract_candidate_families` for Indonesian text. In prose ("…oleh ransomware
    Brain Cipher…") a capitalised word after the noun is a name; in a title-case headline the name must be
    CamelCase or already known."""
    out: dict[str, Extracted] = {}
    for m in RE_NEW_FAMILY_ID.finditer(text or ""):
        noun_raw, name = m.group(1), m.group(2)
        if " " in name and name.split(" ", 1)[1].lower() in ID_GENERIC_WORDS:
            name = name.split(" ", 1)[0]
        low = name.lower()
        if low in ID_GENERIC_WORDS or low in GENERIC_WORDS or low in LEGIT_TOOLS:
            continue
        hit = knowledge.canonical_malware(low)
        if hit:
            out[hit[0].lower()] = Extracted("malware", hit[0].lower(), hit[0], hit[1], "kb")
            continue
        camel = bool(re.search(r"[a-z][A-Z]", name)) or bool(re.search(r"[A-Za-z]\d|\d[A-Za-z]", name))
        if not camel and not noun_raw.islower():
            continue
        if low in known or any(low in k or k in low for k in known):
            continue
        out[low] = Extracted("malware", low, name, NOUN_CATEGORY.get(noun_raw.lower(), "other"), "heuristic")
    return list(out.values())


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
        if low in GENERIC_WORDS or low in LEGIT_TOOLS or len(low) < 3 or low.isdigit():
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
    from .geo import detect_language

    known = extract_known_entities(text)
    names = {e.value for e in known if e.type == "malware"} | {e.display.lower() for e in known}
    families = extract_candidate_families(text, names)
    if detect_language(text) == "id":
        have = names | {f.value for f in families}
        families += [f for f in extract_candidate_families_id(text, have) if f.value not in have]
    return known + families + extract_iocs(text, strict=strict)


def severity_score(text: str, entities: list[Extracted], kind: str = "article") -> int:
    """Backwards-compatible wrapper: first line of ``text`` is treated as the title."""
    from .severity import score_item

    title, _, body = (text or "").partition("\n")
    return score_item(title, body, entities, kind)[0]
