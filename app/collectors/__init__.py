from __future__ import annotations

from .base import Collector, SkipCollector
from .bluesky import BlueskyCollector
from .intel import AnyRunCollector, OTXCollector, RansomwareLiveCollector, ThreatFoxCollector, URLScanCollector
from .mastodon import MastodonCollector
from .misp import MISPCollector
from .rss import RSSCollector
from .x_twitter import XCollector

__all__ = ["DEFAULT_SOURCES", "REGISTRY", "Collector", "SkipCollector", "source_key"]

REGISTRY: dict[str, type[Collector]] = {
    c.kind: c
    for c in (RSSCollector, BlueskyCollector, MastodonCollector, XCollector, OTXCollector,
              URLScanCollector, AnyRunCollector, ThreatFoxCollector, RansomwareLiveCollector, MISPCollector)
}


def _rss(name: str, url: str, every: int = 60, country: str = "") -> dict:
    return {"name": name, "kind": "rss", "category": "news", "interval_minutes": every, "country": country,
            "config": {"url": url}}


def _rss_id(name: str, url: str, every: int = 60) -> dict:
    """Indonesian general technology feed: only security-related entries are kept (topic filter)."""
    return {"name": name, "kind": "rss", "category": "news", "interval_minutes": every, "country": "ID",
            "language": "id", "config": {"url": url, "filter": "security"}}


def _bsky(name: str, handle: str, every: int = 30) -> dict:
    return {"name": f"{name} (Bluesky)", "kind": "bluesky", "category": "social", "interval_minutes": every,
            "config": {"handle": handle}}


def _masto(name: str, account: str, every: int = 30) -> dict:
    return {"name": f"{name} (Mastodon)", "kind": "mastodon", "category": "social", "interval_minutes": every,
            "config": {"account": account}}


def _x(name: str, username: str, enabled: bool = True, every: int = 180) -> dict:
    return {"name": f"{name} (X)", "kind": "x", "category": "social", "interval_minutes": every,
            "enabled": enabled, "config": {"username": username}}


# Seeded on install (and by `python manage.py seed-sources` for existing installs).
# Bluesky / Mastodon handles were verified active on 2026-11-12; X handles cannot be
# verified without an API token.
DEFAULT_SOURCES: list[dict] = [
    # --- News
    _rss("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", 30),
    _rss("Cyber Security News", "https://cybersecuritynews.com/feed/", 30),
    _rss("BleepingComputer", "https://www.bleepingcomputer.com/feed/", 30, "US"),
    _rss("SecurityWeek", "https://www.securityweek.com/feed/", country="US"),
    _rss("The Record", "https://therecord.media/feed", country="US"),
    _rss("Dark Reading", "https://www.darkreading.com/rss.xml", country="US"),
    _rss("The DFIR Report", "https://thedfirreport.com/feed/", 180),
    _rss("Unit 42", "https://unit42.paloaltonetworks.com/feed/", 180, "US"),
    _rss("Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed/index.xml", 120, "US"),
    _rss("SANS ISC Diary", "https://isc.sans.edu/rssfeed_full.xml", 120, "US"),
    _rss("Krebs on Security", "https://krebsonsecurity.com/feed/", 180, "US"),
    _rss("Cisco Talos", "https://blog.talosintelligence.com/rss/", 180, "US"),
    _rss("Securelist (Kaspersky)", "https://securelist.com/feed/", 180),
    _rss("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/", 180, "US"),

    # --- Indonesian news (technology sections, filtered to security topics; feeds verified 2026-11-15)
    _rss_id("Detik Inet", "https://inet.detik.com/rss", 30),
    _rss_id("CNN Indonesia Teknologi", "https://www.cnnindonesia.com/teknologi/rss"),
    _rss_id("CNBC Indonesia Tech", "https://www.cnbcindonesia.com/tech/rss"),
    _rss_id("Antara Tekno", "https://www.antaranews.com/rss/tekno.xml"),
    _rss_id("Liputan6 Tekno", "https://feed.liputan6.com/rss/tekno"),
    _rss_id("Republika Tekno", "https://www.republika.co.id/rss/tekno"),
    _rss_id("Okezone Techno", "https://sindikasi.okezone.com/index.php/rss/16/RSS2.0"),
    _rss_id("Sindonews Tekno", "https://tekno.sindonews.com/rss"),
    _rss_id("Jawa Pos Teknologi", "https://www.jawapos.com/rss/teknologi"),

    # --- Bluesky (public API, no key)
    _bsky("vx-underground", "vxunderground.bsky.social", 60),
    _bsky("Marcus Hutchins", "malwaretech.com"),
    _bsky("MalwareHunterTeam", "malwrhunterteam.bsky.social"),
    _bsky("Kevin Beaumont", "doublepulsar.com"),
    _bsky("Catalin Cimpanu", "campuscodi.risky.biz"),
    _bsky("Will Thomas (BushidoToken)", "bushidotoken.net"),
    _bsky("Zack Whittaker", "zackwhittaker.com", 60),
    _bsky("Lorenzo Franceschi-Bicchierai", "lorenzofb.bsky.social", 60),
    _bsky("Dan Goodin", "dangoodin.bsky.social", 60),
    _bsky("Karsten Hahn", "struppigel.bsky.social", 60),
    _bsky("hasherezade", "hasherezade.bsky.social", 120),
    _bsky("Silas Cutler", "silascutler.bsky.social", 60),
    _bsky("Shadowserver", "shadowserver.bsky.social"),
    _bsky("The DFIR Report", "thedfirreport.bsky.social", 60),
    _bsky("ESET Research", "esetresearch.bsky.social"),
    _bsky("Cisco Talos", "talosintelligence.com"),
    _bsky("SentinelLABS", "sentinellabs.bsky.social", 60),
    _bsky("GreyNoise", "greynoise.io", 60),
    _bsky("Huntress", "huntress.com", 120),
    _bsky("Ransomware.live", "ransomware.live", 20),

    # --- Mastodon / fediverse (public API, no key)
    _masto("Marcus Hutchins", "malwaretech@infosec.exchange"),
    _masto("Brian Krebs", "briankrebs@infosec.exchange"),
    _masto("Brad Duncan (malware-traffic)", "malware_traffic@infosec.exchange"),
    _masto("SANS ISC", "SANS_ISC@infosec.exchange"),
    _masto("Proofpoint Threat Insight", "threatinsight@infosec.exchange"),
    _masto("Thomas Roccia (fr0gger)", "fr0gger@infosec.exchange", 60),
    _masto("ffforward", "ffforward@infosec.exchange", 60),
    _masto("Matt Taggart", "mttaggart@infosec.exchange", 60),
    _masto("Kevin Beaumont", "GossiTheDog@cyberplace.social"),

    # --- X (needs API token or an RSS bridge). The three requested accounts are enabled;
    #     the rest start disabled so a paid-tier read quota isn't burned without intent.
    _x("vx-underground", "vxunderground"),
    _x("Marcus Hutchins", "MalwareTechBlog"),
    _x("MalwareHunterTeam", "malwrhunterteam"),
    *[_x(n, u, enabled=False) for n, u in [
        ("Kevin Beaumont", "GossiTheDog"), ("Florian Roth", "cyb3rops"), ("Germán Fernández", "1ZRR4H"),
        ("Will Thomas", "BushidoToken"), ("The DFIR Report", "TheDFIRReport"), ("Unit 42", "Unit42_Intel"),
        ("abuse.ch", "abuse_ch"), ("Brad Duncan", "malware_traffic"), ("ESET Research", "ESETresearch"),
        ("Microsoft Threat Intelligence", "MsftSecIntel"), ("Execute Malware", "executemalware"),
        ("pr0xylife", "pr0xylife"), ("g0njxa", "g0njxa"), ("Max_Mal_", "Max_Mal_"), ("RedDrip7", "RedDrip7"),
        ("Thomas Roccia", "fr0gger_"), ("StopMalvertising", "StopMalvertisin"), ("ViriBack", "ViriBack"),
        ("Fox_threatintel", "Fox_threatintel"), ("FalconFeeds", "FalconFeedsio"), ("Hackmanac", "H4ckManac"),
        ("ANY.RUN", "anyrun_app"), ("ffforward", "ffforward"),
    ]],

    # --- Threat intel platforms
    {"name": "OTX subscribed pulses", "kind": "otx", "category": "intel", "interval_minutes": 60,
     "config": {"mode": "subscribed"}},
    {"name": "urlscan.io malicious (24h)", "kind": "urlscan", "category": "intel", "interval_minutes": 120,
     "config": {"query": "verdicts.malicious:true AND date:>now-1d"}},
    {"name": "ANY.RUN - Lumma tasks", "kind": "anyrun", "category": "intel", "interval_minutes": 360,
     "config": {"query": 'threatName:"lumma"', "depth": "7"}},
    {"name": "ThreatFox recent IOCs", "kind": "threatfox", "category": "intel", "interval_minutes": 180,
     "config": {}},
    # Disabled by default: the keyless ransomware.live API is for personal use only. Add a free PRO key
    # (Settings -> Threat-intel APIs) before enabling it in an organisation.
    {"name": "ransomware.live recent victims", "kind": "ransomwarelive", "category": "intel", "interval_minutes": 60,
     "enabled": False, "config": {"mode": "recent"}},
    {"name": "ransomware.live victims in Indonesia", "kind": "ransomwarelive", "category": "intel",
     "interval_minutes": 180, "enabled": False, "config": {"country": "ID"}},
]


def source_key(kind: str, config: dict) -> str:
    """Identity of a source, used to avoid seeding duplicates."""
    main = next(iter((config or {}).values()), "") if kind != "otx" else (config or {}).get("mode", "")
    return f"{kind}:{str(main).lower()}"
