"""Sectors (0.10): which critical information infrastructure sector an item is about.

The eight sectors are the ones Indonesia's Perpres 82/2022 on critical information infrastructure lists
(Pasal 4): government administration, energy & mineral resources, transportation, finance, health, ICT, food and
defence. An item gets a sector when the text names organisations or services of that sector as a target or an
affected party ("rumah sakit", "hospital", "bank", "maskapai", ".go.id" sites…), or when the feed states one
(ransomware.live victim sector, OTX industries).

Rules are deliberately strict: the title needs two hits of a sector (or one more in the body), the body alone needs
two hits of the same sector, and newsletters / round-ups only count their title. In a scam report "bank",
"rekening" and "nasabah" name the victim's bank for the transfer, not an attacked finance sector, so finance only
counts there next to an attack word ("dibobol", "breach", "ransomware"). Sectors are stored as ``sector`` entities linked to the item
(origin ``kb``), so every list, filter and graph that works with entities works with sectors too.

    keys = detect(title, body, feed_sector="Healthcare")   # -> ["health", ...]
"""
from __future__ import annotations

import re

from .extractor import Extracted
from .fraud import ROUNDUP as _FRAUD_ROUNDUP

RULES_VERSION = 2  # bump when the rules change: the start-up job re-tags stored items once
# 2 (0.10.1): one title hit is not enough on its own; finance in scam reports needs an attack word

# (key, display name, Indonesian name, case-insensitive pattern, case-sensitive pattern for acronyms)
SECTORS: list[tuple[str, str, str, str, str]] = [
    ("government", "Government administration", "Administrasi pemerintahan",
     r"\bgovernment(?:s|al)?\b(?![\s-](?:backed|sponsored|linked|aligned|funded|hackers?|actors?)\b)|\bministr(?:y|ies)\b|"
     r"\bfederal agenc(?:y|ies)\b|\bgovernment agenc\w*|"
     r"\bpublic sector\b|\bmunicipal(?:ity|ities)?\b|\bcity (?:council|government|hall)\b|\bstate agenc\w*|"
     r"\bembass(?:y|ies)\b|\bparliament\b|\belection (?:commission|system|infrastructure)s?\b|\bkementerian\b|"
     r"\bkemen(?:kes|keu|dagri|kumham|hub|dik\w*|ag|lu|pan\w*|sos|kominfo|perin|dag|aker|parekraf|pora|ko\w*|"
     r"des\w*|pupr|tan|lhk|ham|imipas|investasi|hut|ekraf|kop\w*)\b|\bpemerintah(?:an)?\b|\bpemda\b|\bpemkot\b|\bpemkab\b|\bpemprov\b|\bdinas\b|"
     r"\blembaga (?:negara|pemerintah)\b|\binstansi (?:pemerintah|negara)\b|\b[\w-]+\.go\.id\b|"
     r"pusat data nasional|\bdukcapil\b|\bbadan (?:siber|kepegawaian)\b",
     r"\bPDNS\b|\bKPU\b|\bBKN\b|\bDPRD?\b"),
    ("energy", "Energy & mineral resources", "Energi dan sumber daya mineral",
     r"\benerg(?:y|i)\b(?! drinks?)|\boil (?:and|&) gas\b|\bmigas\b|\bpower (?:grid|plant|station|utilit\w*|compan\w*)|"
     r"\belectric(?:ity|al)? (?:grid|utilit\w*|compan\w*|provider)s?|\butilit(?:y|ies) (?:compan\w*|provider|sector)|"
     r"\bpertamina\b|\brefiner(?:y|ies)\b|\bkilang\b|\bpipeline operators?\b|\bnuclear (?:plant|power|facilit\w*)|"
     r"\bmining (?:compan\w*|firm|sector|industry)|\bpertambangan\b|\bperusahaan tambang\b|\bpembangkit\b|"
     r"\bsolar (?:farm|plant|inverter)s?\b|\bwind (?:farm|turbine)s?\b|\bpetroleum\b|\bsumber daya mineral\b",
     r"\bPLN\b|\bPGN\b|\bESDM\b"),
    ("transportation", "Transportation", "Transportasi",
     r"\btransport(?:ation)?\b(?! layer)|\btransportasi\b|\bairlines?\b|\bairports?\b|\bbandara\b|\bmaskapai\b|\baviation\b|"
     r"\bpenerbangan\b|\brail(?:way|road)s?\b|\bkereta(?: api)?\b|\bshipping (?:compan\w*|lines?|giant|firm)|"
     r"\bmaritime\b|\bport (?:authority|operator|terminal)s?\b|\bpelabuhan\b|\blogistics?\b|\blogistik\b|"
     r"\btrucking\b|\bgaruda indonesia\b|\bjalan tol\b|\bpelni\b|\bpelindo\b|\bangkasa pura\b|"
     r"\b(?:public|mass) transit\b",
     r"\bKAI\b|\bKRL\b|\bMRT\b"),
    ("finance", "Finance", "Keuangan",
     r"\bbank(?:s|ing)?\b|\bperbankan\b|\bfinancial (?:institution|services|sector|firm|compan\w*|industry)|"
     r"\bfinance (?:sector|industry|compan\w*)|\bkeuangan\b|\bfintech\b|\binsurance (?:compan\w*|firm|provider|sector)|"
     r"\binsurers?\b|\basuransi\b|\bpayment (?:processor|provider|gateway|system|platform)s?\b|\bsistem pembayaran\b|"
     r"\be-?wallets?\b|\bdompet digital\b|\bcrypto(?:currency)? exchanges?\b|\bbursa (?:efek|kripto)\b|"
     r"\bstock exchanges?\b|\bbrokerages?\b|\bpinjol\b|\bpinjaman online\b|\blending platforms?\b|\bnasabah\b|"
     r"\brekening\b|\bbank indonesia\b",
     r"\bOJK\b|\bBCA\b|\bBRI\b|\bBNI\b|\bBSI\b|\bBTN\b|\bQRIS\b|\bATMs?\b|\bSWIFT\b"),
    ("health", "Health", "Kesehatan",
     r"\bhealth ?care\b|\bhospitals?\b|\brumah sakit\b|\bmedical (?:cent(?:er|re)|device|records?|provider|group|"
     r"facilit\w*)s?|\bclinics?\b|\bklinik\b|\bpharma(?:ceutical)?s?\b|\bfarmasi\b|\bpatients?\b|\bpasien\b|"
     r"\bkesehatan\b|\bhealth (?:system|sector|ministry|insurance|data|records|services|authority|department)s?\b|"
     r"\bkemenkes\b|\bpuskesmas\b|\bsatusehat\b|\bmedical lab(?:orator(?:y|ies))?\b",
     r"\bBPJS\b"),
    ("ict", "ICT", "Teknologi informasi dan komunikasi",
     r"\btelecom(?:s|munications?)?\b|\btelekomunikasi\b|\btelcos?\b|\b(?:mobile|network|wireless|cellular) "
     r"(?:operator|carrier)s?\b|\boperator seluler\b|\binternet (?:service )?providers?\b|\bdata ?cent(?:er|re)s?\b|"
     r"\bpusat data\b|\bcloud (?:provider|service provider|platform)s?\b|\bhosting (?:provider|compan\w*)|"
     r"\bmanaged service providers?\b|\bsoftware (?:vendor|compan\w*|maker|developer|supply chain)s?\b|"
     r"\btech(?:nology)? (?:compan\w*|firm|giant|sector|vendor)s?\b|\bperusahaan teknologi\b|\btelkom(?:sel)?\b|"
     r"\bindosat\b|\bxl ?axiata\b|\bsmartfren\b|\bsatellite (?:operator|provider|network)s?\b|"
     r"\bdomain registrars?\b",
     r"\bISPs?\b|\bMSPs?\b|\bIT (?:services?|provider|compan\w*|vendor)s?\b"),
    ("food", "Food", "Pangan",
     r"\bfood\b(?! for thought)|\bpangan\b|\bagricultur\w*|\bpertanian\b|\bbulog\b|\bfarm(?:ing|ers?)\b|\bpetani\b|"
     r"\bfood (?:and|&) beverages?\b|\bmakanan\b|\bperikanan\b|\bfisher(?:y|ies)\b|\bperkebunan\b|\bplantations?\b|"
     r"\bsupermarkets?\b|\bgrocer(?:y|ies)\b|\bmeat (?:processor|producer|supplier)s?\b|\bdairy\b|\bbeverages?\b|"
     r"\brefrigeration\b|\bcold chain\b|\bketahanan pangan\b|\bsembako\b",
     r"\bF&B\b"),
    ("defense", "Defence", "Pertahanan",
     r"\bmilitar(?:y|ies)\b|\bmiliter\b|\bdefen[cs]e (?:ministry|contractors?|industry|sector|department|firms?|"
     r"compan\w*|agenc\w*|forces?)\b|\b(?:ministry|department|secretary) of defen[cs]e\b|\bkementerian pertahanan\b|"
     r"\bkemhan\b|\bpertahanan negara\b|\bindustri pertahanan\b|\barmed forces\b|(?<!it )\barmy\b|\bnavy\b|"
     r"\bnaval\b|\bair force\b|\bangkatan (?:darat|laut|udara)\b|\btentara\b|\bdefense industrial base\b|"
     r"\bpentagon\b",
     r"\bTNI\b|\bDoD\b|\bNATO\b"),
]
SECTOR_KEYS = tuple(k for k, *_ in SECTORS)
SECTOR_NAMES = {k: n for k, n, *_ in SECTORS}
SECTOR_NAMES_ID = {k: n for k, _, n, *_ in SECTORS}
_RX = [(k, re.compile(ci, re.I), re.compile(cs) if cs else None) for k, _, _, ci, cs in SECTORS]

# Values feeds use for a victim's sector (ransomware.live "activity", OTX "industries"), matched as substrings.
FEED_SECTORS = [
    ("health", ("health", "hospital", "pharma", "medical")),
    ("finance", ("financ", "bank", "insurance", "fintech", "crypto")),
    ("government", ("government", "public sector", "public administration", "municipal")),
    ("energy", ("energy", "oil", "gas", "utilit", "mining", "power")),
    ("transportation", ("transport", "logistic", "aviation", "airline", "maritime", "shipping")),
    ("ict", ("telecom", "technology", "information", "software", "internet", "hosting")),
    ("food", ("agricultur", "food", "beverage", "farming")),
    ("defense", ("defen", "military", "aerospace")),
]
# Newsletters, round-ups, podcasts and interviews name every sector in passing: only their title counts.
_ROUNDUP = re.compile(_FRAUD_ROUNDUP.pattern + r"|\bstormcast\b|\bnever be afraid\b", re.I)
MAX_SECTORS = 3
BODY_CHARS = 20_000  # long reports are scanned up to here
THRESHOLD = 2  # points: a title hit is 2, a body hit 1
TITLE_ONLY_THRESHOLD = 3  # "Bank account scams rise in Jakarta" alone is no finance-sector item (audit 2026-11 D-9)
ATTACK_CUE = re.compile(r"\b(?:dibobol|membobol|pembobolan|diretas|meretas|peretasan|breach(?:ed|es)?|hack(?:ed|ers?)|"
                        r"ransomware|data (?:leak|breach)|kebocoran data|cyber ?attacks?|serangan|diserang|intrusion|"
                        r"compromised|ddos|lumpuh\w*|outage|systems? (?:down|offline)|hit by|attack(?:s|ed)?|"
                        r"zero[\s-]?days?|exploit\w*|stolen|dicuri|leak(?:s|ed)?|bocor)\b", re.I)


def _hits(rx: re.Pattern, cs: re.Pattern | None, text: str) -> int:
    n = sum(1 for _ in rx.finditer(text))
    if cs is not None:
        n += sum(1 for _ in cs.finditer(text))
    return n


def feed_sectors(values) -> list[str]:
    """Sector keys for the sector names a feed supplies ("Healthcare", "Financial Services"…)."""
    if isinstance(values, str):
        values = [values]
    out: list[str] = []
    for v in values or []:
        s = str(v or "").lower()
        if not s or s in ("not found", "unknown", "n/a", "other"):
            continue
        for key, needles in FEED_SECTORS:
            if key not in out and any(n in s for n in needles):
                out.append(key)
    return out


def detect(title: str, body: str, feed_sector=None, scam: bool = False) -> list[str]:
    """Sector keys an item is about, strongest first (at most ``MAX_SECTORS``). ``scam``: the item is a scam
    report (fraud score > 0)."""
    title, body = title or "", (body or "")[:BODY_CHARS]
    if _ROUNDUP.search(title):
        body = ""
    scores: dict[str, int] = {}
    from_feed = set(feed_sectors(feed_sector))
    for key in from_feed:
        scores[key] = scores.get(key, 0) + 3
    attack = bool(ATTACK_CUE.search(title) or ATTACK_CUE.search(body))
    hits = [(key, _hits(rx, cs, title), min(_hits(rx, cs, body), 4)) for key, rx, cs in _RX]
    in_title = sum(1 for _, t, _ in hits if t)
    for key, t, b in hits:
        if key == "finance" and scam and key not in from_feed and not attack:
            continue
        s = 2 * t + b
        if not s:
            continue
        # one title word and nothing in the body: only when the headline is about an attack on that one sector
        # ("Serangan ransomware lumpuhkan layanan rumah sakit"), not "Hospital food vendor hit by phishing"
        if (not b and key not in from_feed and s < TITLE_ONLY_THRESHOLD
                and not (in_title == 1 and ATTACK_CUE.search(title))):
            continue
        scores[key] = scores.get(key, 0) + s
    keys = [k for k, s in scores.items() if s >= THRESHOLD]
    keys.sort(key=lambda k: (-scores[k], SECTOR_KEYS.index(k)))
    return keys[:MAX_SECTORS]


def entities(keys: list[str]) -> list[Extracted]:
    return [Extracted("sector", k, SECTOR_NAMES[k], "cii", "kb") for k in keys]


def _feed_value(raw: dict | None):
    raw = raw or {}
    return [raw.get("sector") or "", *(raw.get("industries") or [])]


def apply(item) -> list[Extracted]:
    """Sector entities to link to a freshly collected ``item``."""
    body = f"{item.content or ''}\n{' '.join(item.tags or [])}"
    return entities(detect(item.title, body, _feed_value(item.raw), scam=bool(item.fraud_score)))


def retag_all(db, progress=None, batch: int = 500) -> int:
    """Re-detect the sectors of every stored item; only links that changed are written."""
    from sqlalchemy import select

    from ..models import Entity, Item, ItemEntity
    from .pipeline import get_or_create_entity

    ids = [i for (i,) in db.execute(select(Item.id).order_by(Item.id))]
    ents: dict[str, Entity] = {}

    def entity(key: str, seen_at) -> Entity:
        ent = ents.get(key)
        if ent is None:
            ent = ents[key] = get_or_create_entity(db, entities([key])[0], seen_at)
        else:
            ent.first_seen, ent.last_seen = min(ent.first_seen, seen_at), max(ent.last_seen, seen_at)
        return ent

    for n in range(0, len(ids), batch):
        chunk = ids[n:n + batch]
        old: dict[int, dict[str, ItemEntity]] = {}
        for link, value in db.execute(select(ItemEntity, Entity.value).join(Entity, Entity.id == ItemEntity.entity_id)
                                      .where(ItemEntity.item_id.in_(chunk), Entity.type == "sector")):
            old.setdefault(link.item_id, {})[value] = link
        for item in db.execute(select(Item).where(Item.id.in_(chunk))).unique().scalars():
            want = set(detect(item.title, f"{item.content or ''}\n{' '.join(item.tags or [])}", _feed_value(item.raw),
                              scam=bool(item.fraud_score)))
            have = old.get(item.id, {})
            for key in set(have) - want:
                link = have[key]
                ent = db.get(Entity, link.entity_id)
                if ent is not None:
                    ent.mention_count = max(0, (ent.mention_count or 0) - 1)
                db.delete(link)
            for key in want - set(have):
                ent = entity(key, item.published_at)
                db.add(ItemEntity(item_id=item.id, entity_id=ent.id, origin="kb"))
                ent.mention_count = (ent.mention_count or 0) + 1
        db.commit()
        if progress:
            progress(min(n + batch, len(ids)), len(ids))
    return len(ids)
