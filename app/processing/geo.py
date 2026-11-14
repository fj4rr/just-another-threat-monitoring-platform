"""Geography: which countries (and Indonesian provinces) an item is about, in which language it is written
and which country it comes from.

Three separate relations are kept, so that hosting countries never inflate the target heatmap:

* **target** (``item_geo`` rows): countries / provinces named as victims or where activity took place.
  Found in the text (place names, demonyms, Indonesian institutions and ``.go.id``-style domains) or supplied
  by the feed (ransomware.live victim country, OTX targeted countries). Countries that describe the
  *attacker* ("Russian hackers", "China-nexus", "peretas asal Rusia", "attributed to North Korea") are not
  targets.
* **source** (``items.src_country``): the outlet's country (``sources.country``), or Indonesia for items
  written in Indonesian.
* **infrastructure** (``entities.country``): where an indicator is hosted, from GeoIP and the intel
  providers. Only used for the infrastructure view, never for targets.

``region_clause("id")`` is the *National (Indonesia)* filter used by every dashboard and list query:
items that target Indonesia, plus items from Indonesian outlets that do not name another target country.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from sqlalchemy import and_, delete, exists, or_, select
from sqlalchemy.orm import Session, aliased

from .. import gazetteer as gz

NATIONAL = "ID"
REGIONS = {"intl": "International", "id": "National (ID)"}
GEO_VERSION = 1  # bump when the detection rules change; start-up re-tags existing items once

# --------------------------------------------------------------------------- language
_ID_TEXT = """yang dan di ke dari ini itu untuk dengan tidak adalah pada dalam akan oleh juga sudah telah bisa
karena atau mereka kami kita saat sebagai lebih para serta tersebut menjadi secara bahwa hingga
namun belum masih melalui terhadap setelah sejumlah pihak pengguna dilakukan sebanyak sedang dapat
agar ada tak bagi kepada seperti hal tahun jutaan ribuan menurut diduga mengatakan kata ujar
terkait"""
_EN_TEXT = """the and of to in is that for with as on was are by this from have has be it an which were their
been its not or after about into than also more who they had would could should these those such"""
_ID_WORDS = frozenset(_ID_TEXT.split())
_EN_WORDS = frozenset(_EN_TEXT.split())
_WORD = re.compile(r"[a-zA-Z]+")


def detect_language(text: str) -> str:
    """'id', 'en' or '' (too short / other). Stop-word counting is enough to tell Indonesian from English."""
    words = [w.lower() for w in _WORD.findall((text or "")[:4000])]
    if len(words) < 6:
        return ""
    ind = sum(w in _ID_WORDS for w in words)
    eng = sum(w in _EN_WORDS for w in words)
    if ind >= 3 and ind > eng * 1.2:
        return "id"
    if eng >= 3 and eng >= ind:
        return "en"
    return ""


# --------------------------------------------------------------------------- matcher
@dataclass
class _Name:
    kind: str  # country | demonym | province | place | org
    code: str  # ISO2 or ISO 3166-2
    strict: bool = False  # needs a place-like context
    weak: bool = False  # only with another Indonesian signal or in Indonesian text
    indonesian_only: bool = False


def _build() -> tuple[re.Pattern, dict[str, _Name]]:
    names: dict[str, _Name] = {}
    for code, c in gz.COUNTRIES.items():
        for n in [c["name"], *c["aliases"]]:
            names.setdefault(n, _Name("country", code, strict=n in gz.COUNTRY_STRICT,
                                      indonesian_only=n in gz.INDONESIAN_ONLY))
        for d in c["demonyms"]:
            names.setdefault(d, _Name("demonym", code))
    for code, (pname, alts) in gz.PROVINCES.items():
        for n in [pname, *alts]:
            names[n] = _Name("province", code, weak=n in gz.PROVINCE_WEAK)
    for n, code in gz.ID_PLACES.items():
        names.setdefault(n, _Name("place", code))
    for n in gz.ID_ORGS:
        names.setdefault(n, _Name("org", NATIONAL, weak=n in gz.ID_ORGS_WEAK))

    def alt(n: str, spec: _Name) -> str:
        esc = re.escape(n).replace(r"\ ", r"[\s-]+")
        # long, unambiguous country and province names also match in lower case (social posts);
        # city names and acronyms are proper nouns ("medan" is also an Indonesian word)
        loose = (spec.kind in ("country", "province") and len(n) >= 5 and not spec.strict and not spec.weak
                 and n not in gz.COUNTRY_EXACT and not n.isupper())
        return f"(?i:{esc})" if loose else esc

    ordered = sorted(names, key=len, reverse=True)
    pat = re.compile(r"(?<![\w@./-])(" + "|".join(alt(n, names[n]) for n in ordered) + r")(?![\w-]*\.[a-z]{2,}\b)(?!\w)")
    lookup = {_norm(n): spec for n, spec in names.items()}
    return pat, lookup


_PAT: re.Pattern | None = None
_LOOKUP: dict[str, _Name] = {}


def _matcher() -> tuple[re.Pattern, dict[str, _Name]]:
    global _PAT, _LOOKUP
    if _PAT is None:
        _PAT, _LOOKUP = _build()
    return _PAT, _LOOKUP


def _norm(s: str) -> str:
    return re.sub(r"[\s-]+", " ", s).lower()


# Words right after a country / demonym that make it the *attacker*: "Russian hackers", "China-nexus",
# "Iran-linked", "North Korea's Lazarus", "Chinese-speaking actors".
_FOLLOW_ATTR = re.compile(
    r"^(?:'s|’s)?[\s-]*(?:state[\s-]*)?(?:sponsored|backed|linked|nexus|aligned|affiliated|speaking|origin\b|"
    r"based\s+(?:hackers?|threat|apts?|actors?|groups?|gangs?|cyber|attackers?)|hackers?|hacking|hacktivists?|"
    r"threat\s+(?:actors?|groups?|clusters?)|apts?\b|cyber[\s-]*(?:spies|spy|espionage|actors?|criminals?|"
    r"gangs?|army|units?|operatives?|attackers?|threat\s+actors?)|spies|spy\b|espionage|intelligence\b|"
    r"military\s+(?:hackers?|intelligence|units?)|government[\s-]+(?:backed|sponsored|linked|hackers?)|"
    r"nation[\s-]state|state\s+(?:hackers?|actors?)|operators?\b|actors?\b|ransomware\s+(?:gangs?|groups?|"
    r"operators?|actors?)|gangs?\b|it\s+workers|attackers?|adversar|intrusion\s+sets?|"
    r"(?:GRU|FSB|SVR|MSS|IRGC|MOIS|RGB|PLA|Unit\s+\d+)\b)", re.I)
# Words right before it: "hackers from Iran", "attributed to North Korea", "peretas asal Rusia".
_PRECEDE_ATTR = re.compile(
    r"(?:(?:hackers?|actors?|groups?|apts?|spies|gangs?|operators?|attackers?|adversar(?:y|ies)|crews?|"
    r"operatives?)\s+(?:from|based\s+in|linked\s+to|tied\s+to|backed\s+by|sponsored\s+by|working\s+for|"
    r"operating\s+(?:out\s+of|from))|attributed\s+to|linked\s+to|tied\s+to|blamed\s+on|backed\s+by|"
    r"sponsored\s+by|on\s+behalf\s+of|(?:peretas|hacker|kelompok(?:\s+peretas)?|grup(?:\s+peretas)?|geng|"
    r"aktor(?:\s+ancaman)?)(?:\s+(?:asal|dari|yang\s+berbasis\s+di|berbasis\s+di|yang\s+didukung))?|"
    r"dikaitkan\s+dengan|didukung(?:\s+oleh)?|disponsori(?:\s+oleh)?)\s+(?:the\s+)?$", re.I)
# Words right before it that make it the place of activity: "in Indonesia", "targeting Japan".
_PRECEDE_TARGET = re.compile(
    r"(?:\bin|against|targeting|targets|targeted|target|across|throughout|hit|hits|hitting|attacks?\s+on|"
    r"victims?\s+in|organi[sz]ations?\s+in|companies\s+in|users?\s+in|customers\s+in|\bdi|terhadap|menyerang|"
    r"menargetkan|sasaran|wilayah|seluruh|warga)\s+(?:the\s+)?$", re.I)
# "Latin America", "South Korea" are separate names; "North/South/Central/Latin America" is not the US.
_NOT_US = re.compile(r"(?:Latin|South|North|Central)\s+$")
_VICTIM_CC = re.compile(r"\b[\w.-]+\.[a-z]{2,24}\s+\(([A-Z]{2})\)")
_ID_DOMAIN = re.compile(gz.ID_DOMAIN_RE, re.I)


@dataclass
class GeoResult:
    lang: str = ""
    targets: dict[str, float] = field(default_factory=dict)  # ISO2 -> score
    provinces: dict[str, float] = field(default_factory=dict)  # ID-XX -> score
    feed: set[str] = field(default_factory=set)  # countries supplied by the feed / victim posting
    attributed: set[str] = field(default_factory=set)  # countries named as the attacker (not stored)

    def top(self, limit: int = 4, threshold: float = 1.5) -> list[tuple[str, float]]:
        rows = sorted(((c, s) for c, s in self.targets.items() if s >= threshold or c in self.feed),
                      key=lambda r: (-r[1], r[0]))
        return rows[:limit]

    def top_provinces(self, limit: int = 4) -> list[tuple[str, float]]:
        return sorted(((p, s) for p, s in self.provinces.items() if s >= 1), key=lambda r: (-r[1], r[0]))[:limit]


def _scan(text: str, in_title: bool, lang: str, res: GeoResult, weak_hits: list) -> None:
    pat, lookup = _matcher()
    if not text:
        return
    # ALL-CAPS headlines ("PAGE IMPERSONATING ...") would hide proper nouns from the case-sensitive names
    letters = [c for c in text if c.isalpha()]
    if letters and sum(c.isupper() for c in letters) / len(letters) > 0.7:
        text = text.title()
    body_seen: dict[str, int] = {}
    for m in pat.finditer(text):
        spec = lookup.get(_norm(m.group(1)))
        if spec is None:
            continue
        before = text[max(0, m.start() - 48):m.start()]
        after = text[m.end():m.end() + 40]
        if spec.indonesian_only and lang != "id":
            continue
        if spec.kind in ("country", "demonym"):
            if spec.code == "US" and _NOT_US.search(before):
                continue
            if _FOLLOW_ATTR.match(after) or _PRECEDE_ATTR.search(before):
                res.attributed.add(spec.code)
                continue
            cue = bool(_PRECEDE_TARGET.search(before))
            if spec.strict and not cue:
                continue
            if in_title:
                w = 2.0
            else:
                n = body_seen.get(spec.code, 0)
                body_seen[spec.code] = n + 1
                w = 1.0 if n == 0 else 0.5 if n < 5 else 0.0
            if spec.kind == "demonym":
                w *= 0.75
            if cue:
                w *= 1.5
            res.targets[spec.code] = res.targets.get(spec.code, 0.0) + w
            continue
        # Indonesian-specific names: a province / city / institution is a strong signal on its own
        if spec.weak:
            weak_hits.append((spec, in_title))
            continue
        w = 3.0 if in_title else 2.0
        res.targets[NATIONAL] = res.targets.get(NATIONAL, 0.0) + w
        if spec.kind in ("province", "place"):
            res.provinces[spec.code] = res.provinces.get(spec.code, 0.0) + (2.0 if in_title else 1.0)
    # "Kota Malang", "Pemkab Batu": ambiguous place names after an administrative prefix
    for m in re.finditer(gz.ADMIN_PREFIX + r"\s+(" + "|".join(map(re.escape, gz.ID_PLACES_STRICT)) + r")\b", text):
        code = gz.ID_PLACES_STRICT[m.group(1)]
        res.targets[NATIONAL] = res.targets.get(NATIONAL, 0.0) + (3.0 if in_title else 2.0)
        res.provinces[code] = res.provinces.get(code, 0.0) + (2.0 if in_title else 1.0)


def analyse(title: str, body: str = "", *, feed_countries=(), lang: str | None = None) -> GeoResult:
    """Geo attribution for one item (pure function; no database)."""
    title = title or ""
    body = (body or "")[:20000]
    res = GeoResult(lang=detect_language(f"{title}\n{body}") if lang is None else lang)
    weak: list = []
    _scan(title, True, res.lang, res, weak)
    _scan(body, False, res.lang, res, weak)
    # Indonesian government / company domains (victims on leak sites, phishing lures)
    n_dom = len({m.group(0).lower() for m in _ID_DOMAIN.finditer(f"{title}\n{body}")})
    if n_dom:
        res.targets[NATIONAL] = res.targets.get(NATIONAL, 0.0) + min(2.0 * n_dom, 4.0)
    # "<victim>.com (GB)" in leak-site victim postings
    for m in _VICTIM_CC.finditer(f"{title}\n{body}"):
        cc = m.group(1)
        if cc in gz.COUNTRIES:
            res.targets[cc] = res.targets.get(cc, 0.0) + 3.0
    # weak Indonesian acronyms (BCA, KPU, "DIY"...) only count in Indonesian text or next to another signal
    if weak and (res.lang == "id" or res.targets.get(NATIONAL, 0) >= 1.5):
        for spec, in_title in weak:
            res.targets[NATIONAL] = res.targets.get(NATIONAL, 0.0) + (2.0 if in_title else 1.0)
            if spec.kind == "province":
                res.provinces[spec.code] = res.provinces.get(spec.code, 0.0) + (2.0 if in_title else 1.0)
    for c in feed_countries or ():
        cc = gz.normalise_country(c)
        if cc:
            res.feed.add(cc)
            res.targets[cc] = res.targets.get(cc, 0.0) + 10.0
    if NATIONAL not in dict(res.top()):
        res.provinces.clear()
    return res


def feed_countries(raw: dict | None) -> list[str]:
    """Countries a feed states structurally: ransomware.live victims, OTX targeted countries, MISP tags."""
    raw = raw or {}
    out = []
    if raw.get("country"):
        out.append(raw["country"])
    for c in raw.get("targeted_countries") or []:
        out.append(c)
    return [str(c) for c in out if c][:10]


# --------------------------------------------------------------------------- persistence
def tag_item(db: Session, item, source=None, *, replace: bool = True) -> GeoResult:
    """Detect language, source country and targets for ``item`` and store them."""
    from ..models import ItemGeo

    source = source or item.source
    lang = detect_language(f"{item.title}\n{item.content}") or (source.language if source and source.language else "")
    feed = feed_countries(item.raw)
    if replace and item.id and item.slimmed_at:
        # retention dropped ``raw``; keep the countries the feed supplied when the item was collected
        feed += [c for (c,) in db.execute(select(ItemGeo.country).where(ItemGeo.item_id == item.id,
                                                                         ItemGeo.origin == "feed"))]
    res = analyse(item.title, item.content, feed_countries=feed, lang=lang)
    item.lang = lang
    item.src_country = (source.country if source and source.country else "") or ("ID" if item.lang == "id" else "")
    if replace and item.id:
        db.execute(delete(ItemGeo).where(ItemGeo.item_id == item.id))
    top = res.top()
    provs = res.top_provinces()
    for cc, score in top:
        origin = "feed" if cc in res.feed else "text"
        if cc == NATIONAL and provs:
            for code, ps in provs:
                db.add(ItemGeo(item_id=item.id, country=cc, region=code, score=round(score + ps, 2), origin=origin))
        else:
            db.add(ItemGeo(item_id=item.id, country=cc, region="", score=round(score, 2), origin=origin))
    return res


def retag_all(db: Session, progress=None, batch: int = 500) -> int:
    """Re-run geo attribution on every item (after a rules change or ``manage.py geotag``)."""
    from ..models import Item

    ids = [i for (i,) in db.execute(select(Item.id).order_by(Item.id))]
    for n in range(0, len(ids), batch):
        for item in db.execute(select(Item).where(Item.id.in_(ids[n:n + batch]))).unique().scalars():
            tag_item(db, item)
        db.commit()
        if progress:
            progress(min(n + batch, len(ids)), len(ids))
    return len(ids)


def targets_for(db: Session, item_ids: list[int]) -> dict[int, list[dict]]:
    """Target countries (with Indonesian provinces) per item for list views and the API, in one query."""
    from ..models import ItemGeo

    out: dict[int, list[dict]] = {}
    if not item_ids:
        return out
    rows = db.execute(select(ItemGeo.item_id, ItemGeo.country, ItemGeo.region).where(ItemGeo.item_id.in_(item_ids))
                      .order_by(ItemGeo.score.desc())).all()
    for iid, cc, region in rows:
        lst = out.setdefault(iid, [])
        t = next((x for x in lst if x["code"] == cc), None)
        if t is None:
            t = {"code": cc, "provinces": []}
            lst.append(t)
        if region and region not in t["provinces"]:
            t["provinces"].append(region)
    return out


# --------------------------------------------------------------------------- region filter
def norm_region(value: str | None) -> str:
    v = (value or "").strip().lower()
    return v if v in REGIONS else "intl"


def region_clause(region: str):
    """SQL condition on ``Item`` for the selected region, or None for the international (unfiltered) view."""
    from ..models import Item, ItemGeo

    if norm_region(region) != "id":
        return None
    # aliases: the outer query may itself join item_geo (Geography page), which would otherwise be
    # auto-correlated away
    g1, g2 = aliased(ItemGeo), aliased(ItemGeo)
    targets_id = exists().where(g1.item_id == Item.id, g1.country == NATIONAL)
    targets_other = exists().where(g2.item_id == Item.id, g2.country != NATIONAL)
    return or_(targets_id, and_(Item.src_country == NATIONAL, ~targets_other))


def scoped(stmt, region: str):
    """``stmt`` (which must already involve ``Item``) restricted to ``region``."""
    clause = region_clause(region)
    return stmt if clause is None else stmt.where(clause)
