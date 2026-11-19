"""Built-in knowledge base of malware families and threat actors.

Extend it without touching code by creating data/knowledge_extra.json:
{
  "malware": {"NewFamily": {"category": "stealer", "aliases": ["newfam"]}},
  "actors":  {"Some Actor": {"aliases": ["UNC1234"], "category": "nation-state"}}
}
The LLM extractor (if enabled) also adds unknown families to the DB at runtime.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache

from .config import DATA_DIR

CATEGORIES = [
    "ransomware", "stealer", "rat", "loader", "botnet", "banking", "backdoor",
    "c2-framework", "wiper", "miner", "spyware", "rootkit", "worm", "exploit-kit", "other",
]

# name: (category, [aliases])
MALWARE: dict[str, tuple[str, list[str]]] = {
    # --- Ransomware
    "LockBit": ("ransomware", ["lockbit 3.0", "lockbit black", "lockbit 4.0", "lockbit green"]),
    "ALPHV": ("ransomware", ["blackcat", "alphv/blackcat", "noberus"]),
    "Akira": ("ransomware", ["akira ransomware"]),
    "Black Basta": ("ransomware", ["blackbasta"]),
    "Cl0p": ("ransomware", ["clop", "cl0p ransomware"]),
    "Play": ("ransomware", ["playcrypt", "play ransomware"]),
    "Qilin": ("ransomware", ["agenda ransomware", "qilin ransomware"]),
    "RansomHub": ("ransomware", ["ransom hub"]),
    "Medusa": ("ransomware", ["medusa ransomware", "medusalocker"]),
    "BlackSuit": ("ransomware", ["royal ransomware", "blacksuit ransomware"]),
    "Rhysida": ("ransomware", []),
    "8Base": ("ransomware", ["8base ransomware"]),
    "Hunters International": ("ransomware", []),
    "INC Ransom": ("ransomware", ["inc ransomware"]),
    "Interlock": ("ransomware", ["interlock ransomware"]),
    "SafePay": ("ransomware", ["safepay ransomware"]),
    "DragonForce": ("ransomware", ["dragonforce ransomware"]),
    "Fog": ("ransomware", ["fog ransomware"]),
    "Embargo": ("ransomware", ["embargo ransomware"]),
    "BianLian": ("ransomware", []),
    "Conti": ("ransomware", []),
    "Black Hunt": ("ransomware", []),
    "Gunra": ("ransomware", []),
    "Warlock": ("ransomware", ["warlock ransomware"]),
    "Kraken": ("ransomware", ["kraken ransomware"]),
    "Sinobi": ("ransomware", []),
    "The Gentlemen": ("ransomware", ["gentlemen ransomware"]),
    "Chaos": ("ransomware", ["chaos ransomware"]),
    "Babuk": ("ransomware", ["babuk2"]),
    "Mallox": ("ransomware", ["targetcompany"]),
    "Phobos": ("ransomware", []),
    "STOP/Djvu": ("ransomware", ["djvu", "stop ransomware"]),
    "Lynx": ("ransomware", []),
    # --- Info-stealers
    "Lumma Stealer": ("stealer", ["lumma", "lummac2", "lummac", "lumma c2"]),
    "RedLine": ("stealer", ["redline stealer", "redlinestealer"]),
    "Vidar": ("stealer", ["vidar stealer"]),
    "StealC": ("stealer", ["stealc"]),
    "Raccoon Stealer": ("stealer", ["raccoon", "recordbreaker"]),
    "Atomic Stealer": ("stealer", ["amos", "atomic macos stealer", "amos stealer"]),
    "RisePro": ("stealer", []),
    "MetaStealer": ("stealer", ["meta stealer"]),
    "Rhadamanthys": ("stealer", []),
    "Acreed": ("stealer", ["acr stealer", "acrstealer"]),
    "Banshee Stealer": ("stealer", ["banshee"]),
    "Poseidon Stealer": ("stealer", []),
    "Formbook": ("stealer", ["xloader", "formbook/xloader"]),
    "Agent Tesla": ("stealer", ["agenttesla"]),
    "Snake Keylogger": ("stealer", ["404 keylogger", "snakekeylogger"]),
    "Raven Stealer": ("stealer", []),
    "Odyssey Stealer": ("stealer", []),
    "Katz Stealer": ("stealer", []),
    "Amatera": ("stealer", ["amatera stealer"]),
    "Noodlophile": ("stealer", []),
    "Aurora Stealer": ("stealer", []),
    "Mystic Stealer": ("stealer", []),
    "Rilide": ("stealer", []),
    "Glove Stealer": ("stealer", []),
    "MacSync": ("stealer", ["mac.c stealer"]),
    # --- RATs
    "AsyncRAT": ("rat", ["async rat"]),
    "Remcos": ("rat", ["remcosrat", "remcos rat"]),
    "njRAT": ("rat", ["bladabindi"]),
    "Quasar RAT": ("rat", ["quasarrat", "quasar"]),
    "DCRat": ("rat", ["darkcrystal rat", "dcrat"]),
    "XWorm": ("rat", ["xworm rat"]),
    "NanoCore": ("rat", []),
    "Warzone RAT": ("rat", ["ave maria", "avemaria"]),
    "VenomRAT": ("rat", ["venom rat"]),
    "PlugX": ("rat", ["korplug"]),
    "ShadowPad": ("backdoor", []),
    "NetSupport RAT": ("rat", ["netsupport manager rat", "netsupport"]),
    "SectopRAT": ("rat", ["arechclient2"]),
    "Gh0st RAT": ("rat", ["gh0st", "ghost rat"]),
    "PureRAT": ("rat", ["purehvnc", "pure rat"]),
    "SparkRAT": ("rat", []),
    "ValleyRAT": ("rat", ["winos4.0", "winos"]),
    "BRAT": ("rat", []),
    # --- Loaders / initial access
    "SmokeLoader": ("loader", ["smoke loader", "dofoil"]),
    "GuLoader": ("loader", ["cloudeye"]),
    "IcedID": ("loader", ["bokbot"]),
    "Bumblebee": ("loader", []),
    "Pikabot": ("loader", []),
    "Latrodectus": ("loader", []),
    "DarkGate": ("loader", []),
    "SocGholish": ("loader", ["fakeupdates"]),
    "QakBot": ("loader", ["qbot", "pinkslipbot"]),
    "Emotet": ("loader", ["heodo"]),
    "TrickBot": ("loader", []),
    "Amadey": ("loader", []),
    "PrivateLoader": ("loader", []),
    "HijackLoader": ("loader", ["idat loader", "idatloader"]),
    "Matanbuchus": ("loader", []),
    "SSLoad": ("loader", []),
    "Oyster": ("backdoor", ["broomstick", "cleanup loader"]),
    "PureCrypter": ("loader", []),
    "DonutLoader": ("loader", ["donut loader"]),
    "BackConnect": ("backdoor", []),
    "SystemBC": ("backdoor", []),
    "GootLoader": ("loader", ["gootkit loader"]),
    "Raspberry Robin": ("worm", []),
    "CastleLoader": ("loader", []),
    # --- Botnets / IoT
    "Mirai": ("botnet", []),
    "Gafgyt": ("botnet", ["bashlite"]),
    "Mozi": ("botnet", []),
    "Aisuru": ("botnet", []),
    "Kimwolf": ("botnet", []),
    "RondoDox": ("botnet", []),
    "Moobot": ("botnet", []),
    "Androxgh0st": ("botnet", ["androxghost"]),
    "Prometei": ("botnet", []),
    # --- Banking / mobile
    "Grandoreiro": ("banking", []),
    "Anatsa": ("banking", ["teabot"]),
    "Hook": ("banking", ["hook android"]),
    "Octo": ("banking", ["exobot", "octo2"]),
    "GodFather": ("banking", ["godfather android"]),
    "Coper": ("banking", []),
    "Cerberus": ("banking", []),
    "ToxicPanda": ("banking", []),
    "Crocodilus": ("banking", []),
    "BingoMod": ("banking", []),
    "SpyNote": ("spyware", ["spymax"]),
    "Pegasus": ("spyware", []),
    "Predator": ("spyware", ["predator spyware"]),
    "Vultur": ("banking", []),
    "Mekotio": ("banking", []),
    "Casbaneiro": ("banking", []),
    # --- C2 frameworks / red team tooling abused
    "Cobalt Strike": ("c2-framework", ["cobaltstrike", "beacon"]),
    "Sliver": ("c2-framework", ["sliver c2"]),
    "Brute Ratel": ("c2-framework", ["brute ratel c4", "brc4"]),
    "Havoc": ("c2-framework", ["havoc c2"]),
    "Mythic": ("c2-framework", ["mythic c2"]),
    "Metasploit": ("c2-framework", ["meterpreter"]),
    "AdaptixC2": ("c2-framework", ["adaptix"]),
    # --- Wipers / destructive
    "WhisperGate": ("wiper", []),
    "HermeticWiper": ("wiper", []),
    "AcidRain": ("wiper", []),
    "CaddyWiper": ("wiper", []),
    # --- Miners
    "XMRig": ("miner", ["xmrig miner"]),
    # --- Backdoors / APT tooling
    "BPFDoor": ("backdoor", []),
    "SparkCockpit": ("backdoor", []),
    "BRICKSTORM": ("backdoor", ["brickstorm"]),
    "Snake": ("backdoor", ["uroburos"]),
    "KrustyLoader": ("loader", []),
    "WarmCookie": ("backdoor", ["badspace"]),
    "Lazarus Manuscrypt": ("backdoor", ["manuscrypt"]),
}

# name: [aliases]
ACTORS: dict[str, list[str]] = {
    "Lazarus Group": ["lazarus", "hidden cobra", "diamond sleet", "apt38"],
    "Kimsuky": ["apt43", "emerald sleet", "velvet chollima"],
    "APT28": ["fancy bear", "forest blizzard", "sofacy", "sednit"],
    "APT29": ["cozy bear", "midnight blizzard", "nobelium"],
    "Sandworm": ["apt44", "seashell blizzard", "voodoo bear"],
    "Turla": ["secret blizzard", "venomous bear"],
    "Gamaredon": ["primitive bear", "aqua blizzard"],
    "APT41": ["winnti", "brass typhoon", "wicked panda"],
    "Volt Typhoon": ["bronze silhouette", "vanguard panda"],
    "Salt Typhoon": ["ghostemperor", "earth estries", "famoussparrow"],
    "Silk Typhoon": ["hafnium"],
    "Mustang Panda": ["ta416", "earth preta", "twill typhoon"],
    "APT10": ["stone panda", "menupass"],
    "MuddyWater": ["mango sandstorm", "static kitten"],
    "Charming Kitten": ["apt35", "mint sandstorm", "phosphorus"],
    "APT33": ["peach sandstorm", "elfin"],
    "OilRig": ["apt34", "hazel sandstorm"],
    "Scattered Spider": ["unc3944", "octo tempest", "0ktapus", "muddled libra"],
    "ShinyHunters": ["unc6040"],
    "FIN7": ["carbanak", "sangria tempest"],
    "FIN8": [],
    "TA505": ["evil corp", "indrik spider"],
    "TA577": [],
    "TA4557": [],
    "Storm-0501": [],
    "Storm-1811": [],
    "UNC5221": [],
    "UNC3886": [],
    "Andariel": ["onyx sleet", "silent chollima"],
    "BlueNoroff": ["sapphire sleet", "apt38"],
    "Famous Chollima": ["contagious interview"],
    "Transparent Tribe": ["apt36"],
    "SideWinder": ["rattlesnake"],
    "Bitter": ["apt-q-37"],
    "Patchwork": ["dropping elephant"],
    "APT-C-36": ["blind eagle"],
    "TA558": [],
    "Water Hydra": ["darkme"],
    "Velvet Ant": [],
    "Earth Lamia": [],
    "Cl0p Gang": ["fin11", "lace tempest"],
    "Black Basta Group": [],
    "Lapsus$": ["dev-0537", "strawberry tempest"],
    "Hellcat": ["hellcat ransomware group"],
    "Crimson Collective": [],
    "Scattered LAPSUS$ Hunters": ["slsh"],
}


# What kind of group each actor is (dashboard "Threat actors by type"). Actors not listed here, for
# example ones the LLM extractor added, count as "unclassified".
ACTOR_CATEGORIES = ["nation-state", "ransomware", "extortion", "cybercrime", "unclassified"]
_ACTOR_KIND = {
    "nation-state": [
        "Lazarus Group", "Kimsuky", "APT28", "APT29", "Sandworm", "Turla", "Gamaredon", "APT41", "Volt Typhoon",
        "Salt Typhoon", "Silk Typhoon", "Mustang Panda", "APT10", "MuddyWater", "Charming Kitten", "APT33", "OilRig",
        "UNC5221", "UNC3886", "Andariel", "BlueNoroff", "Famous Chollima", "Transparent Tribe", "SideWinder", "Bitter",
        "Patchwork", "Velvet Ant", "Earth Lamia",
    ],
    "ransomware": ["Storm-0501", "Storm-1811", "Cl0p Gang", "Black Basta Group", "Hellcat"],
    "extortion": ["Scattered Spider", "ShinyHunters", "Lapsus$", "Crimson Collective", "Scattered LAPSUS$ Hunters"],
    "cybercrime": ["FIN7", "FIN8", "TA505", "TA577", "TA4557", "TA558", "Water Hydra", "APT-C-36"],
}
ACTOR_KIND: dict[str, str] = {name: kind for kind, names in _ACTOR_KIND.items() for name in names}


def actor_category(name: str) -> str:
    """nation-state / ransomware / extortion / cybercrime, or "unclassified". knowledge_extra.json may set
    ``"category"`` on an actor."""
    extra = (_extra().get("actors") or {}).get(name) or {}
    cat = extra.get("category") or ACTOR_KIND.get(name, "")
    return cat if cat in ACTOR_CATEGORIES else "unclassified"


@lru_cache(maxsize=1)
def _extra() -> dict:
    path = DATA_DIR / "knowledge_extra.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


@lru_cache(maxsize=1)
def malware_table() -> dict[str, tuple[str, list[str]]]:
    table = dict(MALWARE)
    for name, spec in (_extra().get("malware") or {}).items():
        table[name] = (spec.get("category", "other"), [a.lower() for a in spec.get("aliases", [])])
    return table


@lru_cache(maxsize=1)
def actor_table() -> dict[str, list[str]]:
    table = dict(ACTORS)
    for name, spec in (_extra().get("actors") or {}).items():
        table[name] = [a.lower() for a in spec.get("aliases", [])]
    return table


# Everyday English / Indonesian words that are also the name of a family or an actor. Such a name only counts
# next to a qualifier ("Pegasus spyware", "the Bitter APT group"), never on its own: "a bitter dispute over the
# patchwork of state laws" names no actor and "Pegasus airline booking" no spyware (audit 2026-11 D-5). The check
# is by word, so families and actors added in knowledge_extra.json get the same treatment.
_COMMON_WORDS = """
    agenda akira alpha amber angel anchor apex arrow atlas aurora avalanche badger banshee bear beacon bee bitter
    blackout blade blaze blizzard bloom bolt bravo brick broomstick bumblebee butterfly canary carbon cascade chaos
    cheetah chimera cipher cobalt comet condor coral cosmos crane cricket crow crystal cyclone dagger delta diamond
    dragon eagle echo eclipse elephant elfin ember embargo emerald enigma falcon fang ferret flame fog fortress fox
    frost galaxy gecko ghost giant glacier godfather gold golem gorilla granite gravity griffin halo
    harbor harvest havoc hawk hellcat helium hermit hive hook horizon hornet hunter hunters hurricane hydra
    icarus inferno interlock iron jackal jaguar jester joker karma kitten koala kraken lantern legion
    leopard lightning lion lizard lotus lynx magnet mammoth mantis marble mars matrix medusa mercury meteor
    mirage mirai monarch moon mosquito mustang mythic nebula needle neptune nexus night ninja nomad
    nova oasis octo octopus omega onyx oracle orbit orchid oyster panda panther paradox patchwork pegasus
    pelican phantom phoenix phosphorus pirate play pluto polar predator prism prophet puma pulse python
    quasar quartz radar raccoon raptor rattlesnake raven razor rebel redline reaper rhino rocket rogue
    ruby sabre safepay saturn scarab scorpion sentinel serpent shadow shark sidewinder silver siren skull
    sliver snake snowflake solar spark sparrow spectre sphinx spider spirit storm sunburst swan tempest thor
    thunder tiger titan tornado trident triton tsunami typhoon unicorn vampire vector venom viper volcano
    vortex vulture warlock wasp whisper wolf wolverine yeti zeus zephyr
    agen api badai bayangan elang hantu harimau naga ombak petir rajawali serigala ular
"""
COMMON_WORDS = frozenset(_COMMON_WORDS.split())
# Short or common words that are also family names: require a qualifier nearby (the curated list predates
# COMMON_WORDS and keeps names that are no dictionary word but still collide, "conti", "vidar", "emotet").
AMBIGUOUS = {
    "play", "hook", "octo", "snake", "chaos", "fog", "embargo", "medusa", "beacon", "havoc",
    "mythic", "sliver", "kraken", "predator", "hook android", "lynx", "quasar", "raccoon",
    "banshee", "vidar", "agenda", "warlock", "conti", "cerberus", "emotet", "brat", "spark",
} | COMMON_WORDS
QUALIFIERS = r"(?:ransomware|stealer|malware|rat|loader|botnet|trojan|backdoor|infostealer|spyware|wiper|worm|rootkit|dropper|keylogger|miner|gang|group|operators?|affiliates?|c2|implant|payload|variant|strain|banking|campaign|samples?|infections?)"
ACTOR_QUALIFIERS = (r"(?:apt|group|threat (?:actor|group)|actors?|hackers?|hacking (?:group|team|crew)|gang|crew|"
                    r"operators?|espionage|cyber[\s-]?espionage|state[\s-](?:sponsored|backed)|nation[\s-]state|"
                    r"campaigns?|intrusion set|kelompok|grup|peretas|aktor)")


def ambiguous(term: str) -> bool:
    """A family / actor name that is also an everyday word (or too short to stand alone)."""
    low = (term or "").strip().lower()
    return low in AMBIGUOUS or len(low) <= 4


def distinctive(name: str) -> bool:
    """A spelling no everyday word has: an internal capital ("RedLine", "SafePay") or a digit inside a word
    ("Cl0p", "LockBit3"). Written that way, an ambiguous name needs no qualifier (0.13.1)."""
    return bool(re.search(r"[a-z][A-Z]", name or "") or re.search(r"[A-Za-z]\d|\d[A-Za-z]", name or ""))


@lru_cache(maxsize=1)
def compiled_patterns() -> list[tuple[str, str, str, re.Pattern]]:
    """[(entity_type, canonical_name, category, pattern)]"""
    out: list[tuple[str, str, str, re.Pattern]] = []
    for name, (cat, aliases) in malware_table().items():
        for term in {name.lower(), *[a.lower() for a in aliases]}:
            esc = re.escape(term).replace(r"\ ", r"[\s\-_]?")
            if term in AMBIGUOUS or len(term) <= 4:
                qualified = rf"\b{esc}\b[\s\-]+{QUALIFIERS}\b|\b{QUALIFIERS}[\s\-]+(?:called\s+|named\s+)?{esc}\b"
                spelled = name if term == name.lower() else term
                if distinctive(spelled):  # exactly as the family writes itself: "RedLine", "Cl0p"
                    qualified += rf"|(?<![\w-])(?-i:{re.escape(spelled)})(?![\w-])"
                pat = re.compile(qualified, re.I)
            else:
                pat = re.compile(rf"(?<![\w-]){esc}(?![\w-])", re.I)
            out.append(("malware", name, cat, pat))
    for name, aliases in actor_table().items():
        for term in {name.lower(), *[a.lower() for a in aliases]}:
            esc = re.escape(term).replace(r"\ ", r"[\s\-_]?")
            if term in AMBIGUOUS:
                # capitalised, with a qualifier within two words: "Bitter APT", "the Lazarus Group",
                # "APT group Patchwork", "threat actor known as Sidewinder"
                cap = rf"(?-i:{re.escape(term[0].upper())}){re.escape(term[1:])}"
                pat = re.compile(
                    rf"(?<![\w-]){cap}(?![\w-])[\s\-]+(?:\w+\s+){{0,2}}?{ACTOR_QUALIFIERS}\b|"
                    rf"\b{ACTOR_QUALIFIERS}[\s\-]+(?:\w+\s+){{0,2}}?(?:(?:called|named|dubbed|known as|bernama)\s+)?"
                    rf"{cap}(?![\w-])", re.I)
            else:
                pat = re.compile(rf"(?<![\w-]){esc}(?![\w-])", re.I)
            out.append(("actor", name, "", pat))
    return out


def category_for(name: str) -> str:
    spec = malware_table().get(name)
    return spec[0] if spec else "other"


@lru_cache(maxsize=1)
def _alias_index() -> dict[str, tuple[str, str]]:
    """lower-cased name / alias / squashed name -> (canonical, category). Built once."""
    idx: dict[str, tuple[str, str]] = {}
    for canon, (cat, aliases) in malware_table().items():
        for key in (canon.lower(), canon.lower().replace(" ", ""), *aliases):
            idx.setdefault(key, (canon, cat))
    return idx


@lru_cache(maxsize=1)
def _actor_index() -> dict[str, str]:
    idx: dict[str, str] = {}
    for canon, aliases in actor_table().items():
        for key in (canon.lower(), canon.lower().replace(" ", ""), *aliases):
            idx.setdefault(key, canon)
    return idx


def canonical_actor(name: str) -> str | None:
    """Map a free-text actor label (from an LLM or a provider) to the canonical actor name."""
    low = (name or "").strip().lower()
    if not low:
        return None
    idx = _actor_index()
    return idx.get(low) or idx.get(low.replace(" ", ""))


def canonical_malware(name: str) -> tuple[str, str] | None:
    """Map a free-text family label (from VT/OTX/ANY.RUN/LLM) to (canonical, category)."""
    low = (name or "").strip().lower()
    if not low:
        return None
    idx = _alias_index()
    return idx.get(low) or idx.get(low.replace(" ", ""))
