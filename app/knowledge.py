"""Built-in knowledge base of malware families and threat actors.

Extend it without touching code by creating data/knowledge_extra.json:
{
  "malware": {"NewFamily": {"category": "stealer", "aliases": ["newfam"]}},
  "actors":  {"Some Actor": {"aliases": ["UNC1234"], "origin": ""}}
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


@lru_cache(maxsize=1)
def _extra() -> dict:
    path = DATA_DIR / "knowledge_extra.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def malware_table() -> dict[str, tuple[str, list[str]]]:
    table = dict(MALWARE)
    for name, spec in (_extra().get("malware") or {}).items():
        table[name] = (spec.get("category", "other"), [a.lower() for a in spec.get("aliases", [])])
    return table


def actor_table() -> dict[str, list[str]]:
    table = dict(ACTORS)
    for name, spec in (_extra().get("actors") or {}).items():
        table[name] = [a.lower() for a in spec.get("aliases", [])]
    return table


# Short/common words that are also family names: require a qualifier nearby.
AMBIGUOUS = {
    "play", "hook", "octo", "snake", "chaos", "fog", "embargo", "medusa", "beacon", "havoc",
    "mythic", "sliver", "kraken", "predator", "hook android", "lynx", "quasar", "raccoon",
    "banshee", "vidar", "agenda", "warlock", "conti", "cerberus", "emotet", "brat", "spark",
}
QUALIFIERS = r"(?:ransomware|stealer|malware|rat|loader|botnet|trojan|backdoor|infostealer|gang|group|operators?|affiliates?|c2|implant|payload|variant|strain|banking|campaign)"


@lru_cache(maxsize=1)
def compiled_patterns() -> list[tuple[str, str, str, re.Pattern]]:
    """[(entity_type, canonical_name, category, pattern)]"""
    out: list[tuple[str, str, str, re.Pattern]] = []
    for name, (cat, aliases) in malware_table().items():
        for term in {name.lower(), *[a.lower() for a in aliases]}:
            esc = re.escape(term).replace(r"\ ", r"[\s\-_]?")
            if term in AMBIGUOUS or len(term) <= 4:
                pat = re.compile(
                    rf"\b{esc}\b[\s\-]+{QUALIFIERS}\b|\b{QUALIFIERS}[\s\-]+(?:called\s+|named\s+)?{esc}\b",
                    re.I,
                )
            else:
                pat = re.compile(rf"(?<![\w-]){esc}(?![\w-])", re.I)
            out.append(("malware", name, cat, pat))
    for name, aliases in actor_table().items():
        for term in {name.lower(), *[a.lower() for a in aliases]}:
            esc = re.escape(term).replace(r"\ ", r"[\s\-_]?")
            out.append(("actor", name, "", re.compile(rf"(?<![\w-]){esc}(?![\w-])", re.I)))
    return out


def category_for(name: str) -> str:
    spec = malware_table().get(name)
    return spec[0] if spec else "other"


def canonical_malware(name: str) -> tuple[str, str] | None:
    """Map a free-text family label (from VT/OTX/ANY.RUN/LLM) to (canonical, category)."""
    low = name.strip().lower()
    if not low:
        return None
    for canon, (cat, aliases) in malware_table().items():
        if low == canon.lower() or low in aliases or low.replace(" ", "") == canon.lower().replace(" ", ""):
            return canon, cat
    return None
