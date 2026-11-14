"""Place names for geo attribution (app/processing/geo.py).

* ``COUNTRIES``: ISO 3166-1 alpha-2 code -> English name, other names (including the Indonesian spelling)
  and demonyms. Demonyms count as targets ("Indonesian banks") unless they describe an attacker
  ("Russian hackers"); app/processing/geo.py decides which.
* ``PROVINCES``: the 38 Indonesian provinces (ISO 3166-2) with their common short forms.
* ``ID_PLACES``: Indonesian cities and regencies -> province code.
* ``ID_ORGS``: Indonesian agencies and well-known companies. They mark Indonesia as the target without a
  province.

Names that are also ordinary words (Malang, Batu, Solo, Palu, Jordan, Chad, Georgia, Turkey...) are listed
in ``*_STRICT`` sets and only count in the safe form the detector checks for.
"""
from __future__ import annotations

# ISO2 | English name | other names (;-separated) | demonyms (;-separated)
_COUNTRY_TABLE = """
AF|Afghanistan||Afghan
AL|Albania||Albanian
DZ|Algeria|Aljazair|Algerian
AD|Andorra||Andorran
AO|Angola||Angolan
AG|Antigua and Barbuda||
AR|Argentina||Argentine;Argentinian
AM|Armenia||Armenian
AU|Australia||Australian
AT|Austria||Austrian
AZ|Azerbaijan|Azerbaijan|Azerbaijani;Azeri
BS|Bahamas||Bahamian
BH|Bahrain||Bahraini
BD|Bangladesh||Bangladeshi
BB|Barbados||Barbadian
BY|Belarus||Belarusian
BE|Belgium|Belgia|Belgian
BZ|Belize||Belizean
BJ|Benin||Beninese
BT|Bhutan||Bhutanese
BO|Bolivia||Bolivian
BA|Bosnia and Herzegovina|Bosnia|Bosnian
BW|Botswana||
BR|Brazil|Brasil|Brazilian
BN|Brunei|Brunei Darussalam|Bruneian
BG|Bulgaria||Bulgarian
BF|Burkina Faso||Burkinabe
BI|Burundi||Burundian
KH|Cambodia|Kamboja|Cambodian
CM|Cameroon|Kamerun|Cameroonian
CA|Canada|Kanada|Canadian
CV|Cape Verde|Cabo Verde|
CF|Central African Republic||
TD|Chad||Chadian
CL|Chile|Cile|Chilean
CN|China|PRC;People's Republic of China;Tiongkok;Cina|Chinese
CO|Colombia|Kolombia|Colombian
KM|Comoros||
CG|Republic of the Congo|Congo-Brazzaville|
CD|Democratic Republic of the Congo|DR Congo;DRC;Congo-Kinshasa|Congolese
CR|Costa Rica||Costa Rican
CI|Ivory Coast|Côte d'Ivoire;Cote d'Ivoire|Ivorian
HR|Croatia|Kroasia|Croatian
CU|Cuba|Kuba|Cuban
CY|Cyprus|Siprus|Cypriot
CZ|Czech Republic|Czechia;Ceko|Czech
DK|Denmark|Denmark|Danish
DJ|Djibouti||Djiboutian
DM|Dominica||
DO|Dominican Republic|Republik Dominika|Dominican
EC|Ecuador|Ekuador|Ecuadorian
EG|Egypt|Mesir|Egyptian
SV|El Salvador||Salvadoran
GQ|Equatorial Guinea||
ER|Eritrea||Eritrean
EE|Estonia||Estonian
SZ|Eswatini|Swaziland|
ET|Ethiopia|Etiopia|Ethiopian
FJ|Fiji||Fijian
FI|Finland|Finlandia|Finnish
FR|France|Prancis|French
GA|Gabon||Gabonese
GM|Gambia||Gambian
GE|Georgia||Georgian
DE|Germany|Jerman|German
GH|Ghana||Ghanaian
GR|Greece|Yunani|Greek
GD|Grenada||
GT|Guatemala||Guatemalan
GN|Guinea||Guinean
GW|Guinea-Bissau||
GY|Guyana||Guyanese
HT|Haiti||Haitian
HN|Honduras||Honduran
HK|Hong Kong||
HU|Hungary|Hungaria|Hungarian
IS|Iceland|Islandia|Icelandic
IN|India||Indian
ID|Indonesia|Republik Indonesia;NKRI;RI;Tanah Air|Indonesian
IR|Iran||Iranian
IQ|Iraq|Irak|Iraqi
IE|Ireland|Irlandia|Irish
IL|Israel||Israeli
IT|Italy|Italia|Italian
JM|Jamaica||Jamaican
JP|Japan|Jepang|Japanese
JO|Jordan|Yordania|Jordanian
KZ|Kazakhstan||Kazakh;Kazakhstani
KE|Kenya||Kenyan
KI|Kiribati||
KP|North Korea|DPRK;Korea Utara;Korut|North Korean
KR|South Korea|Republic of Korea;Korea Selatan;Korsel|South Korean
XK|Kosovo||Kosovar
KW|Kuwait||Kuwaiti
KG|Kyrgyzstan||Kyrgyz
LA|Laos||Laotian
LV|Latvia||Latvian
LB|Lebanon|Lebanon|Lebanese
LS|Lesotho||
LR|Liberia||Liberian
LY|Libya||Libyan
LI|Liechtenstein||
LT|Lithuania|Lituania|Lithuanian
LU|Luxembourg|Luksemburg|
MO|Macau|Macao|
MG|Madagascar|Madagaskar|Malagasy
MW|Malawi||Malawian
MY|Malaysia|Malaysia|Malaysian
MV|Maldives|Maladewa|Maldivian
ML|Mali||Malian
MT|Malta||Maltese
MH|Marshall Islands||
MR|Mauritania||Mauritanian
MU|Mauritius||Mauritian
MX|Mexico|Meksiko|Mexican
FM|Micronesia||
MD|Moldova||Moldovan
MC|Monaco||
MN|Mongolia||Mongolian
ME|Montenegro||Montenegrin
MA|Morocco|Maroko|Moroccan
MZ|Mozambique|Mozambik|Mozambican
MM|Myanmar|Burma|Burmese
NA|Namibia||Namibian
NR|Nauru||
NP|Nepal||Nepalese;Nepali
NL|Netherlands|Belanda;Holland|Dutch
NZ|New Zealand|Selandia Baru|New Zealander
NI|Nicaragua||Nicaraguan
NE|Niger||Nigerien
NG|Nigeria||Nigerian
MK|North Macedonia|Macedonia|Macedonian
NO|Norway|Norwegia|Norwegian
OM|Oman||Omani
PK|Pakistan||Pakistani
PW|Palau||
PS|Palestine|Palestina;Gaza;West Bank|Palestinian
PA|Panama||Panamanian
PG|Papua New Guinea|Papua Nugini|
PY|Paraguay||Paraguayan
PE|Peru||Peruvian
PH|Philippines|Filipina|Filipino;Philippine
PL|Poland|Polandia|Polish
PT|Portugal||Portuguese
PR|Puerto Rico||Puerto Rican
QA|Qatar||Qatari
RO|Romania|Rumania|Romanian
RU|Russia|Russian Federation;Rusia|Russian
RW|Rwanda||Rwandan
KN|Saint Kitts and Nevis||
LC|Saint Lucia||
VC|Saint Vincent and the Grenadines||
WS|Samoa||Samoan
SM|San Marino||
ST|Sao Tome and Principe||
SA|Saudi Arabia|Arab Saudi;KSA|Saudi
SN|Senegal||Senegalese
RS|Serbia||Serbian
SC|Seychelles||
SL|Sierra Leone||
SG|Singapore|Singapura|Singaporean
SK|Slovakia||Slovak
SI|Slovenia||Slovenian
SB|Solomon Islands||
SO|Somalia||Somali
ZA|South Africa|Afrika Selatan|South African
SS|South Sudan||
ES|Spain|Spanyol|Spanish
LK|Sri Lanka||Sri Lankan
SD|Sudan||Sudanese
SR|Suriname||Surinamese
SE|Sweden|Swedia|Swedish
CH|Switzerland|Swiss;Swiss Confederation|
SY|Syria|Suriah|Syrian
TW|Taiwan||Taiwanese
TJ|Tajikistan||Tajik
TZ|Tanzania||Tanzanian
TH|Thailand|Thailand|Thai
TL|Timor-Leste|East Timor;Timor Leste|Timorese
TG|Togo||Togolese
TO|Tonga||Tongan
TT|Trinidad and Tobago||
TN|Tunisia||Tunisian
TR|Turkey|Türkiye;Turkiye;Turki|Turkish
TM|Turkmenistan||Turkmen
TV|Tuvalu||
UG|Uganda||Ugandan
UA|Ukraine|Ukraina|Ukrainian
AE|United Arab Emirates|UAE;Uni Emirat Arab;Emirates|Emirati
GB|United Kingdom|UK;U.K.;Britain;Great Britain;England;Scotland;Wales;Northern Ireland;Inggris|British
US|United States|US;USA;U.S.;U.S.A.;America;United States of America;Amerika Serikat;AS|American
UY|Uruguay||Uruguayan
UZ|Uzbekistan||Uzbek
VU|Vanuatu||
VA|Vatican|Holy See|
VE|Venezuela||Venezuelan
VN|Vietnam|Viet Nam|Vietnamese
YE|Yemen|Yaman|Yemeni
ZM|Zambia||Zambian
ZW|Zimbabwe||Zimbabwean
"""

COUNTRIES: dict[str, dict] = {}
for _line in _COUNTRY_TABLE.strip().splitlines():
    _code, _name, _alt, _dem = (_line.split("|") + ["", ""])[:4]
    COUNTRIES[_code] = {
        "name": _name,
        "aliases": [a for a in _alt.split(";") if a and a != _name],
        "demonyms": [d for d in _dem.split(";") if d],
    }

# Also ordinary words / given names / US states: these need a capital letter and a place-like context
# ("in Georgia", "Jordan's"), see geo.py.
COUNTRY_STRICT = {"Chad", "Jordan", "Georgia", "Turkey", "Niger", "Guinea", "Mali", "Togo", "Oman", "Peru",
                  "Panama", "America", "Holland", "England", "Wales", "Monaco", "Dominica", "Emirates", "Gaza",
                  "Swiss", "Samoa", "Tonga", "Nauru", "Palau", "Benin", "Malta", "Cuba", "Laos", "Chile", "Jersey",
                  "Kuba", "Brunei"}
# Province short forms that are also common elsewhere ("DIY", "Babel"): only in Indonesian text.
PROVINCE_WEAK = {"NAD", "DIY", "Babel", "DKI", "NTB", "NTT"}
# Short forms that only count in exactly this spelling (case-sensitive).
COUNTRY_EXACT = {"US", "U.S.", "USA", "U.S.A.", "UK", "U.K.", "UAE", "PRC", "DPRK", "DRC", "KSA", "AS", "NKRI", "RI"}
# "AS" (Amerika Serikat), "RI" and "Tanah Air" (Indonesia) are only read in Indonesian text.
INDONESIAN_ONLY = {"AS", "NKRI", "RI", "Tanah Air"}

# --------------------------------------------------------------------------- Indonesia
# ISO 3166-2:ID code -> (name, short forms). Includes the 2022 provinces (Papua Selatan / Tengah / Pegunungan /
# Barat Daya) and Kalimantan Utara.
PROVINCES: dict[str, tuple[str, list[str]]] = {
    "ID-AC": ("Aceh", ["Nanggroe Aceh Darussalam", "NAD"]),
    "ID-SU": ("Sumatera Utara", ["Sumut", "North Sumatra", "North Sumatera"]),
    "ID-SB": ("Sumatera Barat", ["Sumbar", "West Sumatra", "West Sumatera"]),
    "ID-RI": ("Riau", []),
    "ID-KR": ("Kepulauan Riau", ["Kepri", "Riau Islands"]),
    "ID-JA": ("Jambi", []),
    "ID-SS": ("Sumatera Selatan", ["Sumsel", "South Sumatra", "South Sumatera"]),
    "ID-BB": ("Kepulauan Bangka Belitung", ["Bangka Belitung", "Babel", "Bangka-Belitung"]),
    "ID-BE": ("Bengkulu", []),
    "ID-LA": ("Lampung", []),
    "ID-JK": ("DKI Jakarta", ["Jakarta", "DKI"]),
    "ID-JB": ("Jawa Barat", ["Jabar", "West Java"]),
    "ID-BT": ("Banten", []),
    "ID-JT": ("Jawa Tengah", ["Jateng", "Central Java"]),
    "ID-YO": ("DI Yogyakarta", ["Yogyakarta", "DIY", "Jogja", "Jogjakarta", "Yogya"]),
    "ID-JI": ("Jawa Timur", ["Jatim", "East Java"]),
    "ID-BA": ("Bali", []),
    "ID-NB": ("Nusa Tenggara Barat", ["NTB", "West Nusa Tenggara"]),
    "ID-NT": ("Nusa Tenggara Timur", ["NTT", "East Nusa Tenggara"]),
    "ID-KB": ("Kalimantan Barat", ["Kalbar", "West Kalimantan"]),
    "ID-KT": ("Kalimantan Tengah", ["Kalteng", "Central Kalimantan"]),
    "ID-KS": ("Kalimantan Selatan", ["Kalsel", "South Kalimantan"]),
    "ID-KI": ("Kalimantan Timur", ["Kaltim", "East Kalimantan"]),
    "ID-KU": ("Kalimantan Utara", ["Kaltara", "North Kalimantan"]),
    "ID-SA": ("Sulawesi Utara", ["Sulut", "North Sulawesi"]),
    "ID-GO": ("Gorontalo", []),
    "ID-ST": ("Sulawesi Tengah", ["Sulteng", "Central Sulawesi"]),
    "ID-SR": ("Sulawesi Barat", ["Sulbar", "West Sulawesi"]),
    "ID-SN": ("Sulawesi Selatan", ["Sulsel", "South Sulawesi"]),
    "ID-SG": ("Sulawesi Tenggara", ["Sultra", "Southeast Sulawesi"]),
    "ID-MA": ("Maluku", []),
    "ID-MU": ("Maluku Utara", ["Malut", "North Maluku"]),
    "ID-PA": ("Papua", []),
    "ID-PB": ("Papua Barat", ["West Papua"]),
    "ID-PD": ("Papua Barat Daya", ["Southwest Papua"]),
    "ID-PS": ("Papua Selatan", ["South Papua"]),
    "ID-PT": ("Papua Tengah", ["Central Papua"]),
    "ID-PE": ("Papua Pegunungan", ["Highland Papua"]),
}
# The public-domain boundary data (Natural Earth) predates Kalimantan Utara (2012 in law, later in the data)
# and the 2022 Papua provinces; on the map they are drawn with the province they were split from.
MAP_PARENT = {"ID-KU": "ID-KI", "ID-PS": "ID-PA", "ID-PT": "ID-PA", "ID-PE": "ID-PA", "ID-PD": "ID-PB"}

# Cities and regencies -> province.
ID_PLACES: dict[str, str] = {
    # Jakarta / Banten / West Java
    "Jakarta Pusat": "ID-JK", "Jakarta Selatan": "ID-JK", "Jakarta Barat": "ID-JK", "Jakarta Timur": "ID-JK",
    "Jakarta Utara": "ID-JK", "Kepulauan Seribu": "ID-JK",
    "Tangerang": "ID-BT", "Tangerang Selatan": "ID-BT", "Tangsel": "ID-BT", "Serang": "ID-BT", "Cilegon": "ID-BT",
    "Pandeglang": "ID-BT", "Lebak": "ID-BT",
    "Bandung": "ID-JB", "Bekasi": "ID-JB", "Bogor": "ID-JB", "Depok": "ID-JB", "Cimahi": "ID-JB",
    "Cirebon": "ID-JB", "Tasikmalaya": "ID-JB", "Sukabumi": "ID-JB", "Karawang": "ID-JB", "Garut": "ID-JB",
    "Purwakarta": "ID-JB", "Subang": "ID-JB", "Indramayu": "ID-JB", "Cianjur": "ID-JB", "Sumedang": "ID-JB",
    "Majalengka": "ID-JB", "Kuningan": "ID-JB", "Ciamis": "ID-JB", "Banjar": "ID-JB",
    # Central Java / Yogyakarta
    "Semarang": "ID-JT", "Surakarta": "ID-JT", "Magelang": "ID-JT", "Pekalongan": "ID-JT", "Tegal": "ID-JT",
    "Salatiga": "ID-JT", "Kudus": "ID-JT", "Purwokerto": "ID-JT", "Banyumas": "ID-JT", "Cilacap": "ID-JT",
    "Klaten": "ID-JT", "Boyolali": "ID-JT", "Sukoharjo": "ID-JT", "Jepara": "ID-JT", "Pati": "ID-JT",
    "Kebumen": "ID-JT", "Brebes": "ID-JT", "Wonosobo": "ID-JT", "Rembang": "ID-JT",
    "Sleman": "ID-YO", "Bantul": "ID-YO", "Gunungkidul": "ID-YO", "Kulon Progo": "ID-YO",
    # East Java
    "Surabaya": "ID-JI", "Sidoarjo": "ID-JI", "Kediri": "ID-JI", "Madiun": "ID-JI", "Jember": "ID-JI",
    "Banyuwangi": "ID-JI", "Gresik": "ID-JI", "Mojokerto": "ID-JI", "Pasuruan": "ID-JI", "Probolinggo": "ID-JI",
    "Blitar": "ID-JI", "Tulungagung": "ID-JI", "Lamongan": "ID-JI", "Tuban": "ID-JI", "Bojonegoro": "ID-JI",
    "Ponorogo": "ID-JI", "Lumajang": "ID-JI", "Bangkalan": "ID-JI", "Sumenep": "ID-JI", "Madura": "ID-JI",
    # Bali / Nusa Tenggara
    "Denpasar": "ID-BA", "Gianyar": "ID-BA", "Tabanan": "ID-BA", "Buleleng": "ID-BA", "Klungkung": "ID-BA",
    "Mataram": "ID-NB", "Lombok": "ID-NB", "Sumbawa": "ID-NB", "Bima": "ID-NB",
    "Kupang": "ID-NT", "Labuan Bajo": "ID-NT", "Manggarai": "ID-NT", "Sumba": "ID-NT", "Ende": "ID-NT",
    # Sumatra
    "Medan": "ID-SU", "Binjai": "ID-SU", "Pematangsiantar": "ID-SU", "Deli Serdang": "ID-SU", "Sibolga": "ID-SU",
    "Tebing Tinggi": "ID-SU", "Nias": "ID-SU", "Toba": "ID-SU",
    "Banda Aceh": "ID-AC", "Lhokseumawe": "ID-AC", "Sabang": "ID-AC", "Langsa": "ID-AC",
    "Bukittinggi": "ID-SB", "Payakumbuh": "ID-SB", "Pariaman": "ID-SB", "Mentawai": "ID-SB",
    "Pekanbaru": "ID-RI", "Dumai": "ID-RI", "Siak": "ID-RI", "Kampar": "ID-RI",
    "Batam": "ID-KR", "Tanjungpinang": "ID-KR", "Tanjung Pinang": "ID-KR", "Bintan": "ID-KR", "Natuna": "ID-KR",
    "Karimun": "ID-KR",
    "Palembang": "ID-SS", "Prabumulih": "ID-SS", "Lubuklinggau": "ID-SS", "Ogan Komering Ilir": "ID-SS",
    "Pangkalpinang": "ID-BB", "Pangkal Pinang": "ID-BB", "Belitung": "ID-BB", "Bangka": "ID-BB",
    "Bandar Lampung": "ID-LA", "Metro": "ID-LA",
    # Kalimantan
    "Pontianak": "ID-KB", "Singkawang": "ID-KB", "Ketapang": "ID-KB", "Sambas": "ID-KB",
    "Palangka Raya": "ID-KT", "Palangkaraya": "ID-KT", "Kotawaringin": "ID-KT", "Sampit": "ID-KT",
    "Banjarmasin": "ID-KS", "Banjarbaru": "ID-KS", "Kotabaru": "ID-KS",
    "Samarinda": "ID-KI", "Balikpapan": "ID-KI", "Bontang": "ID-KI", "Kutai Kartanegara": "ID-KI",
    "Ibu Kota Nusantara": "ID-KI", "IKN": "ID-KI", "Penajam Paser Utara": "ID-KI",
    "Tarakan": "ID-KU", "Tanjung Selor": "ID-KU", "Nunukan": "ID-KU", "Malinau": "ID-KU",
    # Sulawesi
    "Manado": "ID-SA", "Bitung": "ID-SA", "Tomohon": "ID-SA", "Minahasa": "ID-SA",
    "Mamuju": "ID-SR", "Majene": "ID-SR", "Polewali Mandar": "ID-SR",
    "Makassar": "ID-SN", "Parepare": "ID-SN", "Palopo": "ID-SN", "Gowa": "ID-SN", "Maros": "ID-SN", "Bone": "ID-SN",
    "Kendari": "ID-SG", "Baubau": "ID-SG", "Kolaka": "ID-SG", "Konawe": "ID-SG",
    "Poso": "ID-ST", "Morowali": "ID-ST", "Banggai": "ID-ST", "Donggala": "ID-ST",
    # Maluku / Papua
    "Ambon": "ID-MA", "Tual": "ID-MA", "Seram": "ID-MA",
    "Ternate": "ID-MU", "Tidore": "ID-MU", "Sofifi": "ID-MU", "Halmahera": "ID-MU",
    "Jayapura": "ID-PA", "Sarmi": "ID-PA", "Biak": "ID-PA",
    "Manokwari": "ID-PB", "Fakfak": "ID-PB", "Kaimana": "ID-PB", "Teluk Bintuni": "ID-PB",
    "Sorong": "ID-PD", "Raja Ampat": "ID-PD",
    "Merauke": "ID-PS", "Boven Digoel": "ID-PS", "Asmat": "ID-PS",
    "Nabire": "ID-PT", "Timika": "ID-PT", "Mimika": "ID-PT", "Paniai": "ID-PT",
    "Wamena": "ID-PE", "Jayawijaya": "ID-PE", "Yahukimo": "ID-PE",
}
# Ordinary Indonesian / English words that are also place names: only counted after an administrative
# prefix ("Kota Malang", "Kabupaten Batu", "Pemkot Palu").
ID_PLACES_STRICT: dict[str, str] = {
    "Malang": "ID-JI", "Batu": "ID-JI", "Solo": "ID-JT", "Palu": "ID-ST", "Padang": "ID-SB", "Badung": "ID-BA",
    "Bone": "ID-SN", "Metro": "ID-LA", "Banjar": "ID-JB", "Toba": "ID-SU", "Pati": "ID-JT", "Ende": "ID-NT",
    "Bima": "ID-NB", "Siak": "ID-RI", "Seram": "ID-MA", "Kuningan": "ID-JB", "Lebak": "ID-BT", "Tuban": "ID-JI",
    "Blitar": "ID-JI", "Asmat": "ID-PS", "Sabang": "ID-AC",
}
for _k in ID_PLACES_STRICT:
    ID_PLACES.pop(_k, None)
ADMIN_PREFIX = r"(?:Kota|Kabupaten|Kab\.|Pemkot|Pemkab|Pemda|Polres|Polresta|Dinas\s+\w+|DPRD|RSUD|Bupati|Wali\s?kota|City\s+of|Regency\s+of)"

# Indonesian institutions and companies: Indonesia is the target, the province is unknown (or national).
ID_ORGS = [
    "BSSN", "Badan Siber dan Sandi Negara", "Kominfo", "Kemkominfo", "Kemenkominfo", "Komdigi", "Kemkomdigi",
    "BPJS", "BPJS Kesehatan", "BPJS Ketenagakerjaan", "KPU", "Bawaslu", "Polri", "Mabes Polri", "Bareskrim",
    "TNI", "Kemenhan", "Kementerian Pertahanan", "Kemenkes", "Kementerian Kesehatan", "Kemendikbud",
    "Kemendikbudristek", "Kemendikdasmen", "Kemenkeu", "Kementerian Keuangan", "Ditjen Pajak", "DJP",
    "Dukcapil", "Kemendagri", "Kementerian Dalam Negeri", "Kemenlu", "Kemenag", "Kemnaker", "Kemenhub",
    "Bank Indonesia", "Otoritas Jasa Keuangan", "OJK", "Pusat Data Nasional", "PDNS", "PDN", "BKN",
    "Badan Kepegawaian Negara", "BPOM", "BMKG", "Basarnas", "BNPB", "BRIN", "LKPP", "Imigrasi",
    "Ditjen Imigrasi", "Satgas PASTI", "IASC", "Indonesia Anti-Scam Centre", "Pertamina", "PLN", "Telkom Indonesia",
    "Telkomsel", "Indosat", "Indosat Ooredoo", "XL Axiata", "Smartfren", "Garuda Indonesia", "Bank Rakyat Indonesia",
    "Bank Mandiri", "Bank Negara Indonesia", "Bank Central Asia", "Bank Syariah Indonesia", "BCA", "BRI", "BNI",
    "Tokopedia", "Bukalapak", "Gojek", "GoTo", "Traveloka", "Shopee Indonesia", "Blibli", "DANA", "OVO",
    "GoPay", "LinkAja", "Kereta Api Indonesia", "KAI", "Angkasa Pura", "Pelindo", "Jasa Marga", "Bea Cukai",
    "e-KTP", "KTP", "NIK", "PeduliLindungi", "SatuSehat", "Sirekap", "Lion Air", "MyPertamina", "INAFIS",
]
# Acronyms that are common elsewhere too: case-sensitive, and only in Indonesian text or next to another
# Indonesian signal (see geo.py).
ID_ORGS_WEAK = {"TNI", "KPU", "DJP", "PDN", "BKN", "KAI", "DANA", "OVO", "NIK", "KTP", "BRI", "BNI", "BCA", "PLN",
                "IASC", "GoTo", "BRIN", "LKPP"}
# Indonesian government / academic / company domains
ID_DOMAIN_RE = r"\b[a-z0-9][a-z0-9.-]*\.(?:go|co|ac|or|sch|mil|web|my|net|desa|ponpes|biz)\.id\b"


def country_name(code: str) -> str:
    c = COUNTRIES.get((code or "").upper())
    return c["name"] if c else (code or "")


def province_name(code: str) -> str:
    p = PROVINCES.get(code or "")
    return p[0] if p else (code or "")


def by_name() -> dict[str, str]:
    """Lower-cased English / Indonesian name or alias -> ISO2 (used to normalise provider country names)."""
    out: dict[str, str] = {}
    for code, c in COUNTRIES.items():
        for n in [c["name"], *c["aliases"]]:
            if n not in COUNTRY_EXACT:
                out[n.lower()] = code
    out.update({"united states of america": "US", "korea, republic of": "KR", "russian federation": "RU",
                "iran, islamic republic of": "IR", "viet nam": "VN", "korea, democratic people's republic of": "KP",
                "taiwan, province of china": "TW", "türkiye": "TR", "czechia": "CZ", "netherlands (the)": "NL",
                "hong kong sar": "HK", "republic of korea": "KR", "moldova, republic of": "MD"})
    return out


_BY_NAME: dict[str, str] | None = None


def normalise_country(value) -> str:
    """ISO2 for an ISO2 code or a country name (provider responses use either); '' when unknown."""
    global _BY_NAME
    s = str(value or "").strip()
    if not s:
        return ""
    if len(s) == 2 and s.isalpha():
        return s.upper() if s.upper() in COUNTRIES else ""
    if _BY_NAME is None:
        _BY_NAME = by_name()
    return _BY_NAME.get(s.lower(), "")
