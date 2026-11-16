"""Scam & fraud analysis (0.9): scam types, impersonated brands, scammer identifiers and a fraud score.

Runs on every collected item next to the threat pipeline, so a scam report lands in the same entity graph as
the malware it uses (wedding-invitation APKs and banking trojans, phishing kits, crypto drainers).

    result = analyse(title, body, topic=source.topic, db=db, at=item.published_at)

* **Scam types** come from a fixed taxonomy (English and Bahasa Indonesia). *Strong* phrases count on their own
  ("investasi bodong", "pig butchering"); *weak* ones ("phishing", "deepfake", "APK") only when the item also
  uses a scam word, so ordinary malware reporting does not end up in the fraud section.
* **Brands** (banks, e-wallets, marketplaces, couriers, government bodies, platforms) count when they appear next
  to an impersonation cue ("mengatasnamakan BCA", "fake PayPal") or in the title of a scam item.
* **Scammer identifiers** (phone numbers, bank accounts, e-wallets, crypto wallets) are taken only from scam items,
  only next to a cue that marks them as the scammer's, never when the text marks them as official or as the
  victim's, and account holder names are never stored (UU PDP / Law 27/2022 data minimisation).
* **Fraud score** (0–100), explainable like the severity score: scam type, reported losses (in rupiah), victim
  count, impersonated brand, published identifiers, an official warning or arrest, and spread velocity (reports of
  the same scam type this week against the week before).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .extractor import Extracted

NAMED_TYPES = ("scam_type", "brand")
IDENT_TYPES = ("phone", "bank_account", "ewallet", "crypto_wallet")
FRAUD_TYPES = NAMED_TYPES + IDENT_TYPES
IDENT_LABELS = {"phone": "Phone number", "bank_account": "Bank account", "ewallet": "E-wallet",
                "crypto_wallet": "Crypto wallet"}

# Bump when the rules change: the start-up job re-analyses stored items once per version.
RULES_VERSION = 2

# --------------------------------------------------------------------------- scam types
# (key, display name, weight, strong pattern, weak pattern). Weak patterns need a scam word elsewhere in the item.
SCAM_TYPES: list[tuple[str, str, int, str, str]] = [
    ("investment", "Investment scam", 26,
     r"investment (?:scam|fraud)s?|ponzi|pig[\s-]butchering|investasi (?:bodong|ilegal|palsu|fiktif|abal)|"
     r"robot trading|money game|binary options?|opsi biner|arisan (?:online )?(?:bodong|fiktif)|skema piramida|"
     r"pyramid schemes?|satgas pasti", r"investasi|trading (?:platform|app)"),
    ("illegal_loan", "Illegal online loan", 20,
     r"pinjol (?:ilegal|bodong|tak berizin|tidak berizin)|pinjaman (?:online|daring) (?:ilegal|tak berizin)|"
     r"(?:fake|illegal|predatory) loan apps?|loan app (?:scam|fraud|extortion)s?", r"\bpinjol\b|loan apps?"),
    ("job", "Job / task scam", 20,
     r"job (?:offer )?scams?|fake job(?: offer)?s?|task scams?|employment scams?|recruitment scams?|"
     r"lowongan (?:kerja )?(?:palsu|fiktif|bodong)|penipuan (?:lowongan|rekrutmen|berkedok kerja)|"
     r"part[\s-]time job scams?|(?:like|follow|subscribe) (?:dan|and) (?:subscribe|like) (?:dibayar|berbayar)",
     r"kerja paruh waktu|part[\s-]time job|kerja sampingan|work[\s-]from[\s-]home job|lowongan kerja|\bloker\b|"
     r"job offers?"),
    ("romance", "Romance scam", 20,
     r"romance scams?|love scam(?:ming|s)?|penipuan (?:asmara|cinta|berkedok cinta)|dating scams?|"
     r"kencan (?:online|daring) palsu", r"online dating|kencan online"),
    ("sextortion", "Sextortion", 24,
     r"sextortion|pemerasan (?:seksual|bermodus video|dengan video)|video call (?:sex|seks|mesum)",
     r"\bvcs\b"),
    ("apk_lure", "Malicious APK lure", 28,
     r"apk (?:palsu|berbahaya|jahat)|undangan (?:pernikahan|nikah) (?:digital |online )?(?:berformat |berbentuk )?apk|"
     r"(?:file|berkas) apk (?:undangan|surat|resi|tagihan|tilang)",
     r"\.apk\b|\bapk\b|undangan (?:pernikahan|nikah) digital|surat tilang|tagihan (?:pln|bpjs|pajak)"),
    ("courier", "Courier / package lure", 18,
     r"resi (?:paket|pengiriman) palsu|kurir (?:paket )?palsu|(?:fake|bogus) (?:delivery|parcel|package|shipping) "
     r"(?:notice|text|message|sms)s?|package (?:delivery )?scams?|undeliverable package",
     r"(?:cek|lacak) resi|paket (?:tertahan|bermasalah|gagal dikirim)|parcel delivery"),
    ("impersonation", "Impersonation", 16,
     r"mengaku (?:sebagai )?(?:petugas|pegawai|polisi|pihak|customer service|cs|kurir|teller|staf|karyawan)|"
     r"(?:cs|customer service|petugas) (?:bank )?palsu|impersonation scams?",
     r"mengatasnamakan|mencatut nama|catut nama|dicatut|akun palsu|impersonat(?:e|es|ed|ing|ion|ors?)\b|posing as|"
     r"pretending to be|spoof(?:ed|ing) (?:caller|number|email|sender)"),
    ("phishing", "Phishing", 18,
     r"(?:link|tautan|situs|website|laman|sms) palsu|\bphising\b|\bpishing\b|"
     r"phishing (?:scam|text|sms|message|link)s?|penipuan (?:phishing|online)",
     r"phishing|smishing|vishing|quishing"),
    ("otp", "OTP theft / account takeover", 24,
     r"kode otp|(?:minta|meminta|bagikan|membagikan|memberikan|menyerahkan) (?:kode )?otp|otp (?:scam|fraud)|"
     r"sim[\s-]swap(?:ping)?|pembajakan akun|akun (?:whatsapp|wa|instagram|telegram|facebook) (?:dibajak|diretas|"
     r"diambil alih)|whatsapp (?:account )?(?:hijack|takeover)", r"account takeover|\botp\b"),
    ("gambling", "Online gambling", 12,
     r"judi (?:online|daring|slot)|\bjudol\b|situs judi|slot online|online gambling|illegal gambling|"
     r"gambling (?:site|ads?|promotion|spam)s?", ""),
    ("shopping", "Fake shop / marketplace", 15,
     r"(?:toko|online shop) (?:online |daring )?(?:palsu|fiktif|bodong)|fake (?:online )?(?:store|shop|webshop)s?|"
     r"penipuan (?:jual beli|belanja|transaksi) online|non-delivery scams?|fake marketplace",
     r"marketplace|e-commerce|jual beli online"),
    ("prize", "Prize / giveaway scam", 14,
     r"(?:giveaway|hadiah|undian|kuis|voucher) (?:palsu|bodong|fiktif)|lottery scams?|prize scams?|"
     r"sweepstakes scams?|fake giveaways?|(?:bansos|subsidi|bantuan sosial) palsu|fake (?:grant|subsidy|relief)",
     r"giveaway|undian berhadiah|menang(?:kan)? undian|bansos|hadiah"),
    ("crypto", "Crypto scam / drainer", 22,
     r"(?:wallet )?drainers?\b|crypto(?:currency)? (?:scam|fraud|phishing)s?|rug[\s-]?pulls?|fake airdrops?|"
     r"airdrop (?:palsu|scam)s?|address poisoning|penipuan (?:kripto|crypto|aset kripto)|seed phrase (?:scam|phishing|theft)",
     r"airdrop|seed phrase|crypto wallet|dompet kripto|aset kripto"),
    ("tech_support", "Tech support / refund scam", 18,
     r"tech(?:nical)? support scams?|refund scams?|fake (?:microsoft|apple|windows|it) support|support scams?", ""),
    ("bec", "BEC / invoice fraud", 24,
     r"business email compromise|\bbec\b|invoice fraud|ceo fraud|payment diversion|"
     r"penipuan (?:invoice|faktur|tagihan palsu)", ""),
    ("qris", "QRIS / QR code fraud", 18,
     r"qris (?:palsu|fiktif|ditempel)|(?:stiker|kode) qr(?:is)? palsu|qr code (?:scam|fraud|phishing)s?", ""),
    ("deepfake", "Deepfake scam", 22,
     r"deepfake (?:scam|fraud|video call|voice|penipuan)s?|penipuan (?:\w+ )?deepfake|(?:ai|voice) clon(?:e|ing) scams?|"
     r"suara (?:tiruan|kloning)", r"deepfake"),
]
OTHER = ("other", "Other scam", 10)
SCAM_NAMES = {k: n for k, n, *_ in SCAM_TYPES} | {OTHER[0]: OTHER[1]}

# A word that makes the item *about* a scam. Weak scam-type phrases and "Other scam" need one.
FRAUD_CUE = re.compile(
    r"\bscam(?:s|mer|mers|med|ming)?\b|\bfraud(?:s|ster|sters)?\b|\bpenipuan\b|\bpenipu\b|\bmenipu\b|\bditipu\b|"
    r"\btertipu\b|\bdefraud(?:ed|ing)?\b|\bswindl\w*|\bcon artists?\b|\bmodus (?:baru|penipuan|operandi)\b|"
    r"\bkorban penipuan\b|\bpenipuan online\b", re.I)
_STRONG_CUE = re.compile(r"\bscam(?:s|mer|mers)?\b|\bpenipuan\b|\bpenipu\b|\bfraud(?:ster|sters)?\b|\bditipu\b|"
                         r"\btertipu\b|\bdefraud", re.I)

_TYPES = [(k, n, w, re.compile(s, re.I), re.compile(wk, re.I) if wk else None) for k, n, w, s, wk in SCAM_TYPES]


# Newsletters and weekly round-ups mention every scam of the week in passing: only their title counts.
ROUNDUP = re.compile(r"\b(?:week(?:ly)? in (?:review|security)|a week in|in review|round-?up|recap|digest|newsletter|"
                     r"lessons from|podcast|episode|webinar|interview|this week in|rangkuman|sepekan)\b", re.I)


def scam_types(title: str, body: str, topic: str = "") -> list[tuple[str, str, int]]:
    """Scam types an item is about: [(key, name, weight)], strongest first."""
    if ROUNDUP.search(title or ""):
        body = ""
    text = f"{title}\n{body}"
    cue = bool(FRAUD_CUE.search(text))
    out = []
    for key, name, weight, strong, weak in _TYPES:
        if strong.search(text) or (cue and weak is not None and weak.search(text)):
            out.append((key, name, weight))
    if not out:
        n = len(_STRONG_CUE.findall(text))
        if (topic == "fraud" and n >= 1) or (n >= 2 and _STRONG_CUE.search(title or "")) or n >= 4:
            out.append(OTHER)
    return sorted(out, key=lambda t: -t[2])


# --------------------------------------------------------------------------- brands
# (name, category, pattern, case-sensitive). Ambiguous words ("dana" = funds, "mandiri" = independent) are
# matched case-sensitively or only in an unambiguous form.
BRANDS: list[tuple[str, str, str, bool]] = [
    # banks
    ("BCA", "bank", r"\bBCA\b|Bank Central Asia|KlikBCA|myBCA|Halo BCA", True),
    ("BRI", "bank", r"\bBRI\b|Bank Rakyat Indonesia|BRImo", True),
    ("Bank Mandiri", "bank", r"Bank Mandiri|Livin'? by Mandiri|\bMandiri (?:Online|Syariah)\b", False),
    ("BNI", "bank", r"\bBNI\b|Bank Negara Indonesia|BNI Mobile", True),
    ("BSI", "bank", r"Bank Syariah Indonesia|\bBSI Mobile\b|\bBank BSI\b", False),
    ("BTN", "bank", r"\bBTN\b|Bank Tabungan Negara", True),
    ("CIMB Niaga", "bank", r"CIMB Niaga|OCTO Mobile", False),
    ("Bank Permata", "bank", r"(?:Bank )?Permata(?:Bank| ME| Mobile)\b|Bank Permata", False),
    ("Danamon", "bank", r"\bDanamon\b", False),
    ("Jenius", "bank", r"\bJenius\b", True),
    ("Bank Jago", "bank", r"Bank Jago", False),
    ("SeaBank", "bank", r"\bSeaBank\b", False),
    # e-wallets / payment
    ("DANA", "ewallet", r"\bDANA\b(?! (?:Moneter|Internasional|IMF))|aplikasi DANA|DANA Kaget", True),
    ("OVO", "ewallet", r"\bOVO\b", True),
    ("GoPay", "ewallet", r"\bGoPay\b", False),
    ("ShopeePay", "ewallet", r"\bShopeePay\b", False),
    ("LinkAja", "ewallet", r"\bLinkAja\b", False),
    ("QRIS", "payment", r"\bQRIS\b", True),
    ("PayPal", "payment", r"\bPayPal\b", False),
    # marketplaces / super apps
    ("Shopee", "marketplace", r"\bShopee\b(?!Pay)", False),
    ("Tokopedia", "marketplace", r"\bTokopedia\b", False),
    ("Lazada", "marketplace", r"\bLazada\b", False),
    ("Bukalapak", "marketplace", r"\bBukalapak\b", False),
    ("Blibli", "marketplace", r"\bBlibli\b", False),
    ("TikTok Shop", "marketplace", r"TikTok Shop", False),
    ("Amazon", "marketplace", r"\bAmazon\b(?! Web Services| S3|\.com/aws)", True),
    ("Gojek", "app", r"\bGojek\b", False),
    ("Grab", "app", r"\bGrab\b(?:Food|Pay| app| driver)?", True),
    ("Traveloka", "app", r"\bTraveloka\b", False),
    # couriers
    ("J&T Express", "courier", r"J&(?:amp;)?T(?: Express)?\b", True),
    ("JNE", "courier", r"\bJNE\b", True),
    ("SiCepat", "courier", r"\bSiCepat\b", False),
    ("Pos Indonesia", "courier", r"Pos Indonesia", False),
    ("AnterAja", "courier", r"\bAnterAja\b", False),
    ("DHL", "courier", r"\bDHL\b", True),
    ("FedEx", "courier", r"\bFedEx\b", False),
    ("USPS", "courier", r"\bUSPS\b", True),
    # telecom / utilities
    ("Telkomsel", "telco", r"\bTelkomsel\b", False),
    ("Indosat", "telco", r"\bIndosat\b", False),
    ("XL Axiata", "telco", r"\bXL Axiata\b|\bXL(?:Center| Prioritas)\b", False),
    ("PLN", "utility", r"\bPLN\b", True),
    ("Pertamina", "utility", r"\bPertamina\b", False),
    # government / regulators / law enforcement
    ("OJK", "government", r"\bOJK\b|Otoritas Jasa Keuangan", True),
    ("Bank Indonesia", "government", r"Bank Indonesia\b", True),
    ("BPJS", "government", r"\bBPJS\b", True),
    ("DJP (tax office)", "government", r"\bDJP\b|Direktorat Jenderal Pajak|Ditjen Pajak|Coretax", True),
    ("Bea Cukai (customs)", "government", r"Bea (?:dan )?Cukai", False),
    ("Polri (police)", "government", r"\bPolri\b|Bareskrim", True),
    ("Komdigi / Kominfo", "government", r"\bKomdigi\b|\bKominfo\b", False),
    ("Dukcapil", "government", r"\bDukcapil\b", False),
    ("ETLE (traffic tickets)", "government", r"\bETLE\b|tilang elektronik", False),
    ("IRS", "government", r"\bIRS\b", True),
    ("FBI", "government", r"\bFBI\b", True),
    # platforms
    ("WhatsApp", "platform", r"\bWhatsApp\b", False),
    ("Instagram", "platform", r"\bInstagram\b", False),
    ("Facebook", "platform", r"\bFacebook\b", False),
    ("Telegram", "platform", r"\bTelegram\b", False),
    ("Microsoft", "platform", r"\bMicrosoft\b|\bOffice ?365\b|\bOutlook\b", False),
    ("Apple", "platform", r"\bApple\b|\biCloud\b", True),
    ("Google", "platform", r"\bGoogle\b|\bGmail\b", False),
    ("Netflix", "platform", r"\bNetflix\b", False),
    # crypto
    ("Binance", "crypto", r"\bBinance\b", False),
    ("Coinbase", "crypto", r"\bCoinbase\b", False),
    ("MetaMask", "crypto", r"\bMetaMask\b", False),
    ("Indodax", "crypto", r"\bIndodax\b", False),
    ("Tokocrypto", "crypto", r"\bTokocrypto\b", False),
]
_BRANDS = [(n, c, re.compile(p, 0 if cs else re.I)) for n, c, p, cs in BRANDS]
BANK_CODES = {"bca": "BCA", "bri": "BRI", "bni": "BNI", "mandiri": "Bank Mandiri", "bsi": "BSI", "btn": "BTN",
              "cimb": "CIMB Niaga", "permata": "Bank Permata", "danamon": "Danamon", "jago": "Bank Jago",
              "seabank": "SeaBank", "jenius": "Jenius"}
# Platforms (WhatsApp, Telegram…) and government bodies are usually the channel or the one issuing the warning
# ("FBI warns of…", "lewat WhatsApp"), so they need a strong cue; banks, shops and couriers also count next to a
# plain scam word.
IMPERSONATION_STRONG = re.compile(
    r"mengatasnamakan|catut|dicatut|palsu|fiktif|\bfake\b|impersonat\w*|posing as|pretend\w*|spoof\w*|mengaku|"
    r"tiruan|mirip|look-?alike|clone[ds]?|kloning|berkedok|kedok", re.I)
IMPERSONATION_CUE = re.compile(IMPERSONATION_STRONG.pattern + r"|phish\w*|phising|\bscam\w*|penipuan|modus", re.I)
STRONG_ONLY = ("platform", "government")
BRAND_WINDOW = 80
# For platforms and government bodies the cue must sit right next to the name: "mengatasnamakan OJK", "fake PayPal
# support", "akun WhatsApp palsu" — not "… beredar lewat WhatsApp".
_STRONG_BEFORE = re.compile(
    r"(?:mengatasnamakan|mencatut(?: nama)?|catut(?: nama)?|\bfake|impersonat\w*|posing as|pretending to be|"
    r"mengaku(?: sebagai)?(?: (?:petugas|pegawai|pihak|staf|dari))?|tiruan|kloning|spoofed|palsu)\s+(?:\S+\s+){0,1}$", re.I)
_STRONG_AFTER = re.compile(r"^\s*(?:\S+\s+){0,2}?(?:palsu|fiktif|gadungan|abal-abal|look-?alikes?|clones?|"
                           r"impersonators?)\b", re.I)


def brands(title: str, body: str) -> list[tuple[str, str]]:
    """Brands impersonated in a scam item: [(name, category)]."""
    if ROUNDUP.search(title or ""):
        body = ""
    text = f"{title}\n{body}"
    out: dict[str, str] = {}
    for name, cat, rx in _BRANDS:
        for m in rx.finditer(text):
            in_title = m.start() < len(title or "")
            near = text[max(0, m.start() - BRAND_WINDOW): m.end() + BRAND_WINDOW]
            if cat in STRONG_ONLY:
                hit = bool(_STRONG_BEFORE.search(text[max(0, m.start() - 40): m.start()])
                           or _STRONG_AFTER.search(text[m.end(): m.end() + 30]))
            else:
                hit = in_title or bool(IMPERSONATION_CUE.search(near))
            if hit:
                out[name] = cat
                break
    return list(out.items())


# --------------------------------------------------------------------------- identifiers
_SEP = r"[\s.\-]?"
RE_PHONE = re.compile(r"(?<![\w+])(?:\+62|62|0)" + _SEP + r"8\d{1,2}(?:" + _SEP + r"\d{2,5}){2,3}(?![\w])"
                      r"|(?<![\w])\+(?!62)[1-9]\d{0,2}[\s.\-]?\(?\d{1,4}\)?(?:[\s.\-]?\d{2,4}){2,4}(?![\w])")
RE_ACCOUNT = re.compile(
    r"(?:no(?:mor|\.)?\s*rek(?:ening|\.)?|rekening|\brek\.|account (?:number|no\.?)|\ba/c(?: no\.?)?)\s*"
    r"(?:bank\s+)?(?:(?P<bank>[A-Za-z]{3,8})\s+)?(?:no\.?\s*|nomor\s*|number\s*|#\s*)?[:.]?\s*"
    r"(?P<num>\d(?:[\s.\-]?\d){7,17})(?!\d)", re.I)
RE_EWALLET = re.compile(r"\b(?P<w>DANA|OVO|GoPay|Gopay|ShopeePay|LinkAja)\b[^\d+\n]{0,25}"
                        r"(?P<num>(?:\+62|62|0)" + _SEP + r"8\d{1,2}(?:" + _SEP + r"\d{2,5}){2,3})(?!\d)")
RE_BTC = re.compile(r"\bbc1[02-9ac-hj-np-z]{11,71}\b|\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b")
RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RE_TRON = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
CRYPTO_CUE = re.compile(r"bitcoin|\bbtc\b|ethereum|\beth\b|usdt|tether|\btron\b|trc-?20|erc-?20|wallet|dompet|"
                        r"crypto|kripto|address|alamat", re.I)
SCAMMER_CUE = re.compile(
    r"nomor|nomer|\bno\.|\bwa\b|whatsapp|hubungi|menghubungi|dihubungi|telepon|\btelp|\bsms\b|penipu|pelaku|"
    r"scammer|fraudster|calls? from|texts? from|call(?:ed|ing)?|contact|phone|number|rekening|transfer|kirim|"
    r"account|dompet|wallet|address|alamat|dikirim", re.I)
OFFICIAL_CUE = re.compile(r"resmi|official|verified|terverifikasi|call cent(?:er|re)|hotline|layanan pengaduan|"
                          r"kontak resmi|customer care|pusat panggilan|pengaduan", re.I)
VICTIM_CUE = re.compile(r"(?:nomor|no\.?|number|rekening|account|milik)\s+(?:hp\s+|telepon\s+|wa\s+|bank\s+)?"
                        r"(?:milik\s+)?(?:korban|victim'?s?|pelapor|nasabah)", re.I)
CUE_BEFORE = 70


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def norm_phone(raw: str) -> str | None:
    d = _digits(raw)
    if raw.strip().startswith("+") and not d.startswith("62"):
        return "+" + d if 8 <= len(d) <= 15 else None
    if d.startswith("62"):
        d = d[2:]
    elif d.startswith("0"):
        d = d[1:]
    if not d.startswith("8") or not 9 <= len(d) <= 12:
        return None
    return "+62" + d


_SENTENCE_END = re.compile(r"[.!?;]\s+(?=[A-Z0-9\"'(])|\n")


def _before(text: str, start: int, n: int) -> str:
    """Up to ``n`` characters before ``start``, but not past the start of the sentence: a cue in the previous
    sentence ("... nomor milik korban 0813…. Saldo dikirim ke DANA 0857…") says nothing about this number."""
    chunk = text[max(0, start - n): start]
    ends = list(_SENTENCE_END.finditer(chunk))
    return chunk[ends[-1].end():] if ends else chunk


def _excluded(text: str, start: int, end: int) -> bool:
    """Official (hotline, call centre) or the victim's own number / account."""
    return bool(OFFICIAL_CUE.search(_before(text, start, 45)) or VICTIM_CUE.search(_before(text, start, CUE_BEFORE)))


def _cue_ok(text: str, start: int) -> bool:
    return bool(SCAMMER_CUE.search(_before(text, start, CUE_BEFORE))) and not _excluded(text, start, start)


def identifiers(text: str) -> list[Extracted]:
    """Scammer phone numbers, bank accounts, e-wallets and crypto wallets mentioned in a scam item."""
    text = text or ""
    out: dict[tuple[str, str], Extracted] = {}
    taken: set[str] = set()
    for m in RE_EWALLET.finditer(text):
        num = norm_phone(m.group("num"))
        # "DANA 0812…" names the account itself, so no scammer cue is needed; official / victim ones are skipped
        if not num or _excluded(text, m.start(), m.end()):
            continue
        wallet = {"gopay": "GoPay"}.get(m.group("w").lower(), m.group("w"))
        value = f"{wallet.lower()}:{num}"
        out[("ewallet", value)] = Extracted("ewallet", value, f"{wallet} {num}", wallet.lower(), "regex")
        taken.add(num)
    for m in RE_PHONE.finditer(text):
        num = norm_phone(m.group(0))
        if not num or num in taken or not _cue_ok(text, m.start()):
            continue
        out[("phone", num)] = Extracted("phone", num, num, "id-mobile" if num.startswith("+628") else "intl", "regex")
    for m in RE_ACCOUNT.finditer(text):
        num = _digits(m.group("num"))
        if not 8 <= len(num) <= 18 or norm_phone(m.group("num")):
            continue
        if _excluded(text, m.start(), m.end()) or VICTIM_CUE.search(m.group(0)):
            continue
        code = (m.group("bank") or "").lower()
        bank = BANK_CODES.get(code)
        if not bank:  # "rekening BCA nomor ..." is caught above; "rekening 123 (BRI)" looks right after
            after = text[m.end(): m.end() + 20].lower()
            bank = next((v for k, v in BANK_CODES.items() if re.search(rf"\b{k}\b", after)), "")
        key = next((k for k, v in BANK_CODES.items() if v == bank), "")
        value = f"{key}:{num}" if key else num
        out[("bank_account", value)] = Extracted("bank_account", value, f"{bank} {num}".strip(), key, "regex")
    if CRYPTO_CUE.search(text):
        for rx, chain in ((RE_BTC, "btc"), (RE_ETH, "eth"), (RE_TRON, "tron")):
            for m in rx.finditer(text):
                v = m.group(0)
                if chain == "btc" and not v.startswith("bc1") and not re.search(r"[a-z]", v[1:]):
                    continue  # base58 always mixes cases; an all-caps token is something else
                value = v.lower() if chain == "eth" else v
                out[("crypto_wallet", value)] = Extracted("crypto_wallet", value, v, chain, "regex")
    return list(out.values())


# --------------------------------------------------------------------------- losses and victims
_UNITS = {"triliun": 1e12, "t": 1e12, "miliar": 1e9, "milyar": 1e9, "m": 1e6, "juta": 1e6, "jt": 1e6,
          "ribu": 1e3, "rb": 1e3, "k": 1e3, "billion": 1e9, "bn": 1e9, "b": 1e9, "million": 1e6, "mn": 1e6,
          "thousand": 1e3}
RE_RUPIAH = re.compile(r"(?:\brp\.?|\bidr)\s?(?P<n>\d[\d.,]*)\s*(?P<u>triliun|miliar|milyar|juta|ribu|jt|rb)?\b"
                       r"|(?P<n2>\d[\d.,]*)\s*(?P<u2>triliun|miliar|milyar|juta)\s+rupiah", re.I)
RE_DOLLAR = re.compile(r"(?:us\$|\$|\busd\s?)(?P<n>\d[\d.,]*)\s*(?P<u>billion|million|thousand|bn|mn|[mbk])?\b"
                       r"|(?P<n2>\d[\d.,]*)\s*(?P<u2>billion|million)\s+(?:us )?dollars", re.I)
LOSS_CUE = re.compile(
    r"kerugian|rugi|merugi|kehilangan|hilang|raib|terkuras|dikuras|ludes|meraup|raup|menggondol|digondol|dibawa kabur|uang korban|dana korban|total (?:dana|uang)|"
    r"senilai|mencapai|losses|\blost\b|\bloss\b|stole|stolen|defrauded|swindled|scammed (?:out )?of|cost (?:victims|"
    r"consumers)|cheated|bilked|laundered|hasil kejahatan", re.I)
# Money that was saved, frozen or returned is not a loss ("menyelamatkan dana Rp 811 miliar").
NOT_LOSS = re.compile(r"menyelamatkan|diselamatkan|dikembalikan|diblokir|dibekukan|disita|saved|recovered|returned|"
                      r"frozen|seized|blocked|refunded", re.I)
RE_VICTIMS = re.compile(r"(?P<n>\d[\d.,]*)\s*(?:orang\s+)?(?:korban|nasabah (?:menjadi )?korban|pelapor)\b"
                        r"|(?P<n2>\d[\d.,]*)\s+(?:victims|people (?:were |have been )?(?:scammed|defrauded|targeted|duped))",
                        re.I)
WORD_VICTIMS = [(re.compile(r"puluhan (?:orang )?korban|dozens of (?:victims|people)", re.I), 20),
                (re.compile(r"ratusan (?:orang )?korban|hundreds of (?:victims|people)", re.I), 200),
                (re.compile(r"ribuan (?:orang )?korban|thousands of (?:victims|people)", re.I), 2000),
                (re.compile(r"(?:jutaan (?:orang )?korban|millions of (?:victims|people))", re.I), 1_000_000)]


def _number(s: str, comma_decimal: bool, has_unit: bool) -> float | None:
    """Parse "1.250.000", "1,2", "1.5", "500,000". Indonesian amounts use '.' for thousands and ',' for
    decimals; English amounts the other way round. A single separator followed by 1–2 digits before a unit is a
    decimal point in either convention ("Rp1.5 miliar", "$1,5 million")."""
    s = s.strip(".,")
    if not s:
        return None
    seps = re.findall(r"[.,]", s)
    if len(seps) == 1 and has_unit and re.search(r"[.,]\d{1,2}$", s):
        return float(s.replace(",", "."))
    dec, thou = (",", ".") if comma_decimal else (".", ",")
    s = s.replace(thou, "")
    if s.count(dec) > 1:
        s = s.replace(dec, "")
    try:
        return float(s.replace(dec, "."))
    except ValueError:
        return None


def losses_idr(text: str, usd_rate: float = 16_500.0) -> float:
    """Largest reported loss in rupiah, counting amounts next to a loss word only."""
    best = 0.0
    for rx, rate, comma_dec in ((RE_RUPIAH, 1.0, True), (RE_DOLLAR, usd_rate, False)):
        for m in rx.finditer(text or ""):
            raw, unit = (m.group("n"), m.group("u")) if m.group("n") else (m.group("n2"), m.group("u2"))
            window = text[max(0, m.start() - 90): m.end() + 40]
            if not LOSS_CUE.search(window) or NOT_LOSS.search(_before(text, m.start(), 40)):
                continue
            n = _number(raw, comma_dec, bool(unit))
            if n is None:
                continue
            value = n * _UNITS.get((unit or "").lower(), 1.0) * rate
            if value < 100_000:  # rupiah amounts below this are fees and prices, not losses
                continue
            best = max(best, value)
    return min(best, 1e16)


def victims(text: str) -> int:
    best = 0
    for m in RE_VICTIMS.finditer(text or ""):
        raw = (m.group("n") or m.group("n2") or "").strip(".,")
        digits = re.sub(r"[.,](?=\d{3}\b)", "", raw)
        try:
            n = int(float(digits.replace(",", ".")))
        except ValueError:
            continue
        if 1 < n < 100_000_000:
            best = max(best, n)
    for rx, n in WORD_VICTIMS:
        if rx.search(text or ""):
            best = max(best, n)
    return best


def fmt_idr(v: float | None) -> str:
    v = float(v or 0)
    for div, unit in ((1e12, "trillion"), (1e9, "billion"), (1e6, "million")):
        if v >= div:
            n = v / div
            return f"Rp {n:,.1f} {unit}".replace(".0 ", " ")
    return f"Rp {v:,.0f}"


# --------------------------------------------------------------------------- score
OFFICIAL_SOURCE = re.compile(
    r"\bojk\b|satgas pasti|\biasc\b|\bpolri\b|bareskrim|\bpolda\b|\bpolres\b|ditangkap|diringkus|tersangka|"
    r"\barrest(?:ed|s)?\b|\bcharged\b|\bindicted\b|\bsentenced\b|\bfbi\b|\bic3\b|\bftc\b|europol|interpol|"
    r"\bkominfo\b|\bkomdigi\b|\bbssn\b|\bbank indonesia\b", re.I)
VELOCITY_MIN = 5  # reports this week before "spreading" is considered


@dataclass
class FraudResult:
    score: int = 0
    reasons: list[dict] = field(default_factory=list)
    loss_idr: float = 0.0
    victims: int = 0
    entities: list[Extracted] = field(default_factory=list)


def velocity(db, key: str, at: datetime) -> tuple[int, int]:
    """Items of scam type ``key`` in the 7 days up to ``at`` and in the 7 days before that."""
    from sqlalchemy import func, select

    from ..models import Entity, Item, ItemEntity

    def count(lo, hi):
        return db.scalar(
            select(func.count(func.distinct(Item.id))).join(ItemEntity, ItemEntity.item_id == Item.id)
            .join(Entity, Entity.id == ItemEntity.entity_id)
            .where(Entity.type == "scam_type", Entity.value == key, Item.published_at > lo, Item.published_at <= hi)
        ) or 0

    return count(at - timedelta(days=7), at), count(at - timedelta(days=14), at - timedelta(days=7))


def _loss_points(v: float) -> int:
    for floor, pts in ((1e12, 30), (1e11, 25), (1e10, 20), (1e9, 15), (1e8, 10)):
        if v >= floor:
            return pts
    return 5 if v > 0 else 0


def _victim_points(n: int) -> int:
    for floor, pts in ((10_000, 20), (1_000, 15), (100, 10), (10, 5)):
        if n >= floor:
            return pts
    return 0


def analyse(title: str, body: str, *, topic: str = "", db=None, at: datetime | None = None,
            usd_rate: float | None = None, extract_identifiers: bool | None = None) -> FraudResult:
    """Fraud score, reasons and fraud entities of one item. Items that are not about a scam get score 0."""
    from .. import settings
    from ..models import utcnow

    title, body = title or "", body or ""
    types = scam_types(title, body, topic)
    res = FraudResult()
    if not types:
        return res
    text = f"{title}\n{body}"
    usd_rate = float(usd_rate if usd_rate is not None else settings.get("fraud_usd_idr") or 16_500)
    if extract_identifiers is None:
        extract_identifiers = bool(settings.get("fraud_identifiers"))
    reasons = []
    key, name, weight = types[0]
    reasons.append({"label": f"scam type: {name}", "points": weight})
    extra = min(8, 4 * (len(types) - 1))
    if extra:
        reasons.append({"label": "also: " + ", ".join(n for _, n, _ in types[1:4]), "points": extra})
    res.entities += [Extracted("scam_type", k, n, "", "kb") for k, n, _ in types]

    found_brands = brands(title, body)
    if found_brands:
        res.entities += [Extracted("brand", n.lower(), n, c, "kb") for n, c in found_brands]
        top = sorted(found_brands, key=lambda b: b[1] not in ("government", "bank", "ewallet"))[0]
        pts = 10 if top[1] in ("government", "bank", "ewallet") else 6
        reasons.append({"label": f"impersonates {top[0]}", "points": pts})

    res.loss_idr = losses_idr(text, usd_rate)
    if res.loss_idr:
        reasons.append({"label": f"reported losses {fmt_idr(res.loss_idr)}", "points": _loss_points(res.loss_idr)})
    res.victims = victims(text)
    if _victim_points(res.victims):
        reasons.append({"label": f"{res.victims:,} victims reported", "points": _victim_points(res.victims)})

    if extract_identifiers:
        ids = identifiers(text)
        if ids:
            res.entities += ids
            reasons.append({"label": f"scammer identifiers published ({len(ids)})", "points": 8})
    if OFFICIAL_SOURCE.search(text):
        reasons.append({"label": "official warning or law enforcement", "points": 8})
    if db is not None and key != "other":
        now, before = velocity(db, key, at or utcnow())
        if now >= VELOCITY_MIN and now >= 2 * max(1, before):
            reasons.append({"label": f"spreading: {now} reports this week, {before} the week before", "points": 8})
    res.reasons = reasons
    res.score = max(1, min(100, sum(r["points"] for r in reasons)))
    return res


def apply(db, item, topic: str = "") -> list[Extracted]:
    """Analyse ``item`` and store its fraud fields. Returns the fraud entities to link."""
    body = f"{item.content or ''}\n{' '.join(item.tags or [])}"
    r = analyse(item.title, body, topic=topic, db=db, at=item.published_at)
    item.fraud_score, item.fraud_detail = r.score, r.reasons
    item.fraud_loss_idr, item.fraud_victims = r.loss_idr, r.victims
    return r.entities


def check_links(e) -> list[tuple[str, str]]:
    """Where an analyst can look an identifier up by hand. No automatic lookups: cekrekening.id sits behind a
    CAPTCHA and the explorers have their own terms."""
    if e.type == "bank_account":
        return [("cekrekening.id", "https://cekrekening.id/home")]
    if e.type == "crypto_wallet":
        v = e.display or e.value
        if e.category == "eth":
            return [("Etherscan", f"https://etherscan.io/address/{v}")]
        if e.category == "tron":
            return [("Tronscan", f"https://tronscan.org/#/address/{v}")]
        return [("Blockchain.com", f"https://www.blockchain.com/explorer/addresses/btc/{v}")]
    return []


def retag_item(db, item) -> None:
    """Re-run the fraud analysis on a stored item, replacing its fraud entities (rules may have changed)."""
    from sqlalchemy import select

    from ..models import Entity, ItemEntity
    from .pipeline import link_entities

    old = db.execute(select(ItemEntity).join(Entity, Entity.id == ItemEntity.entity_id)
                     .where(ItemEntity.item_id == item.id, Entity.type.in_(FRAUD_TYPES))).scalars().all()
    for link in old:
        link.entity.mention_count = max(0, (link.entity.mention_count or 0) - 1)
        db.delete(link)
    db.flush()
    link_entities(db, item, apply(db, item, item.source.topic or "" if item.source else ""))


def retag_all(db, progress=None, batch: int = 500) -> int:
    """Fraud analysis of every stored item, oldest first so the spread velocity sees earlier reports."""
    from sqlalchemy import func, select

    from ..models import Item

    total = db.scalar(select(func.count(Item.id))) or 0
    ids = [i for (i,) in db.execute(select(Item.id).order_by(Item.published_at, Item.id))]
    for n, item_id in enumerate(ids, 1):
        item = db.get(Item, item_id)
        if item is not None:
            retag_item(db, item)
        if n % batch == 0:
            db.commit()
            if progress:
                progress(n, total)
    db.commit()
    if progress:
        progress(total, total)
    return total
