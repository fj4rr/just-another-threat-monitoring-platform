"""0.13.1: rule tuning from the first quality report. Every fix comes with the case that motivated it and the
counter-examples it must not break (the labelled sets in tests/quality carry them too)."""
import pytest

from app.processing.extractor import extract_all
from app.processing.fraud import scam_types
from app.processing.geo import analyse
from app.processing.sectors import detect
from app.processing.severity import score_item


def _iocs(text):
    return {(e.type, e.value) for e in extract_all(text) if e.type in ("ip", "domain", "url")}


def _fams(text):
    return {e.display for e in extract_all(text) if e.type in ("malware", "actor")}


def _sev(title, body=""):
    return score_item(title, body, extract_all(f"{title}\n{body}"))[0]


# --------------------------------------------------------------------------- indicators
def test_server_is_no_version_prefix():
    assert ("ip", "91.92.243.10") in _iocs("Exfiltration server 91.92.243.10, staging")
    assert not _iocs("update to version 10.2.3.4") and not _iocs("v1.2.3.4 is out")


def test_public_resolvers_are_no_indicators():
    assert not _iocs("The implant checks connectivity with 8.8.8.8 and 1.1.1.1")
    assert ("ip", "45.155.205.233") in _iocs("C2 at 45.155.205.233")


def test_abused_hosting_url_is_an_indicator_its_domain_is_not():
    got = _iocs("Payload URL: hxxps://pastebin[.]com/raw/abcd1234 decodes to stage two")
    assert got == {("url", "https://pastebin.com/raw/abcd1234")}
    got = _iocs("Downloaded from hxxps://github[.]com/evil/repo/releases/download/x.zip")
    assert got == {("url", "https://github.com/evil/repo/releases/download/x.zip")}
    assert not _iocs("see hxxps://pastebin[.]com for details") and not _iocs("Read the code on github.com")


# --------------------------------------------------------------------------- families
@pytest.mark.parametrize("text,want", [
    ("LummaC2 and RedLine dominate infostealer logs", {"Lumma Stealer", "RedLine"}),
    ("Cl0p exploits Oracle E-Business Suite zero-day", {"Cl0p"}),
    ("SafePay claims attack on retailer", {"SafePay"}),
    ("the project crossed a redline", set()),
    ("REDLINE: the deadline passed", set()),
    ("clop clop went the horse", set()),
    ("Safepay checkout is now available", set()),
])
def test_distinctive_spelling_needs_no_qualifier(text, want):
    assert _fams(text) == want


# --------------------------------------------------------------------------- geography
@pytest.mark.parametrize("title,body,want", [
    ("New stealer malware sold on Russian forums", "It targets browsers worldwide.", []),
    ("Attack infrastructure hosted in the Netherlands targets Indonesian banks",
     "The phishing servers were rented from a Dutch provider.", ["ID"]),
    ("Server di Singapura dipakai untuk phishing bank Indonesia", "Nasabah bank di Indonesia jadi sasaran.", ["ID"]),
    ("Ransomware hits hospitals in the Netherlands", "Dutch hospitals were affected.", ["NL"]),
    ("Russian energy firms hit by wiper", "The attack disrupted pipelines in Russia.", ["RU"]),
    ("Data of Indonesian users sold on dark web forums", "Penjual menawarkan data warga Indonesia.", ["ID"]),
])
def test_marketplaces_and_hosting_are_no_targets(title, body, want):
    assert [cc for cc, _ in analyse(title, body).top()] == want


# --------------------------------------------------------------------------- scams and sectors
@pytest.mark.parametrize("title,body,want", [
    ("Hati-hati telepon mengaku dari Bea Cukai soal paket tertahan", "Penipu meminta transfer ke rekening pribadi.", True),
    ("Deepfake video of the president promotes fraudulent investment app", "The scam video spread online.", True),
    ("Bank Indonesia warns of fake QRIS stickers at mosques", "Penipu menempel stiker QRIS palsu di kotak amal.", True),
    ("Warga Medan tertipu jual beli mobil online, rugi Rp 150 juta", "Penjual fiktif meminta uang muka.", True),
    ("SMS phishing impersonates toll road operator over unpaid fees", "The smishing messages link to a fake payment page.",
     True),
    ("Pejabat mengaku dari partai lain saat kampanye", "Ia menjelaskan program kerjanya.", False),
    ("APT29 spear-phishing campaign targets diplomats", "The phishing emails carried a malicious PDF.", False),
    ("Bank BRI luncurkan fitur QRIS baru", "Nasabah bisa membayar dengan kode QR.", False),
    ("Pasar jual beli mobil bekas online tumbuh 20 persen", "Penjualan mobil bekas meningkat.", False),
    ("Microsoft details login page redesign", "The new login page is faster.", False),
])
def test_scam_rules(title, body, want):
    assert bool(scam_types(title, body)) is want


def test_fuel_stations_are_energy_but_fuel_prices_are_not_a_target():
    assert detect("Pertamina confirms cyber attack on fuel payment system", "Pembayaran di SPBU terganggu.") == ["energy"]
    assert detect("Harga BBM naik", "Pemerintah menaikkan harga bahan bakar.") == []


# --------------------------------------------------------------------------- severity
@pytest.mark.parametrize("title,body,notable", [
    ("Ransomware attack halts production at car maker plants", "The gang threatens to leak stolen data.", True),
    ("Data breach exposes 279 million BPJS records sold on hacker forum", "The leak includes NIK numbers.", True),
    ("Salt Typhoon breached nine US telecoms and accessed wiretap systems", "State-sponsored hackers stayed for months.",
     True),
    ("Supply chain attack: malicious update of popular npm package steals credentials",
     "The backdoor was downloaded 2 million times before removal.", True),
    ("Weekly roundup: ransomware, zero-days and breaches", "A summary of this week's security news.", False),
    ("App reaches 2 million users", "The startup celebrates growth.", False),
    ("Smartphone sales reach 279 million units", "Shipments grew in Asia.", False),
    ("Company halts production of its older phone model", "The model will be replaced next year.", False),
])
def test_severity_signals(title, body, notable):
    assert (_sev(title, body) >= 30) is notable
