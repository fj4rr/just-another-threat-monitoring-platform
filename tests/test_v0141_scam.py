"""0.14.1 scam rules: brands that speak or act are not impersonated, advisories name nobody, impersonated people."""
from app.processing import fraud


def names(t, b=""):
    return {n for n, _ in fraud.brands(t, b)}


def test_anti_scam_is_no_scam_word():
    t = "Indodax: Aplikasi Anti-Scam OJK bantu masyarakat verifikasi transaksi"
    b = "Pelaku industri aset kripto menilai positif rencana OJK untuk meluncurkan aplikasi anti-scam."
    assert fraud.scam_types(t, b) == []
    assert "Indodax" not in names(t, b)


def test_brand_advisory_names_no_impersonated_brand():
    t = "Lawan Penipuan Perbankan, BRI Ajak Kenali Kanal Komunikasi Resmi"
    b = ("Nasabah diimbau berhati-hati saat menerima komunikasi yang mengatasnamakan BRI dan pastikan informasi itu "
         "berasal dari kanal resmi sebelum melakukan apa pun.")
    assert "BRI" not in names(t, b)
    # a warning about a campaign that is going round still names the brand
    assert "BRI" in names("BRI imbau nasabah waspada penipuan mengatasnamakan BRI yang marak", "Korban diminta klik link.")
    assert "Shopee" in names("Shopee warns customers about fake Shopee websites")


def test_brand_that_acts_is_not_impersonated():
    t = "Coinbase blocks $4.7 million in transfers to Elon Musk deepfake scam"
    b = ("Coinbase says it blocked $4.7 million in cryptocurrency transfers to scammers promoting a fake giveaway "
         "using an AI-generated deepfake of Elon Musk. AI News Scams Coinbase deepfake")
    assert "Coinbase" not in names(t, b)
    assert "Coinbase" not in names("Scam centre raid", "Separately, Coinbase identified more than 65 active scam victims.")
    assert "Coinbase" not in names("Coinbase data exposed", "Coinbase’s support scam guidance says staff never ask.")
    assert "BCA" in names("Waspada phishing BCA", "Penipu mengirim link.")


def test_impersonated_people():
    assert fraud.persons("Coinbase blocks $4.7 million in transfers to Elon Musk deepfake scam", "") == ["Elon Musk"]
    assert fraud.persons("Deepfake Elon Musk nearly costs viewers $4.7 million in crypto", "") == ["Elon Musk"]
    assert fraud.persons("Waspada penipuan mencatut nama Menteri Keuangan Sri Mulyani", "") == ["Sri Mulyani"]
    assert fraud.persons("Penipu mencatut nama Bupati Bandung Dadang Supriatna", "Korban rugi.") == ["Dadang Supriatna"]
    assert fraud.persons("Penipuan mengatasnamakan Presiden Prabowo beredar", "") == ["Prabowo Subianto"]
    # no office, no known name: may be a private person, left alone; a plain mention is no impersonation
    assert fraud.persons("Penipu mengatasnamakan Budi Santoso minta transfer", "") == []
    assert fraud.persons("Trump signs crypto bill as scams rise", "Investment scams grew.") == []
    r = fraud.analyse("Deepfake Elon Musk crypto giveaway scam", "Victims sent crypto.", usd_rate=16_500,
                      extract_identifiers=False)
    assert ("brand", "elon musk", "person") in {(e.type, e.value, e.category) for e in r.entities}
    assert any(x["label"] == "impersonates Elon Musk" for x in r.reasons)
