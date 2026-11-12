from app.knowledge import canonical_malware
from app.processing.extractor import extract_all, extract_iocs, refang, severity_score


def test_refang_variants():
    assert refang("hxxps://evil[.]example[.]com/x") == "https://evil.example.com/x"
    assert refang("1.2.3[.]4") == "1.2.3.4"
    assert refang("bad(dot)example(dot)net") == "bad.example.net"


def test_strict_mode_only_takes_defanged_network_iocs():
    text = "Read more at https://thehackernews.com/story and the C2 hxxp://c2[.]evil-domain[.]top/gate.php"
    found = {(e.type, e.value) for e in extract_iocs(text, strict=True)}
    assert ("url", "http://c2.evil-domain.top/gate.php") in found
    assert ("domain", "c2.evil-domain.top") in found
    assert not any(t == "domain" and "thehackernews" in v for t, v in found)


def test_hashes_cves_techniques_and_ips():
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    text = f"Sample {sha} exploits CVE-2024-3400 via T1059.001 from 45.33.32.156 (not 10.0.0.1, not version 1.2.3.4)"
    found = {(e.type, e.value) for e in extract_iocs(text, strict=False)}
    assert ("sha256", sha) in found
    assert ("cve", "CVE-2024-3400") in found
    assert ("technique", "T1059.001") in found
    assert ("ip", "45.33.32.156") in found
    assert ("ip", "10.0.0.1") not in found
    assert ("ip", "1.2.3.4") not in found


def test_known_family_and_alias_resolution():
    ents = extract_all("A new LummaC2 campaign abuses ClickFix; the Lumma operators also push Vidar stealer.")
    names = {e.display for e in ents if e.type == "malware"}
    assert "Lumma Stealer" in names
    assert "Vidar" in names
    assert canonical_malware("trojan.lumma/lummac2") is None  # resolve_family handles tokenised labels
    assert canonical_malware("LummaC2") == ("Lumma Stealer", "stealer")
    assert canonical_malware("black basta") == ("Black Basta", "ransomware")


def test_candidate_family_heuristic():
    ents = extract_all("Researchers detail the PipeMagic backdoor used against Azure tenants.")
    heur = [e for e in ents if e.origin == "heuristic"]
    assert any(e.display == "PipeMagic" and e.category == "backdoor" for e in heur)
    # generic words never become families
    ents = extract_all("A new ransomware strain hit the city. The malware spreads fast.")
    assert not [e for e in ents if e.origin == "heuristic"]


def test_severity_score_bounds():
    assert severity_score("", []) == 0
    high = severity_score("zero-day actively exploited by ransomware gang in supply-chain attack", [])
    assert 0 < high <= 100
