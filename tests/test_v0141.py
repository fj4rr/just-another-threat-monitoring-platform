"""Newsletter / round-up items (Cisco Talos "Threat Source") must not correlate with everything they list."""
from sqlalchemy import select

from app.db import session_scope
from app.models import Item, Source, utcnow
from app.processing import trends
from app.processing.digest import is_digest
from app.processing.extractor import Extracted
from app.processing.pipeline import link_entities


def _src(db, name, config=None):
    src = db.execute(select(Source).where(Source.name == name)).scalar_one_or_none()
    if not src:
        src = Source(name=name, kind="rss", category="news", config={"url": f"https://{name}.example/f", **(config or {})})
        db.add(src)
        db.flush()
    return src


def _hashes(n, tag):
    return [Extracted("md5", f"{tag}{i:02d}".ljust(32, "a"), f"{tag}{i:02d}".ljust(32, "a"), "", "regex") for i in range(n)]


def test_is_digest(installed):
    with session_scope() as db:
        s = _src(db, "zz-dig-a")
        assert is_digest(Item(source=s, title="Never be afraid to ask questions", tags=["Threat Source newsletter"]))
        assert is_digest(Item(source=s, title="Week in review: top stories", tags=[]))
        assert not is_digest(Item(source=s, title="LockBit affiliates abuse a new loader", tags=["ransomware"]))
        forced = _src(db, "zz-dig-forced", {"digest": True})
        assert is_digest(Item(source=forced, title="Plain title", tags=[]))
        optout = _src(db, "zz-dig-optout", {"digest": False})
        assert not is_digest(Item(source=optout, title="Weekly roundup", tags=[]))


TALOS_TITLES = ["The internet needs a nap (and you do, too)", "Never be afraid to ask questions", "A quiet week in infosec <.<",
                "I had plans for that second", "Give yourself room to be human.", "Making sure the checks get printed",
                "Trust and the enticing consultancy offer", "We've got one word for it, and it's usually the wrong one"]


def test_talos_issues_are_caught_by_body_when_title_and_tags_say_nothing(installed):
    body = "Welcome to this week's edition of the Threat Source newsletter. Upcoming events where you can find Talos"
    with session_scope() as db:
        s = _src(db, "zz-dig-talos2")
        for t in TALOS_TITLES:
            assert is_digest(Item(source=s, title=t, tags=[], content=body)), t
            assert not is_digest(Item(source=s, title=t, tags=[], content="A research post about a loader."))


def test_round_up_title_variants(installed):
    with session_scope() as db:
        s = _src(db, "zz-dig-var")
        for t in ["Risky Bulletin: Microsoft patches", "ThreatsDay Bulletin: Wi-Fi flaw, new RAT", "In Other News: ICS flaws",
                  "Cyber Security Headlines - Friday", "The Week in Ransomware - November 14th", "Weekly Threat Report",
                  "Cyber Threat Weekly", "Threat Intelligence Briefing 2026-11-18", "Rangkuman dan ulasan mingguan siber"]:
            assert is_digest(Item(source=s, title=t, tags=[], content="")), t
        for t in ["We analyzed a DPRK-linked Contagious Interview intrusion where fake job lures abused npm",
                  "Pakistani APT adopts contagious interview tactics", "Lessons from 59 Linux Kernel Bug Reports",
                  "Webinar: See How Identity Blind Spots Put Your SOC at Risk",
                  "LockBit affiliates abuse a new loader", "Microsoft security bulletin MS26-114 fixes RCE",
                  "Harian Kompas: peretas bobol data BPJS", "Pentagon briefing on the cyberattack", "Executive brief: Akira"]:
            assert not is_digest(Item(source=s, title=t, tags=[], content="")), t


VERSION_TEXTS = [
    "Fixed OpenJDK builds include 17.0.21.1, 21.0.13.1, 25.0.5.1, and 27.0.1.1. Administrators should check",
    "IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker",
    "IBM MQ 9.2.0.0 through 9.2.0.44 LTS, 9.3.0.0 through 9.3.0.42 LTS, 9.4.0.0 through 9.4.0.26 are affected",
    "Dell Alienware Command Center (AWCC), versions prior to 6.14.105.0, contain a TOCTOU race condition",
    "A vulnerability has been found in DrayTek Vigor2960 up to 1.5.1.6. The vendor recommends: \"1.5.1.6 isn't the latest\"",
    "The supported version that is affected is 21.1.0.7. Difficult to exploit vulnerability allows",
]


def test_four_part_version_numbers_are_not_ips():
    from app.processing.extractor import extract_iocs

    for text in VERSION_TEXTS:
        assert [e.value for e in extract_iocs(text) if e.type == "ip"] == [], text
    # real indicators next to the same words still count
    got = {e.value for e in extract_iocs("The loader connects to 91.92.243.10 and 185.220.101.4, then beacons to 45.9.148.21")
           if e.type == "ip"}
    assert got == {"91.92.243.10", "185.220.101.4", "45.9.148.21"}
    assert [e.value for e in extract_iocs("Server 91.92.243.10 hosts the payload") if e.type == "ip"] == ["91.92.243.10"]


def test_git_commit_in_a_page_title_is_not_a_sample_hash():
    from app.processing.extractor import extract_iocs

    sha = "4fbffbc6c2ece137f15ded6cfaae785caa7098d8"
    assert not [e for e in extract_iocs(f"scalar_ninja.py at {sha} · scalar/scalar") if e.type == "sha1"]
    assert [e.value for e in extract_iocs(f"Sample SHA1: {sha}") if e.type == "sha1"] == [sha]


def test_digests_do_not_correlate_through_recurring_hashes(installed):
    with session_scope() as db:
        talos, other = _src(db, "zz-dig-talos"), _src(db, "zz-dig-other")
        shared = _hashes(5, "zzdig")
        issues = []
        for n in range(3):  # weekly issues repeating the same "most prevalent files"
            it = Item(source_id=talos.id, external_id=f"zzdig-{n}", title=f"Issue {n}", tags=["Threat Source newsletter"],
                      published_at=utcnow())
            db.add(it)
            db.flush()
            link_entities(db, it, shared)
            issues.append(it)
        story = Item(source_id=other.id, external_id="zzdig-story", title="Loader drops stealer", tags=[], published_at=utcnow())
        real = Item(source_id=other.id, external_id="zzdig-real", title="Same loader, new campaign", tags=[], published_at=utcnow())
        db.add_all([story, real])
        db.flush()
        link_entities(db, story, shared)
        link_entities(db, real, shared)
        db.flush()

        ids = {r["item"].id for r in trends.correlated_items(db, issues[0])}
        assert issues[1].id not in ids and issues[2].id not in ids  # digest <-> digest: boilerplate
        rows = {r["item"].id: r for r in trends.correlated_items(db, story)}
        assert real.id in rows and not rows[real.id]["digest"] and rows[real.id]["strong"]  # real reports still link
        assert all(r["digest"] and not r["strong"] for iid, r in rows.items() if iid != real.id)
