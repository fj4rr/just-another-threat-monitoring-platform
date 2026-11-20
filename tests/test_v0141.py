"""Newsletter / round-up items (Cisco Talos "Threat Source") must not correlate with everything they list."""
from sqlalchemy import select

from app.db import session_scope
from app.models import Entity, Item, Source, utcnow
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


def test_ioc_clean_removes_only_judgeable_regex_links(installed):
    from app.models import Entity, ItemEntity
    from app.processing.ioccheck import clean_false_iocs

    with session_scope() as db:
        s = _src(db, "zz-clean")
        bad = Item(source_id=s.id, external_id="zzclean-1", published_at=utcnow(), title="CVE advisory",
                   content="IBM API Connect 12.1.0.0 through 12.1.1.2 is affected. C2 at 91.92.243.77 seen.")
        trimmed = Item(source_id=s.id, external_id="zzclean-2", published_at=utcnow(), title="Old post", content="trimmed")
        db.add_all([bad, trimmed])
        db.flush()
        link_entities(db, bad, [Extracted("ip", "12.1.0.0", "12.1.0.0", "", "regex"),
                                Extracted("ip", "91.92.243.77", "91.92.243.77", "", "regex"),
                                Extracted("ip", "12.1.1.2", "12.1.1.2", "", "feed")])
        link_entities(db, trimmed, [Extracted("ip", "33.44.55.66", "33.44.55.66", "", "regex")])
        db.flush()
        ids = [bad.id, trimmed.id]
        dry = clean_false_iocs(db, apply=False, item_ids=ids)
        assert dry["links"] == 1 and dry["kept_unjudged"] == 1  # 12.1.0.0 only; 33.44.55.66 has no text to judge
        out = clean_false_iocs(db, apply=True, item_ids=ids)
        assert out["links"] == 1 and out["entities_deleted"] == 1
        vals = {e.value for e in db.execute(select(Entity).join(ItemEntity, ItemEntity.entity_id == Entity.id)
                                            .where(ItemEntity.item_id.in_(ids))).scalars()}
        assert vals == {"91.92.243.77", "12.1.1.2", "33.44.55.66"}  # real IP, feed link and unjudgeable link stay


def test_reextract_keeps_entities_that_only_a_feed_links(tmp_path):
    """Regression: reextract recounted mentions in the session but deleted before flushing, so an indicator listed
    only by a feed looked unreferenced and went, taking its verdict and its link with it."""
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    env = {**__import__("os").environ, "JATMP_DATA_DIR": str(tmp_path)}
    setup = (
        "from app.setup_service import perform_install; perform_install(mode='single', seed_sources=False)\n"
        "from app.db import session_scope\n"
        "from app.models import Entity, Item, ItemEntity, Source, utcnow\n"
        "with session_scope() as db:\n"
        "    s = Source(name='zz-feed', kind='rss', category='intel', config={}); db.add(s); db.flush()\n"
        "    i = Item(source_id=s.id, external_id='r1', title='list', content='nothing here', published_at=utcnow())\n"
        "    db.add(i); db.flush()\n"
        "    e = Entity(type='domain', value='evil-feed.example', display='evil-feed.example', mention_count=1,\n"
        "               verdict='malicious'); db.add(e); db.flush()\n"
        "    db.add(ItemEntity(item_id=i.id, entity_id=e.id, origin='feed'))\n")
    check = ("from app.db import session_scope\nfrom app.models import Entity\nfrom sqlalchemy import select\n"
             "with session_scope() as db:\n"
             "    print([(e.value, e.mention_count, e.verdict) for e in db.execute(select(Entity)).scalars()])\n")
    for code in (setup,):
        subprocess.run([sys.executable, "-c", code], cwd=root, env=env, check=True, capture_output=True)
    subprocess.run([sys.executable, "manage.py", "reextract"], cwd=root, env=env, check=True, capture_output=True)
    res = subprocess.run([sys.executable, "-c", check], cwd=root, env=env, check=True, capture_output=True, text=True)
    assert "('evil-feed.example', 1, 'malicious')" in res.stdout


def test_digests_do_not_correlate_through_recurring_hashes(installed):
    with session_scope() as db:
        talos, other = _src(db, "zz-dig-talos"), _src(db, "zz-dig-other")
        shared = _hashes(5, "zzdig")
        issues = []
        for n in range(3):  # weekly issues repeating the same "most prevalent files"
            it = Item(source_id=talos.id, external_id=f"zzdig-{n}", title=f"Issue {n}", tags=["Threat Source newsletter"],
                      published_at=utcnow(), is_digest=True)
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


def _volta_case(db, tag):
    """A hash listed in a newsletter's "prevalent files" next to the family of another story, and the same family
    in a real report with another hash. Returns (digest hash id, real hash id, family id)."""
    news, other = _src(db, f"zz-co-news-{tag}"), _src(db, f"zz-co-other-{tag}")
    fam = Extracted("malware", f"zzfam{tag}", f"ZzFam{tag}", "stealer", "kb")
    h_news = Extracted("sha256", (f"a{tag}" * 32)[:64], (f"a{tag}" * 32)[:64], "", "regex")
    h_real = Extracted("sha256", (f"b{tag}" * 32)[:64], (f"b{tag}" * 32)[:64], "", "regex")
    digest = Item(source_id=news.id, external_id=f"co-d-{tag}", title="Threat Source", tags=["Threat Source newsletter"],
                  published_at=utcnow(), is_digest=True)
    real = Item(source_id=other.id, external_id=f"co-r-{tag}", title="Stealer analysis", published_at=utcnow())
    db.add_all([digest, real])
    db.flush()
    link_entities(db, digest, [fam, h_news])
    link_entities(db, real, [fam, h_real])
    db.flush()
    ent = {(e.type, e.value): e.id for e in db.execute(select(Entity)).scalars()}
    return ent[("sha256", h_news.value)], ent[("sha256", h_real.value)], ent[("malware", fam.value)]


def test_co_mentions_skip_digests(installed):
    from app.routers.pages import related_chips

    with session_scope() as db:
        h_news, h_real, fam = _volta_case(db, "1")
        assert trends.co_occurring(db, h_news, ("malware",)) == []  # the newsletter's hash is not tied to the family
        assert [c["id"] for c in trends.co_occurring(db, h_real, ("malware",))] == [fam]
        assert h_news not in related_chips(db, [h_news, h_real], ("malware",))
        assert [c["id"] for c in related_chips(db, [h_real], ("malware",))[h_real]] == [fam]
        # from the family's side only the real report's indicator is listed
        assert [c["id"] for c in trends.co_occurring(db, fam, ("sha256",))] == [h_real]


def test_ingest_flags_digests_and_retag_keeps_trimmed_ones(installed):
    from app.processing import digest as dg
    from app.processing.pipeline import RawItem, ingest

    with session_scope() as db:
        s = _src(db, "zz-ingest-dig")
        ids = ingest(db, s, [
            RawItem(external_id="zzi-1", title="Never be afraid to ask questions", url="https://x.example/1", kind="article",
                    content="Welcome to this week's edition of the Threat Source newsletter. Upcoming events where you can find Talos",
                    tags=[]),
            RawItem(external_id="zzi-2", title="Loader drops a stealer", url="https://x.example/2", kind="article",
                    content="A research post about a loader.", tags=[])])
        db.flush()
        a, b = (db.get(Item, i) for i in ids)
        assert a.is_digest is True and b.is_digest is False
        # retention trims the body: the flag it already had stays, nothing is flagged by the rerun that was not before
        a.content, a.slimmed_at = "Welcome", utcnow()
        db.flush()
        dg.retag_all(db)
        assert db.get(Item, a.id).is_digest is True and db.get(Item, b.id).is_digest is False


def test_ioc_page_separates_providers_from_co_mentions(client):
    with session_scope() as db:
        h_news, h_real, fam = _volta_case(db, "2")
    page = client.get(f"/entities/{h_real}").text
    assert "Seen in the same items as" in page and "not attribution" in page
    assert client.get(f"/entities/{h_news}").status_code == 200
    fam_page = client.get(f"/entities/{fam}").text  # the family lists its real report's hash, not the newsletter's
    assert ("b2" * 32) in fam_page and ("a2" * 32) not in fam_page
