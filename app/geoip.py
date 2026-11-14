"""Offline GeoIP for the *infrastructure* location of IP indicators.

Any MaxMind-format database in ``<data dir>/geoip/`` works: DB-IP *IP to Country Lite* (free, no account,
CC BY 4.0, fetched by ``python manage.py geoip-update``), or MaxMind GeoLite2 Country / City (free account;
``manage.py geoip-update`` downloads it when ``MAXMIND_LICENSE_KEY`` is set). Without a database the
country comes from the intel providers (VirusTotal, AbuseIPDB, OTX, IPinfo...) during enrichment.
"""
from __future__ import annotations

import gzip
import ipaddress
import logging
import shutil
import tarfile
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path

from .config import DATA_DIR

log = logging.getLogger(__name__)
GEOIP_DIR = DATA_DIR / "geoip"
_lock = threading.Lock()
_reader = None
_reader_path: Path | None = None
_checked_mtime: float | None = None


def database_path() -> Path | None:
    if not GEOIP_DIR.is_dir():
        return None
    files = sorted(GEOIP_DIR.glob("*.mmdb"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def _get_reader():
    global _reader, _reader_path, _checked_mtime
    path = database_path()
    if path is None:
        return None
    mtime = path.stat().st_mtime
    with _lock:
        if _reader is None or path != _reader_path or mtime != _checked_mtime:
            try:
                import maxminddb
            except ImportError:  # pragma: no cover - dependency is in requirements.txt
                return None
            if _reader is not None:
                _reader.close()
            _reader = maxminddb.open_database(str(path))
            _reader_path, _checked_mtime = path, mtime
        return _reader


def country(ip: str) -> str:
    """ISO2 country of a public IP, or '' (no database, private address, not found)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if not addr.is_global:
        return ""
    try:
        reader = _get_reader()
        if reader is None:
            return ""
        rec = reader.get(str(addr)) or {}
    except Exception as e:  # a corrupt file must not break ingestion
        log.warning("GeoIP lookup failed: %s", e)
        return ""
    c = (rec.get("country") or rec.get("registered_country") or {}).get("iso_code") or ""
    return c.upper() if len(c) == 2 else ""


def status() -> dict:
    path = database_path()
    if not path:
        return {"installed": False}
    meta = {}
    try:
        reader = _get_reader()
        if reader is not None:
            m = reader.metadata()
            meta = {"type": m.database_type, "built": datetime.fromtimestamp(m.build_epoch, UTC).strftime("%Y-%m-%d")}
    except Exception as e:
        meta = {"error": str(e)}
    return {"installed": True, "file": path.name, **meta}


def update(license_key: str = "", client=None) -> str:
    """Download a fresh country database into ``data/geoip/``. Returns a short description."""
    import httpx

    GEOIP_DIR.mkdir(parents=True, exist_ok=True)
    own = client is None
    client = client or httpx.Client(timeout=120, follow_redirects=True)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            if license_key:
                url = "https://download.maxmind.com/app/geoip_download"
                r = client.get(url, params={"edition_id": "GeoLite2-Country", "license_key": license_key,
                                            "suffix": "tar.gz"})
                r.raise_for_status()
                archive = tmpdir / "geolite2.tar.gz"
                archive.write_bytes(r.content)
                with tarfile.open(archive) as tar:
                    member = next((m for m in tar.getmembers() if m.name.endswith(".mmdb") and m.isfile()), None)
                    if member is None:
                        raise RuntimeError("no .mmdb file in the GeoLite2 archive")
                    src = tar.extractfile(member)
                    target = GEOIP_DIR / "GeoLite2-Country.mmdb"
                    with open(tmpdir / "new.mmdb", "wb") as out:
                        shutil.copyfileobj(src, out)
                label = "MaxMind GeoLite2 Country"
            else:
                now = datetime.now(UTC)
                r = None
                for months_back in (0, 1):
                    y, m = now.year, now.month - months_back
                    if m < 1:
                        y, m = y - 1, 12
                    url = f"https://download.db-ip.com/free/dbip-country-lite-{y}-{m:02d}.mmdb.gz"
                    r = client.get(url)
                    if r.status_code == 200:
                        break
                r.raise_for_status()
                with open(tmpdir / "new.mmdb", "wb") as out:
                    out.write(gzip.decompress(r.content))
                target = GEOIP_DIR / "dbip-country-lite.mmdb"
                label = "DB-IP IP to Country Lite (CC BY 4.0, https://db-ip.com)"
            import maxminddb

            with maxminddb.open_database(str(tmpdir / "new.mmdb")) as test:  # refuse a broken download
                test.metadata()
            global _reader, _reader_path
            with _lock:  # an open (memory-mapped) file cannot be replaced on Windows
                if _reader is not None:
                    _reader.close()
                _reader, _reader_path = None, None
            for old in GEOIP_DIR.glob("*.mmdb"):
                if old != target:
                    old.unlink()
            shutil.move(str(tmpdir / "new.mmdb"), target)
    finally:
        if own:
            client.close()
    return f"{label} saved as {target.name}"
