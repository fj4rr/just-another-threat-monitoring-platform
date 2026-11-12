"""Install-time configuration (data/config.json).

Runtime settings (API keys, LLM, collector options) live in the database and are
editable from the UI; this file only holds what must exist before the DB does.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Load a local .env (same keys as .env.example) before any env lookup. Real environment
# variables always win; python-dotenv is optional so a minimal install still works.
try:  # pragma: no cover - import guard
    from dotenv import load_dotenv

    load_dotenv(BASE_DIR / ".env", override=False)
except ImportError:  # pragma: no cover
    pass

DATA_DIR = Path(os.getenv("JATMP_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = DATA_DIR / "config.json"

DEFAULT_CONFIG = {
    "installed": False,
    "mode": "single",  # "single" | "multi"
    "app_name": "JATMP",
    "secret_key": "",
    "database_url": "",
}

_cache: dict | None = None
_lock = threading.Lock()


def load_config() -> dict:
    global _cache
    if _cache is not None:
        return _cache
    with _lock:
        if _cache is not None:
            return _cache
        cfg = dict(DEFAULT_CONFIG)
        if CONFIG_PATH.exists():
            try:
                cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                pass
        if not cfg.get("secret_key"):
            cfg["secret_key"] = secrets.token_urlsafe(48)
            _write(cfg)
        _cache = cfg
    return cfg


def _write(cfg: dict) -> None:
    """Atomic write; the file holds the session secret so keep it owner-readable."""
    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:  # pragma: no cover - Windows / exotic FS
        pass
    os.replace(tmp, CONFIG_PATH)


def save_config(cfg: dict) -> None:
    global _cache
    with _lock:
        _write(cfg)
        _cache = cfg


def database_url() -> str:
    env = os.getenv("JATMP_DATABASE_URL")
    if env:
        return env
    cfg_url = load_config().get("database_url")
    if cfg_url:
        return cfg_url
    return f"sqlite:///{(DATA_DIR / 'jatmp.db').as_posix()}"


def is_installed() -> bool:
    return bool(load_config().get("installed"))


def is_multi_user() -> bool:
    return load_config().get("mode") == "multi"


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")
