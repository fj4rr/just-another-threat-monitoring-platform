"""One-time setup token for the first-run wizard (audit 2026-11 S-8).

Before installation nobody can log in, so whoever opens the wizard first becomes the admin. From the machine
itself (loopback) that is the person installing it; from anywhere else (another host on the LAN, a Docker port
mapping) the wizard also asks for a token that only someone with access to the server's console or data
directory can read: it is printed to the log at start-up and stored in ``data/setup-token``. The file is removed
once the install is done.
"""
from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import secrets

from .config import DATA_DIR

log = logging.getLogger("jatmp")
TOKEN_PATH = DATA_DIR / "setup-token"


def token() -> str:
    """The current token, created on first use (shared by every worker process through the file)."""
    try:
        value = TOKEN_PATH.read_text(encoding="utf-8").strip()
        if len(value) >= 16:
            return value
    except OSError:
        pass
    value = secrets.token_urlsafe(18)
    TOKEN_PATH.write_text(value + "\n", encoding="utf-8")
    try:
        os.chmod(TOKEN_PATH, 0o600)
    except OSError:  # Windows: ACLs, not modes
        pass
    return value


def announce() -> None:
    log.warning("JATMP is not installed yet. Open /setup from this machine, or from elsewhere with the setup "
                "token %s (also in %s).", token(), TOKEN_PATH)


def required(request) -> bool:
    """A token is needed unless the browser runs on this machine."""
    host = (request.client.host if request.client else "") or ""
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host != "testclient"  # Starlette's TestClient


def valid(value: str) -> bool:
    return bool(value) and hmac.compare_digest(value.strip().encode(), token().encode())


def discard() -> None:
    try:
        TOKEN_PATH.unlink()
    except OSError:
        pass
