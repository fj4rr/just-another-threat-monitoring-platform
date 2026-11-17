"""Outbound HTTP for collectors, intel providers, the LLM client, MISP, GeoIP and webhooks (0.10.1).

Every request JATMP makes on its own goes through :func:`client` (audit 2026-11 S-3, S-4, S-12):

* **SSRF guard.** A request may only reach a public address. The check runs for every hop of a redirect chain,
  and the connection is made to the very address that was checked: the name is not looked up a second time, so a
  DNS-rebinding name cannot answer "public" to the check and "127.0.0.1" to the connect. Private, loopback and
  link-local targets (a local Ollama, an internal MISP, a self-hosted RSS-Bridge) need an entry in
  Settings → Sharing → "Private hosts JATMP may contact", or the switch that allows all of them.
* **Size cap.** Bodies are read in chunks *after* decompression and refused past ``max_bytes``, so neither a
  hostile feed nor a gzip bomb can fill the memory of a collector thread.

Behind an HTTP proxy from the environment (``HTTPS_PROXY``…) the connection goes to the proxy, so the address
check runs on the request URL before sending instead (the proxy does the final lookup).
"""
from __future__ import annotations

import ipaddress
import re
import socket
import urllib.request
from urllib.parse import urlsplit

import httpcore
import httpx

DEFAULT_MAX_BYTES = 20 * 1024 * 1024  # feeds, API answers; GeoIP downloads pass a larger cap
_SPLIT = re.compile(r"[\s,;]+")


class ResponseTooLarge(httpx.HTTPError):
    """The response body is larger than the cap for this client."""


# --------------------------------------------------------------------------- policy
def _setting(key: str, default=None):
    from . import settings

    try:
        return settings.get(key, default)
    except Exception:  # no database yet (install wizard, unit tests): nothing allowed beyond the defaults
        return default


def private_allowlist() -> tuple[set[str], list[ipaddress._BaseNetwork]]:
    """Host names and address ranges an admin allowed although they are private (Settings → Sharing)."""
    names: set[str] = set()
    nets: list[ipaddress._BaseNetwork] = []
    for tok in _SPLIT.split(str(_setting("outbound_private_hosts") or "")):
        tok = tok.strip().lower().strip("[]")
        if not tok:
            continue
        if "://" in tok:
            tok = urlsplit(tok).hostname or ""
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            if tok:
                names.add(tok.rstrip("."))
    return names, nets


class Policy:
    """Which addresses a client may connect to. ``allow_private``: None = the install's settings."""

    def __init__(self, allow_private: bool | None = None):
        self.allow_all = bool(_setting("outbound_allow_private")) if allow_private is None else allow_private
        self.names, self.nets = (set(), []) if self.allow_all else private_allowlist()

    def _ok(self, host: str, addr: ipaddress._BaseAddress) -> bool:
        if self.allow_all or addr.is_global:
            return True
        if host.lower().rstrip(".") in self.names:
            return True
        return any(addr in net for net in self.nets)

    def resolve(self, host: str, port: int) -> str:
        """The address to connect to for ``host``, after checking it; raises httpcore.ConnectError."""
        host = (host or "").strip("[]")
        try:
            addrs = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except (socket.gaierror, UnicodeError, OSError) as e:
                raise httpcore.ConnectError(f"cannot resolve {host}: {e}") from e
            addrs = [ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos]
        if not addrs:
            raise httpcore.ConnectError(f"cannot resolve {host}")
        for addr in addrs:
            if not self._ok(host, addr):
                raise httpcore.ConnectError(
                    f"blocked: {host} resolves to a private or local address ({addr}); an admin can allow it under "
                    "Settings → Sharing → Private hosts JATMP may contact")
        return str(addrs[0])

    def check_url(self, url: str) -> str | None:
        """Error message, or None when ``url`` may be fetched (scheme, credentials, address)."""
        try:
            parts = urlsplit((url or "").strip())
        except ValueError:
            return "not a valid URL"
        if parts.scheme not in ("https", "http"):
            return "the URL must start with https:// (or http://)"
        if not parts.hostname:
            return "the URL has no host"
        if parts.username or parts.password:
            return "credentials in the URL are not allowed"
        try:
            self.resolve(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
        except httpcore.ConnectError as e:
            return str(e)
        return None


class _GuardedBackend(httpcore.SyncBackend):
    """Resolves and checks the host itself, then connects to that address (TLS still uses the host name)."""

    def __init__(self, policy: Policy):
        self.policy = policy

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        addr = self.policy.resolve(host, port)
        return super().connect_tcp(addr, port, timeout=timeout, local_address=local_address,
                                   socket_options=socket_options)


def _env_proxied() -> bool:
    proxies = urllib.request.getproxies()
    return bool(proxies.get("http") or proxies.get("https") or proxies.get("all"))


# --------------------------------------------------------------------------- client
def _limit_hook(max_bytes: int):
    def hook(response: httpx.Response) -> None:
        length = response.headers.get("content-length", "")
        if length.isdigit() and int(length) > max_bytes:
            response.close()
            raise ResponseTooLarge(f"response from {response.request.url.host} is larger than "
                                   f"{max_bytes // (1024 * 1024)} MB")
        buf = bytearray()
        for chunk in response.iter_bytes():  # decompressed: a gzip bomb stops here too
            buf += chunk
            if len(buf) > max_bytes:
                response.close()
                raise ResponseTooLarge(f"response from {response.request.url.host} is larger than "
                                       f"{max_bytes // (1024 * 1024)} MB")
        response._content = bytes(buf)  # what Response.read() keeps; later reads return it

    return hook


def client(*, timeout: float = 30, headers: dict | None = None, follow_redirects: bool = True,
           max_bytes: int = DEFAULT_MAX_BYTES, verify=True, allow_private: bool | None = None) -> httpx.Client:
    """An httpx client with the SSRF guard and the size cap (see the module docstring)."""
    policy = Policy(allow_private)

    def check_request(request: httpx.Request) -> None:
        if request.url.scheme not in ("http", "https"):
            raise httpx.UnsupportedProtocol(f"refusing {request.url.scheme}:// URLs", request=request)
        if not pinned:
            try:
                policy.resolve(request.url.host, request.url.port or (443 if request.url.scheme == "https" else 80))
            except httpcore.ConnectError as e:
                raise httpx.ConnectError(str(e), request=request) from None

    hooks = {"request": [check_request], "response": [_limit_hook(max_bytes)]}
    common = {"timeout": timeout, "headers": headers or {}, "follow_redirects": follow_redirects,
              "event_hooks": hooks}
    pinned = False
    if not _env_proxied():
        transport = httpx.HTTPTransport(verify=verify)
        pool = getattr(transport, "_pool", None)
        if isinstance(pool, httpcore.ConnectionPool) and hasattr(pool, "_network_backend"):
            pool._network_backend = _GuardedBackend(policy)
            pinned = True
            return httpx.Client(transport=transport, **common)
    return httpx.Client(verify=verify, **common)


# --------------------------------------------------------------------------- upgrade helper
_LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".intranet", ".corp", ".localdomain", ".docker")


def _looks_private(host: str, resolve: bool) -> bool:
    host = host.strip("[]").lower()
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    if host == "localhost" or "." not in host or host.endswith(_LOCAL_SUFFIXES):
        return True
    if not resolve:
        return False
    try:
        return any(not ipaddress.ip_address(str(i[4][0]).split("%")[0]).is_global
                   for i in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM))
    except (socket.gaierror, UnicodeError, OSError, ValueError):
        return False


def seed_allowlist(db) -> list[str]:
    """Once, on the first start of 0.10.1: allow the private hosts an admin already configured (a local LLM, an
    internal MISP, a self-hosted RSS-Bridge, RSS feeds on the LAN), so the upgrade breaks nothing. New private
    targets need an explicit entry afterwards."""
    from sqlalchemy import select

    from . import settings
    from .models import Source

    if settings.get("netguard_seeded"):
        return []
    urls: list[tuple[str, bool]] = []
    provider = str(settings.get("llm_provider") or "none")
    if provider in ("ollama", "openai_compatible"):
        urls.append((str(settings.get("llm_base_url") or "http://localhost:11434"), True))
    for key in ("misp_url", "anyrun_api_base"):
        urls.append((str(settings.get(key) or ""), True))
    for (cfg,) in db.execute(select(Source.config)):
        for key in ("url", "rss_bridge"):
            urls.append((str((cfg or {}).get(key) or ""), False))  # no DNS for every feed: names and IPs only
    have = str(settings.get("outbound_private_hosts") or "")
    known = set(_SPLIT.split(have.lower()))
    added: list[str] = []
    for url, resolve in urls:
        host = (urlsplit(url).hostname or "") if url else ""
        if host and host not in known and _looks_private(host, resolve):
            known.add(host)
            added.append(host)
    if added:
        settings.set("outbound_private_hosts", ", ".join([h for h in (have,) if h.strip()] + added))
    settings.set("netguard_seeded", True)
    return added


def allow_host(url: str) -> str | None:
    """Add the host of ``url`` to the private host list (an admin just configured a local service there)."""
    from . import settings

    host = (urlsplit(url or "").hostname or "").lower()
    if not host or not _looks_private(host, resolve=True):
        return None
    have = str(settings.get("outbound_private_hosts") or "")
    if host in set(_SPLIT.split(have.lower())):
        return None
    settings.set("outbound_private_hosts", ", ".join([h for h in (have.strip(),) if h] + [host]))
    return host
