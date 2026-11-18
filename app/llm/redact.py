"""Personal data out of AI prompts (PM review 2026-11, item 14; UU PDP data minimisation).

Item text can carry scammers' and victims' phone numbers, bank accounts, e-wallets, e-mail addresses and ID numbers.
Before a prompt goes to a cloud model, ``redact()`` replaces each of them with a placeholder that stays the same
for the same value inside one prompt (``[phone 1]``, ``[account 2]``…), so the model can still tell them apart.
Crypto wallets, IPs, domains and hashes stay: they are indicators the analysis needs, not people.

Setting ``llm_redact``: ``cloud`` (default) redacts when the model runs outside this network, ``always`` and
``never`` do what they say. Whether a model is "cloud" is decided by ``is_cloud()``.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .. import settings
from ..processing.fraud import RE_ACCOUNT, RE_PHONE

RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")
# 10 to 18 digits in one run: NIK (16), card numbers, account numbers written without a cue. Amounts are written
# with separators ("Rp 1.500.000") and stay; IPs, versions and CVE ids have dots or dashes.
RE_LONG_NUMBER = re.compile(r"(?<![\w.,/-])\d{10,18}(?![\w/-]|[.,]\d)")
LOCAL_SUFFIXES = (".local", ".lan", ".internal", ".home", ".localdomain")


def is_cloud() -> bool:
    """True when prompts leave this machine / network: Anthropic, or an OpenAI-compatible / Ollama server on a
    public host name. Loopback, private addresses and single-label or .local / .internal names are local."""
    from . import client

    p = client.provider()
    if p == "none":
        return False
    if p == "anthropic":
        return True
    host = (urlsplit(str(settings.get("llm_base_url") or "")).hostname or "").lower()
    if not host or host == "localhost" or "." not in host or host.endswith(LOCAL_SUFFIXES):
        return False
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return True  # a public host name: OpenRouter, Groq, a hosted vLLM…


def enabled() -> bool:
    mode = str(settings.get("llm_redact") or "cloud")
    return mode == "always" or (mode == "cloud" and is_cloud())


class Redactor:
    """Replaces personal data across several texts of one prompt, with one placeholder per distinct value."""

    def __init__(self):
        self.seen: dict[tuple[str, str], str] = {}
        self.count = 0

    def _tag(self, kind: str, value: str) -> str:
        key = (kind, re.sub(r"\D", "", value) if kind != "email" else value.lower())
        if key not in self.seen:
            n = sum(1 for k in self.seen if k[0] == kind) + 1
            self.seen[key] = f"[{kind} {n}]"
        self.count += 1
        return self.seen[key]

    def __call__(self, text: str) -> str:
        if not text:
            return text
        text = RE_EMAIL.sub(lambda m: self._tag("email", m.group(0)), text)
        # account numbers named as such ("rekening BCA 1234567890"): only the number goes
        text = RE_ACCOUNT.sub(lambda m: m.group(0)[:m.start("num") - m.start(0)] + self._tag("account", m.group("num")),
                              text)
        text = RE_PHONE.sub(lambda m: self._tag("phone", m.group(0)), text)
        return RE_LONG_NUMBER.sub(lambda m: self._tag("number", m.group(0)), text)


def redact(text: str) -> str:
    return Redactor()(text)
