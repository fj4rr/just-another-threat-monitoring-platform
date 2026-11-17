"""Brakes for manual actions that cost provider quota or worker time (audit 2026-11 S-7).

* :func:`check` – at most ``limit`` calls per ``window`` seconds per key (user + action), in memory.
* :func:`exclusive` – one run at a time per key (the same entity enriched twice in parallel only burns quota).
"""
from __future__ import annotations

import threading
import time
from collections import deque
from contextlib import contextmanager

from fastapi import HTTPException

_lock = threading.Lock()
_calls: dict[str, deque] = {}
_busy: set[str] = set()


def check(key: str, limit: int, window: int = 60) -> None:
    """Raise HTTP 429 once ``key`` was used ``limit`` times in the last ``window`` seconds."""
    now = time.monotonic()
    with _lock:
        q = _calls.setdefault(key, deque())
        while q and q[0] <= now - window:
            q.popleft()
        if len(q) >= limit:
            retry = max(1, int(q[0] + window - now) + 1)
            raise HTTPException(429, f"too many requests, try again in {retry} s", headers={"Retry-After": str(retry)})
        q.append(now)
        if len(_calls) > 10_000:  # bounded memory: forget idle keys
            for k in [k for k, v in _calls.items() if not v or v[-1] <= now - window]:
                _calls.pop(k, None)


@contextmanager
def exclusive(key: str, message: str = "this lookup is already running"):
    """Refuse a second concurrent run for ``key`` with HTTP 409."""
    with _lock:
        if key in _busy:
            raise HTTPException(409, message)
        _busy.add(key)
    try:
        yield
    finally:
        with _lock:
            _busy.discard(key)


def reset() -> None:
    """For tests."""
    with _lock:
        _calls.clear()
        _busy.clear()
