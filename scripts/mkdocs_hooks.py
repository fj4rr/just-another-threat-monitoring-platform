"""MkDocs hooks: the Markdown under docs/ stays readable on GitHub, and the same files build the docs site.

* The root ``CHANGELOG.md`` becomes the site's ``changelog.md`` page (one source of truth, no copy in docs/).
* Links that only make sense on GitHub are rewritten: ``../CHANGELOG.md`` -> ``changelog.md``,
  ``../README.md`` -> the repository, ``docs/x.md`` (inside the changelog) -> ``x.md``.
* The "← Documentation index" / "← Project README" back links are dropped; the site has its own navigation.
"""
from __future__ import annotations

import re
from pathlib import Path

from mkdocs.structure.files import File

ROOT = Path(__file__).resolve().parent.parent
BACK_LINK = re.compile(r"^\[← [^\]]*\]\([^)]*\)\s*\n+", re.M)


def on_files(files, config):
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    files.append(File.generated(config, "changelog.md", content=text))
    return files


def on_page_markdown(markdown: str, page, config, files) -> str:
    repo = (config.get("repo_url") or "").rstrip("/")
    markdown = BACK_LINK.sub("", markdown)
    markdown = markdown.replace("](../CHANGELOG.md", "](changelog.md")
    markdown = markdown.replace("](../README.md)", f"]({repo}#readme)" if repo else "](README.md)")
    if page.file.src_uri == "changelog.md":
        markdown = re.sub(r"\]\(docs/([^)]+)\)", r"](\1)", markdown)
    return markdown
