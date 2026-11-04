"""Which report files the UI may serve, and the path resolution that keeps it to them.

An allowlist of names first: a report name has no separator, so nothing with `/`
or `..` in it even reaches the filesystem, and `native/` stays out altogether —
those are raw engine output for ASPM upload, and native/trufflehog.json holds the
secret values every other report masks. Then the filesystem: a symlink is refused
outright rather than followed and judged (a scanned repo must not be able to make
this server read outside the directory), and the opened file is re-checked with
O_NOFOLLOW in case one appears in between.

summary.html carries one inline script, its category filter. The CSP allows that
exact script by hash, taken from the template's source, and nothing else: a bug in
how a finding is escaped would still inject no running code. A sandbox on top gives
the page an opaque origin, so even that script cannot reach the UI.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import os
import re
import stat
from pathlib import Path

from .paths import ROOT, check_name, reports_dir

_NAMES = re.compile(r"summary\.html|summary\.md|review-brief\.md|findings\.json"
                    r"|sbom\.[a-z0-9][a-z0-9.-]*\.json")
_LIST_ORDER = ["summary.html", "summary.md", "review-brief.md", "findings.json"]
_SCRIPT = re.compile(r"<script>(.*?)</script>", re.S)

TEXT_CSP = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox"


def content_type(filename: str) -> str:
    if filename.endswith(".html"):
        return "text/html; charset=utf-8"
    if filename.endswith(".json"):
        return "application/json"
    return "text/plain; charset=utf-8"   # markdown: shown, never interpreted


@functools.lru_cache(maxsize=1)
def summary_csp() -> str:
    source = (ROOT / "orchestrator" / "summary.py").read_text(encoding="utf-8")
    match = _SCRIPT.search(source)
    script = "'none'"
    if match:
        digest = hashlib.sha256(match.group(1).encode("utf-8")).digest()
        script = f"'sha256-{base64.b64encode(digest).decode()}'"
    return (f"default-src 'none'; script-src {script}; style-src 'unsafe-inline'; img-src data:; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox allow-scripts")


def csp_for(filename: str) -> str:
    return summary_csp() if filename.endswith(".html") else TEXT_CSP


def resolve_report(name: str, filename: str) -> Path | None:
    """The report's real path, or None for anything that is not a report of this project."""
    if not _NAMES.fullmatch(filename):
        return None
    base = reports_dir(check_name(name))
    candidate = base / filename
    try:
        if base.is_symlink() or candidate.is_symlink():
            return None
        real_base, real = base.resolve(strict=True), candidate.resolve(strict=True)
        if real.parent != real_base or not real.is_file():
            return None
    except (OSError, RuntimeError):   # RuntimeError: a symlink loop further up
        return None
    return real


def open_report(name: str, filename: str) -> tuple[int, int] | None:
    """(fd, size) of the report, opened without following a last-moment symlink."""
    path = resolve_report(name, filename)
    if path is None:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        return None
    return fd, info.st_size


def listed_reports(name: str) -> list[str]:
    base = reports_dir(name)
    found = [f for f in _LIST_ORDER if resolve_report(name, f)]
    try:
        found += sorted(f for f in os.listdir(base)
                        if f.startswith("sbom.") and resolve_report(name, f))
    except OSError:
        pass
    return found
