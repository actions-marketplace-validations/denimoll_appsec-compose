"""Baseline / delta support: gate only on findings new since an accepted run.

A baseline is a set of finding fingerprints stored in a JSON file the user
commits as their accepted state. On a scan we classify each current finding as
`new` (not in the baseline) or `known`, and report baseline entries no longer
seen as `fixed`. When baseline mode is on, the policy gate applies to `new`
findings only.

Fingerprints identify a finding by what it is, not where it happens to sit:
the code on its line rather than the line number, so adding a line above a
known finding does not turn it into a new one and fail the build. Version 1
hashed the line number; a v1 baseline is still honoured (matched with the v1
scheme) until it is re-snapshotted with --update-baseline.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from dedup import _norm_file, iac_class
from normalize import Finding

FINGERPRINT_VERSION = 2

# Files larger than this are not read for line content; their findings fall
# back to the line number. Generated bundles are not worth the memory.
_MAX_FILE_BYTES = 5 * 1024 * 1024

# Secret material must never reach a fingerprint: findings.json and the baseline
# travel further than the repo (ASPM uploads, CI artifacts), and a hash of a
# short password is a dictionary lookup away from the password itself.
_QUOTED = re.compile(r"""(["'`]).*?\1""")
_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-.:@]{8,}")


def _legacy_norm_file(path: str) -> str:
    # v1 hashed paths as _norm_file shaped them then, dot of ".github" lost.
    p = (path or "").lstrip("./").lstrip("/")
    return p[len("code/"):] if p.startswith("code/") else p


def legacy_fingerprint(f: Finding) -> str:
    """The v1 fingerprint, kept to read baselines written before v2."""
    parts = [f.category, f.rule_id, _legacy_norm_file(f.file), f.package or "",
             str(f.line) if f.line is not None else ""]
    # An identity from old baseline files, not a security control; v1 is sha1.
    return hashlib.sha1(  # nosemgrep: insecure-hash-algorithm-sha1
        "|".join(parts).encode(), usedforsecurity=False).hexdigest()


def _vuln_key(f: Finding) -> str:
    """One id for a vulnerability whichever engines (and alias sets) saw it."""
    ids = sorted({f.rule_id.upper(), *(a.upper() for a in f.aliases)})
    return next((i for i in ids if i.startswith("CVE-")), ids[0])


def _package_name(package: str | None) -> str:
    """name@version -> name. A version bump that is still vulnerable is the
    same accepted risk, not a new one. Scoped npm names keep their @scope."""
    if not package:
        return ""
    name, sep, _ = package.rpartition("@")
    return name if sep and name else package


class _Source:
    """Reads lines of the scanned repo, confined to its root."""

    def __init__(self, root: str | None):
        self.root = os.path.realpath(root) if root else None
        self._cache: dict[str, list[str] | None] = {}

    def line(self, path: str, line: int | None) -> str | None:
        if not self.root or not path or not line or line < 1:
            return None
        if path not in self._cache:
            self._cache[path] = self._read(path)
        lines = self._cache[path]
        if lines is None or line > len(lines):
            return None
        return lines[line - 1]

    def _read(self, path: str) -> list[str] | None:
        full = os.path.realpath(os.path.join(self.root, _norm_file(path)))
        # A symlink in the scanned repo must not reach outside it.
        if not full.startswith(self.root + os.sep):
            return None
        try:
            if os.path.getsize(full) > _MAX_FILE_BYTES:
                return None
            with open(full, encoding="utf-8", errors="replace") as fh:
                return fh.read().splitlines()
        except OSError:
            return None


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _mask_secret(f: Finding, text: str) -> str:
    if f.column and f.column >= 1:
        start = f.column - 1
        end = (f.end_column - 1 if f.end_column and f.end_line in (None, f.line)
               else len(text))
        text = text[:start] + "*" + text[max(end, start):]
    # Masked whether or not the engine gave a span: TruffleHog reports none,
    # and a span is not guaranteed to cover every copy on the line.
    return _TOKEN.sub("*", _QUOTED.sub("*", text))


def _identity(f: Finding, source: _Source) -> list[str]:
    path = _norm_file(f.file)
    if f.category == "sca":
        return ["sca", _vuln_key(f), _package_name(f.package), path]
    cls = iac_class(f.rule_id) if f.category == "iac" else None
    if cls:
        # Equivalent IaC policies merge per file (engines disagree on the
        # line), so the line plays no part in their identity either.
        return ["iac", cls, path]

    text = source.line(f.file, f.line)
    if text is None:
        anchor = f"L{f.line}" if f.line is not None else ""
    else:
        anchor = _normalize(_mask_secret(f, text) if f.category == "secrets"
                            else text)
    # Secrets merge across engines by location, so the engine's rule id is
    # not part of what makes one secret the same secret.
    rule = "" if f.category == "secrets" else f.rule_id
    return [f.category, rule, path, anchor]


def assign(findings: list[Finding], code_dir: str | None = None) -> None:
    """Set `fingerprint` on every finding.

    Identical code can legitimately trigger the same rule more than once in a
    file; such repeats are told apart by their order of appearance, which
    survives lines being added or removed elsewhere.
    """
    source = _Source(code_dir)
    seen: dict[str, int] = {}
    for f in sorted(findings, key=lambda f: (_norm_file(f.file), f.line or 0)):
        key = "|".join(_identity(f, source))
        n = seen.get(key, 0)
        seen[key] = n + 1
        if n:
            key += f"|#{n}"
        f.fingerprint = hashlib.sha256(
            f"v{FINGERPRINT_VERSION}|{key}".encode()).hexdigest()[:40]


@dataclass
class Baseline:
    fingerprints: set[str]
    version: int = FINGERPRINT_VERSION

    @property
    def legacy(self) -> bool:
        return self.version < FINGERPRINT_VERSION and bool(self.fingerprints)


@dataclass
class Delta:
    new: list[Finding]
    known: list[Finding]
    fixed: int           # baseline fingerprints not seen in this run
    legacy: bool = False  # matched against a v1 baseline


def load(path: str) -> Baseline:
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return Baseline(set())
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError:
        return Baseline(set())
    # A file without a version predates v2.
    return Baseline(set(data.get("fingerprints", [])),
                    int(data.get("version", 1)))


def classify(findings: list[Finding], baseline: Baseline) -> Delta:
    key = legacy_fingerprint if baseline.legacy else (lambda f: f.fingerprint)
    new, known, seen = [], [], set()
    for f in findings:
        fp = key(f)
        seen.add(fp)
        (known if fp in baseline.fingerprints else new).append(f)
    fixed = len(baseline.fingerprints - seen)
    return Delta(new=new, known=known, fixed=fixed, legacy=baseline.legacy)


def save(path: str, findings: list[Finding]) -> int:
    fps = sorted({f.fingerprint for f in findings})
    Path(path).write_text(json.dumps({
        "version": FINGERPRINT_VERSION,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "fingerprints": fps,
    }, indent=2))
    return len(fps)
