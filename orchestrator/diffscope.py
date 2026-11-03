"""Diff mode in the collector: report and gate on the change, nothing else.

run.sh --diff narrows the engines to the files a change touched
(scripts/diff-scope.py), and records what it decided in /diff/scope.json. The
engines still report outside that set in places — SCA runs over the whole repo
once a manifest changed, the IaC engines see the Terraform files beside a
changed one — so the collector applies the same scope to the findings.

Gating is per changed *file*, not per changed line. A change is often
dangerous through code it did not touch: a new call into an existing unsafe
function, a sanitizer removed above an unchanged sink, an IaC attribute whose
finding is reported on the resource's first line. Semgrep reports the sink, so
a line-level gate would pass exactly those. File-level gating catches them, at
the price of also surfacing pre-existing findings in a touched file; baseline
mode separates those, and every finding carries `on_changed_line` so a reviewer
can start with the lines the change wrote.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from dedup import _norm_file
from normalize import Finding

# The engine that walks the branch's commits as well as the changed files.
_HISTORY_TOOLS = {"gitleaks"}
HISTORY_REPORT = "gitleaks-history.sarif"


@dataclass
class DiffScope:
    base: str
    merge_base: str
    head: str
    files: list[str]
    new_files: list[str] = field(default_factory=list)
    changed_lines: dict = field(default_factory=dict)
    sca_dirs: list[str] = field(default_factory=list)
    iac_files: list[str] = field(default_factory=list)
    iac_context: list[str] = field(default_factory=list)
    commits: int = 0
    history_scanned: bool = False
    history_note: str = ""
    excluded: int = 0
    deleted: int = 0
    parts: dict = field(default_factory=dict)
    skipped_engines: dict = field(default_factory=dict)
    skipped_reports: dict = field(default_factory=dict)
    run_engines: list[str] = field(default_factory=list)
    dropped: int = 0                     # findings outside the scope, set by filter

    def __post_init__(self):
        self._files = set(self.files)
        self._new = set(self.new_files)
        self._sca_dirs = set(self.sca_dirs)

    @classmethod
    def load(cls, path: str) -> "DiffScope":
        data = json.loads(Path(path).read_text())
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})

    def skipped(self, part: str) -> bool:
        """True when the part (sast/secrets/sca/iac) had nothing to scan."""
        return not self.parts.get(part, True)

    def expected(self, expected: set[str]) -> set[str]:
        """The reports a diff run should produce, given those of a full one.

        A skipped engine leaves no report, by design — that must not read as
        a crashed one under `strict`.
        """
        out = expected - set(self.skipped_reports)
        if self.history_scanned and "gitleaks.sarif" in expected:
            out.add(HISTORY_REPORT)
        return out

    def in_scope(self, f: Finding) -> bool:
        path = _norm_file(f.file)
        if path in self._files:
            return True
        # A secret from the branch's commits is in the change by definition,
        # even when the file no longer differs (committed, then removed).
        if f.category == "secrets" and f.tool in _HISTORY_TOOLS and self.history_scanned:
            return True
        # A manifest and its lock file are one unit: a vulnerable package is
        # reported against the lock even when only the manifest was edited.
        if f.category == "sca" and f.package and os.path.dirname(path) in self._sca_dirs:
            return True
        return False

    def filter(self, findings: list[Finding]) -> list[Finding]:
        kept = [f for f in findings if self.in_scope(f)]
        self.dropped = len(findings) - len(kept)
        return kept

    def on_changed_line(self, f: Finding) -> bool | None:
        """Does the finding touch a line the change added or modified?

        None when the question has no answer: no line (a dependency), or a file
        that is not in the working-tree diff (a secret found only in history).
        """
        path = _norm_file(f.file)
        if path in self._new:
            return True
        if path not in self._files or not f.line:
            return None
        start, end = f.line, max(f.end_line or f.line, f.line)
        return any(lo <= end and start <= hi for lo, hi in self.changed_lines.get(path, []))

    def provenance(self) -> dict:
        return {
            "mode": "diff",
            "base": self.base,
            "merge_base": self.merge_base,
            "head": self.head,
            "files": len(self.files),
            "paths": list(self.files),
            "commits": self.commits,
            "history_scanned": self.history_scanned,
            "excluded": self.excluded,
            "deleted": self.deleted,
            "skipped_engines": dict(self.skipped_engines),
            "skipped_reports": dict(self.skipped_reports),
            "out_of_scope_dropped": self.dropped,
        }

    def label(self) -> str:
        """One line for the console and the summaries."""
        return (f"diff vs {self.base} (merge-base {self.merge_base[:12]}): "
                f"{len(self.files)} changed file(s), {self.commits} commit(s)")


FULL_SCOPE = {"mode": "full"}


def load(enabled: bool, path: str) -> DiffScope | None:
    """The run's diff scope, or None for a full scan."""
    if not enabled:
        return None
    return DiffScope.load(path)
