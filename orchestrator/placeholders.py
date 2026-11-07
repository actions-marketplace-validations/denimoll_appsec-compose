"""Secret findings whose value is a placeholder, not a credential.

`ghp_` followed by 36 x's matches GitHub's token format exactly, so a format
rule cannot tell it from a real token — but no issuer ever minted it. Such a
finding is moved to the suppressed list with its reason, where a reviewer can
still see it, rather than gating the run or costing a triage.

Deliberately narrow: only values that are one character repeated (after the
token's prefix) or spelled as a placeholder. A real credential is random, so
it never looks like either; anything less certain stays a finding.
"""
from __future__ import annotations

import re

from baseline import _Source
from normalize import Finding

REASON = "placeholder value, not a credential (detected by appsec-compose)"

_QUOTED = re.compile(r"""(["'`])(.*?)\1""")
# A token's vendor prefix: ghp_, sk-, xoxb-, AKIA..., glpat-, ...
_PREFIX = re.compile(r"^[A-Za-z]{1,8}[_-]")
_WORDS = re.compile(r"(?i)(your[_-]?[a-z_-]*(key|token|secret|password)|changeme|placeholder"
                    r"|replace[_-]?me|<[^>]+>|\$\{[^}]+\}|x{8,}|\*{8,})")
_MIN_LEN = 8


def _is_placeholder(value: str) -> bool:
    value = value.strip()
    if len(value) < _MIN_LEN:
        return False
    body = _PREFIX.sub("", value, count=1)
    if len(body) >= _MIN_LEN and len(set(body)) == 1:
        return True
    return bool(_WORDS.search(value))


def _candidates(f: Finding, text: str) -> list[str]:
    """The value the engine pointed at, or every quoted string on the line."""
    if f.column and f.end_column and f.end_line in (None, f.line) and f.end_column > f.column:
        span = text[f.column - 1:f.end_column - 1]
        quoted = [m.group(2) for m in _QUOTED.finditer(span)]
        # A span over `KEY = 'value'` holds the value in quotes; else it is the value.
        span_value = quoted[-1] if quoted else span.split("=")[-1].split(":")[-1]
        return [span_value]
    return [m.group(2) for m in _QUOTED.finditer(text)]


def split(findings: list[Finding], code_dir: str | None) -> tuple[list[Finding], list[Finding]]:
    """(kept, placeholders). Without the code (an image scan) nothing moves."""
    if not code_dir:
        return findings, []
    source = _Source(code_dir)
    kept, placeholders = [], []
    for f in findings:
        text = source.line(f.file, f.line) if f.category == "secrets" else None
        values = [v for v in _candidates(f, text) if len(v.strip()) >= _MIN_LEN] if text else []
        # Every candidate must be a placeholder: a line holding a real key
        # next to a dummy one keeps its finding.
        if values and all(_is_placeholder(v) for v in values):
            placeholders.append(f)
        else:
            kept.append(f)
    return kept, placeholders
