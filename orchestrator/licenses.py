"""Dependency license policy (opt-in `licenses:` in scan-config.yml).

Trivy's license scanner runs on the same target as its vulnerability scan and
writes trivy-license.json (`--list-all-pkgs`, so every package arrives with its
name, version, declared licenses and lockfile line). This module turns the
packages whose license the policy denies into ordinary SCA findings
(`rule_id` LICENSE:<license>), so the existing gate, suppressions and baseline
apply to them unchanged.

The decision is ours, not Trivy's: Trivy also classifies each license
(forbidden/restricted/notice) with severities of its own, which encode
Google's policy rather than this project's, so they are ignored.

Where the data comes from matters, and it is uneven. Measured with Trivy 0.74:
npm lockfiles (v2+), composer.lock and installed packages (node_modules,
site-packages) carry licenses; Maven poms get them only online, from the
remote pom; requirements.txt, poetry/uv lockfiles, go.mod and Cargo.lock carry
none. Packages without license data are counted, never silently passed.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

from normalize import Finding

REPORT = "trivy-license.json"
DEFAULT_SEVERITY = "high"
WARN_SEVERITY = "info"

# A plain SPDX id also covers its -only / -or-later / + spellings: Trivy
# normalises "GPL-3.0" to "GPL-3.0-only" and "GPL-3.0+" to "GPL-3.0-or-later",
# and a `deny: [GPL-3.0]` that silently missed both would be worse than none.
_SUFFIXES = ("", "-only", "-or-later", "+")


@dataclass
class Policy:
    deny: list[str] = field(default_factory=list)
    warn: list[str] = field(default_factory=list)
    severity: str = DEFAULT_SEVERITY

    @property
    def active(self) -> bool:
        return bool(self.deny or self.warn)


@dataclass
class Stats:
    packages: int = 0
    unlicensed: int = 0
    unlicensed_ecosystems: list[str] = field(default_factory=list)
    denied: int = 0
    warned: int = 0


def policy_from(raw: dict) -> Policy:
    block = raw.get("licenses") or {}
    return Policy(deny=[str(p) for p in block.get("deny") or []],
                  warn=[str(p) for p in block.get("warn") or []],
                  severity=str(block.get("severity", DEFAULT_SEVERITY)).lower())


def _matches(term: str, patterns: list[str]) -> str | None:
    """The pattern that matches one license term (case-insensitive), if any."""
    t = term.strip().upper()
    for pattern in patterns:
        p = pattern.strip().upper()
        if any(c in p for c in "*?["):
            if fnmatchcase(t, p):
                return pattern
        elif t in {p + s.upper() for s in _SUFFIXES}:
            return pattern
    return None


# --- SPDX expressions: OR < AND < WITH, parentheses -------------------------

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def _parse(tokens: list[str]):
    def expr(i):                     # or-expr
        node, i = term(i)
        alts = [node]
        while i < len(tokens) and tokens[i].upper() == "OR":
            node, i = term(i + 1)
            alts.append(node)
        return (("or", alts) if len(alts) > 1 else alts[0]), i

    def term(i):                     # and-expr
        node, i = atom(i)
        parts = [node]
        while i < len(tokens) and tokens[i].upper() == "AND":
            node, i = atom(i + 1)
            parts.append(node)
        return (("and", parts) if len(parts) > 1 else parts[0]), i

    def atom(i):
        if i < len(tokens) and tokens[i] == "(":
            node, i = expr(i + 1)
            return node, (i + 1 if i < len(tokens) and tokens[i] == ")" else i)
        words = []
        while i < len(tokens) and tokens[i] not in ("(", ")") \
                and tokens[i].upper() not in ("AND", "OR"):
            words.append(tokens[i])
            i += 1
        # "GPL-2.0-only WITH Classpath-exception-2.0" stays one term, as does
        # free text Trivy could not map ("SEE LICENSE IN LICENSE.md").
        return ("id", " ".join(words)), i

    node, _ = expr(0)
    return node


def _hit(node, patterns: list[str]) -> str | None:
    """The matching pattern when the expression cannot be satisfied without a
    listed license: every OR alternative must hit, any AND part suffices."""
    kind, value = node
    if kind == "id":
        return _matches(value, patterns) if value else None
    hits = [_hit(child, patterns) for child in value]
    if kind == "or":
        return hits[0] if all(hits) else None
    return next((h for h in hits if h), None)


def verdict(licenses: list[str], patterns: list[str]) -> str | None:
    """Whether a package's declared licenses are all caught by `patterns`.

    Several entries for one package are alternatives (composer's license
    array is disjunctive; so, in practice, are multiple Maven <license>s): a
    package offered under MIT *or* GPL-3.0 is not a GPL dependency.
    """
    if not licenses or not patterns:
        return None
    tree = ("or", [_parse(_TOKEN.findall(l)) for l in licenses]) if len(licenses) > 1 \
        else _parse(_TOKEN.findall(licenses[0]))
    return _hit(tree, patterns)


def _rule(licenses: list[str]) -> str:
    text = " OR ".join(l.strip() for l in licenses)
    if text.startswith("(") and text.endswith(")") and len(licenses) == 1:
        text = text[1:-1]
    return f"LICENSE:{text}"


def evaluate(path: Path, policy: Policy) -> tuple[list[Finding], Stats]:
    """Findings for every package the policy denies or warns about.

    Raises ValueError when the report is unreadable, like the SARIF parsers.
    """
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name}: unreadable Trivy license report ({exc})") from exc

    stats, findings = Stats(), []
    unlicensed: Counter = Counter()
    for result in data.get("Results") or []:
        # Application dependencies only: an image's OS packages (glibc, bash)
        # are mostly GPL by design and are not what a dependency policy means.
        if result.get("Class") != "lang-pkgs":
            continue
        target = result.get("Target", "")
        for pkg in result.get("Packages") or []:
            name, version = pkg.get("Name", ""), pkg.get("Version", "")
            if not name or not version:
                continue                  # the project's own root entry
            stats.packages += 1
            licenses = [str(l) for l in pkg.get("Licenses") or [] if str(l).strip()]
            if not licenses:
                stats.unlicensed += 1
                unlicensed[result.get("Type", "unknown")] += 1
                continue
            denied = verdict(licenses, policy.deny)
            warned = None if denied else verdict(licenses, policy.warn)
            if not (denied or warned):
                continue
            pattern = denied or warned
            listed = "licenses.deny" if denied else "licenses.warn"
            stats.denied += bool(denied)
            stats.warned += bool(warned)
            locations = pkg.get("Locations") or []
            line = locations[0].get("StartLine") if locations else None
            single = licenses[0] if len(licenses) == 1 else ""
            findings.append(Finding(
                tool="trivy", category="sca", rule_id=_rule(licenses),
                severity=policy.severity if denied else WARN_SEVERITY,
                message=(f"{name}@{version} is licensed {' OR '.join(licenses)}, "
                         f"which matches `{pattern}` in {listed}"),
                file=pkg.get("FilePath") or target, line=line,
                end_line=locations[0].get("EndLine") if locations else None,
                package=f"{name}@{version}",
                description=f"Dependency license policy ({listed} in scan-config.yml).",
                url=(f"https://spdx.org/licenses/{single}.html"
                     if re.fullmatch(r"[A-Za-z0-9.+-]+", single) else ""),
                # A policy decision, not a score: nothing should outrank it.
                severity_stated=True,
            ))
    stats.unlicensed_ecosystems = sorted(unlicensed)
    return findings, stats
