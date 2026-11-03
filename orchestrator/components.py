"""Vulnerable components: SCA findings grouped by the package they are in.

A dependency with nine CVEs is one thing to upgrade, not nine things to read.
Findings stay per vulnerability — that is what the gate, suppressions and the
baseline act on, and what ASPM imports — and this is the view on top: one
entry per package@version, with every vulnerability found in it.

`upgrade_to` answers what to upgrade to. Engines list a fix per maintained
branch ("2.9.10.8, 2.12.6.1, 2.13.2.1"), so the raw list is no answer, and
"the highest of each vulnerability's lowest fix" is wrong across branches: a
fix listed for 2.18 and 2.21 but not 2.20 leaves 2.20.x vulnerable. Instead,
`upgrade_to` is the lowest of all the named fixes that covers every
vulnerability, where a version covers one when its own branch (major.minor)
has a listed fix at or below it, or when it is above all of that
vulnerability's listed fixes. Only plain dotted numeric versions are compared
(1.2.3, v1.2.3, 2.9.10.8): a pre-release or distro version in the mix, or a
vulnerability with no fix, leaves `upgrade_to` empty rather than guessing,
and the per-vulnerability fixes are always listed alongside.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from dedup import _norm_file
from normalize import _SEVERITY_RANK, Finding

_ORDER = ["critical", "high", "medium", "low", "info"]
_NUMERIC = re.compile(r"^v?(\d+(?:\.\d+)*)$")


def _vkey(version: str) -> tuple[int, ...] | None:
    m = _NUMERIC.match(version.strip())
    return tuple(int(p) for p in m.group(1).split(".")) if m else None


def _fixes(f: Finding) -> list[str]:
    return [v.strip() for v in f.fixed_version.split(",") if v.strip()]


def _covers(version: tuple[int, ...], fixes: list[tuple[int, ...]]) -> bool:
    if version >= max(fixes):
        return True
    return any(f <= version and f[:2] == version[:2] for f in fixes)


def upgrade_target(installed: str, per_vuln_fixes: list[list[str]]) -> str | None:
    """The lowest named fix above `installed` that covers every vulnerability."""
    have = _vkey(installed)
    keyed = [[_vkey(v) for v in fixes] for fixes in per_vuln_fixes]
    if have is None or not keyed or any(not ks or None in ks for ks in keyed):
        return None
    names = {_vkey(v): v for fixes in per_vuln_fixes for v in fixes}
    for candidate in sorted(k for k in names if k > have):
        if all(_covers(candidate, ks) for ks in keyed):
            return names[candidate]
    return None


@dataclass
class Component:
    package: str                  # name@version, as the engines name it
    name: str
    version: str
    files: list[str] = field(default_factory=list)      # manifests declaring it
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return max((f.severity for f in self.findings),
                   key=lambda s: _SEVERITY_RANK.get(s, 0), default="info")

    @property
    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in _ORDER}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return {s: n for s, n in c.items() if n}

    @property
    def fixed_in(self) -> list[str]:
        """Every version an engine names as a fix, in first-seen order."""
        seen: list[str] = []
        for f in self.findings:
            for v in (x.strip() for x in f.fixed_version.split(",")):
                if v and v not in seen:
                    seen.append(v)
        return seen

    @property
    def upgrade_to(self) -> str | None:
        """The lowest version that fixes every vulnerability listed, if every
        one of them has a comparable fix; else None."""
        return upgrade_target(self.version, [_fixes(f) for f in self.findings])

    @property
    def unfixed(self) -> int:
        return sum(1 for f in self.findings if not f.fixed_version)

    @property
    def malicious(self) -> bool:
        return any(f.malicious for f in self.findings)

    @property
    def exploitable(self) -> bool:
        return any(f.exploitable or f.kev for f in self.findings)


def _split(package: str) -> tuple[str, str]:
    name, sep, version = package.rpartition("@")
    return (name, version) if sep and name else (package, "")


def group(findings: list[Finding]) -> list[Component]:
    """SCA findings by package, worst component first."""
    by_pkg: dict[str, Component] = {}
    for f in findings:
        if f.category != "sca":
            continue
        key = f.package or f.rule_id
        comp = by_pkg.get(key)
        if comp is None:
            name, version = _split(key)
            comp = by_pkg[key] = Component(key, name, version)
        comp.findings.append(f)
        path = _norm_file(f.file)
        if path and path not in comp.files:
            comp.files.append(path)
    for comp in by_pkg.values():
        comp.findings.sort(key=lambda f: (-_SEVERITY_RANK.get(f.severity, 0), f.rule_id))
    return sorted(by_pkg.values(), key=lambda c: (
        not c.malicious, -_SEVERITY_RANK.get(c.severity, 0), -len(c.findings), c.package))


def to_dict(comp: Component) -> dict:
    return {
        "package": comp.package, "name": comp.name, "version": comp.version,
        "files": comp.files, "severity": comp.severity, "counts": comp.counts,
        "vulnerabilities": len(comp.findings),
        "upgrade_to": comp.upgrade_to,
        "fixed_in": comp.fixed_in, "unfixed": comp.unfixed,
        "malicious": comp.malicious, "exploitable": comp.exploitable,
        "findings": [f.fingerprint for f in comp.findings],
    }
