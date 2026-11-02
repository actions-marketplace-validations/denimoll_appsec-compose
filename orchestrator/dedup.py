"""Merge duplicate findings reported by multiple tools.

Operates only on our internal model (the raw native per-tool reports are left
untouched for ASPM import). Dedup key depends on category:

- secrets : same location (file, line) is the same secret, regardless of tool.
- sca     : same package@version + file, clustered by overlapping vuln IDs so
            that e.g. Trivy's CVE-2018-1000656 and Grype's GHSA-562c-5r94-xh97
            (whose relatedVulnerabilities lists that CVE) collapse into one.
- iac     : engines use different ids for the same policy, so findings whose
            rule maps to a known equivalence class merge per file; the rest
            fall back to the same rule at the same (file, line).
- sast    : same rule at the same (file, line).

A merged finding records every tool that reported it (provenance) plus the
union of equivalent IDs (aliases). Its severity is the highest among the tools
that actually assigned one — a score-derived severity never outranks a verdict,
for the same reason it does not inside a single report (see _tool_severity).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from normalize import Finding, _SEVERITY_RANK, _max_severity

# Cross-tool IaC rule equivalence. Trivy, Checkov and Hadolint each use their
# own id for the same Dockerfile policy, so keying on the rule id alone leaves
# obvious duplicates in the report. Ids below were confirmed against the
# engines' own output; anything unmapped keeps its (rule, file, line) identity.
_IAC_EQUIVALENCE = {
    "docker.latest-tag":        ["DS-0001", "CKV_DOCKER_7", "DL3007", "DL3006"],
    "docker.root-user":         ["DS-0002", "CKV_DOCKER_3", "CKV_DOCKER_8", "DL3002"],
    "docker.ssh-port":          ["DS-0004", "CKV_DOCKER_1"],
    "docker.add-instead-copy":  ["DS-0005", "CKV_DOCKER_4", "DL3020"],
    "docker.relative-workdir":  ["DS-0009", "CKV_DOCKER_10", "DL3000"],
    "docker.no-healthcheck":    ["DS-0026", "CKV_DOCKER_2"],
    "docker.apt-recommends":    ["DS-0029", "DL3015"],
}

_IAC_CLASS = {rule: cls for cls, rules in _IAC_EQUIVALENCE.items() for rule in rules}


def iac_class(rule_id: str) -> str | None:
    """Equivalence class for an IaC rule id, or None when it has no known peer."""
    return _IAC_CLASS.get((rule_id or "").upper())


@dataclass
class DedupStats:
    raw: int
    unique: int

    @property
    def removed(self) -> int:
        return self.raw - self.unique


def _norm_file(path: str) -> str:
    # Align paths across tools: some report relative ("app.py"), others report
    # the container mount ("/code/app.py"). /code is our fixed mount root.
    # Strip "./" and "/" as prefixes only: lstrip("./") would also eat the dot
    # of ".github/" and point at a file that does not exist.
    p = path or ""
    while p.startswith(("./", "/")):
        p = p[2:] if p.startswith("./") else p[1:]
    if p.startswith("code/"):
        p = p[len("code/"):]
    return p


def _id_tokens(f: Finding) -> set[str]:
    return {f.rule_id.upper()} | {a.upper() for a in f.aliases}


def _merge_group(group: list[Finding]) -> Finding:
    # Engines that stated a severity themselves decide it. OSV-Scanner reports
    # no verdict, so its CVSS-derived level would otherwise override Trivy and
    # Grype whenever an advisory's raw score disagrees with its own rating —
    # re-inflating exactly what reading the verdict was meant to fix.
    verdicts = [f for f in group if f.severity_stated]
    ranked = verdicts or group

    rep = max(ranked, key=lambda f: _SEVERITY_RANK[f.severity])
    tools = sorted({t for f in group for t in f.tools})
    ids = sorted({t for f in group for t in _id_tokens(f)})

    severity = "info"
    for f in ranked:
        severity = _max_severity(severity, f.severity)

    # Prefer a CVE id as the canonical rule_id for readability/ASPM matching.
    rule_id = next((i for i in ids if i.startswith("CVE-")), rep.rule_id)
    aliases = [i for i in ids if i != rule_id.upper()]

    description = next((f.description for f in group if f.description), "")
    url = next((f.url for f in group if f.url), "")
    fixed_version = next((f.fixed_version for f in group if f.fixed_version), "")
    cwe = sorted({c for f in group for c in f.cwe}, key=lambda c: int(c[4:]))
    # Columns locate a secret's span on the line; TruffleHog reports none, so
    # borrow them from an engine that flagged the same line.
    span = next((f for f in [rep, *group]
                 if f.column is not None and f.line == rep.line), rep)

    return Finding(
        tool=rep.tool, category=rep.category, rule_id=rule_id, severity=severity,
        message=rep.message, file=rep.file, line=rep.line, package=rep.package,
        aliases=aliases, tools=tools, description=description, url=url,
        severity_stated=bool(verdicts), end_line=span.end_line,
        column=span.column, end_column=span.end_column, cwe=cwe,
        fixed_version=fixed_version,
    )


def _cluster_sca(findings: list[Finding]) -> list[list[Finding]]:
    """Union-find within each (package, file) bucket, joined by shared vuln IDs."""
    buckets: dict[tuple, list[Finding]] = {}
    for f in findings:
        key = (f.package or f.rule_id, _norm_file(os.path.basename(f.file)))
        buckets.setdefault(key, []).append(f)

    groups: list[list[Finding]] = []
    for bucket in buckets.values():
        parent = list(range(len(bucket)))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            parent[find(a)] = find(b)

        token_owner: dict[str, int] = {}
        for i, f in enumerate(bucket):
            for tok in _id_tokens(f):
                if tok in token_owner:
                    union(i, token_owner[tok])
                else:
                    token_owner[tok] = i

        clusters: dict[int, list[Finding]] = {}
        for i, f in enumerate(bucket):
            clusters.setdefault(find(i), []).append(f)
        groups.extend(clusters.values())
    return groups


def merge(findings: list[Finding], enabled: bool = True) -> tuple[list[Finding], DedupStats]:
    raw = len(findings)
    if not enabled:
        return list(findings), DedupStats(raw=raw, unique=raw)

    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    groups: list[list[Finding]] = []
    for category, items in by_cat.items():
        if category == "sca":
            groups.extend(_cluster_sca(items))
        else:
            keyed: dict[tuple, list[Finding]] = {}
            for f in items:
                if category == "secrets":
                    sig = (_norm_file(f.file), f.line)
                elif category == "iac" and iac_class(f.rule_id):
                    # Engines flag the same policy on different lines of a file
                    # (the FROM line vs. line 1), so equivalence merges per file.
                    sig = (iac_class(f.rule_id), _norm_file(f.file), None)
                else:
                    sig = (f.rule_id, _norm_file(f.file), f.line)
                keyed.setdefault(sig, []).append(f)
            groups.extend(keyed.values())

    merged = [_merge_group(g) for g in groups]
    merged.sort(key=lambda f: (-_SEVERITY_RANK[f.severity], f.category, f.tools))
    return merged, DedupStats(raw=raw, unique=len(merged))
