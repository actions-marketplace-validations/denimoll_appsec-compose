"""Detect SCA blind spots — an engine that ran cleanly and saw nothing.

The policy gate only reasons about findings, so a dependency scanner that
parsed nothing at all looks exactly like a project with no vulnerabilities.
That is the most dangerous failure mode we have: a green build that never
inspected a single dependency.

We can prove the blind spot rather than guess at it: if the repo has dependency
manifests but the generated SBOM has no components, no engine resolved them.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

# Manifest/lock filenames per ecosystem. Lock files are listed separately
# because their presence means versions ARE resolvable.
_MANIFESTS = {
    "python": ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py"],
    "node": ["package.json"],
    "go": ["go.mod"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "ruby": ["Gemfile"],
    "php": ["composer.json"],
    "rust": ["Cargo.toml"],
    "dotnet": [],           # matched by suffix below
}
_MANIFEST_SUFFIXES = {".csproj": "dotnet"}

_LOCKFILES = {
    "requirements.lock", "poetry.lock", "Pipfile.lock", "uv.lock",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum",
    "Gemfile.lock", "composer.lock", "Cargo.lock",
}

# A requirements.txt line pins an exact version only with `==` or `@`.
_REQ_LINE = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(?P<op>[<>=!~]+|@)?")

_MAX_WALK = 20_000


@dataclass
class CoverageWarning:
    kind: str        # short machine-readable id
    message: str     # what we observed
    advice: str      # what to do about it


@dataclass
class Coverage:
    manifests: list[str]          # repo-relative manifest paths we found
    ecosystems: list[str]
    sbom_components: int | None   # None => no SBOM was generated
    warnings: list[CoverageWarning]


def _walk_manifests(code_dir: Path, excludes: set[str]) -> tuple[list[str], set[str], bool]:
    """Find dependency manifests, their ecosystems, and whether a lock file exists."""
    manifests: list[str] = []
    ecosystems: set[str] = set()
    has_lock = False
    by_name = {name: eco for eco, names in _MANIFESTS.items() for name in names}
    scanned = 0

    for root, dirs, files in os.walk(code_dir):
        dirs[:] = [d for d in dirs if d not in excludes and not d.startswith(".")]
        for filename in files:
            scanned += 1
            eco = by_name.get(filename) or _MANIFEST_SUFFIXES.get(Path(filename).suffix)
            if eco:
                rel = os.path.relpath(os.path.join(root, filename), code_dir)
                manifests.append(rel)
                ecosystems.add(eco)
            if filename in _LOCKFILES:
                has_lock = True
        if scanned > _MAX_WALK:
            break
    return manifests, ecosystems, has_lock


def _sbom_components(reports_dir: Path) -> int | None:
    """Total components across every generated SBOM, or None if there is none."""
    total = None
    for path in sorted(reports_dir.glob("sbom.*.json")):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        count = _count_components(data)
        total = count if total is None else max(total, count)
    return total


def _count_components(data: dict) -> int:
    """Real dependency count, excluding the SBOM's own root component.

    CycloneDX keeps the scanned artefact in `metadata.component`, but SPDX lists
    it among `packages` — so an empty SPDX SBOM still reports one package and
    would mask exactly the blind spot we are looking for.
    """
    if "components" in data:
        return len(data.get("components") or [])
    packages = data.get("packages") or []
    roots = set(data.get("documentDescribes") or [])
    roots.update(rel.get("relatedSpdxElement") for rel in (data.get("relationships") or [])
                 if rel.get("relationshipType") == "DESCRIBES")
    return sum(1 for p in packages if p.get("SPDXID") not in roots)


def _unpinned_requirements(code_dir: Path, manifests: list[str]) -> list[str]:
    """requirements.txt files that specify ranges instead of exact versions.

    Trivy and Syft resolve a package only from an exact version, so a file of
    `pkg>=1.2` lines yields no components at all.
    """
    offenders = []
    for rel in manifests:
        if Path(rel).name != "requirements.txt":
            continue
        try:
            lines = (code_dir / rel).read_text(errors="replace").splitlines()
        except OSError:
            continue
        pinned = ranged = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            match = _REQ_LINE.match(line)
            if not match:
                continue
            op = match.group("op") or ""
            if op in ("==", "@"):
                pinned += 1
            else:
                ranged += 1
        if ranged and not pinned:
            offenders.append(rel)
    return offenders


def analyse(code_dir: str, reports_dir: str, enabled: set[str],
            excludes: set[str], image_mode: bool = False,
            sca_findings: int = 0) -> Coverage:
    """Compare what the repo declares against what the SCA engines resolved.

    `sca_findings` is proof of the opposite: an engine that reported a
    vulnerable dependency clearly resolved the manifests, whatever the SBOM
    says — OSV reports on version ranges that Trivy and Syft cannot express as
    SBOM components, so the SBOM alone would raise a false alarm there.
    """
    sca_engines = {"trivy", "grype", "osv"} & enabled
    code = Path(code_dir)
    if image_mode or not sca_engines or not code.is_dir():
        return Coverage([], [], None, [])

    # The manifests are listed whatever happens next — a report that found
    # vulnerable dependencies must still say where it looked.
    manifests, ecosystems, has_lock = _walk_manifests(code, excludes)
    components = _sbom_components(Path(reports_dir))
    warnings: list[CoverageWarning] = []

    if manifests and components == 0 and not sca_findings:
        # Only recommend an engine the user hasn't already turned on.
        spare = [name for name in ("osv", "grype") if name not in enabled]
        suggestion = (f"enable the `{spare[0]}` scanner" if spare
                      else "check the enabled SCA engines' logs")
        unpinned = _unpinned_requirements(code, manifests)
        if unpinned:
            # Only OSV resolves ranges; Grype shares Syft's exact-version
            # requirement, so suggesting it here would be useless advice.
            resolver = (", or enable the `osv` scanner, which resolves ranges"
                        if "osv" not in enabled else "")
            warnings.append(CoverageWarning(
                kind="sca-unpinned-requirements",
                message=(f"{', '.join(sorted(unpinned))} specifies version ranges, "
                         f"not exact versions — Trivy and Syft resolve a package "
                         f"only from an exact version, so nothing was scanned."),
                advice=(f"Pin the versions (`pkg==1.2.3`), commit a lock file"
                        f"{resolver}."),
            ))
        else:
            warnings.append(CoverageWarning(
                kind="sca-no-components",
                message=(f"{len(manifests)} dependency manifest(s) present "
                         f"({', '.join(sorted(ecosystems))}) but the SBOM has no "
                         f"components — no dependency was actually scanned."),
                advice=(f"Commit a lock file for this ecosystem, or {suggestion}."),
            ))
    elif manifests and components is None and not has_lock and not sca_findings:
        warnings.append(CoverageWarning(
            kind="sca-unverifiable",
            message=("SBOM generation is off, so SCA coverage cannot be verified "
                     "— zero findings may mean zero dependencies were parsed."),
            advice="Set `sbom: true` to make dependency coverage observable.",
        ))

    return Coverage(manifests=manifests, ecosystems=sorted(ecosystems),
                    sbom_components=components, warnings=warnings)
