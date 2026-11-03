"""Normalize heterogeneous scanner reports into a single findings model.

Most tools emit SARIF (our common denominator); Grype is read from its native
JSON instead, because that carries package info and relatedVulnerabilities
(GHSA<->CVE aliases) needed for cross-tool SCA de-duplication.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict, field
from pathlib import Path
from urllib.parse import unquote

# Each source: (filename, tool label, category, parser format).
SOURCES = [
    ("semgrep.sarif", "semgrep", "sast", "sarif"),
    ("trivy-fs.sarif", "trivy", "sca", "sarif"),
    ("trivy-config.sarif", "trivy", "iac", "sarif"),
    ("gitleaks.sarif", "gitleaks", "secrets", "sarif"),
    # Diff mode only: the branch's commits (merge-base..HEAD), see diffscope.py.
    ("gitleaks-history.sarif", "gitleaks", "secrets", "sarif"),
    ("checkov.sarif", "checkov", "iac", "sarif"),
    ("grype.json", "grype", "sca", "grype-json"),
    ("trufflehog.sarif", "trufflehog", "secrets", "sarif"),  # generated from json
    ("hadolint.sarif", "hadolint", "iac", "sarif"),
    ("osv.sarif", "osv", "sca", "sarif"),
]

# Which report file(s) each configured scanner is expected to produce.
# syft produces only an SBOM artifact (no findings), so it has none.
SCANNER_FILES = {
    "semgrep": ["semgrep.sarif"],
    "trivy": ["trivy-fs.sarif", "trivy-config.sarif"],
    "gitleaks": ["gitleaks.sarif"],
    "checkov": ["checkov.sarif"],
    "grype": ["grype.json"],
    "trufflehog": ["trufflehog.sarif"],
    "syft": [],
    "hadolint": ["hadolint.sarif"],
    "osv": ["osv.sarif"],
}


def expected_reports(enabled_scanners) -> set[str]:
    """Report filenames we should expect, given the enabled scanners."""
    files: set[str] = set()
    for name in enabled_scanners:
        files.update(SCANNER_FILES.get(name, []))
    return files

# SARIF level -> our severity when no numeric CVSS is available.
_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

# Categories where a finding is inherently serious; floor its severity.
_CATEGORY_FLOOR = {
    "secrets": "high",
}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# A tool's own severity word, when it states one in the rule's SARIF tags.
# "unknown" is deliberately not a real level: the collector resolves it through
# the `unknown_severity` setting before anything ranks or compares it.
_TOOL_SEVERITY_WORDS = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFO": "info", "NONE": "info", "UNKNOWN": "unknown",
}


@dataclass
class Finding:
    tool: str
    category: str
    rule_id: str
    severity: str
    message: str
    file: str
    line: int | None
    package: str | None = None        # SCA: "name@version" for dedup/grouping
    aliases: list[str] = field(default_factory=list)  # equivalent IDs (e.g. CVEs)
    tools: list[str] = field(default_factory=list)     # set on merge (provenance)
    description: str = ""              # human explanation / remediation hint
    url: str = ""                     # advisory / docs link
    # Exploitability, filled in by enrich.py when CVE-PaaS is configured.
    priority: str = ""                # CVE-PaaS verdict (Critical..Info/Undefined)
    epss: float | None = None         # probability of exploitation in the wild
    kev: bool = False                 # listed in CISA KEV
    poc: bool = False                 # public proof of concept exists
    nuclei: bool = False              # Nuclei template exists
    exploitable: bool = False         # kev or poc or nuclei
    scanner_severity: str = ""        # original severity, if reprioritized
    # True when the tool stated this severity itself, rather than us deriving
    # it from a CVSS score or a coarse SARIF level. Merging prefers verdicts.
    severity_stated: bool = False
    end_line: int | None = None
    column: int | None = None         # 1-based, as in SARIF
    end_column: int | None = None
    cwe: list[str] = field(default_factory=list)       # e.g. ["CWE-89"]
    fixed_version: str = ""           # SCA: version(s) that fix it, as reported
    fingerprint: str = ""             # stable identity, set by baseline.assign

    def __post_init__(self):
        if not self.tools:
            self.tools = [self.tool]


# Grype severity strings -> our scale. "negligible" is a real verdict and maps
# to info; "unknown" is the absence of one, so it goes through the same
# `unknown_severity` resolution as every other tool's undetermined finding.
_GRYPE_SEVERITY = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "negligible": "info", "unknown": "unknown",
}


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _max_severity(a: str, b: str) -> str:
    return a if _SEVERITY_RANK[a] >= _SEVERITY_RANK[b] else b


def _tool_severity(rule: dict) -> str | None:
    """The severity the tool itself assigned, if the report states it.

    This has to outrank the raw CVSS score, because the two genuinely disagree
    and the tool's verdict is the better answer. Trivy resolves severity
    through the vendor that owns the advisory (`SeveritySource`: ghsa, redhat,
    debian, …), and an advisory routinely carries a CVSS vector that its own
    maintainers consider unrepresentative — GHSA-63hf-3vf5-4wqf (CVE-2026-34520
    in aiohttp) is scored LOW by GitHub while carrying a CVSS v3 vector worth
    9.1. Reading the number instead of the verdict turned that into the single
    "critical" finding of a report, contradicting the native output we ship
    alongside it.
    """
    for tag in (rule.get("properties") or {}).get("tags") or []:
        word = _TOOL_SEVERITY_WORDS.get(str(tag).strip().upper())
        if word:
            return word
    return None


def _security_severity(props: dict) -> str | None:
    """Read the SARIF `security-severity` (CVSS string) if present."""
    if not props:
        return None
    raw = props.get("security-severity")
    if raw is None:
        return None
    try:
        return _severity_from_cvss(float(raw))
    except (TypeError, ValueError):
        return None


_CWE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)


def _cwes(rule: dict, res: dict) -> list[str]:
    """CWE ids from the rule's tags (Semgrep: "CWE-89: Improper ...")."""
    tags = [*((rule.get("properties") or {}).get("tags") or []),
            *((res.get("properties") or {}).get("tags") or [])]
    found = {f"CWE-{m}" for tag in tags for m in _CWE.findall(str(tag))}
    return sorted(found, key=lambda c: int(c[4:]))


_TRIVY_PKG = re.compile(r"Package:\s*(.+)")
_TRIVY_VER = re.compile(r"Installed Version:\s*(.+)")
_TRIVY_FIX = re.compile(r"Fixed Version:\s*(.+)")
# OSV message: "Package 'urllib3@1.23.0' is vulnerable to ..."
_OSV_PKG = re.compile(r"Package '([^']+)'")


def _trivy_package(message: str) -> str | None:
    name = _TRIVY_PKG.search(message)
    ver = _TRIVY_VER.search(message)
    if name and ver:
        return f"{name.group(1).strip()}@{ver.group(1).strip()}"
    return name.group(1).strip() if name else None


def _osv_package(message: str) -> str | None:
    m = _OSV_PKG.search(message)
    return m.group(1).strip() if m else None


_SCA_PACKAGE = {"trivy": _trivy_package, "osv": _osv_package}

# The repo is bind-mounted at /code inside the scanners; strip that prefix (and
# any file:// scheme / percent-encoding) so report paths are repo-relative.
def _clean_path(uri: str) -> str:
    if not uri:
        return ""
    p = unquote(uri)
    if p.startswith("file://"):
        p = p[len("file://"):]
    # Most tools report "/code/x"; checkov drops the leading slash ("code/x").
    stripped = p.lstrip("/")
    if stripped.startswith("code/"):
        return stripped[len("code/"):]
    if stripped == "code":
        return ""
    return p


def _parse_sarif(path: Path, tool: str, category: str) -> list[Finding]:
    """Parse one SARIF file. Raises ValueError if the file is not valid SARIF."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"{path.name}: unreadable SARIF ({exc})") from exc

    findings: list[Finding] = []
    for run in data.get("runs", []) or []:
        # Build ruleId -> full rule object for severity/description lookups.
        rules = {}
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules", []) or []:
            rules[rule.get("id")] = rule

        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or res.get("ruleIndex") or "unknown"
            rule = rules.get(rule_id, {})

            # Severity: the tool's own verdict first, then CVSS from the result
            # or the rule, then the coarse SARIF level. CVSS is a fallback, not
            # an override — see _tool_severity.
            stated = _tool_severity(rule)
            # SARIF §3.27.10: a result without a level takes its rule's
            # defaultConfiguration.level, and only then "warning". Semgrep puts
            # the level on the rule and never on the result, so reading the
            # result alone turned every ERROR rule into medium — and the
            # default `fail_on: high` gate could never fail on SAST.
            level = (res.get("level")
                     or (rule.get("defaultConfiguration") or {}).get("level")
                     or "warning")
            sev = (
                stated
                or _security_severity(res.get("properties") or {})
                or _security_severity(rule.get("properties") or {})
                or _LEVEL_TO_SEVERITY.get(level, "medium")
            )
            floor = _CATEGORY_FLOOR.get(category)
            if floor:
                # A secret whose severity the tool could not determine is still
                # a secret, so the floor applies rather than the fallback level.
                sev = (_max_severity(sev, floor) if sev in _SEVERITY_RANK
                       else floor)

            msg = ((res.get("message") or {}).get("text") or "").strip()

            # Description: rule's full text/help/short description (whichever first).
            description = (
                (rule.get("fullDescription") or {}).get("text")
                or (rule.get("help") or {}).get("text")
                or (rule.get("shortDescription") or {}).get("text")
                or ""
            ).strip()
            url = rule.get("helpUri", "") or ""

            file_path, region = "", {}
            locs = res.get("locations") or []
            if locs:
                phys = (locs[0].get("physicalLocation") or {})
                file_path = _clean_path((phys.get("artifactLocation") or {}).get("uri", ""))
                region = phys.get("region") or {}

            package, fixed = None, ""
            if category == "sca" and tool in _SCA_PACKAGE:
                package = _SCA_PACKAGE[tool](msg)
            if category == "sca" and tool == "trivy":
                m = _TRIVY_FIX.search(msg)
                fixed = m.group(1).strip() if m else ""

            findings.append(Finding(
                tool=tool, category=category, rule_id=str(rule_id), severity=sev,
                message=msg or str(rule_id), file=file_path,
                line=region.get("startLine"),
                package=package, description=description, url=url,
                severity_stated=stated is not None,
                end_line=region.get("endLine"), column=region.get("startColumn"),
                end_column=region.get("endColumn"), cwe=_cwes(rule, res),
                fixed_version=fixed,
            ))
    return findings


def _parse_grype_json(path: Path, tool: str, category: str) -> list[Finding]:
    """Parse Grype native JSON, capturing package + alias (CVE) info."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"{path.name}: unreadable Grype JSON ({exc})") from exc

    findings: list[Finding] = []
    for match in data.get("matches", []) or []:
        vuln = match.get("vulnerability") or {}
        vid = vuln.get("id", "unknown")
        sev = _GRYPE_SEVERITY.get(str(vuln.get("severity", "")).lower(), "unknown")

        aliases = [r.get("id") for r in match.get("relatedVulnerabilities", [])
                   if r.get("id")]

        art = match.get("artifact") or {}
        name, version = art.get("name", ""), art.get("version", "")
        package = f"{name}@{version}" if name else None
        locs = art.get("locations") or []
        file_path = (locs[0].get("path", "") if locs else "").lstrip("/")

        related = match.get("relatedVulnerabilities", [])
        description = (vuln.get("description")
                       or (related[0].get("description") if related else "")
                       or "").strip()
        url = vuln.get("dataSource", "") or ""
        fix = vuln.get("fix") or {}
        fixed = ", ".join(fix.get("versions") or []) if fix.get("state") == "fixed" else ""

        findings.append(Finding(
            tool=tool, category=category, rule_id=str(vid), severity=sev,
            message=f"{vid} in {package or name}", file=file_path, line=None,
            package=package, aliases=aliases, description=description, url=url,
            # Grype's native JSON carries its own verdict, not a raw score.
            severity_stated=True, fixed_version=fixed,
        ))
    return findings


_PARSERS = {"sarif": _parse_sarif, "grype-json": _parse_grype_json}


@dataclass
class ScanResult:
    findings: list[Finding]
    reports_found: list[str]
    reports_missing: list[str]
    reports_errored: list[str]


def load_findings(native_dir: str = "/reports/native",
                  expected: set[str] | None = None) -> ScanResult:
    base = Path(native_dir)
    findings: list[Finding] = []
    found, missing, errored = [], [], []

    for filename, tool, category, fmt in SOURCES:
        if expected is not None and filename not in expected:
            continue  # scanner disabled in config — don't expect its report
        path = base / filename
        if path.exists() and path.stat().st_size > 0:
            try:
                findings.extend(_PARSERS[fmt](path, tool, category))
                found.append(filename)
            except ValueError as exc:
                errored.append(str(exc))
        else:
            missing.append(filename)

    return ScanResult(findings=findings, reports_found=found,
                      reports_missing=missing, reports_errored=errored)


def finding_to_dict(f: Finding) -> dict:
    return asdict(f)
