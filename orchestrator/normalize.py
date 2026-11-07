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
from urllib.parse import quote, unquote

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
    # CI/CD workflows are infrastructure-as-code for the pipeline; the
    # findings.json category enum is a published contract, so no new category.
    ("zizmor.sarif", "zizmor", "iac", "sarif"),
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
    "zizmor": ["zizmor.sarif"],
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
    "LOW": "low", "INFO": "info", "INFORMATIONAL": "info", "NONE": "info",
    "UNKNOWN": "unknown",
}

# Tools that state severity per result rather than per rule. zizmor's rules are
# audits (`template-injection`), and how serious one finding of an audit is
# depends on what it found, so the verdict sits on the result. Its SARIF
# `level` is only the coarse error/warning/note projection of that verdict.
_RESULT_SEVERITY_KEY = "zizmor/severity"
# zizmor also says how sure it is. Kept in the message for the reviewer rather
# than folded into severity: the verdict stays the tool's own.
_RESULT_CONFIDENCE_KEY = "zizmor/confidence"


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
    # SCA: the advisory says the package itself is malware (a hijacked release,
    # a typosquat), not that it has a bug. Always critical; see _malicious.
    malicious: bool = False
    # How sure the rule's author is that a match is a real issue: "high",
    # "medium" or "low", when the engine says (Semgrep's rule metadata, zizmor's
    # per-result confidence); "" when it does not. A low-confidence rule is a
    # lead to check, not a verdict, and `min_confidence` can keep it off the gate.
    confidence: str = ""

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


def _result_severity(res: dict) -> str | None:
    """A severity the tool stated on the result itself (see _RESULT_SEVERITY_KEY)."""
    word = (res.get("properties") or {}).get(_RESULT_SEVERITY_KEY)
    return _TOOL_SEVERITY_WORDS.get(str(word).strip().upper()) if word else None


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


# [ \t]*, not \s*: Trivy prints "Fixed Version: " with nothing after it when no
# fix exists, and \s* would run on to the next line and take "Link: [...]".
_TRIVY_PKG = re.compile(r"Package:[ \t]*(\S.*)")
_TRIVY_VER = re.compile(r"Installed Version:[ \t]*(\S.*)")
_TRIVY_FIX = re.compile(r"Fixed Version:[ \t]*(\S.*)")
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


# --- malicious packages -----------------------------------------------------
# No report says "malware" in a field of its own: Trivy, Grype and OSV all ship
# a malicious-package advisory as one more vulnerability, scored like one —
# Trivy rates the September 2025 debug/chalk hijack HIGH. So it is recognised
# by what the advisory databases call it:
#   - an OpenSSF malicious-packages id, MAL-YYYY-N (OSV, as id or alias);
#   - CWE-506, Embedded Malicious Code;
#   - the title GitHub gives malware advisories: "Malware in X", "Malicious
#     code in X", "Malicious Package in X", "Embedded Malicious Code in X",
#     "Embedded malware in X", "X contains malware ...", and NVD's wording
#     that Trivy shows for some CVEs ("npm account takeover leads to malware").
# The titles are matched at the start (after an "ID: " / "pkg: " prefix),
# because "malicious" alone is everywhere in ordinary advisories ("via a
# malicious payload"). Over every GitHub advisory in Grype's DB (162,836) the
# pattern matched 125,644 malware advisories and none of the 478 ordinary ones
# that merely mention malicious input.
_MAL_ID = re.compile(r"\bMAL-\d{4}-\d+\b")
_MAL_TITLE = re.compile(
    r"^(?:malware in|malicious (?:code|package) in|malicious package\b|"
    r"embedded malicious code\b|embedded malware\b)|\b(?:contains|leads to) malware\b",
    re.IGNORECASE)
_TITLE_PREFIX = re.compile(r"^[^\s:]+:\s+")


def _malicious(rule_id: str, aliases, title: str, cwe, message: str = "") -> bool:
    if _MAL_ID.search(" ".join([rule_id, *aliases])) or _MAL_ID.search(message):
        return True
    if "CWE-506" in cwe:
        return True
    title = (title or "").strip()
    return bool(_MAL_TITLE.search(title) or _MAL_TITLE.search(_TITLE_PREFIX.sub("", title, 1)))


def _flag_malicious(f: "Finding") -> None:
    """Malware is critical whatever its CVSS: it is not a flaw with a score."""
    f.malicious = True
    if f.severity != "critical":
        f.scanner_severity = f.severity
        f.severity = "critical"
    f.severity_stated = True
    if not f.message.startswith("MALICIOUS PACKAGE"):
        f.message = f"MALICIOUS PACKAGE — {f.message}"

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


def _result_category(tool: str, category: str, rule: dict) -> str:
    """The category of one result, when a report mixes several.

    trivy-fs.sarif carries Trivy's secret scanner next to its vulnerabilities.
    Filed under the report's `sca` they had no package, escaped the secrets
    floor and cross-tool merge, and were gated by the SCA threshold: one GitLab
    token came out twice, as Trivy sca/critical and Gitleaks secrets/high.
    Trivy tags each secret rule `secret` (vulnerabilities: `vulnerability`).
    """
    if tool == "trivy" and category == "sca":
        tags = {str(t).lower() for t in (rule.get("properties") or {}).get("tags") or []}
        if "secret" in tags:
            return "secrets"
    return category


def _source_suppression(res: dict) -> str | None:
    """Why the engine itself says this result is suppressed, if it does.

    SARIF records `# nosemgrep`, a Checkov skip comment and the like as a
    `suppressions` entry on the result. Code scanning honours it; a gate that
    did not would fail a build on a finding the code already says was
    reviewed. A suppression whose status is "rejected" or "underReview" is not
    in effect (SARIF 3.35.3).
    """
    for sup in res.get("suppressions") or []:
        if sup.get("status", "accepted") == "accepted":
            why = (sup.get("justification") or "").strip()
            return f"suppressed in source ({sup.get('kind', 'inSource')})" + (f": {why}" if why else "")
    return None


_CONFIDENCE_TAG = re.compile(r"^(low|medium|high) confidence$", re.I)
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _confidence(rule: dict, res: dict) -> str:
    """The engine's own confidence: zizmor states it per result, Semgrep per
    rule, as a "LOW CONFIDENCE" tag. Anything else is "" — not stated."""
    stated = str((res.get("properties") or {}).get(_RESULT_CONFIDENCE_KEY) or "").lower()
    if stated in CONFIDENCE_RANK:
        return stated
    for tag in (rule.get("properties") or {}).get("tags") or []:
        m = _CONFIDENCE_TAG.match(str(tag).strip())
        if m:
            return m.group(1).lower()
    return ""


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
            kind = _result_category(tool, category, rule)

            # Severity: the tool's own verdict first, then CVSS from the result
            # or the rule, then the coarse SARIF level. CVSS is a fallback, not
            # an override — see _tool_severity.
            stated = _tool_severity(rule) or _result_severity(res)
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
            floor = _CATEGORY_FLOOR.get(kind)
            if floor:
                # A secret whose severity the tool could not determine is still
                # a secret, so the floor applies rather than the fallback level.
                sev = (_max_severity(sev, floor) if sev in _SEVERITY_RANK
                       else floor)

            msg = ((res.get("message") or {}).get("text") or "").strip()
            confidence = _confidence(rule, res)
            doubt = str((res.get("properties") or {}).get(_RESULT_CONFIDENCE_KEY) or "")
            if msg and doubt and doubt.lower() != "high":
                msg += f" (confidence: {doubt.lower()})"   # zizmor's doubt, read in place

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
            if kind == "sca" and tool in _SCA_PACKAGE:
                package = _SCA_PACKAGE[tool](msg)
            if kind == "sca" and tool == "trivy":
                m = _TRIVY_FIX.search(msg)
                fixed = m.group(1).strip() if m else ""

            finding = Finding(
                tool=tool, category=kind, rule_id=str(rule_id), severity=sev,
                message=msg or str(rule_id), file=file_path,
                line=region.get("startLine"),
                package=package, description=description, url=url,
                severity_stated=stated is not None,
                end_line=region.get("endLine"), column=region.get("startColumn"),
                end_column=region.get("endColumn"), cwe=_cwes(rule, res),
                fixed_version=fixed, confidence=confidence,
            )
            # The advisory title is the rule's short description (Trivy:
            # "pkg: title", OSV: "ID: title"); OSV names MAL- aliases only in
            # its message ("also known as 'MAL-2025-46974'").
            title = (rule.get("shortDescription") or {}).get("text") or ""
            if kind == "sca" and _malicious(finding.rule_id, finding.aliases, title,
                                            finding.cwe, msg):
                _flag_malicious(finding)
            finding.source_suppression = _source_suppression(res)
            findings.append(finding)
    return findings


def _grype_name(artifact: dict) -> str:
    """Grype names a Maven artifact by its artifactId alone; Trivy and OSV use
    groupId:artifactId. The purl carries both, and without them the same
    jackson-databind CVE never merges across engines and is reported twice."""
    name = artifact.get("name", "")
    purl = unquote(artifact.get("purl") or "")
    if purl.startswith("pkg:maven/"):
        coords = purl[len("pkg:maven/"):].split("@", 1)[0].split("?", 1)[0]
        group, _, artifact_id = coords.rpartition("/")
        if group and artifact_id:
            return f"{group}:{artifact_id}"
    return name


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
        name, version = _grype_name(art), art.get("version", "")
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

        finding = Finding(
            tool=tool, category=category, rule_id=str(vid), severity=sev,
            message=f"{vid} in {package or name}", file=file_path, line=None,
            package=package, aliases=aliases, description=description, url=url,
            # Grype's native JSON carries its own verdict, not a raw score.
            severity_stated=True, fixed_version=fixed,
        )
        # For a GitHub advisory Grype's `description` is its title
        # ("Malware in chalk"); its JSON carries no CWE.
        if _malicious(finding.rule_id, aliases, vuln.get("description") or "", []):
            _flag_malicious(finding)
        findings.append(finding)
    return findings


_PARSERS = {"sarif": _parse_sarif, "grype-json": _parse_grype_json}


@dataclass
class ScanResult:
    findings: list[Finding]
    reports_found: list[str]
    reports_missing: list[str]
    reports_errored: list[str]


def relativize_sarif(native_dir: str) -> None:
    """Make the locations in the native SARIF reports repo-relative.

    The engines run with the repository mounted at /code and report that
    ("/code/app.py", "code/app.py"), a path that exists nowhere else: GitHub
    code scanning and ASPMs cannot place such a result on a file in the repo.
    Only artifact locations change; results, rules and levels stay the engine's.
    """
    def fix(node) -> bool:
        changed = False
        if isinstance(node, dict):
            loc = node.get("artifactLocation")
            if isinstance(loc, dict) and isinstance(loc.get("uri"), str):
                new = quote(_clean_path(loc["uri"]), safe="/:@")
                if new and new != loc["uri"]:
                    loc["uri"] = new
                    changed = True
            for value in node.values():
                changed = fix(value) or changed
        elif isinstance(node, list):
            for value in node:
                changed = fix(value) or changed
        return changed

    for path in Path(native_dir).glob("*.sarif"):
        try:
            data = json.loads(path.read_text())
            if fix(data.get("runs")):
                path.write_text(json.dumps(data))
        except (OSError, ValueError, AttributeError):
            continue            # load_findings reports an unreadable one


def _engine_failures(path: Path) -> list[str]:
    """What a SARIF report admits about its own run going wrong.

    An engine can fail and still write a valid report: Semgrep killed by the
    out-of-memory killer writes `executionSuccessful: true`, no results, and
    an error-level notification ("engine was killed"). Reading only the
    results, that is a clean "0 findings". A run marked unsuccessful, or any
    error-level notification, makes the report incomplete; warnings (a file
    that did not parse, a rule that timed out) do not.
    """
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return []
    failures = []
    for run in data.get("runs", []) or []:
        for inv in run.get("invocations", []) or []:
            errors = [n for n in inv.get("toolExecutionNotifications", []) or []
                      if n.get("level") == "error"]
            if inv.get("executionSuccessful") is False and not errors:
                failures.append("the engine reported an unsuccessful run")
            for n in errors[:3]:
                text = " ".join(str((n.get("message") or {}).get("text", "")).split())
                failures.append(text[:200] or "error-level notification")
            if len(errors) > 3:
                failures.append(f"and {len(errors) - 3} more error(s)")
    return failures


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
                continue
            # Read, but the engine says its run went wrong: keep what it found
            # and flag the report as incomplete (strict fails on it).
            failures = _engine_failures(path) if fmt == "sarif" else []
            if failures:
                errored.append(f"{filename}: incomplete — {'; '.join(failures)}")
        else:
            missing.append(filename)

    return ScanResult(findings=findings, reports_found=found,
                      reports_missing=missing, reports_errored=errored)


def finding_to_dict(f: Finding) -> dict:
    return asdict(f)
