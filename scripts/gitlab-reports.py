#!/usr/bin/env python3
"""Convert findings.json into GitLab security reports.

GitLab's `artifacts:reports` for sast, secret_detection and
dependency_scanning read GitLab's own JSON formats
(gitlab-org/security-products/security-report-schemas), not SARIF — a SARIF
file there is rejected as an invalid report. This writes one report per type
from the consolidated findings, so GitLab sees the de-duplicated, suppressed
and fingerprinted result rather than each engine's raw output:

    gl-sast-report.json              SAST and IaC (GitLab files IaC under sast)
    gl-secret-detection-report.json  secrets
    gl-dependency-scanning-report.json  SCA (filesystem scans only)

Every report is written even when empty, so GitLab can tell a clean scan from
a missing one and resolve vulnerabilities that were fixed.

    gitlab-reports.py <findings.json> <out-dir>

CI_COMMIT_SHA, when set, is recorded as the commit of secret findings.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

# Declared report schema. 15.0.x is accepted by every GitLab release that
# reads 15.x reports, and the output also validates against 15.2.x.
GITLAB_SCHEMA = "15.0.7"

_SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium",
             "low": "Low", "info": "Info"}

# Manifest or lock file name -> GitLab package_manager.
_PACKAGE_MANAGERS = {
    "requirements.txt": "pip", "pyproject.toml": "pip", "setup.py": "pip",
    "Pipfile": "pipenv", "Pipfile.lock": "pipenv", "poetry.lock": "poetry",
    "uv.lock": "uv", "package.json": "npm", "package-lock.json": "npm",
    "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm", "go.mod": "go", "go.sum": "go",
    "composer.json": "composer", "composer.lock": "composer",
    "Gemfile": "bundler", "Gemfile.lock": "bundler",
    "Cargo.toml": "cargo", "Cargo.lock": "cargo", "pom.xml": "maven",
    "build.gradle": "gradle", "build.gradle.kts": "gradle",
    "packages.lock.json": "nuget",
}

_REPORTS = {
    "sast": ("gl-sast-report.json", {"sast", "iac"}),
    "secret_detection": ("gl-secret-detection-report.json", {"secrets"}),
    "dependency_scanning": ("gl-dependency-scanning-report.json", {"sca"}),
}

_NO_COMMIT = "0" * 40


def _vuln_id(f: dict) -> str:
    # Stable across pipelines, so GitLab tracks one vulnerability, not one
    # per run.
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"appsec-compose:{f['fingerprint']}"))


def _split_package(package: str) -> tuple[str, str]:
    name, sep, version = package.rpartition("@")
    return (name, version) if sep and name else (package, "")


def _identifiers(f: dict) -> list[dict]:
    """Primary identifier first: GitLab tracks a vulnerability by it."""
    ids: list[dict] = []
    if f["category"] == "sca":
        for vid in [f["rule_id"], *f.get("aliases", [])]:
            kind = "cve" if vid.upper().startswith("CVE-") else vid.split("-")[0].lower()
            ids.append({"type": kind, "name": vid, "value": vid})
    else:
        ids.append({"type": f"{f['tool']}_id", "name": f["rule_id"],
                    "value": f["rule_id"]})
    for cwe in f.get("cwe", []):
        ids.append({"type": "cwe", "name": cwe, "value": cwe.split("-", 1)[1]})
    return ids


def _location(f: dict, report: str, commit: str) -> dict:
    if report == "dependency_scanning":
        name, version = _split_package(f.get("package") or f["rule_id"])
        return {"file": f["file"] or "unknown",
                "dependency": {"package": {"name": name}, "version": version}}
    loc: dict = {"file": f["file"]}
    if isinstance(f.get("line"), int):
        loc["start_line"] = f["line"]
        if isinstance(f.get("end_line"), int):
            loc["end_line"] = max(f["end_line"], f["line"])
    if report == "secret_detection":
        loc["commit"] = {"sha": commit}
    return loc


def _vulnerability(f: dict, report: str, commit: str) -> dict:
    if f["category"] == "sca":
        name = f"{f['rule_id']} in {f.get('package') or 'a dependency'}"
    else:
        name = " ".join(f["message"].split()) or f["rule_id"]
    vuln = {
        "id": _vuln_id(f),
        "name": name[:255],
        "description": f.get("description") or f["message"],
        "severity": _SEVERITY.get(f["severity"], "Unknown"),
        "identifiers": _identifiers(f),
        "location": _location(f, report, commit),
    }
    if f.get("fixed_version"):
        vuln["solution"] = (f"Upgrade {_split_package(f['package'])[0]} to "
                            f"{f['fixed_version']}."[:7000] if f.get("package")
                            else f"Fixed in {f['fixed_version']}."[:7000])
    url = f.get("url") or ""
    if url.startswith(("http://", "https://")):
        vuln["links"] = [{"url": url}]
    return vuln


def _scan(doc: dict, report: str, engines: list[str]) -> dict:
    prov = doc["provenance"]
    version = prov.get("appsec_compose") or "unknown"
    # GitLab wants yyyy-mm-ddThh:mm:ss, without the zone designator.
    when = prov["generated"].rstrip("Z")
    tool = {"id": "appsec-compose", "name": "appsec-compose",
            "version": version, "vendor": {"name": "appsec-compose"},
            "url": "https://github.com/denimoll/appsec-compose"}
    scanner = dict(tool)
    if engines:
        scanner["name"] = f"appsec-compose ({', '.join(engines)})"
    return {"analyzer": tool, "scanner": scanner, "type": report,
            "start_time": when, "end_time": when, "status": "success"}


def _dependency_files(findings: list[dict]) -> list[dict]:
    files: dict[str, dict] = {}
    for f in findings:
        path = f["file"] or "unknown"
        entry = files.setdefault(path, {
            "path": path,
            "package_manager": _PACKAGE_MANAGERS.get(os.path.basename(path), "unknown"),
            "dependencies": [],
        })
        name, version = _split_package(f.get("package") or f["rule_id"])
        dep = {"package": {"name": name}, "version": version}
        if dep not in entry["dependencies"]:
            entry["dependencies"].append(dep)
    return list(files.values())


def convert(doc: dict, commit: str = _NO_COMMIT) -> dict[str, dict]:
    """findings.json -> {report filename: GitLab report}."""
    major = str(doc.get("schema_version", "")).split(".")[0]
    if major != "1":
        raise ValueError(f"unsupported findings.json schema_version "
                         f"{doc.get('schema_version')!r}; expected 1.x")
    image_scan = doc["provenance"].get("target") != "filesystem"
    out: dict[str, dict] = {}
    for report, (filename, categories) in _REPORTS.items():
        if report == "dependency_scanning" and image_scan:
            continue     # image packages belong to Container Scanning, not here
        findings = [f for f in doc["findings"] if f["category"] in categories]
        engines = sorted({t for f in findings for t in f.get("tools", [])})
        body = {"version": GITLAB_SCHEMA, "scan": _scan(doc, report, engines),
                "vulnerabilities": [_vulnerability(f, report, commit) for f in findings]}
        if report == "dependency_scanning":
            body["dependency_files"] = _dependency_files(findings)
        out[filename] = body
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: gitlab-reports.py <findings.json> <out-dir>", file=sys.stderr)
        return 2
    doc = json.loads(Path(argv[1]).read_text())
    out_dir = Path(argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    commit = os.environ.get("CI_COMMIT_SHA") or _NO_COMMIT
    for filename, body in convert(doc, commit).items():
        (out_dir / filename).write_text(json.dumps(body, indent=2))
        print(f"{filename}: {len(body['vulnerabilities'])} vulnerabilit(y/ies)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
