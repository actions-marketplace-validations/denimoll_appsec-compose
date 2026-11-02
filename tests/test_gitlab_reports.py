"""scripts/gitlab-reports.py: GitLab rejects a security report that does not
match its schema, so every report is validated against the schema versions
GitLab accepts (vendored from gitlab-org/security-products/security-report-schemas,
MIT)."""
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "tests" / "fixtures" / "gitlab-schemas"


@pytest.fixture(scope="module")
def gl():
    spec = importlib.util.spec_from_file_location(
        "gitlab_reports", ROOT / "scripts" / "gitlab-reports.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _finding(**kw):
    base = {"fingerprint": "a" * 40, "tool": "semgrep", "tools": ["semgrep"],
            "category": "sast", "rule_id": "py.exec", "aliases": [],
            "severity": "high", "severity_stated": True, "message": "exec of input",
            "description": "", "url": "https://semgrep.dev/r/py.exec",
            "file": "app.py", "line": 2, "end_line": 3, "cwe": ["CWE-78"],
            "package": None, "fixed_version": ""}
    base.update(kw)
    return base


def _doc(target="filesystem"):
    return {"schema_version": "1.0",
            "provenance": {"appsec_compose": "1.2.0", "generated": "2026-11-02T10:00:00Z",
                           "target": target},
            "findings": [
                _finding(),
                _finding(fingerprint="b" * 40, tool="checkov", tools=["checkov", "trivy"],
                         category="iac", rule_id="CKV_DOCKER_3", cwe=[], file="Dockerfile",
                         line=1, end_line=None, severity="medium"),
                _finding(fingerprint="c" * 40, tool="gitleaks", tools=["gitleaks"],
                         category="secrets", rule_id="generic-api-key", cwe=[],
                         file="settings.py", line=4, end_line=4, url=""),
                _finding(fingerprint="d" * 40, tool="trivy", tools=["trivy", "grype"],
                         category="sca", rule_id="CVE-2023-30861",
                         aliases=["GHSA-m2qf-hxjv-5gpq"], cwe=["CWE-539"],
                         file="requirements.txt", line=None, end_line=None,
                         package="flask@2.2.0", fixed_version="2.2.5", severity="unknown"),
            ]}


SCHEMA_FILES = {"gl-sast-report.json": "sast",
                "gl-secret-detection-report.json": "secret-detection",
                "gl-dependency-scanning-report.json": "dependency-scanning"}


@pytest.mark.parametrize("version", ["15.0.7", "15.2.4"])
def test_every_report_validates_against_gitlabs_schema(gl, version):
    reports = gl.convert(_doc(), commit="f" * 40)
    assert set(reports) == set(SCHEMA_FILES)
    for filename, body in reports.items():
        schema = json.loads((SCHEMAS / f"{SCHEMA_FILES[filename]}-{version}.json").read_text())
        jsonschema.validate(body, schema)


def test_categories_land_in_the_right_report(gl):
    reports = gl.convert(_doc())
    sast = reports["gl-sast-report.json"]["vulnerabilities"]
    assert sorted(v["identifiers"][0]["value"] for v in sast) == ["CKV_DOCKER_3", "py.exec"]
    secret, = reports["gl-secret-detection-report.json"]["vulnerabilities"]
    assert secret["location"]["commit"]["sha"] == "0" * 40
    dep, = reports["gl-dependency-scanning-report.json"]["vulnerabilities"]
    assert dep["identifiers"][:2] == [
        {"type": "cve", "name": "CVE-2023-30861", "value": "CVE-2023-30861"},
        {"type": "ghsa", "name": "GHSA-m2qf-hxjv-5gpq", "value": "GHSA-m2qf-hxjv-5gpq"}]
    assert dep["location"]["dependency"] == {"package": {"name": "flask"}, "version": "2.2.0"}
    assert dep["solution"] == "Upgrade flask to 2.2.5."
    assert dep["severity"] == "Unknown"


def test_vulnerability_ids_are_stable_across_runs(gl):
    first = gl.convert(_doc())["gl-sast-report.json"]["vulnerabilities"][0]["id"]
    again = gl.convert(_doc())["gl-sast-report.json"]["vulnerabilities"][0]["id"]
    assert first == again


def test_image_scans_skip_dependency_scanning(gl):
    assert "gl-dependency-scanning-report.json" not in gl.convert(_doc("alpine:3"))


def test_an_unknown_findings_major_is_refused(gl):
    doc = _doc()
    doc["schema_version"] = "2.0"
    with pytest.raises(ValueError, match="schema_version"):
        gl.convert(doc)
