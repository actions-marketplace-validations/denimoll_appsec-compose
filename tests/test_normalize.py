import json

import pytest

from normalize import (Finding, _clean_path, _severity_from_cvss, expected_reports,
                       load_findings)


@pytest.mark.parametrize("uri,expected", [
    ("/code/app.py", "app.py"),                       # gitleaks, trivy
    ("code/orchestrator/Dockerfile", "orchestrator/Dockerfile"),   # checkov
    ("file:///code/requirements.txt", "requirements.txt"),         # osv
    ("file:///code/a%20b.py", "a b.py"),              # percent-encoded
    ("app.py", "app.py"),                             # already relative
    ("/code", ""),
    ("code", ""),
    ("", ""),
    ("/usr/lib/libssl.so", "/usr/lib/libssl.so"),     # image mode: OS path kept
])
def test_clean_path(uri, expected):
    assert _clean_path(uri) == expected


@pytest.mark.parametrize("score,severity", [
    (9.8, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"),
    (6.9, "medium"), (4.0, "medium"), (3.9, "low"), (0.1, "low"), (0.0, "info"),
])
def test_severity_from_cvss(score, severity):
    assert _severity_from_cvss(score) == severity


def test_expected_reports_tracks_enabled_scanners():
    assert expected_reports({"trivy"}) == {"trivy-fs.sarif", "trivy-config.sarif"}
    assert expected_reports({"syft"}) == set()       # SBOM only, no findings
    assert expected_reports({"nope"}) == set()


def _sarif(results, rules=None):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "t", "rules": rules or []}},
        "results": results,
    }]}


def test_secrets_severity_is_floored_to_high(tmp_path):
    (tmp_path / "gitleaks.sarif").write_text(json.dumps(_sarif([{
        "ruleId": "generic-api-key",
        "level": "note",                              # tool says "low"...
        "message": {"text": "key found"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "/code/a.py"},
            "region": {"startLine": 3}}}],
    }])))
    result = load_findings(str(tmp_path), expected={"gitleaks.sarif"})
    assert [f.severity for f in result.findings] == ["high"]   # ...secrets floor


def test_unreadable_report_is_errored_not_missing(tmp_path):
    (tmp_path / "semgrep.sarif").write_text("{not json")
    result = load_findings(str(tmp_path), expected={"semgrep.sarif"})
    assert result.findings == []
    assert result.reports_found == []
    assert result.reports_missing == []
    assert len(result.reports_errored) == 1


def test_empty_report_counts_as_missing(tmp_path):
    (tmp_path / "semgrep.sarif").write_text("")
    result = load_findings(str(tmp_path), expected={"semgrep.sarif"})
    assert result.reports_missing == ["semgrep.sarif"]


def test_cvss_beats_sarif_level(tmp_path):
    (tmp_path / "trivy-fs.sarif").write_text(json.dumps(_sarif([{
        "ruleId": "CVE-2021-1", "level": "note",
        "message": {"text": "Package: flask\nInstalled Version: 1.0"},
        "properties": {"security-severity": "9.4"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "/code/requirements.txt"}}}],
    }])))
    result = load_findings(str(tmp_path), expected={"trivy-fs.sarif"})
    f = result.findings[0]
    assert f.severity == "critical"
    assert f.package == "flask@1.0"


def test_finding_defaults_tools_to_its_own_tool():
    assert Finding("semgrep", "sast", "r", "high", "m", "a.py", 1).tools == ["semgrep"]


# --- severity: the tool's verdict outranks the raw CVSS ---------------------

def _rule(rule_id, tags=None, security_severity=None):
    props = {}
    if tags is not None:
        props["tags"] = tags
    if security_severity is not None:
        props["security-severity"] = security_severity
    return {"id": rule_id, "properties": props}


def _one(tmp_path, filename, rule, level="warning"):
    (tmp_path / filename).write_text(json.dumps(_sarif(
        [{"ruleId": rule["id"], "level": level, "message": {"text": "m"},
          "locations": [{"physicalLocation": {
              "artifactLocation": {"uri": "/code/requirements.txt"}}}]}],
        rules=[rule])))
    return load_findings(str(tmp_path), expected={filename}).findings[0]


def test_a_stated_severity_beats_a_contradicting_cvss(tmp_path):
    """CVE-2026-34520: GitHub rates it LOW while its CVSS v3 vector scores 9.1.

    Reading the number turned it into the only 'critical' of a whole report,
    contradicting the Trivy output shipped next to it.
    """
    finding = _one(tmp_path, "trivy-fs.sarif",
                   _rule("CVE-2026-34520",
                         tags=["vulnerability", "security", "LOW"],
                         security_severity="9.1"),
                   level="note")
    assert finding.severity == "low"


def test_a_stated_critical_is_kept(tmp_path):
    finding = _one(tmp_path, "trivy-fs.sarif",
                   _rule("CVE-1", tags=["vulnerability", "security", "CRITICAL"],
                         security_severity="9.8"), level="error")
    assert finding.severity == "critical"


def test_an_undetermined_severity_is_not_silently_info(tmp_path):
    """Trivy ships UNKNOWN findings with security-severity 0.0."""
    finding = _one(tmp_path, "trivy-fs.sarif",
                   _rule("TEMP-123", tags=["vulnerability", "security", "UNKNOWN"],
                         security_severity="0.0"), level="note")
    assert finding.severity == "unknown"        # resolved later by config


def test_cvss_still_ranks_tools_that_state_no_severity(tmp_path):
    """OSV-Scanner levels every result `warning`, so CVSS is its only gradation."""
    finding = _one(tmp_path, "osv.sarif",
                   _rule("CVE-2", security_severity="9.4"), level="warning")
    assert finding.severity == "critical"


def test_level_is_the_last_resort(tmp_path):
    finding = _one(tmp_path, "checkov.sarif", _rule("CKV_1"), level="error")
    assert finding.severity == "high"


def test_the_secrets_floor_applies_to_an_undetermined_severity(tmp_path):
    """A secret nobody could score is still a secret — it must not fall to the
    generic `unknown_severity` and rank below a plain one."""
    finding = _one(tmp_path, "gitleaks.sarif",
                   _rule("generic", tags=["UNKNOWN"]), level="note")
    assert finding.severity == "high"


def _grype(tmp_path, severity):
    (tmp_path / "grype.json").write_text(json.dumps({"matches": [{
        "vulnerability": {"id": "CVE-9", "severity": severity},
        "artifact": {"name": "pkg", "version": "1.0", "locations": []},
    }]}))
    return load_findings(str(tmp_path), expected={"grype.json"}).findings[0]


def test_grype_negligible_is_a_verdict_and_stays_info(tmp_path):
    assert _grype(tmp_path, "Negligible").severity == "info"


def test_grype_unknown_is_the_absence_of_a_verdict(tmp_path):
    """It must reach `unknown_severity` like every other tool's, not become info."""
    assert _grype(tmp_path, "Unknown").severity == "unknown"
    assert _grype(tmp_path, "").severity == "unknown"


# --- detail fields: span, CWE, fix ------------------------------------------

def test_sarif_region_span_and_cwe_are_kept(tmp_path):
    rule = _rule("py.sqli", tags=["CWE-89: Improper Neutralization of SQL",
                                  "OWASP-A03:2021 - Injection", "security"])
    (tmp_path / "semgrep.sarif").write_text(json.dumps(_sarif([{
        "ruleId": "py.sqli", "level": "error", "message": {"text": "m"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "/code/app.py"},
            "region": {"startLine": 4, "endLine": 5,
                       "startColumn": 2, "endColumn": 9}}}],
    }], rules=[rule])))
    f = load_findings(str(tmp_path), expected={"semgrep.sarif"}).findings[0]
    assert (f.line, f.end_line, f.column, f.end_column) == (4, 5, 2, 9)
    assert f.cwe == ["CWE-89"]


def test_trivy_fixed_version_is_read_from_the_message(tmp_path):
    (tmp_path / "trivy-fs.sarif").write_text(json.dumps(_sarif([{
        "ruleId": "CVE-2021-1", "level": "error",
        "message": {"text": "Package: flask\nInstalled Version: 1.0\n"
                            "Vulnerability CVE-2021-1\nSeverity: HIGH\n"
                            "Fixed Version: 1.1.4, 2.0.1\nLink: [CVE-2021-1](x)"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "/code/requirements.txt"}}}],
    }])))
    f = load_findings(str(tmp_path), expected={"trivy-fs.sarif"}).findings[0]
    assert f.fixed_version == "1.1.4, 2.0.1"


def test_grype_fixed_version_only_when_a_fix_exists(tmp_path):
    def fixed(fix):
        (tmp_path / "grype.json").write_text(json.dumps({"matches": [{
            "vulnerability": {"id": "CVE-9", "severity": "High", "fix": fix},
            "artifact": {"name": "pkg", "version": "1.0", "locations": []},
        }]}))
        return load_findings(str(tmp_path), expected={"grype.json"}).findings[0].fixed_version
    assert fixed({"versions": ["1.2.0"], "state": "fixed"}) == "1.2.0"
    assert fixed({"versions": [], "state": "not-fixed"}) == ""


def test_a_result_without_a_level_takes_its_rules_default(tmp_path):
    # Semgrep: the level lives on the rule (defaultConfiguration), never on the
    # result. An ERROR rule must come out high, not the "warning" fallback.
    rules = [{"id": "php.exec", "defaultConfiguration": {"level": "error"}},
             {"id": "php.info", "defaultConfiguration": {"level": "note"}}]
    results = [{"ruleId": r["id"], "message": {"text": "m"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "/code/a.php"},
                    "region": {"startLine": 1}}}]} for r in rules]
    (tmp_path / "semgrep.sarif").write_text(json.dumps(_sarif(results, rules=rules)))
    found = load_findings(str(tmp_path), expected={"semgrep.sarif"}).findings
    assert {f.rule_id: f.severity for f in found} == {"php.exec": "high", "php.info": "low"}


def test_a_results_own_level_still_wins_over_the_rule_default(tmp_path):
    rule = {"id": "r", "defaultConfiguration": {"level": "error"}}
    assert _one(tmp_path, "semgrep.sarif", rule, level="note").severity == "low"
