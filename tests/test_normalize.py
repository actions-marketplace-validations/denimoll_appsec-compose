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


# --- Trivy's secret scanner shares trivy-fs.sarif with its vulnerabilities ---

def test_trivy_secrets_are_secrets_and_merge_with_gitleaks(tmp_path):
    from dedup import merge
    loc = [{"physicalLocation": {"artifactLocation": {"uri": "config.env"},
                                 "region": {"startLine": 2, "startColumn": 1,
                                            "endLine": 2, "endColumn": 1}}}]
    (tmp_path / "trivy-fs.sarif").write_text(json.dumps(_sarif([
        {"ruleId": "gitlab-pat", "level": "error", "locations": loc,
         "message": {"text": "Artifact: config.env\nType: \nSecret GitLab Personal "
                             "Access Token\nSeverity: CRITICAL\nMatch: GITLAB_TOKEN=****"}},
        {"ruleId": "CVE-2023-1", "level": "error", "message": {"text": "Package: flask\n"
                                                              "Installed Version: 1.0"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "requirements.txt"}}}]},
    ], rules=[{"id": "gitlab-pat", "properties": {"tags": ["secret", "security", "CRITICAL"]}},
              {"id": "CVE-2023-1", "properties": {"tags": ["vulnerability", "security", "HIGH"]}}])))
    (tmp_path / "gitleaks.sarif").write_text(json.dumps(_sarif([
        {"ruleId": "gitlab-pat", "level": "error", "message": {"text": "gitlab-pat"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/code/config.env"},
                                             "region": {"startLine": 2, "startColumn": 14}}}]}])))
    found = load_findings(str(tmp_path), expected={"trivy-fs.sarif", "gitleaks.sarif"}).findings
    by_rule = {(f.tool, f.rule_id): f for f in found}
    secret = by_rule[("trivy", "gitlab-pat")]
    assert secret.category == "secrets" and secret.package is None
    assert by_rule[("trivy", "CVE-2023-1")].category == "sca"
    merged, _ = merge(found)
    secrets = [f for f in merged if f.category == "secrets"]
    assert len(secrets) == 1 and secrets[0].tools == ["gitleaks", "trivy"]


# --- zizmor: verdict and confidence live on the result ----------------------

def _zizmor(tmp_path, severity, confidence, level="warning"):
    """A result shaped like zizmor 1.31's SARIF: the rule says nothing about
    severity (tags: ["security"]); the result's properties do."""
    (tmp_path / "zizmor.sarif").write_text(json.dumps(_sarif([{
        "ruleId": "zizmor/template-injection", "level": level, "kind": "fail",
        "message": {"text": "code injection via template expansion: "
                            "may expand into attacker-controllable code"},
        "properties": {"zizmor/severity": severity, "zizmor/confidence": confidence,
                       "zizmor/persona": "regular"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": ".github/workflows/ci.yml"},
            "region": {"startLine": 21, "endLine": 21,
                       "startColumn": 40, "endColumn": 80}}}],
    }], rules=[{"id": "zizmor/template-injection",
                "helpUri": "https://docs.zizmor.sh/audits/#template-injection",
                "properties": {"tags": ["security"]}}])))
    return load_findings(str(tmp_path), expected={"zizmor.sarif"}).findings[0]


def test_zizmor_findings_are_iac_with_zizmors_own_severity(tmp_path):
    f = _zizmor(tmp_path, "High", "High", level="error")
    assert (f.tool, f.category, f.rule_id) == ("zizmor", "iac", "zizmor/template-injection")
    assert f.severity == "high" and f.severity_stated
    assert f.file == ".github/workflows/ci.yml" and f.line == 21
    assert f.url == "https://docs.zizmor.sh/audits/#template-injection"


@pytest.mark.parametrize("word,severity", [
    ("High", "high"), ("Medium", "medium"), ("Low", "low"), ("Informational", "info"),
])
def test_zizmor_severity_words(tmp_path, word, severity):
    # level "note" throughout: the result property decides, not the level.
    assert _zizmor(tmp_path, word, "High", level="note").severity == severity


def test_zizmor_doubt_is_shown_but_does_not_change_the_verdict(tmp_path):
    f = _zizmor(tmp_path, "Medium", "Low")
    assert f.severity == "medium"
    assert f.message.endswith("(confidence: low)")
    assert "confidence" not in _zizmor(tmp_path, "Medium", "High").message


def test_zizmor_is_expected_when_enabled():
    assert expected_reports({"zizmor"}) == {"zizmor.sarif"}


# --- malicious packages: critical whatever the score ------------------------
# Shapes and titles below are what Trivy 0.74.0, OSV-Scanner 2.5.1 and Grype
# 0.117.0 actually reported for known-hijacked npm releases.

def _trivy_vuln(tmp_path, rule_id, title, tag, pkg="debug", ver="4.4.2"):
    (tmp_path / "trivy-fs.sarif").write_text(json.dumps(_sarif([{
        "ruleId": rule_id, "level": "error",
        "message": {"text": f"Package: {pkg}\nInstalled Version: {ver}\n"
                            f"Vulnerability {rule_id}\nSeverity: {tag}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "package-lock.json"}}}],
    }], rules=[{"id": rule_id, "shortDescription": {"text": title},
                "properties": {"tags": ["vulnerability", "security", tag]}}])))
    return load_findings(str(tmp_path), expected={"trivy-fs.sarif"}).findings[0]


@pytest.mark.parametrize("rule_id,title,tag", [
    # Trivy rates the Sept 2025 hijack HIGH: the score must not decide.
    ("CVE-2025-59144", "debug: debug@4.4.2 contains malware after npm account takeover", "HIGH"),
    ("GHSA-9x64-5r7x-2q53", "Malicious Package in flatmap-stream", "CRITICAL"),
    ("NSWG-ECO-477", "Embedded Malicious Code", "CRITICAL"),
    ("CVE-2021-4229", "Embedded malware in ua-parser-js", "HIGH"),
    ("CVE-2025-59330", "error-ex: error-ex: npm account takeover leads to malware", "HIGH"),
])
def test_trivy_malware_advisories_are_malicious_and_critical(tmp_path, rule_id, title, tag):
    f = _trivy_vuln(tmp_path, rule_id, title, tag)
    assert f.malicious and f.severity == "critical" and f.severity_stated
    assert f.scanner_severity == ("high" if tag == "HIGH" else "")
    assert f.message.startswith("MALICIOUS PACKAGE")
    assert f.package == "debug@4.4.2"


@pytest.mark.parametrize("title", [
    "Polymorphic deserialization of malicious object in jackson-databind",
    "Composer has a command injection via malicious git branch name",
    "nx: Nx: OS command injection via git revisions and remote refs",
])
def test_an_advisory_that_merely_mentions_malice_is_a_vulnerability(tmp_path, title):
    f = _trivy_vuln(tmp_path, "CVE-2024-1", title, "HIGH")
    assert not f.malicious and f.severity == "high"


def test_osv_names_the_mal_alias_only_in_its_message(tmp_path):
    (tmp_path / "osv.sarif").write_text(json.dumps(_sarif([{
        "ruleId": "CVE-2025-59144", "level": "warning",
        "message": {"text": "Package 'debug@4.4.2' is vulnerable to 'CVE-2025-59144' "
                            "(also known as 'MAL-2025-46974', 'GHSA-4x49-vf9v-38px')."},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "file:///code/package-lock.json"}}}],
    }], rules=[{"id": "CVE-2025-59144",
                "shortDescription": {"text": "CVE-2025-59144: Malicious code in debug (npm)"}}])))
    f = load_findings(str(tmp_path), expected={"osv.sarif"}).findings[0]
    assert f.malicious and f.severity == "critical" and f.package == "debug@4.4.2"


def test_grype_github_malware_advisories_are_malicious(tmp_path):
    """chalk@5.6.1: Trivy's DB does not have it; Grype's does, as 'Malware in chalk'."""
    (tmp_path / "grype.json").write_text(json.dumps({"matches": [{
        "vulnerability": {"id": "GHSA-2v46-p5h4-248w", "severity": "Critical",
                          "description": "Malware in chalk"},
        "artifact": {"name": "chalk", "version": "5.6.1", "locations": []},
        "relatedVulnerabilities": [],
    }]}))
    f = load_findings(str(tmp_path), expected={"grype.json"}).findings[0]
    assert f.malicious and f.severity == "critical"


def test_one_engine_knowing_it_is_malware_is_enough_after_merge():
    from dedup import merge
    plain = Finding("trivy", "sca", "CVE-2025-59144", "high", "m", "package-lock.json",
                    None, package="debug@4.4.2", severity_stated=True)
    marked = Finding("osv", "sca", "CVE-2025-59144", "high", "m", "package-lock.json",
                     None, package="debug@4.4.2", aliases=["MAL-2025-46974"])
    from normalize import _flag_malicious
    _flag_malicious(marked)
    merged, _ = merge([plain, marked])
    assert len(merged) == 1 and merged[0].malicious and merged[0].severity == "critical"
    assert merged[0].message.startswith("MALICIOUS PACKAGE")
