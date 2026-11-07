"""findings.json is a published contract: run the collector end to end over
fixture reports and hold its output to schemas/findings.schema.json."""
import json
from pathlib import Path

import jsonschema
import pytest

import main
from config import load_config

SCHEMA = json.loads((Path(__file__).resolve().parent.parent
                     / "schemas" / "findings.schema.json").read_text())


# Assembled at run time so this file is not itself a finding for Gitleaks.
SECRET = "sk_" "live_" "9fQ2rT7x" "Lm4Pz8Wc"


def _sarif(results, rules=()):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "t", "rules": list(rules)}}, "results": results}]}


def _loc(uri, line=None):
    region = {"region": {"startLine": line}} if line else {}
    return [{"physicalLocation": {"artifactLocation": {"uri": uri}, **region}}]


@pytest.fixture
def run(tmp_path, monkeypatch):
    code, reports = tmp_path / "code", tmp_path / "reports"
    native = reports / "native"
    code.mkdir()
    native.mkdir(parents=True)
    (code / "app.py").write_text("import os\nos.system(cmd)\n")
    (code / "requirements.txt").write_text("flask==1.0\n")
    (code / "settings.py").write_text(f'DEBUG = False\nTOKEN = "{SECRET}"\n')
    (native / "semgrep.sarif").write_text(json.dumps(_sarif(
        [{"ruleId": "py.exec", "level": "error", "message": {"text": "exec"},
          "locations": _loc("/code/app.py", 2)}],
        [{"id": "py.exec", "properties": {"tags": ["CWE-78: OS Command Injection"]}}])))
    (native / "trivy-fs.sarif").write_text(json.dumps(_sarif(
        [{"ruleId": "CVE-2023-1", "level": "error",
          "message": {"text": "Package: flask\nInstalled Version: 1.0\n"
                              "Fixed Version: 2.2.5"},
          "locations": _loc("/code/requirements.txt")}],
        [{"id": "CVE-2023-1", "properties": {"tags": ["HIGH"]}}])))
    (native / "trivy-config.sarif").write_text(json.dumps(_sarif([])))
    (native / "gitleaks.sarif").write_text(json.dumps(_sarif(
        [{"ruleId": "generic-api-key", "level": "error",
          "message": {"text": "generic-api-key has detected secret"},
          "locations": [{"physicalLocation": {
              "artifactLocation": {"uri": "/code/settings.py"},
              "region": {"startLine": 2, "startColumn": 10, "endColumn": 30}}}]}])))
    config = tmp_path / "scan-config.yml"
    config.write_text("baseline: true\n")

    monkeypatch.setattr(main, "REPORTS_DIR", str(reports))
    monkeypatch.setattr(main, "NATIVE_DIR", str(native))
    monkeypatch.setattr(main, "CODE_DIR", str(code))
    monkeypatch.setattr(main, "BASELINE_PATH", str(tmp_path / "baseline.json"))
    monkeypatch.setattr(main, "load_config", lambda: load_config(str(config)))
    monkeypatch.setenv("ASS_ENABLED", "semgrep trivy gitleaks")

    def _run(update_baseline=False):
        monkeypatch.setenv("ASS_UPDATE_BASELINE", "1" if update_baseline else "")
        code_ = main.main()
        out = reports / "findings.json"
        return code_, (json.loads(out.read_text()) if out.exists() else None)
    _run.code = code
    _run.config = config
    return _run


def test_findings_json_matches_the_published_schema(run):
    exit_code, doc = run()
    jsonschema.validate(doc, SCHEMA)
    assert exit_code == doc["policy"]["exit_code"] == 1
    by_cat = {f["category"]: f for f in doc["findings"]}
    assert by_cat["sast"]["cwe"] == ["CWE-78"]
    assert by_cat["sca"]["fixed_version"] == "2.2.5"


def test_a_line_shift_does_not_make_known_findings_new(run):
    assert run(update_baseline=True)[0] == 0
    # Two lines added above the flagged call; the engine now reports line 4.
    (run.code / "app.py").write_text("import os\n\n# moved down\nos.system(cmd)\n")
    native = Path(main.NATIVE_DIR) / "semgrep.sarif"
    sarif = json.loads(native.read_text())
    sarif["runs"][0]["results"][0]["locations"] = _loc("/code/app.py", 4)
    native.write_text(json.dumps(sarif))
    exit_code, doc = run()
    assert doc["baseline"] == {"enabled": True, "new": 0, "known": 3, "fixed": 0,
                               "legacy_format": False}
    assert exit_code == 0


def test_review_brief_shows_the_flagged_code_and_the_blind_spots(run):
    _, doc = run()
    brief = (Path(main.REPORTS_DIR) / "review-brief.md").read_text()
    sast = next(f for f in doc["findings"] if f["category"] == "sast")
    assert sast["fingerprint"] in brief
    assert ">   2 | os.system(cmd)" in brief
    assert "#### `flask@1.0` — 1 vulnerability (1 high)" in brief
    assert "upgrade to **2.2.5**" in brief
    assert "Cross-file data flow" in brief and "Git history" in brief
    assert "GATING" in brief


def test_the_brief_says_when_workflows_went_unchecked_or_offline(run, monkeypatch):
    (run.code / ".github" / "workflows").mkdir(parents=True)
    (run.code / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    run()                                          # zizmor not enabled
    brief = (Path(main.REPORTS_DIR) / "review-brief.md").read_text()
    assert "**CI/CD workflows:**" in brief and "zizmor is disabled" in brief

    monkeypatch.setenv("ASS_ENABLED", "semgrep trivy gitleaks zizmor")
    (Path(main.NATIVE_DIR) / "zizmor.sarif").write_text(json.dumps(_sarif([])))
    run()
    brief = (Path(main.REPORTS_DIR) / "review-brief.md").read_text()
    assert "**CI/CD online audits:** zizmor ran offline" in brief

    monkeypatch.setenv("ASS_ZIZMOR_ONLINE", "1")
    run()
    assert "CI/CD" not in (Path(main.REPORTS_DIR) / "review-brief.md").read_text()


def test_a_malicious_package_is_labelled_in_every_report(run):
    (Path(main.NATIVE_DIR) / "trivy-fs.sarif").write_text(json.dumps(_sarif(
        [{"ruleId": "GHSA-9x64-5r7x-2q53", "level": "error",
          "message": {"text": "Package: flatmap-stream\nInstalled Version: 0.1.1\n"},
          "locations": _loc("/code/package-lock.json")}],
        [{"id": "GHSA-9x64-5r7x-2q53",
          "shortDescription": {"text": "Malicious Package in flatmap-stream"},
          "properties": {"tags": ["vulnerability", "security", "HIGH"]}}])))
    _, doc = run()
    jsonschema.validate(doc, SCHEMA)
    mal = next(f for f in doc["findings"] if f["rule_id"] == "GHSA-9x64-5r7x-2q53")
    assert mal["malicious"] and mal["severity"] == "critical" and mal["scanner_severity"] == "high"
    reports = Path(main.REPORTS_DIR)
    assert "MALICIOUS PACKAGE" in (reports / "review-brief.md").read_text()
    assert "**MALICIOUS**" in (reports / "summary.md").read_text()
    assert ">MALICIOUS</span>" in (reports / "summary.html").read_text()


def test_a_denied_license_gates_like_any_sca_finding(run):
    import shutil
    shutil.copy(Path(__file__).parent / "fixtures" / "trivy" / "trivy-license.json",
                Path(main.NATIVE_DIR) / "trivy-license.json")
    run.config.write_text("licenses:\n  deny: [AGPL-*]\nfail_on:\n  sca: high\n"
                          "  default: none\nignore:\n  - rule: CVE-2023-1\n    reason: r\n")
    code, doc = run()
    jsonschema.validate(doc, SCHEMA)
    assert code == main.EXIT_POLICY                 # the AGPL dependency gates
    assert [f["rule_id"] for f in doc["findings"] if f["rule_id"].startswith("LICENSE:")] \
        == ["LICENSE:AGPL-3.0-only"]
    assert doc["licenses"]["denied"] == 1 and doc["licenses"]["unlicensed"] >= 2
    assert "trivy-license.json" in doc["reports_found"]
    assert "**License policy:**" in (Path(main.REPORTS_DIR) / "review-brief.md").read_text()

    # ...and an ignore entry suppresses it like any other finding.
    run.config.write_text(run.config.read_text() + "  - rule: 'LICENSE:AGPL-*'\n    reason: r\n")
    assert run()[0] == main.EXIT_PASS


def test_a_missing_license_report_under_strict_exits_3(run):
    run.config.write_text("strict: true\nlicenses:\n  deny: [AGPL-*]\n")
    assert run()[0] == main.EXIT_SCAN


def test_no_report_carries_the_secret_value(run):
    run()
    for name in ("review-brief.md", "findings.json", "summary.md", "summary.html"):
        assert SECRET not in (Path(main.REPORTS_DIR) / name).read_text(), name
    assert 'TOKEN = *' in (Path(main.REPORTS_DIR) / "review-brief.md").read_text()


# --- exit codes: 1 is a verdict, never an accident --------------------------

def test_a_clean_gate_exits_0(run):
    run.config.write_text("fail_on: none\n")
    assert run()[0] == main.EXIT_PASS


def test_an_invalid_config_exits_2_not_1(run):
    run.config.write_text("fail_on: severe\n")
    assert run()[0] == main.EXIT_USAGE


def test_a_malformed_expiry_exits_2(run):
    run.config.write_text("ignore:\n  - rule: CVE-1\n    reason: r\n    expires: soon\n")
    assert run()[0] == main.EXIT_USAGE


def test_a_missing_report_under_strict_exits_3(run):
    run.config.write_text("strict: true\n")
    (Path(main.NATIVE_DIR) / "semgrep.sarif").unlink()
    assert run()[0] == main.EXIT_SCAN


def test_a_collector_crash_exits_3(run, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("bug")
    monkeypatch.setattr(main, "merge", boom)
    monkeypatch.setenv("ASS_UPDATE_BASELINE", "")
    assert main.run() == main.EXIT_SCAN


def test_a_secret_in_another_findings_context_is_masked(run):
    # A SAST finding one line above the secret: its context window covers it.
    native = Path(main.NATIVE_DIR) / "semgrep.sarif"
    sarif = json.loads(native.read_text())
    sarif["runs"][0]["results"].append(
        {"ruleId": "py.debug", "level": "warning", "message": {"text": "debug"},
         "locations": _loc("/code/settings.py", 1)})
    native.write_text(json.dumps(sarif))
    run()
    brief = (Path(main.REPORTS_DIR) / "review-brief.md").read_text()
    assert "DEBUG = False" in brief and SECRET not in brief


def test_an_in_source_suppression_is_honoured_and_recorded(run):
    # `# nosemgrep` reaches us as a SARIF suppression on the result.
    native = Path(main.NATIVE_DIR) / "semgrep.sarif"
    sarif = json.loads(native.read_text())
    sarif["runs"][0]["results"][0]["suppressions"] = [{"kind": "inSource"}]
    native.write_text(json.dumps(sarif))
    _, doc = run()
    jsonschema.validate(doc, SCHEMA)
    assert not [f for f in doc["findings"] if f["category"] == "sast"]
    sup, = [s for s in doc["suppressed"] if s["category"] == "sast"]
    assert sup["reason"] == "suppressed in source (inSource)" and sup["fingerprint"]


def test_a_rejected_suppression_is_not_in_effect(run):
    native = Path(main.NATIVE_DIR) / "semgrep.sarif"
    sarif = json.loads(native.read_text())
    sarif["runs"][0]["results"][0]["suppressions"] = [{"kind": "external", "status": "rejected"}]
    native.write_text(json.dumps(sarif))
    _, doc = run()
    assert [f for f in doc["findings"] if f["category"] == "sast"]


def test_sca_is_grouped_by_component(run):
    _, doc = run()
    jsonschema.validate(doc, SCHEMA)
    comp, = doc["components"]
    sca = [f for f in doc["findings"] if f["category"] == "sca"]
    assert comp["package"] == "flask@1.0" and comp["name"] == "flask" and comp["version"] == "1.0"
    assert comp["severity"] == "high" and comp["counts"] == {"high": 1}
    assert comp["fixed_in"] == ["2.2.5"] and comp["upgrade_to"] == "2.2.5" and comp["unfixed"] == 0
    assert comp["findings"] == [f["fingerprint"] for f in sca]
    html = (Path(main.REPORTS_DIR) / "summary.html").read_text()
    assert "Vulnerable components" in html and "flask" in html


def test_provenance_records_where_the_time_went(run, monkeypatch):
    monkeypatch.setenv("ASS_ENGINE_TIMINGS", '{"semgrep": 18.4, "trivy": 5.0}')
    monkeypatch.setenv("ASS_SCAN_SECONDS", "19")
    _, doc = run()
    jsonschema.validate(doc, SCHEMA)
    t = doc["provenance"]["timings"]
    assert t["engines"] == {"semgrep": 18.4, "trivy": 5.0} and t["scanners_s"] == 19
    assert t["collector_s"] >= 0
    assert "semgrep 18.4 s" in (Path(main.REPORTS_DIR) / "summary.md").read_text()


def test_strict_fails_when_an_engine_died_mid_run(run):
    native = Path(main.NATIVE_DIR) / "semgrep.sarif"
    sarif = json.loads(native.read_text())
    sarif["runs"][0]["invocations"] = [{"executionSuccessful": True, "toolExecutionNotifications": [
        {"level": "error", "message": {"text": "engine was killed"}}]}]
    native.write_text(json.dumps(sarif))
    _, doc = run()                                   # not strict: report, flag it
    assert any("incomplete" in e for e in doc["reports_errored"])
    assert "**Incomplete report:**" in (Path(main.REPORTS_DIR) / "review-brief.md").read_text()
    run.config.write_text("strict: true\n")
    assert run()[0] == main.EXIT_SCAN


def _semgrep(results, rules):
    (Path(main.NATIVE_DIR) / "semgrep.sarif").write_text(json.dumps(_sarif(results, rules)))


def test_repeats_and_low_confidence_rules_are_one_line_each(run):
    (run.code / "app.py").write_text("import os\n" + "".join(
        f"os.system(cmd{n})\n" for n in range(6)) + "eval(x)\n")
    _semgrep([{"ruleId": "py.exec", "level": "error", "message": {"text": "exec"},
               "locations": _loc("/code/app.py", n)} for n in range(2, 8)]
             + [{"ruleId": "py.eval", "level": "error", "message": {"text": "eval"},
                 "locations": _loc("/code/app.py", 8)}],
             [{"id": "py.exec", "properties": {"tags": ["HIGH CONFIDENCE"]}},
              {"id": "py.eval", "properties": {"tags": ["LOW CONFIDENCE"]}}])
    run.config.write_text("min_confidence: medium\n")
    _, doc = run()
    jsonschema.validate(doc, SCHEMA)
    sast = [f for f in doc["findings"] if f["category"] == "sast"]
    assert {f["confidence"] for f in sast} == {"high", "low"}
    assert doc["policy"]["min_confidence"] == "medium"
    # Six exec matches gate; the low-confidence eval is reported, not gated.
    assert doc["policy"]["breaching"] == 6 + 2      # + the secret and the CVE
    brief = (Path(main.REPORTS_DIR) / "review-brief.md").read_text()
    assert brief.count("#### `app.py:") == 3        # three exec with code
    assert "### More of the same rules" in brief and "#### py.exec — 3" in brief
    assert "### Low-confidence rules (not gating)" in brief and "#### py.eval — 1" in brief
    assert ">   8 | eval(x)" not in brief            # one line, no code
    m = doc["metrics"]
    assert m["brief"]["repeated"] == 3 and m["brief"]["low_confidence"] == 1
    assert m["brief"]["approx_tokens"] > 0
    assert m["findings"]["low_confidence"] == 1 and m["findings"]["gating"] == 8


def test_every_run_ends_with_its_metrics(run, capsys):
    _, doc = run()
    out = capsys.readouterr().out
    assert "Run metrics" in out and "brief     :" in out and "findings  :" in out
    m = doc["metrics"]
    assert m["reports"] == {"read": 4, "missing": 0, "errored": 0}
    assert m["findings"]["reported"] == len(doc["findings"])
    assert SECRET not in json.dumps(m)
