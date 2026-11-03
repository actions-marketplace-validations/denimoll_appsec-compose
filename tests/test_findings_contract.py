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


SECRET = "sk_live_9fQ2rT7xLm4Pz8Wc"


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
    assert "flask@1.0` → fixed in 2.2.5" in brief
    assert "Cross-file data flow" in brief and "Git history" in brief
    assert "GATING" in brief


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
