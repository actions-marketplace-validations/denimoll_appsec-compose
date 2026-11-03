"""Diff mode in the collector: scope filtering, provenance, gate, brief.

Runs main.main() end to end over fixture reports and a scope.json as
scripts/diff-scope.py writes it, and holds the output to the published schema.
"""
import json
from pathlib import Path

import jsonschema
import pytest

import diffscope
import main
from config import load_config
from normalize import Finding

SCHEMA = json.loads((Path(__file__).resolve().parent.parent
                     / "schemas" / "findings.schema.json").read_text())
SHA_BASE, SHA_HEAD = "a" * 40, "b" * 40


def _sarif(results, rules=()):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "t", "rules": list(rules)}}, "results": results}]}


def _result(rule, uri, line=None, level="error", text="x"):
    region = {"region": {"startLine": line}} if line else {}
    return {"ruleId": rule, "level": level, "message": {"text": text},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, **region}}]}


def _scope(**over):
    scope = {
        "base": "main", "merge_base": SHA_BASE, "head": SHA_HEAD,
        "files": ["app.py", "settings.py"], "new_files": ["settings.py"],
        "changed_lines": {"app.py": [[4, 4]]}, "sca_dirs": [], "iac_files": [],
        "iac_context": [], "commits": 1, "history_scanned": False, "history_note": "",
        "excluded": 0, "deleted": 0,
        "parts": {"sast": True, "secrets": True, "sca": False, "iac": False},
        "skipped_engines": {"checkov": "no IaC file changed"},
        "skipped_reports": {"trivy-fs.sarif": "no dependency manifest or lock file changed",
                            "trivy-config.sarif": "no IaC file changed",
                            "checkov.sarif": "no IaC file changed"},
        "run_engines": ["semgrep", "trivy", "gitleaks"],
    }
    scope.update(over)
    return scope


@pytest.fixture
def run(tmp_path, monkeypatch):
    code, reports = tmp_path / "code", tmp_path / "reports"
    native = reports / "native"
    code.mkdir()
    native.mkdir(parents=True)
    # app.py: the change added a call on line 4 into the sink on line 2.
    (code / "app.py").write_text("import os\ndef sink(c): os.system(c)\n\nsink(input())\n")
    (code / "old.py").write_text("eval(x)\n")                  # unchanged
    (code / "requirements.txt").write_text("flask>=1.0\n")     # unchanged, unpinned
    (code / "settings.py").write_text('TOKEN = "sk_' 'live_' '9fQ2rT7x' 'Lm4Pz8Wc"\n')
    (native / "semgrep.sarif").write_text(json.dumps(_sarif([
        _result("py.exec", "/code/app.py", 2), _result("py.exec", "/code/app.py", 4),
        _result("py.eval", "/code/old.py", 1)])))
    (native / "gitleaks.sarif").write_text(json.dumps(_sarif([
        _result("generic-api-key", "/code/settings.py", 1)])))
    config = tmp_path / "scan-config.yml"
    config.write_text("fail_on: high\n")
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(_scope()))

    monkeypatch.setattr(main, "REPORTS_DIR", str(reports))
    monkeypatch.setattr(main, "NATIVE_DIR", str(native))
    monkeypatch.setattr(main, "CODE_DIR", str(code))
    monkeypatch.setattr(main, "BASELINE_PATH", str(tmp_path / "baseline.json"))
    monkeypatch.setattr(main, "DIFF_SCOPE_PATH", str(scope_file))
    monkeypatch.setattr(main, "load_config", lambda: load_config(str(config)))
    monkeypatch.setenv("ASS_ENABLED", "semgrep trivy gitleaks checkov")
    monkeypatch.setenv("ASS_DIFF", "1")
    monkeypatch.delenv("ASS_STRICT", raising=False)

    def _run(update_baseline=False, **scope_over):
        if scope_over:
            scope_file.write_text(json.dumps(_scope(**scope_over)))
        monkeypatch.setenv("ASS_UPDATE_BASELINE", "1" if update_baseline else "")
        code_ = main.main()
        out = reports / "findings.json"
        return code_, (json.loads(out.read_text()) if out.exists() else None)
    _run.native, _run.config, _run.reports = native, config, reports
    _run.baseline = tmp_path / "baseline.json"
    return _run


def test_only_the_changed_files_are_reported_and_gated(run):
    code, doc = run()
    jsonschema.validate(doc, SCHEMA)
    assert doc["schema_version"] == "1.1"
    assert sorted((f["file"], f["line"]) for f in doc["findings"]) == [
        ("app.py", 2), ("app.py", 4), ("settings.py", 1)]
    assert code == 1 and doc["policy"]["breaching"] == 3
    scope = doc["provenance"]["scope"]
    assert scope["mode"] == "diff" and scope["merge_base"] == SHA_BASE
    assert scope["files"] == 2 and scope["paths"] == ["app.py", "settings.py"]
    assert scope["out_of_scope_dropped"] == 1
    assert scope["skipped_engines"] == {"checkov": "no IaC file changed"}


def test_findings_on_changed_lines_are_marked_but_all_gate(run):
    """The sink on line 2 did not change; the call on line 4 that reaches it
    did. Both are in a changed file, so both gate — a line-level gate would
    have passed the vulnerable sink."""
    _, doc = run()
    marks = {(f["file"], f["line"]): f["on_changed_line"] for f in doc["findings"]}
    assert marks == {("app.py", 2): False, ("app.py", 4): True, ("settings.py", 1): True}


def test_skipped_engines_are_not_missing_reports_under_strict(run):
    run.config.write_text("strict: true\nfail_on: none\n")
    code, doc = run()
    assert code == main.EXIT_PASS
    assert doc["reports_missing"] == []


def test_a_crashed_engine_still_fails_strict(run):
    run.config.write_text("strict: true\nfail_on: none\n")
    (run.native / "semgrep.sarif").unlink()
    assert run()[0] == main.EXIT_SCAN


def test_skipped_sca_raises_no_coverage_warning(run):
    """requirements.txt has ranges and there is no SBOM: a full scan would warn
    (and fail under strict). In a diff that did not touch it, SCA never ran."""
    run.config.write_text("strict: true\nfail_on: none\n")
    code, doc = run()
    assert code == main.EXIT_PASS and doc["coverage"]["warnings"] == []


def test_sca_findings_follow_the_changed_manifest_directory(run):
    (run.native / "trivy-fs.sarif").write_text(json.dumps(_sarif([
        _result("CVE-1", "requirements.txt", text="Package: flask\nInstalled Version: 1.0"),
        _result("CVE-2", "web/package-lock.json",
                text="Package: lodash\nInstalled Version: 4.0")])))
    _, doc = run(sca_dirs=[""], parts={"sast": True, "secrets": True, "sca": True,
                                       "iac": False},
                 skipped_reports={"trivy-config.sarif": "no IaC file changed",
                                  "checkov.sarif": "no IaC file changed"})
    sca = [f["rule_id"] for f in doc["findings"] if f["category"] == "sca"]
    assert sca == ["CVE-1"]
    assert next(f for f in doc["findings"] if f["rule_id"] == "CVE-1")["on_changed_line"] is None


def test_a_secret_from_the_branch_history_is_in_scope(run):
    """Committed and removed again: the file no longer differs, the leak stands."""
    (run.native / "gitleaks-history.sarif").write_text(json.dumps(_sarif([
        _result("aws-access-token", "deploy/creds.txt", 1)])))
    _, doc = run(history_scanned=True)
    secret = next(f for f in doc["findings"] if f["file"] == "deploy/creds.txt")
    assert secret["on_changed_line"] is None
    assert "gitleaks-history.sarif" in doc["reports_found"]


def test_a_missing_history_report_fails_strict(run):
    run.config.write_text("strict: true\nfail_on: none\n")
    assert run(history_scanned=True)[0] == main.EXIT_SCAN


def test_baseline_gates_new_only_and_does_not_claim_fixes(run):
    run.config.write_text("fail_on: high\nbaseline: true\n")
    run.baseline.write_text(json.dumps({"fingerprints": [], "version": 2}))
    _, doc = run()
    accepted = [f["fingerprint"] for f in doc["findings"] if f["file"] == "app.py"]
    run.baseline.write_text(json.dumps({"fingerprints": accepted + ["f" * 40],
                                        "version": 2}))
    code, doc = run()
    jsonschema.validate(doc, SCHEMA)
    assert doc["baseline"]["new"] == 1 and doc["baseline"]["known"] == 2
    # "f"*40 was not seen — because nothing outside the change was looked at.
    assert doc["baseline"]["fixed"] is None
    assert code == 1 and doc["policy"]["breaching"] == 1


def test_updating_the_baseline_from_a_diff_is_refused(run):
    assert run(update_baseline=True)[0] == main.EXIT_USAGE
    assert not run.baseline.exists()


def test_the_brief_says_what_a_diff_scan_cannot_see(run):
    run()
    brief = (run.reports / "review-brief.md").read_text()
    assert "Unchanged code was not scanned" in brief
    assert "Cross-file effects of the change are not covered" in brief
    assert "Dependencies (SCA) were not checked" in brief
    assert "checkov not run: no IaC file changed" in brief
    assert "CHANGED LINE" in brief
    assert "**diff vs main" in brief
    # The working-tree-only caveat belongs to full scans.
    assert "Git history" not in brief


def test_the_summaries_show_the_scope(run):
    run()
    md = (run.reports / "summary.md").read_text()
    html = (run.reports / "summary.html").read_text()
    assert "Scope: diff vs main" in md and "unchanged code was not scanned" in md
    assert " Δ |" in md
    assert "Diff scan" in html and "&Delta; line" in html


def test_a_full_scan_records_its_scope_and_no_line_marks(run, monkeypatch):
    monkeypatch.setenv("ASS_DIFF", "")
    for name in ("trivy-fs.sarif", "trivy-config.sarif", "checkov.sarif"):
        (run.native / name).write_text(json.dumps(_sarif([])))
    _, doc = run()
    jsonschema.validate(doc, SCHEMA)
    assert doc["provenance"]["scope"] == {"mode": "full"}
    assert all("on_changed_line" not in f for f in doc["findings"])
    assert len(doc["findings"]) == 4


def test_on_changed_line_spans():
    scope = diffscope.DiffScope(base="m", merge_base=SHA_BASE, head=SHA_HEAD,
                                files=["a.py"], changed_lines={"a.py": [[10, 12]]})

    def f(line, end=None):
        return Finding(tool="semgrep", category="sast", rule_id="r", severity="high",
                       message="", file="/code/a.py", line=line, end_line=end)
    assert scope.on_changed_line(f(5, 10)) is True        # span reaches into the hunk
    assert scope.on_changed_line(f(13)) is False
    assert scope.on_changed_line(f(None)) is None
