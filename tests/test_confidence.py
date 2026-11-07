"""Rule confidence: read from the engines, merged, and kept off the gate on request."""
import json
from datetime import datetime, timezone

import pytest

import main
from config import load_config
from dedup import merge
from normalize import Finding, load_findings
from policy import breaches


def _f(confidence="", tool="semgrep", line=3, severity="high"):
    return Finding(tool=tool, category="sast", rule_id="r", severity=severity,
                   message="m", file="a.py", line=line, confidence=confidence)


def _cfg(tmp_path, text):
    p = tmp_path / "c.yml"
    p.write_text(text)
    return load_config(str(p))


def test_semgreps_confidence_tag_is_read_from_the_rule(tmp_path):
    (tmp_path / "semgrep.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "x", "properties": {"tags": ["CWE-1: y", "LOW CONFIDENCE", "security"]}}]}},
        "results": [{"ruleId": "x", "level": "error", "message": {"text": "m"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                                         "region": {"startLine": 1}}}]}]}]}))
    f = load_findings(str(tmp_path), expected={"semgrep.sarif"}).findings[0]
    assert f.confidence == "low" and f.severity == "high"


def test_a_merged_finding_is_as_sure_as_its_surest_engine():
    merged, _ = merge([_f("low"), _f("high", tool="other")])
    assert merged[0].confidence == "high"
    merged, _ = merge([_f("low"), _f("", tool="other")])
    assert merged[0].confidence == ""          # one engine states none: not "low"


def test_min_confidence_takes_less_sure_rules_off_the_gate(tmp_path):
    cfg = _cfg(tmp_path, "min_confidence: medium\n")
    assert not breaches(_f("low"), cfg)
    assert breaches(_f("medium"), cfg) and breaches(_f("high"), cfg)
    assert breaches(_f(""), cfg)               # unstated never drops off
    assert breaches(_f("low"), _cfg(tmp_path, "fail_on: high\n"))   # default: all gate


def test_min_confidence_is_validated_and_overridable(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="min_confidence"):
        _cfg(tmp_path, "min_confidence: sure\n")
    monkeypatch.setenv("ASS_MIN_CONFIDENCE", "high")
    assert _cfg(tmp_path, "min_confidence: low\n").min_confidence == "high"


def test_database_age_is_whole_days():
    now = datetime(2026, 11, 7, 12, tzinfo=timezone.utc)
    assert main._db_age_days({"trivy": "2026-11-03T01:30:30.031564361Z",
                              "grype": "garbage"}, now) == {"trivy": 4}


def test_zizmors_confidence_does_not_cost_it_its_stated_severity(tmp_path):
    (tmp_path / "zizmor.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "zizmor", "rules": [{"id": "z", "properties": {"tags": ["security"]}}]}},
        "results": [{"ruleId": "z", "level": "warning", "message": {"text": "m"},
                     "properties": {"zizmor/severity": "High", "zizmor/confidence": "Low"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "w.yml"},
                                                         "region": {"startLine": 1}}}]}]}]}))
    f = load_findings(str(tmp_path), expected={"zizmor.sarif"}).findings[0]
    assert f.confidence == "low" and f.severity == "high" and f.severity_stated
