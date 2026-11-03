"""scripts/effective-config.py: a project config states only what differs."""
import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "effective-config.py"
spec = importlib.util.spec_from_file_location("effective_config", SCRIPT)
ec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ec)


def run(tmp_path, project: str):
    (tmp_path / "p.yml").write_text(project)
    proc = subprocess.run([sys.executable, str(SCRIPT), str(ROOT / "scan-config.yml"),
                           str(tmp_path / "p.yml"), str(tmp_path / "out.yml")],
                          capture_output=True, text=True)
    out = yaml.safe_load((tmp_path / "out.yml").read_text()) if proc.returncode == 0 else None
    return proc.returncode, out, proc.stderr


def test_an_ignore_only_project_keeps_every_default_engine(tmp_path):
    code, out, _ = run(tmp_path, "ignore:\n  - rule: CVE-1\n    reason: accepted\n")
    defaults = yaml.safe_load((ROOT / "scan-config.yml").read_text())
    assert code == 0 and out["scanners"] == defaults["scanners"]
    assert out["ignore"] == [{"rule": "CVE-1", "reason": "accepted"}]


def test_mappings_merge_per_key_and_lists_replace(tmp_path):
    code, out, _ = run(tmp_path, "scanners:\n  zizmor:\n    enabled: false\n"
                                 "exclude: [vendor]\nfail_on: {secrets: low}\n")
    assert code == 0
    assert out["scanners"]["zizmor"]["enabled"] is False
    assert out["scanners"]["zizmor"]["version"]          # kept from the defaults
    assert out["scanners"]["semgrep"]["enabled"] is True
    assert out["exclude"] == ["vendor"]
    assert out["fail_on"] == {"secrets": "low"}          # scalar default replaced whole


def test_errors_name_the_project_file(tmp_path):
    code, _, err = run(tmp_path, "strickt: true\n")
    assert code == 2 and "p.yml" in err and "strict" in err
    assert run(tmp_path, "- not\n- a mapping\n")[0] == 2
    assert run(tmp_path, "fail_on: [oops\n")[0] == 2


def test_merge_is_deep_for_mappings_only():
    assert ec.merge({"a": {"b": 1, "c": 2}}, {"a": {"c": 3}}) == {"a": {"b": 1, "c": 3}}
    assert ec.merge({"a": [1, 2]}, {"a": [3]}) == {"a": [3]}
    assert ec.merge({"a": "x"}, {"a": {"k": 1}}) == {"a": {"k": 1}}
