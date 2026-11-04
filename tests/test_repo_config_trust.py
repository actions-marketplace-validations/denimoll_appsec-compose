"""A scanned repository's own config is not trusted like one the user passes."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "effective-config.py"
spec = importlib.util.spec_from_file_location("effective_config_trust", SCRIPT)
ec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ec)


def run(tmp_path, repo_text, *before):
    (tmp_path / ".appsec-compose.yml").write_text(repo_text)
    proc = subprocess.run([sys.executable, str(SCRIPT), str(ROOT / "scan-config.yml"), *before,
                           "--repo", str(tmp_path / ".appsec-compose.yml"), str(tmp_path / "out.yml")],
                          capture_output=True, text=True)
    out = yaml.safe_load((tmp_path / "out.yml").read_text()) if proc.returncode == 0 else None
    return proc, out


def test_a_repo_cannot_redirect_keys_or_pick_images(tmp_path):
    defaults = yaml.safe_load((ROOT / "scan-config.yml").read_text())
    proc, out = run(tmp_path, """
enrich: {cve_paas: {enabled: true, url: "https://evil.example", fail_on_exploitable: false}}
scanners:
  semgrep: {version: "evil", rules: ["https://evil.example/r.yml"]}
  trufflehog: {enabled: true, verify: true}
  checkov: {frameworks: ["x --output /reports/y"], guidelines: true}
secrets_history_range: "--output=/reports/x"
""")
    assert proc.returncode == 0
    assert out["enrich"] == defaults.get("enrich")
    assert out["scanners"]["semgrep"]["version"] == defaults["scanners"]["semgrep"]["version"]
    assert out["scanners"]["semgrep"].get("rules") == defaults["scanners"]["semgrep"].get("rules")
    assert out["scanners"]["trufflehog"]["enabled"] is True          # policy: allowed
    assert not out["scanners"]["trufflehog"].get("verify")
    assert "frameworks" not in out["scanners"]["checkov"]
    assert "secrets_history_range" not in defaults or out["secrets_history_range"] == defaults["secrets_history_range"]
    report = json.loads(proc.stdout)
    assert {"enrich", "secrets_history_range", "scanners.semgrep.version",
            "scanners.trufflehog.verify"} <= set(report["dropped"])
    assert "ignored from" in proc.stderr


def test_project_policy_still_applies_and_is_reported(tmp_path):
    proc, out = run(tmp_path, """
fail_on: none
exclude: [src]
ignore: [{rule: CVE-1, reason: accepted}]
scanners: {semgrep: {rules: [default, auto]}, zizmor: {enabled: false}}
""")
    assert out["fail_on"] == "none" and out["exclude"] == ["src"]
    assert out["scanners"]["semgrep"]["rules"] == ["default", "auto"]
    assert out["scanners"]["zizmor"]["enabled"] is False
    report = json.loads(proc.stdout)
    assert report["file"] == ".appsec-compose.yml" and report["dropped"] == []
    assert {"fail_on", "exclude", "ignore"} <= set(report["applied"])


def test_exclude_entries_cannot_smuggle_engine_options(tmp_path):
    proc, out = run(tmp_path, 'exclude: ["ok/dir", "a --config /x", "--output=y", "$(id)"]\n')
    assert out["exclude"] == ["ok/dir"]
    assert "exclude (unsafe entries)" in json.loads(proc.stdout)["dropped"]


def test_an_explicit_config_stays_trusted(tmp_path):
    own = tmp_path / "own.yml"
    own.write_text('scanners: {semgrep: {version: "1.2.3"}}\n')
    proc = subprocess.run([sys.executable, str(SCRIPT), str(ROOT / "scan-config.yml"), str(own),
                           str(tmp_path / "out.yml")], capture_output=True, text=True)
    assert proc.returncode == 0 and proc.stdout == ""
    assert yaml.safe_load((tmp_path / "out.yml").read_text())["scanners"]["semgrep"]["version"] == "1.2.3"


def test_the_allowlist_refuses_what_it_does_not_know():
    kept, dropped = ec.apply_repo_policy({"some_future_key": 1})
    assert kept == {} and dropped == ["some_future_key"]
