"""Code scanning gets SARIF without what the code itself suppresses."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "sarif-for-upload.py"
spec = importlib.util.spec_from_file_location("sarif_for_upload", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_in_source_suppressions_are_left_out_of_the_upload(tmp_path):
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": [
        {"ruleId": "a", "suppressions": [{"kind": "inSource"}]},
        {"ruleId": "b"},
        {"ruleId": "c", "suppressions": [{"kind": "external", "status": "underReview"}]},
        {"ruleId": "d", "suppressions": [{"kind": "inSource", "status": "accepted"}]},
    ]}]}
    src, out = tmp_path / "in.sarif", tmp_path / "out.sarif"
    src.write_text(json.dumps(doc))
    proc = subprocess.run([sys.executable, str(SCRIPT), str(src), str(out)],
                          capture_output=True, text=True, check=True)
    assert [r["ruleId"] for r in json.loads(out.read_text())["runs"][0]["results"]] == ["b", "c"]
    assert "2 result(s)" in proc.stdout
    assert json.loads(src.read_text()) == doc                    # native stays whole
