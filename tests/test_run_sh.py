"""run.sh exit codes, with `docker` replaced by a stub on PATH.

The unit tests cannot see the wrapper, and the wrapper is where a failure most
easily turns into a misleading 1: compose reports its own errors as 1, and so
does bash under `set -e`. These pin the mapping without starting a container.
"""
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

STUB = """#!/bin/sh
[ -n "$STUB_LOG" ] && echo "$*" >> "$STUB_LOG"
case " $* " in
  *" up "*) exit "${STUB_UP:-0}" ;;
  *" run "*)
    [ -n "$STUB_FINDINGS" ] && echo '{}' > "$ASS_REPORTS_DIR/findings.json"
    exit "${STUB_RUN:-0}" ;;
esac
exit 0
"""


@pytest.fixture
def scan(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(STUB)
    (bin_dir / "docker").chmod(0o755)
    target = tmp_path / "repo"
    target.mkdir()
    config = tmp_path / "scan-config.yml"
    config.write_text((ROOT / "scan-config.yml").read_text())

    def _scan(*args, target_dir=target, **stub):
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
               **{f"STUB_{k.upper()}": str(v) for k, v in stub.items()}}
        cmd = [str(ROOT / "run.sh"), str(target_dir), "--config", str(config),
               "--reports", str(tmp_path / "reports"),
               "--baseline", str(tmp_path / "baseline.json"), "--name", "exit-test",
               *args]
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=tmp_path)
        _scan.stdout = proc.stdout
        return proc.returncode, proc.stderr
    _scan.config = config
    _scan.target = target
    return _scan


def test_a_verdict_passes_through(scan):
    assert scan(run=0, findings=1)[0] == 0
    assert scan(run=1, findings=1)[0] == 1


def test_a_fail_without_a_verdict_is_a_broken_scan(scan):
    # e.g. the collector image failed to build: compose says 1, no report exists
    code, err = scan(run=1)
    assert code == 3 and "did not produce a verdict" in err


def test_docker_being_down_is_not_a_finding(scan):
    code, err = scan(up=1)
    assert code == 3 and "scan aborted" in err


def test_collector_codes_2_and_3_pass_through(scan):
    assert scan(run=2)[0] == 2
    assert scan(run=3)[0] == 3


def test_an_unexpected_collector_code_is_a_broken_scan(scan):
    assert scan(run=137, findings=1)[0] == 3       # OOM-killed


@pytest.mark.parametrize("content", ["fail_on: [unclosed\n", "strickt: true\n", "- a\n- b\n"])
def test_config_errors_exit_2(scan, content):
    scan.config.write_text(content)
    code, err = scan(run=0, findings=1)
    assert code == 2 and "ERROR" in err


def test_a_missing_target_exits_2(scan, tmp_path):
    assert scan(target_dir=tmp_path / "nope")[0] == 2


# --- diff mode -----------------------------------------------------------------

_GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull}


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                   env={**os.environ, **_GIT_ENV})


@pytest.fixture
def repo(scan):
    r = scan.target
    _git(r, "init", "-q", "-b", "main")
    (r / "app.py").write_text("print(1)\n")
    _git(r, "add", ".")
    _git(r, "commit", "-qm", "init")
    return r


def _calls(log):
    return log.read_text().splitlines() if log.exists() else []


def test_diff_starts_only_the_engines_with_something_to_scan(scan, repo, tmp_path):
    (repo / "app.py").write_text("print(2)\n")             # uncommitted code edit
    log = tmp_path / "docker.log"
    code, err = scan("--diff", "main", run=0, findings=1, log=log)
    assert code == 0, err
    up = [c for c in _calls(log) if " up " in f" {c} "]
    assert len(up) == 1 and up[0].split()[-2:] == ["semgrep", "gitleaks"]
    assert "Diff     : vs main" in scan.stdout and "1 changed file(s)" in scan.stdout
    assert "trivy (no dependency manifest" in scan.stdout


def test_a_diff_with_nothing_in_it_starts_no_engine(scan, repo, tmp_path):
    log = tmp_path / "docker.log"
    assert scan("--diff", "main", run=0, findings=1, log=log)[0] == 0
    calls = _calls(log)
    assert not [c for c in calls if " up " in f" {c} "]
    assert [c for c in calls if " run " in f" {c} "]         # the collector still runs


@pytest.mark.parametrize("args,message", [
    (("--diff", "nope"), "unknown ref 'nope'"),
    (("--diff",), "needs a base ref"),
    (("--diff", "--strict"), "needs a base ref"),
    (("--diff", "main", "--update-baseline"), "needs a full scan"),
])
def test_diff_usage_errors_exit_2(scan, repo, args, message):
    code, err = scan(*args, run=0, findings=1)
    assert code == 2 and message in err


def test_diff_outside_a_git_repo_exits_2(scan):
    code, err = scan("--diff", "main", run=0, findings=1)
    assert code == 2 and "git repository" in err


def test_diff_with_an_image_exits_2(scan, tmp_path):
    env = {**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    proc = subprocess.run([str(ROOT / "run.sh"), "--image", "alpine:3", "--diff", "main",
                           "--config", str(scan.config), "--reports", str(tmp_path / "r"),
                           "--name", "exit-test"],
                          env=env, capture_output=True, text=True, cwd=tmp_path)
    assert proc.returncode == 2 and "--image/--build" in proc.stderr
