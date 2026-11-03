"""run.sh exit codes, with `docker` replaced by a stub on PATH.

The unit tests cannot see the wrapper, and the wrapper is where a failure most
easily turns into a misleading 1: compose reports its own errors as 1, and so
does bash under `set -e`. These pin the mapping without starting a container.

The stub also records what run.sh handed to compose (the rendered .env, the
generated exclude files, the environment) into STUB_DUMP, so the tests can see
what the engines would have been told.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

STUB = """#!/bin/sh
dump="$STUB_DUMP"
echo "$*" >> "$dump/calls"
prev=""
for a in "$@"; do
  if [ "$prev" = "--env-file" ]; then cp "$a" "$dump/env"; fi
  prev="$a"
done
[ -n "$STUB_LOG" ] && echo "$*" >> "$STUB_LOG"
case " $* " in
  *" up "*)
    cp "$ASS_EXCLUDES_DIR/trufflehog.txt" "$dump/trufflehog.txt" 2>/dev/null
    env > "$dump/environ"
    exit "${STUB_UP:-0}" ;;
  *" run "*)
    if [ -n "$STUB_FINDINGS" ]; then
      printf '%s' '{"severity_counts": {"high": 2, "low": 1}, "policy": {"breaching": 2},
        "baseline": {"enabled": false, "new": null}}' > "$ASS_REPORTS_DIR/findings.json"
      echo brief > "$ASS_REPORTS_DIR/review-brief.md"
    fi
    exit "${STUB_RUN:-0}" ;;
  *" image inspect "*) exit "${STUB_INSPECT:-0}" ;;
  *" build "*) exit "${STUB_BUILD:-0}" ;;
esac
exit 0
"""


def stub_docker(tmp_path):
    """A bin dir holding the stub, and the dir it dumps into."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(STUB)
    (bin_dir / "docker").chmod(0o755)
    dump = tmp_path / "dump"
    dump.mkdir()
    return bin_dir, dump


def read_env(path):
    """The rendered .env as a dict (values are single-quoted)."""
    out = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            out[key] = value.strip("'")
    return out


@pytest.fixture
def scan(tmp_path):
    bin_dir, dump = stub_docker(tmp_path)
    target = tmp_path / "repo"
    target.mkdir()
    config = tmp_path / "scan-config.yml"
    config.write_text((ROOT / "scan-config.yml").read_text())

    def _scan(*args, target_dir=target, **stub):
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
               "STUB_DUMP": str(dump), "ASS_CACHE_DIR": str(tmp_path / "cache"),
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
    _scan.dump = dump
    _scan.reports = tmp_path / "reports"
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


def test_a_collector_that_cannot_be_built_is_a_broken_scan(scan):
    # No local build, no pullable image (the stub's pull "succeeds" but the
    # image carries no matching label), and the build fails.
    code, err = scan(inspect=1, build=1, run=0, findings=1)
    assert code == 3 and "could not build the collector" in err


# ---- --json ---------------------------------------------------------------

def one_json_object(stdout):
    """stdout must be exactly one JSON object and nothing else."""
    lines = stdout.strip().splitlines()
    assert len(lines) == 1, stdout
    obj = json.loads(lines[0])
    assert set(obj) >= {"exit_code", "verdict", "reports_dir", "findings_json",
                        "review_brief", "severity_counts", "breaching", "baseline"}
    return obj


@pytest.mark.parametrize("stub, code, verdict", [
    ({"run": 0, "findings": 1}, 0, "pass"),
    ({"run": 1, "findings": 1}, 1, "fail"),
    ({"run": 2}, 2, "usage_error"),
    ({"up": 1}, 3, "scan_error"),
    ({"run": 1}, 3, "scan_error"),           # a "fail" with no verdict behind it
])
def test_json_answers_every_exit_code(scan, stub, code, verdict):
    rc, err = scan("--json", **stub)
    obj = one_json_object(scan.stdout)
    assert rc == code and obj["exit_code"] == code and obj["verdict"] == verdict
    assert "Target" in err                   # the human output went to stderr


def test_json_carries_the_verdict_details(scan):
    rc, _ = scan("--json", run=1, findings=1)
    obj = one_json_object(scan.stdout)
    assert obj["reports_dir"] == str(scan.reports)
    assert obj["findings_json"] == str(scan.reports / "findings.json")
    assert obj["review_brief"] == str(scan.reports / "review-brief.md")
    assert obj["severity_counts"] == {"high": 2, "low": 1}
    assert obj["breaching"] == 2
    assert obj["baseline"] is None           # not enabled -> null


def test_json_on_a_bad_flag(scan):
    rc, err = scan("--json", "--bogus")
    obj = one_json_object(scan.stdout)
    assert rc == 2 and obj["verdict"] == "usage_error" and "Unknown argument" in err


def test_json_on_a_config_error(scan):
    scan.config.write_text("strickt: true\n")
    rc, _ = scan("--json")
    assert rc == 2 and one_json_object(scan.stdout)["verdict"] == "usage_error"


def test_json_never_reports_a_previous_runs_findings(scan, tmp_path):
    # A usage error stops before the old reports are cleared; they must not be
    # passed off as this run's.
    scan.reports.mkdir(parents=True, exist_ok=True)
    (scan.reports / "findings.json").write_text('{"severity_counts": {"high": 9}}')
    rc, _ = scan("--json", target_dir=tmp_path / "nope")
    obj = one_json_object(scan.stdout)
    assert rc == 2 and obj["findings_json"] is None and obj["severity_counts"] is None


def test_without_json_stdout_stays_human(scan):
    scan(run=0, findings=1)
    assert "Done." in scan.stdout


# ---- reports inside the scanned tree ---------------------------------------

def test_reports_inside_the_target_are_excluded(scan):
    reports = scan.target / "appsec-reports"
    code, _ = scan("--reports", str(reports), run=0, findings=1)
    assert code == 0 and "Excluded : appsec-reports" in scan.stdout
    env = read_env(scan.dump / "env")
    assert "--exclude=appsec-reports" in env["SEMGREP_EXCLUDES"]
    assert "--skip-dirs=**/appsec-reports" in env["TRIVY_SKIP_DIRS"]
    assert "appsec-reports" in env["ASS_EXCLUDES"].split()
    assert r"(^|/)appsec\-reports(/|$)" in (scan.dump / "trufflehog.txt").read_text()


def test_nested_reports_are_excluded_by_relative_path(scan):
    code, _ = scan("--reports", str(scan.target / "out" / "scan"), run=0, findings=1)
    assert code == 0
    assert "--exclude=out/scan" in read_env(scan.dump / "env")["SEMGREP_EXCLUDES"]


def test_reports_outside_the_target_add_no_exclusion(scan):
    code, _ = scan(run=0, findings=1)
    assert code == 0 and "Excluded" not in scan.stdout
    assert "reports" not in read_env(scan.dump / "env")["ASS_EXCLUDES"]


def test_reports_must_not_be_the_target_itself(scan):
    code, err = scan("--reports", str(scan.target))
    assert code == 2 and "must not be the scan target" in err


# ---- cache location ------------------------------------------------------

def test_the_cache_dir_is_handed_to_compose(scan, tmp_path):
    scan(run=0, findings=1)
    environ = (scan.dump / "environ").read_text().splitlines()
    assert f"ASS_CACHE_DIR={tmp_path / 'cache'}" in environ
    assert (tmp_path / "cache" / "trivy").is_dir()
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
