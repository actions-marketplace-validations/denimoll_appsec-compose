"""The `appsec-compose` launcher, install.sh and the collector-image choice.

Docker is a stub on PATH (see test_run_sh.py), so these check the wiring — which
config, baseline, reports dir, cache and image a scan would get — not a scan.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

from test_run_sh import ROOT, read_env, stub_docker

LAUNCHER = ROOT / "bin" / "appsec-compose"


@pytest.fixture
def cli(tmp_path):
    bin_dir, dump = stub_docker(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "project"
    target.mkdir()
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()

    def _cli(*args, cwd=cwd, launcher=LAUNCHER, **stub):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("XDG_", "ASS_"))}
        env.update({"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(home),
                    "STUB_DUMP": str(dump),
                    **{f"STUB_{k.upper()}": str(v) for k, v in stub.items()}})
        proc = subprocess.run([str(launcher), *args], env=env, cwd=cwd,
                              capture_output=True, text=True)
        return proc
    _cli.home, _cli.target, _cli.cwd, _cli.dump = home, target, cwd, dump
    return _cli


def environ(dump):
    return dict(line.split("=", 1) for line in (dump / "environ").read_text().splitlines()
                if "=" in line)


def test_scan_picks_up_the_project_conventions(cli):
    (cli.target / ".appsec-compose.yml").write_text(
        (ROOT / "scan-config.yml").read_text() + "\n")
    (cli.target / ".appsec-baseline.json").write_text('{"fingerprints": []}')
    proc = cli("scan", str(cli.target), "--json", run=1, findings=1)
    result = json.loads(proc.stdout)
    assert proc.returncode == 1 and result["verdict"] == "fail"
    reports = cli.cwd / "appsec-reports"
    assert result["reports_dir"] == str(reports)
    assert (reports / ".gitignore").read_text().strip().endswith("*")
    env = environ(cli.dump)
    # The project file is laid over the defaults into the run's own config.
    assert f"Config   : {cli.target / '.appsec-compose.yml'}" in proc.stderr
    assert "/.run/run." in env["ASS_CONFIG_FILE"]
    assert env["ASS_BASELINE_FILE"] == str(cli.target / ".appsec-baseline.json")
    assert env["ASS_CACHE_DIR"] == str(cli.home / ".cache" / "appsec-compose")
    assert env["COMPOSE_PROJECT_NAME"] == "appsec-project"


def test_explicit_flags_win_over_conventions(cli, tmp_path):
    (cli.target / ".appsec-compose.yml").write_text("strickt: true\n")   # would fail
    own = tmp_path / "own.yml"
    own.write_text((ROOT / "scan-config.yml").read_text())
    proc = cli("scan", str(cli.target), "--config", str(own),
               "--reports", str(tmp_path / "r"), "--name", "a-own", run=0, findings=1)
    assert proc.returncode == 0, proc.stderr
    env = environ(cli.dump)
    assert f"Config   : {own}" in proc.stdout + proc.stderr
    assert env["ASS_REPORTS_DIR"] == str(tmp_path / "r")
    assert env["COMPOSE_PROJECT_NAME"] == "appsec-a-own"


def test_no_baseline_file_is_created_in_the_project_uninvited(cli):
    proc = cli("scan", str(cli.target), run=0, findings=1)
    assert proc.returncode == 0, proc.stderr
    assert not (cli.target / ".appsec-baseline.json").exists()
    assert "ASS_BASELINE_FILE" not in environ(cli.dump)


def test_update_baseline_writes_the_project_baseline(cli):
    proc = cli("scan", str(cli.target), "--update-baseline", run=0)
    assert proc.returncode == 0, proc.stderr
    assert (cli.target / ".appsec-baseline.json").exists()


def test_scanning_the_current_directory_excludes_its_reports(cli):
    proc = cli("scan", "--json", cwd=cli.target, run=0, findings=1)   # path defaults to .
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["reports_dir"] == str(cli.target / "appsec-reports")
    assert "--exclude=appsec-reports" in read_env(cli.dump / "env")["SEMGREP_EXCLUDES"]


def test_a_missing_target_is_a_usage_error_in_json_too(cli):
    proc = cli("scan", str(cli.target / "nope"), "--json")
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["verdict"] == "usage_error"


def test_an_unknown_command_is_a_usage_error(cli):
    proc = cli("frobnicate", "--json")
    assert proc.returncode == 2 and json.loads(proc.stdout)["verdict"] == "usage_error"
    assert cli("frobnicate").returncode == 2


def test_the_launcher_works_through_a_symlink(cli, tmp_path):
    link_dir = tmp_path / "links"
    link_dir.mkdir()
    (link_dir / "appsec-compose").symlink_to(LAUNCHER)
    proc = cli("version", launcher=link_dir / "appsec-compose")
    assert proc.returncode == 0, proc.stderr
    assert f"install: {ROOT}" in proc.stdout and "appsec-compose " in proc.stdout


# ---- install.sh --------------------------------------------------------------

def run_install(cli, *args, path_prefix=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("XDG_", "ASS_"))}
    bin_dir = path_prefix or (cli.dump.parent / "bin")
    env.update({"HOME": str(cli.home), "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "STUB_DUMP": str(cli.dump)})
    return subprocess.run([str(ROOT / "install.sh"), *args], env=env, cwd=cli.cwd,
                          capture_output=True, text=True)


def test_install_from_a_local_checkout_is_idempotent(cli):
    for _ in range(2):
        proc = run_install(cli, "--from", str(ROOT))
        assert proc.returncode == 0, proc.stderr
    dest = cli.home / ".local" / "share" / "appsec-compose" / "local"
    link = cli.home / ".local" / "bin" / "appsec-compose"
    assert link.is_symlink() and link.resolve() == (dest / "bin" / "appsec-compose").resolve()
    assert not (dest / ".git").exists() and (dest / "run.sh").exists()
    assert "Uninstall" in proc.stderr
    version = cli("version", launcher=link)
    assert version.returncode == 0 and f"install: {dest}" in version.stdout


def test_install_names_every_missing_prerequisite(cli, tmp_path):
    # A docker without the compose v2 plugin.
    no_compose = tmp_path / "nocompose"
    no_compose.mkdir()
    (no_compose / "docker").write_text(
        '#!/bin/sh\n[ "$1" = compose ] && exit 1\nexit 0\n')
    (no_compose / "docker").chmod(0o755)
    proc = run_install(cli, "--from", str(ROOT), path_prefix=no_compose)
    assert proc.returncode == 1
    assert "docker compose v2" in proc.stderr and "Nothing was installed" in proc.stderr
    assert not (cli.home / ".local" / "bin" / "appsec-compose").exists()


# ---- scripts/collector-image.sh ---------------------------------------------------

IMAGE_STUB = """#!/bin/sh
echo "$*" >> "$STUB_DUMP/calls"
for last; do :; done
case "$1" in
  image)
    case "$last" in
      appsec-compose-collector:local-*) [ -n "$STUB_HAVE_LOCAL" ] || exit 1 ;;
      *) [ -n "$STUB_HAVE_PUBLISHED" ] || [ -f "$STUB_DUMP/pulled" ] || exit 1 ;;
    esac
    case " $* " in *" --format "*) echo "$STUB_LABEL" ;; esac
    exit 0 ;;
  pull) [ -n "$STUB_PULLABLE" ] || exit 1; touch "$STUB_DUMP/pulled"; exit 0 ;;
  build) exit "${STUB_BUILD:-0}" ;;
esac
exit 0
"""

HASH = subprocess.run([str(ROOT / "scripts" / "collector-image.sh"), "--hash"],
                      capture_output=True, text=True, check=True).stdout.strip()
VERSION = (ROOT / "VERSION").read_text().strip()
PUBLISHED = f"ghcr.io/denimoll/appsec-compose-collector:v.{VERSION}"
LOCAL = f"appsec-compose-collector:local-{HASH[:12]}"


@pytest.fixture
def pick(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(IMAGE_STUB)
    (bin_dir / "docker").chmod(0o755)

    def _pick(*args, **stub):
        env = {k: v for k, v in os.environ.items() if k != "ASS_COLLECTOR_IMAGE"}
        env.update({"PATH": f"{bin_dir}:{os.environ['PATH']}", "STUB_DUMP": str(tmp_path),
                    **{(k if k.startswith("ASS_") else f"STUB_{k.upper()}"): str(v)
                       for k, v in stub.items()}})
        proc = subprocess.run([str(ROOT / "scripts" / "collector-image.sh"), *args],
                              env=env, capture_output=True, text=True)
        calls = (tmp_path / "calls").read_text() if (tmp_path / "calls").exists() else ""
        return proc.returncode, proc.stdout.strip(), calls
    return _pick


def test_a_previous_local_build_of_this_content_is_reused(pick):
    code, image, calls = pick(have_local=1)
    assert (code, image) == (0, LOCAL) and "pull" not in calls and "build" not in calls


def test_the_published_image_is_used_when_its_label_matches(pick):
    code, image, calls = pick(have_published=1, label=HASH)
    assert (code, image) == (0, PUBLISHED) and "pull" not in calls


def test_the_published_image_is_pulled_when_absent(pick):
    code, image, calls = pick(pullable=1, label=HASH)
    assert (code, image) == (0, PUBLISHED) and f"pull -q {PUBLISHED}" in calls


@pytest.mark.parametrize("stub", [
    {"pullable": 1, "label": "something-else"},       # a dev checkout's edits
    {"pullable": 0},                                   # unreleased VERSION
    {"have_published": 1, "label": "something-else"},  # stale local copy: no re-pull
])
def test_anything_else_builds_locally(pick, stub):
    code, image, calls = pick(**stub)
    assert (code, image) == (0, LOCAL) and "build" in calls
    if stub.get("have_published"):
        assert "pull" not in calls


def test_offline_never_pulls(pick):
    code, image, calls = pick("--offline", pullable=1, label=HASH)
    assert (code, image) == (0, LOCAL) and "pull" not in calls


def test_an_explicit_image_is_used_as_is(pick):
    code, image, calls = pick(ASS_COLLECTOR_IMAGE="mirror.local/collector:1")
    assert (code, image, calls) == (0, "mirror.local/collector:1", "")


def test_a_failed_build_fails(pick):
    assert pick(build=1)[0] == 1


def test_mcp_without_setup_says_how_and_keeps_stdout_clean(tmp_path):
    # stdout is the MCP stdio channel: a stray line there breaks the client.
    env = {**os.environ, "XDG_DATA_HOME": str(tmp_path / "data")}
    proc = subprocess.run([str(LAUNCHER), "mcp"], env=env, capture_output=True, text=True)
    assert proc.returncode == 2
    assert proc.stdout == "" and "appsec-compose mcp --setup" in proc.stderr


def test_a_new_build_drops_superseded_local_images(pick, tmp_path):
    code, image, calls = pick(build=0)
    assert code == 0 and image == LOCAL
    assert "images --format" in calls          # pruning ran without failing the pick


def test_a_repos_config_is_passed_as_untrusted_and_can_be_refused(cli):
    (cli.target / ".appsec-compose.yml").write_text(
        'fail_on: none\nscanners: {semgrep: {version: "evil"}}\n')
    (cli.target / ".appsec-baseline.json").write_text('{"fingerprints": []}')
    proc = cli("scan", str(cli.target), "--json", run=0, findings=1)
    assert proc.returncode == 0 and "the repository's own; project policy only" in proc.stderr
    assert "scanners.semgrep.version" in proc.stderr
    assert '"scanners.semgrep.version"' in environ(cli.dump)["ASS_REPO_CONFIG"]
    proc = cli("scan", str(cli.target), "--no-repo-config", "--json", run=0, findings=1)
    env = environ(cli.dump)
    assert proc.returncode == 0 and "the repository's own" not in proc.stderr
    assert "ASS_REPO_CONFIG" not in env or not env["ASS_REPO_CONFIG"]
    assert str(cli.target) not in env.get("ASS_BASELINE_FILE", "")
