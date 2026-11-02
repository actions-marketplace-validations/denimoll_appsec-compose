"""Tests for scripts/render-env.py (loaded by path — its name isn't importable)."""
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def renv():
    spec = importlib.util.spec_from_file_location(
        "render_env", ROOT / "scripts" / "render-env.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_image_ref_accepts_tags_and_digests(renv):
    assert renv._image_ref("aquasec/trivy", "0.74.0") == "aquasec/trivy:0.74.0"
    assert renv._image_ref("r", "sha256:abc") == "r@sha256:abc"
    assert renv._image_ref("r", "@sha256:abc") == "r@sha256:abc"


def test_path_regex_anchors_on_path_segments(renv):
    rx = re.compile(renv._path_regex("node_modules"))
    assert rx.search("a/node_modules/b") and rx.search("node_modules/b")
    assert not rx.search("my_node_modules_backup/b")


def test_path_regex_escapes_dots(renv):
    rx = re.compile(renv._path_regex(".venv"))
    assert rx.search("x/.venv/lib") and not rx.search("x/avenv/lib")


def test_every_engine_gets_an_exclusion(renv):
    flags = renv._exclude_flags(["node_modules"])
    assert flags["SEMGREP_EXCLUDES"] == "--exclude=node_modules"
    assert flags["TRIVY_SKIP_DIRS"] == "--skip-dirs=**/node_modules"
    assert flags["OSV_EXCLUDES"] == "--experimental-exclude=node_modules"
    assert flags["HADOLINT_PRUNE"] == "-not -path */node_modules/*"
    # grype/syft take a comma-separated list covering top level and nested.
    assert flags["SYFT_EXCLUDE"] == "./node_modules/**,./**/node_modules/**"
    assert flags["GRYPE_EXCLUDE"] == flags["SYFT_EXCLUDE"]


def test_exclude_values_carry_no_quotes(renv):
    """The .env parser has no escapes and the container shell runs `set -f`."""
    for value in renv._exclude_flags(["node_modules", ".venv", "docs/**"]).values():
        assert "'" not in value and '"' not in value


def test_glob_entries_skip_engines_that_only_take_names(renv):
    flags = renv._exclude_flags(["docs/**"])
    assert flags["OSV_EXCLUDES"] == ""             # takes a directory name only


def test_a_file_glob_reaches_trivys_file_exclusion_too(renv):
    """--skip-dirs alone never excludes a file, so a glob feeds both flags."""
    flags = renv._exclude_flags(["*.log"])
    assert flags["TRIVY_SKIP_DIRS"] == "--skip-dirs=*.log --skip-files=*.log"
    assert flags["SYFT_EXCLUDE"] == "./*.log,./**/*.log"   # nested logs too


def test_empty_entries_are_dropped(renv):
    assert renv._exclude_flags(["", "  ", None if False else "/x/"])["SEMGREP_EXCLUDES"] \
        == "--exclude=x"


def test_write_exclude_files_generates_engine_configs(renv, tmp_path):
    renv._write_exclude_files(["node_modules", ".venv"], tmp_path / "excludes")
    toml = (tmp_path / "excludes" / "gitleaks.toml").read_text()
    assert "useDefault = true" in toml and "[[allowlists]]" in toml
    assert toml.count("'''") == 4                  # two quoted regexes
    lines = (tmp_path / "excludes" / "trufflehog.txt").read_text().split()
    assert len(lines) == 2 and all(re.compile(l) for l in lines)


def test_write_exclude_files_with_no_excludes_still_writes_valid_configs(
        renv, tmp_path):
    renv._write_exclude_files([], tmp_path / "excludes")
    toml = (tmp_path / "excludes" / "gitleaks.toml").read_text()
    assert "useDefault = true" in toml and "[[allowlists]]" not in toml
    assert (tmp_path / "excludes" / "trufflehog.txt").read_text() == ""


def test_out_dir_keeps_a_run_out_of_the_tool_directory(tmp_path):
    """run.sh renders per run; nothing may land in (or race on) the shared dir."""
    import os
    import subprocess
    import sys
    env_file = ROOT / ".env"
    before = env_file.stat().st_mtime_ns if env_file.exists() else None
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "render-env.py"),
         "--out-dir", str(tmp_path / "run")],
        capture_output=True, text=True, check=True,
        env={**os.environ, "ASS_CONFIG_FILE": str(ROOT / "scan-config.yml")})
    assert "ASS_ENABLED=" in out.stdout
    assert "SEMGREP_IMAGE=" in (tmp_path / "run" / ".env").read_text()
    assert (tmp_path / "run" / "excludes" / "gitleaks.toml").is_file()
    assert (tmp_path / "run" / "excludes" / "trufflehog.txt").is_file()
    after = env_file.stat().st_mtime_ns if env_file.exists() else None
    assert before == after


def test_is_pinned_detects_digest_refs(renv):
    assert renv._is_pinned({"T_IMAGE": "r@sha256:abc"}, "T", {}) is True
    assert renv._is_pinned({"T_IMAGE": "r:1.0"}, "T", {}) is False


def test_tool_defaults_cover_every_scanner_in_the_shipped_config(renv):
    import yaml
    cfg = yaml.safe_load((ROOT / "scan-config.yml").read_text())
    assert set(cfg["scanners"]) == set(renv.TOOLS)


def test_shipped_defaults_keep_one_engine_per_category_enabled(renv):
    """Out of the box the scan must stay light: alternates are opt-in."""
    import yaml
    cfg = yaml.safe_load((ROOT / "scan-config.yml").read_text())
    enabled = {n for n, c in cfg["scanners"].items() if (c or {}).get("enabled")}
    assert enabled == {"semgrep", "trivy", "gitleaks", "checkov"}


def test_smoke_test_fixture_exercises_every_category(renv):
    """The fixture must keep tripping each engine, or the smoke test proves nothing."""
    fixture = ROOT / "tests" / "fixtures" / "vulnerable-repo"
    present = {p.name for p in fixture.rglob("*")}
    assert {"Dockerfile", "requirements.txt", "app.py", "config.env"} <= present
    reqs = (fixture / "requirements.txt").read_text()
    assert "==" in reqs, "dependencies must be pinned or SCA resolves nothing"
