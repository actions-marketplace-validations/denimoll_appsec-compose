"""scripts/diff-scope.py: the changed set, computed with git on real repos."""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import coverage
import diffscope
import normalize

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("diff_scope", ROOT / "scripts" / "diff-scope.py")
ds = importlib.util.module_from_spec(_spec)
sys.modules["diff_scope"] = ds          # dataclasses look their module up
_spec.loader.exec_module(ds)

DEFAULT = ["semgrep", "trivy", "gitleaks", "checkov"]
_GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull}


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                          text=True, env={**os.environ, **_GIT_ENV}).stdout


def write(repo, rel, text):
    path = Path(repo, rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture
def repo(tmp_path):
    """main: a small app. feat: one commit, then uncommitted and untracked edits."""
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    write(r, "app.py", "import os\n\ndef run(cmd):\n    return cmd\n")
    write(r, "lib/util.py", "a = 1\nb = 2\nc = 3\n")
    write(r, "gone.py", "x = 1\n")
    write(r, "old_name.py", "".join(f"line{i} = {i}\n" for i in range(20)))
    write(r, "requirements.txt", "flask==1.0\n")
    write(r, "infra/main.tf", 'resource "aws_s3_bucket" "b" {\n  bucket = var.name\n}\n')
    write(r, "infra/vars.tf", 'variable "name" {}\n')
    write(r, "infra/README.md", "docs\n")
    write(r, ".gitignore", "ignored.py\n")
    git(r, "add", ".")
    git(r, "commit", "-qm", "init")
    git(r, "checkout", "-qb", "feat")
    # Committed on the branch: a modified line and a new file.
    write(r, "app.py", "import os\n\ndef run(cmd):\n    return os.system(cmd)\n")
    write(r, "new.py", "print(1)\n")
    git(r, "add", ".")
    git(r, "commit", "-qm", "change")
    # Uncommitted: an edit, a rename with an edit, a deletion; untracked and ignored files.
    write(r, "lib/util.py", "a = 1\nb = 20\nc = 3\nd = 4\n")
    git(r, "mv", "old_name.py", "new_name.py")
    write(r, "new_name.py", "".join(f"line{i} = {i}\n" for i in range(20)).replace(
        "line5 = 5", "line5 = 55"))
    os.remove(r / "gone.py")
    write(r, "untracked.py", "u = 1\n")
    write(r, "ignored.py", "i = 1\n")
    write(r, "node_modules/dep/index.js", "eval(x)\n")
    return r


def test_changed_set_is_merge_base_to_working_tree(repo):
    scope = ds.compute(str(repo), "main", ["node_modules"], DEFAULT)
    # Committed, uncommitted, renamed and untracked — not ignored, deleted or excluded.
    assert scope.files == ["app.py", "lib/util.py", "new.py", "new_name.py", "untracked.py"]
    assert sorted(scope.new_files) == ["new.py", "untracked.py"]
    assert scope.deleted == 1 and scope.excluded == 1
    assert scope.commits == 1 and scope.history_scanned
    assert scope.merge_base == git(repo, "rev-parse", "main").strip()


def test_changed_lines_are_the_new_side_of_each_hunk(repo):
    scope = ds.compute(str(repo), "main", [], DEFAULT)
    assert scope.changed_lines["app.py"] == [[4, 4]]
    assert scope.changed_lines["lib/util.py"] == [[2, 2], [4, 4]]
    # A rename is diffed against the old file, so only the edited line counts.
    assert scope.changed_lines["new_name.py"] == [[6, 6]]
    assert "new.py" not in scope.changed_lines       # new: every line is changed


def test_no_manifest_or_iac_change_skips_those_engines(repo):
    scope = ds.compute(str(repo), "main", [], DEFAULT)
    assert scope.parts == {"sast": True, "secrets": True, "sca": False, "iac": False}
    assert scope.run_engines == ["semgrep", "gitleaks"]
    assert set(scope.skipped_engines) == {"trivy", "checkov"}
    assert set(scope.skipped_reports) == {"trivy-fs.sarif", "trivy-config.sarif",
                                          "checkov.sarif"}


def test_a_changed_manifest_runs_sca(repo):
    write(repo, "requirements.txt", "flask==1.0\nrequests==2.0\n")
    scope = ds.compute(str(repo), "main", [], DEFAULT + ["grype", "syft"])
    assert scope.parts["sca"] and scope.sca_dirs == [""]
    assert "trivy" in scope.run_engines and "grype" in scope.run_engines
    assert "trivy-fs.sarif" not in scope.skipped_reports
    assert "trivy-config.sarif" in scope.skipped_reports    # trivy runs, its IaC part not


def test_a_changed_terraform_file_brings_its_module(repo):
    write(repo, "infra/main.tf", 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n')
    scope = ds.compute(str(repo), "main", [], DEFAULT)
    assert scope.iac_files == ["infra/main.tf"]
    assert scope.iac_context == ["infra/vars.tf"]
    assert "checkov" in scope.run_engines and "checkov.sarif" not in scope.skipped_reports


def test_an_engine_diff_mode_does_not_know_runs_as_usual(repo):
    scope = ds.compute(str(repo), "main", [], DEFAULT + ["zizmor"])
    assert "zizmor" in scope.run_engines


def test_nothing_changed_runs_nothing(repo):
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "all")
    scope = ds.compute(str(repo), "HEAD", [], DEFAULT)
    assert scope.files == [] and scope.commits == 0
    assert scope.run_engines == []
    assert set(scope.skipped_engines) == set(DEFAULT)


def test_only_commits_still_scans_history(repo):
    """A branch whose change was committed and then reverted: no file differs,
    but the commits are still searched for secrets."""
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "all")
    base = git(repo, "rev-parse", "HEAD").strip()
    write(repo, "s.txt", "secret\n")
    git(repo, "add", "s.txt")
    git(repo, "commit", "-qm", "leak")
    git(repo, "rm", "-q", "s.txt")
    git(repo, "commit", "-qm", "unleak")
    scope = ds.compute(str(repo), base, [], DEFAULT)
    assert scope.files == [] and scope.commits == 2 and scope.history_scanned
    assert scope.run_engines == ["gitleaks"]


def test_a_subdirectory_target_is_scoped_to_it(repo):
    scope = ds.compute(str(repo / "lib"), "main", [], DEFAULT)
    assert scope.files == ["util.py"]
    assert scope.changed_lines["util.py"] == [[2, 2], [4, 4]]
    # The container sees lib/ only, without the repository's .git.
    assert not scope.history_scanned and "subdirectory" in scope.history_note


def test_not_a_repo_is_a_usage_error(tmp_path):
    with pytest.raises(ds.UsageError, match="git repository"):
        ds.compute(str(tmp_path), "main", [], DEFAULT)


def test_an_unknown_ref_is_a_usage_error(repo):
    with pytest.raises(ds.UsageError, match="unknown ref 'nope'"):
        ds.compute(str(repo), "nope", [], DEFAULT)


def test_main_exits_2_on_usage_errors(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text("ASS_EXCLUDES='.git'\n")
    code = ds.main(["--target", str(tmp_path), "--base", "main", "--env-file", str(env),
                    "--out-dir", str(tmp_path / "diff")])
    assert code == 2 and "git repository" in capsys.readouterr().err


def test_main_materializes_the_trees_and_prints_shell(repo, tmp_path, capsys):
    write(repo, "infra/main.tf", 'resource "aws_s3_bucket" "b" {}\n')
    env = tmp_path / ".env"
    env.write_text("ASS_EXCLUDES='.git node_modules'\n")
    out = tmp_path / "diff"
    assert ds.main(["--target", str(repo), "--base", "main", "--enabled", " ".join(DEFAULT),
                    "--env-file", str(env), "--out-dir", str(out)]) == 0
    tree = sorted(str(p.relative_to(out / "tree")) for p in (out / "tree").rglob("*")
                  if p.is_file())
    assert tree == ["app.py", "infra/main.tf", "lib/util.py", "new.py", "new_name.py",
                    "untracked.py"]
    iac = sorted(str(p.relative_to(out / "iac")) for p in (out / "iac").rglob("*")
                 if p.is_file())
    assert iac == ["infra/main.tf", "infra/vars.tf"]
    # The printed lines are valid shell for run.sh to eval.
    printed = capsys.readouterr().out
    shown = subprocess.run(
        ["bash", "-c", 'eval "$1"; printf "%s|" "$DIFF_RUN_ENGINES" "$ASS_DIFF_SCA" '
                       '"$ASS_DIFF_IAC" "$ASS_DIFF_LOG_OPTS" "$GITLEAKS_CMD" "$DIFF_SUMMARY"',
         "_", printed], capture_output=True, text=True, check=True).stdout.split("|")
    engines, sca, iac, log_opts, gitleaks_cmd, summary = shown[:6]
    assert engines == "semgrep trivy gitleaks checkov"
    assert (sca, iac, gitleaks_cmd) == ("0", "1", "dir")
    assert log_opts == f"--log-opts={git(repo, 'rev-parse', 'main').strip()}..{git(repo, 'rev-parse', 'HEAD').strip()}"
    assert summary.startswith("Diff     : vs main") and "6 changed file(s)" in summary
    # The collector reads the same file back.
    scope = diffscope.DiffScope.load(str(out / "scope.json"))
    assert scope.files == json.loads((out / "scope.json").read_text())["files"]


def test_engine_reports_match_the_collector():
    for engine, parts in ds.ENGINE_REPORTS.items():
        reports = [r for part in parts.values() for r in part]
        assert sorted(reports) == sorted(normalize.SCANNER_FILES[engine]), engine
        assert set(parts) == set(ds.ENGINE_PARTS[engine]), engine
    assert set(ds.ENGINE_PARTS) == set(normalize.SCANNER_FILES)


def test_every_manifest_the_coverage_check_knows_triggers_sca():
    for names in coverage._MANIFESTS.values():
        for name in names:
            assert ds.is_sca_manifest(name), name
    for name in coverage._LOCKFILES:
        assert ds.is_sca_manifest(name), name
    assert ds.is_sca_manifest("web/App.csproj")
    assert ds.is_sca_manifest("requirements-dev.txt")


@pytest.mark.parametrize("path,iac", [
    ("Dockerfile", True), ("docker/Dockerfile.prod", True), ("api.dockerfile", True),
    ("k8s/deploy.yaml", True), ("main.tf", True), ("cfn.json", True),
    ("package.json", False), ("pnpm-lock.yaml", False), ("app.py", False),
])
def test_iac_classification(path, iac):
    assert ds.is_iac(path) is iac
