"""manager/: profiles, projects, git targets, history, batch, cron and schedules.

Everything runs through the real launcher and run.sh with docker and git stubbed
(manager_helpers.py), so the exit codes and the config precedence asserted here
are the ones a user gets. The UI's security is in test_manager_web.py.
"""
import json
import os
import shlex
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml

from manager_helpers import ROOT, Sandbox

from manager import batch, cron, jobs, runner, runs, store, targets
from manager.paths import UsageError, check_name


@pytest.fixture
def box(tmp_path, monkeypatch):
    return Sandbox(tmp_path, monkeypatch)


# ---- names and targets -------------------------------------------------------

@pytest.mark.parametrize("name", ["../x", "..", "a/b", "A", "-x", "", ".a", "a b", "a\n", "a_b",
                                  "x" * 64, "a\x00"])
def test_a_bad_name_cannot_exist(name):
    with pytest.raises(UsageError):
        check_name(name)


@pytest.mark.parametrize("name", ["a", "0", "api-2", "a-b-c"])
def test_good_names(name):
    assert check_name(name) == name


def test_a_traversing_name_writes_nothing(box):
    proc = box.cli("project", "add", "../../evil", box.repo())
    assert proc.returncode == 2 and "invalid project name" in proc.stderr
    assert not list(box.tmp.rglob("evil*"))


@pytest.mark.parametrize("url", [
    "ext::sh -c id", "ext::id", "fd::17", "file:///etc/passwd", "FILE:///etc/passwd",
    "http://example.com/a.git", "ftp://example.com/a.git", "git://example.com/a.git",
    "-oProxyCommand=id", "--upload-pack=id",
    "https://user:token@example.com/a.git", "https://token@example.com/a.git",
    "ssh://user:pw@example.com/a.git", "ssh://-oProxyCommand=id/a.git",
    "ssh://git@-oProxyCommand=id/a.git", "git@-oProxyCommand=id:a.git", "-x@example.com:a.git",
    "git@example.com:-a.git", "https://example.com", "https://example.com/",
    "https://example.com/a b", "https://example.com/a\nb", "https://example.com/a?x=1",
    "https://example.com:notaport/a", "https://exa_mple.com/a", "https://example.com/a\\b",
])
def test_unsafe_git_urls_are_rejected(url, box):
    assert targets.is_git_url(url)
    with pytest.raises(UsageError):
        targets.check_git_url(url)
    if not url.startswith("-"):      # argparse takes the rest as an option: also exit 2
        assert box.cli("project", "add", "p", url).returncode == 2
    assert not box.definition("p").exists()


@pytest.mark.parametrize("url", [
    "https://github.com/a/b.git", "https://github.com/a/b", "HTTPS://github.com/a/b",
    "ssh://git@github.com/a/b.git", "ssh://git@host.example:2222/a/b.git", "ssh://host.example/a",
    "git@github.com:a/b.git", "git@10.0.0.1:/srv/a.git",
])
def test_https_and_ssh_are_accepted(url):
    assert targets.check_git_url(url) == url


def test_a_hand_edited_definition_gets_the_same_checks(box):
    box.add("p")
    box.definition("p").write_text("target: ext::sh -c id\n")
    proc = box.cli("project", "scan", "p")
    assert proc.returncode == 2 and "not allowed" in proc.stderr
    box.definition("p").write_text("target: /x\nprofile: ../../etc/passwd\n")
    assert box.cli("project", "scan", "p").returncode == 2
    box.definition("p").write_text("target: /x\nschedule: '* * * *'\n")
    assert box.cli("project", "show", "p").returncode == 2
    box.definition("p").write_text("target: /x\nname: other\n")
    assert box.cli("project", "show", "p").returncode == 2
    box.definition("p").write_text("target: /x\ntypo: 1\n")
    assert "typo" in box.cli("project", "show", "p").stderr


def test_a_relative_path_is_made_absolute_and_a_missing_one_refused(box):
    box.repo("rel")
    assert box.cli("project", "add", "p", "rel", cwd=box.tmp).returncode == 0
    assert yaml.safe_load(box.definition("p").read_text())["target"] == str((box.tmp / "rel").resolve())
    proc = box.cli("project", "add", "q", box.tmp / "nope")
    assert proc.returncode == 2 and "not a directory" in proc.stderr


# ---- definitions -------------------------------------------------------------

def test_add_list_show_rm(box):
    target = box.repo()
    (target / "keep.txt").write_text("x")
    box.profile("base", "strict: true\n")
    proc = box.cli("project", "add", "api", target, "--profile", "base",
                   "--meta", "owner=me", "--meta", "tier=1", "--json")
    assert json.loads(proc.stdout) == {"name": "api", "target": str(target.resolve()), "profile": "base",
                                       "meta": {"owner": "me", "tier": "1"}}
    assert box.cli("project", "add", "api", target).returncode == 2   # already exists
    listed = json.loads(box.cli("project", "list", "--json").stdout)
    assert [p["name"] for p in listed["projects"]] == ["api"] and listed["broken"] == []
    assert "api" in box.cli("project", "list").stdout
    shown = json.loads(box.cli("project", "show", "api", "--json").stdout)
    assert shown["meta"] == {"owner": "me", "tier": "1"} and shown["runs"] == []
    assert shown["profile_file"].endswith("profiles/base.yml")

    assert box.cli("project", "scan", "api").returncode == 0
    state = box.project_state("api")
    assert (state / "reports" / "summary.html").exists()
    assert box.cli("project", "rm", "api").returncode == 0
    assert not box.definition("api").exists() and not state.exists()
    assert (target / "keep.txt").exists()                  # the user's code is never touched
    assert box.cli("project", "rm", "api").returncode == 2


def test_rm_can_keep_the_state(box):
    box.add("p")
    box.cli("project", "scan", "p")
    assert box.cli("project", "rm", "p", "--keep-state").returncode == 0
    assert box.project_state("p").exists() and not box.definition("p").exists()


def test_rm_refuses_a_project_being_scanned(box):
    box.add("p")
    with runs.project_lock("p"):
        proc = box.cli("project", "rm", "p")
    assert proc.returncode == 2 and "being scanned" in proc.stderr and box.definition("p").exists()


@pytest.mark.parametrize("flags,message", [
    (("--profile", "nope"), "no profile named"),
    (("--profile", "../x"), "invalid profile name"),
    (("--meta", "novalue"), "expected key=value"),
    (("--meta", "bad key=v"), "meta key"),
])
def test_add_refuses_bad_options(box, flags, message):
    proc = box.cli("project", "add", "p", box.repo(), *flags)
    assert proc.returncode == 2 and message in proc.stderr and not box.definition("p").exists()


def test_new_is_reserved_by_the_ui(box):
    assert box.cli("project", "add", "new", box.repo()).returncode == 2


def test_usage_errors_answer_json_callers(box):
    proc = box.cli("project", "show", "nope", "--json")
    assert proc.returncode == 2 and json.loads(proc.stdout)["verdict"] == "usage_error"
    proc = box.cli("project", "scan", "--bogus", "--json")
    assert proc.returncode == 2 and json.loads(proc.stdout)["verdict"] == "usage_error"


def test_definitions_are_private(box):
    box.add("p")
    assert oct(box.definition("p").stat().st_mode & 0o777) == "0o600"
    box.cli("project", "scan", "p")
    assert oct(box.project_state("p").stat().st_mode & 0o777) == "0o700"


def test_someone_who_never_uses_projects_gets_no_state(box):
    target = box.repo()
    proc = box.cli("scan", target, cwd=box.home)
    assert proc.returncode == 0, proc.stderr
    assert not box.config.exists() and not box.state.exists()


# ---- profile precedence ------------------------------------------------------

def test_precedence_defaults_then_profile_then_repo(box):
    target = box.repo()
    box.profile("hard", "fail_on: low\nstrict: true\nscanners:\n  zizmor:\n    enabled: false\n"
                        "ignore:\n  - rule: FROM-PROFILE\n    reason: r\n")
    (target / ".appsec-compose.yml").write_text(
        "fail_on: critical\nignore:\n  - rule: FROM-REPO\n    reason: r\n")
    box.add("p", target, "--profile", "hard")
    assert box.cli("project", "scan", "p").returncode == 0
    config = yaml.safe_load(box.effective_config("p").read_text())
    defaults = yaml.safe_load((ROOT / "scan-config.yml").read_text())
    assert config["fail_on"] == "critical"                          # repo beats profile
    assert config["ignore"] == [{"rule": "FROM-REPO", "reason": "r"}]   # a repo's suppressions hold
    assert config["strict"] is True                                 # profile beats defaults
    assert config["scanners"]["zizmor"]["enabled"] is False
    assert config["scanners"]["semgrep"] == defaults["scanners"]["semgrep"]   # defaults stay


def test_a_profile_alone_applies_with_no_repo_config(box):
    box.profile("hard", "strict: true\nignore:\n  - rule: FROM-PROFILE\n    reason: r\n")
    box.add("p", box.repo(), "--profile", "hard")
    assert box.cli("project", "scan", "p").returncode == 0
    config = yaml.safe_load(box.effective_config("p").read_text())
    assert config["strict"] is True and config["ignore"][0]["rule"] == "FROM-PROFILE"


def test_an_invalid_profile_is_exit_2_naming_it(box):
    box.profile("typo", "strickt: true\n")
    box.add("p", box.repo(), "--profile", "typo")
    proc = box.cli("project", "scan", "p", "--json")
    result = json.loads(proc.stdout)
    assert proc.returncode == 2 and result["verdict"] == "usage_error"
    assert "typo.yml" in result["error"] and "strict" in result["error"]


def test_a_deleted_profile_is_exit_2(box):
    box.profile("gone", "strict: true\n")
    box.add("p", box.repo(), "--profile", "gone")
    (box.config / "appsec-compose" / "profiles" / "gone.yml").unlink()
    proc = box.cli("project", "scan", "p")
    assert proc.returncode == 2 and "does not exist" in proc.stderr


def test_run_sh_takes_a_profile_directly(box):
    box.profile("p", "strict: true\n")
    profile = box.config / "appsec-compose" / "profiles" / "p.yml"
    proc = box.cli("scan", box.repo(), "--profile", profile, "--name", "project-direct",
                   "--reports", box.tmp / "r")
    assert proc.returncode == 0, proc.stderr
    assert f"Profile  : {profile}" in proc.stdout
    assert yaml.safe_load(box.effective_config("direct").read_text())["strict"] is True


def test_run_sh_with_a_missing_profile_exits_2(box):
    proc = box.cli("scan", box.repo(), "--profile", box.tmp / "nope.yml", "--json")
    assert proc.returncode == 2 and json.loads(proc.stdout)["verdict"] == "usage_error"
    assert "profile" in proc.stderr


def test_scanning_without_a_profile_writes_no_merged_config(box):
    assert box.cli("scan", box.repo(), "--name", "project-plain", "--reports", box.tmp / "r").returncode == 0
    assert not box.effective_config("plain").exists()


def test_store_validates_a_profile_when_it_is_saved(box):
    store.save_profile("good", "fail_on: high\r\nstrict: true\r\n", create=True)
    assert store.read_profile("good") == "fail_on: high\nstrict: true\n"
    for text in ("strickt: true\n", "- a\n", "a: [unclosed\n", "scanners:\n  nosuch:\n    enabled: true\n"):
        with pytest.raises(UsageError):
            store.save_profile("bad", text, create=True)
    assert store.list_profiles() == ["good"]
    with pytest.raises(UsageError):
        store.save_profile("good", "", create=True)        # exists
    with pytest.raises(UsageError):
        store.save_profile("absent", "")                   # edit of nothing


def test_a_profile_in_use_cannot_be_deleted(box):
    box.profile("used", "strict: true\n")
    box.add("p", box.repo(), "--profile", "used")
    with pytest.raises(UsageError, match="used by: p"):
        store.delete_profile("used")
    box.cli("project", "rm", "p")
    store.delete_profile("used")
    assert store.list_profiles() == []


# ---- scanning one project ----------------------------------------------------

@pytest.mark.parametrize("outcome,code,verdict", [
    ("STUB_RUN=0", 0, "pass"),
    ("STUB_RUN=1", 1, "fail"),
    ("STUB_RUN=2; STUB_NO_FINDINGS=1", 2, "usage_error"),
    ("STUB_UP=1", 3, "scan_error"),
    ("STUB_RUN=1; STUB_NO_FINDINGS=1", 3, "scan_error"),   # a fail with no verdict behind it
])
def test_a_project_scan_keeps_the_exit_code_contract(box, outcome, code, verdict):
    box.add("p")
    box.outcome("p", outcome)
    proc = box.cli("project", "scan", "p", "--json")
    result = json.loads(proc.stdout)
    assert len(proc.stdout.strip().splitlines()) == 1
    assert proc.returncode == code and result["verdict"] == verdict and result["project"] == "p"
    run = runs.read_runs("p")[-1]
    assert run["exit_code"] == code and run["verdict"] == verdict


def test_reports_and_names_are_per_project(box):
    box.add("p")
    proc = box.cli("project", "scan", "p", "--json")
    result = json.loads(proc.stdout)
    reports = box.project_state("p") / "reports"
    assert result["reports_dir"] == str(reports) and (reports / "findings.json").exists()
    env = box.environ("p")
    assert env["ASS_REPORTS_DIR"] == str(reports)
    assert env["COMPOSE_PROJECT_NAME"] == "appsec-project-p"
    assert not (box.tmp / "appsec-reports").exists()


def test_scan_flags_pass_through(box):
    box.add("p")
    box.outcome("p", "STUB_RUN=0")
    assert box.cli("project", "scan", "p", "--strict", "--fail-on", "critical").returncode == 0
    assert box.environ("p")["ASS_STRICT"] == "1"


def test_engine_output_goes_to_a_private_log_and_only_error_lines_surface(box):
    box.profile("typo", "strickt: true\n")
    box.add("p", box.repo(), "--profile", "typo")
    box.cli("project", "scan", "p")
    log = box.project_state("p") / "scan.log"
    assert oct(log.stat().st_mode & 0o777) == "0o600"
    assert "strickt" in log.read_text() and "strickt" in runs.read_runs("p")[-1]["error"]


def test_local_targets_keep_the_baseline_in_the_repo(box):
    target = box.repo()
    box.add("p", target)
    box.cli("project", "scan", "p")
    assert not (target / ".appsec-baseline.json").exists()         # never created uninvited
    assert box.cli("project", "scan", "p", "--update-baseline").returncode == 0
    assert (target / ".appsec-baseline.json").exists()
    box.cli("project", "scan", "p")
    assert box.environ("p")["ASS_BASELINE_FILE"] == str((target / ".appsec-baseline.json").resolve())


def test_history_keeps_the_last_n_runs(box, monkeypatch):
    monkeypatch.setenv("APPSEC_COMPOSE_KEEP_RUNS", "2")
    box.add("p")
    for code in ("0", "1", "0"):
        box.outcome("p", f"STUB_RUN={code}")
        box.cli("project", "scan", "p")
    history = runs.read_runs("p")
    assert [r["verdict"] for r in history] == ["fail", "pass"]
    run = history[-1]
    assert run["severity_counts"]["high"] == 2 and run["breaching"] == 2
    assert run["finished"] and run["trigger"] == "manual" and run["has_reports"] is True


def test_trend_counts_only_runs_that_reached_a_verdict():
    history = [{"severity_counts": {"high": 8}}, {"severity_counts": None},
               {"severity_counts": {"high": 2, "low": 2}}]
    info = runs.trend(history)
    assert info["totals"] == [8, 4] and info["delta"] == -4 and len(info["spark"]) == 2
    assert runs.trend([])["delta"] is None
    assert runs.trend([{"severity_counts": {"high": 0}}])["totals"] == [0]


def test_top_component_prefers_malicious_then_severity(box):
    def top(components):
        path = box.tmp / "f.json"
        path.write_text(json.dumps({"severity_counts": {}, "components": components}))
        return runs.summarize(path)["top_component"]
    base = {"name": "x", "version": "1", "vulnerabilities": 9, "severity": "medium", "upgrade_to": "2"}
    assert top([{**base, "package": "low@1"}]) == "low@1 -> 2"
    assert top([{**base, "package": "a@1"}, {**base, "package": "b@1", "severity": "critical"}]) == "b@1 -> 2"
    assert top([{**base, "package": "b@1", "severity": "critical"},
                {**base, "package": "evil@1", "malicious": True}]) == "remove evil@1 (malicious)"
    assert top([{**base, "package": "n@1", "upgrade_to": None}]) == "n@1 (no single fix)"
    assert top([]) is None and top("nonsense") is None


def test_summarize_survives_any_findings_file(tmp_path):
    for text in ("", "[]", "not json", '{"severity_counts": "x", "policy": 3, "components": 7}'):
        path = tmp_path / "f.json"
        path.write_text(text)
        assert runs.summarize(path)["severity_counts"] is None
    assert runs.summarize(tmp_path / "absent.json")["breaching"] is None


def test_two_scans_of_one_project_never_overlap(box):
    box.add("p")
    with runs.project_lock("p"):
        assert runs.is_running("p")
        proc = box.cli("project", "scan", "p", "--json")
    result = json.loads(proc.stdout)
    assert proc.returncode == 3 and "another scan" in result["error"]
    assert runs.read_runs("p") == []                     # a scan that never ran is no run
    assert not runs.is_running("p")


# ---- git targets -------------------------------------------------------------

URL = "https://git.example/a/b.git"


def test_a_git_target_is_cloned_shallowly_with_argv_hardening(box):
    box.add("g", URL)
    proc = box.cli("project", "scan", "g", "--json")
    assert proc.returncode == 0, proc.stderr
    source = box.project_state("g") / "source"
    assert (source / "app.py").exists()
    clone = next(c for c in box.git_calls() if "clone" in c)
    assert clone[-3:] == ["--", URL, f"{source}.new"]    # the URL can never be read as an option
    assert "--depth" in clone and "--no-recurse-submodules" in clone
    assert "core.symlinks=false" in clone
    env = (box.dump / "git-env").read_text()
    assert "GIT_ALLOW_PROTOCOL=https:ssh" in env and "GIT_TERMINAL_PROMPT=0" in env


def test_a_second_scan_updates_in_place(box):
    box.add("g", URL)
    box.cli("project", "scan", "g")
    (box.dump / "git-origin").write_text(URL + "\n")
    (box.dump / "git-calls").unlink()
    assert box.cli("project", "scan", "g").returncode == 0
    verbs = [c[c.index("-C") + 2] for c in box.git_calls() if "-C" in c]
    assert verbs == ["remote", "fetch", "reset", "clean"]
    fetch = next(c for c in box.git_calls() if "fetch" in c)
    assert fetch[-3:] == ["--", "origin", "HEAD"] and "--depth" in fetch


def test_a_changed_url_reclones(box):
    box.add("g", URL)
    box.cli("project", "scan", "g")
    (box.dump / "git-origin").write_text("https://git.example/old.git\n")
    (box.dump / "git-calls").unlink()
    assert box.cli("project", "scan", "g").returncode == 0
    assert any("clone" in c for c in box.git_calls())


def test_a_failed_clone_is_exit_3_and_recorded(box, monkeypatch):
    box.add("g", URL)
    monkeypatch.setenv("STUB_GIT_FAIL", "1")
    proc = box.cli("project", "scan", "g", "--json")
    result = json.loads(proc.stdout)
    assert proc.returncode == 3 and result["verdict"] == "scan_error"
    assert "could not read from remote" in result["error"]
    run = runs.read_runs("g")[-1]
    assert run["exit_code"] == 3 and not run["has_reports"]
    assert not (box.project_state("g") / "source").exists()
    assert not (box.project_state("g") / "source.new").exists()


def test_git_baseline_lives_in_state(box):
    box.add("g", URL)
    box.cli("project", "scan", "g", "--update-baseline")
    baseline = box.project_state("g") / "baseline.json"
    assert baseline.exists() and not (box.project_state("g") / "source" / ".appsec-baseline.json").exists()
    box.cli("project", "scan", "g")
    assert box.environ("g")["ASS_BASELINE_FILE"] == str(baseline)


def test_a_real_git_refuses_a_disallowed_transport(tmp_path):
    # fetch() validates first, whatever a caller or a definition file holds.
    with pytest.raises(UsageError):
        targets.fetch("ext::sh -c 'touch pwned'", tmp_path / "dest")
    assert not (tmp_path / "dest").exists()


# ---- batch -------------------------------------------------------------------

@pytest.mark.parametrize("outcomes,worst", [
    (["STUB_RUN=0", "STUB_RUN=0"], 0),
    (["STUB_RUN=0", "STUB_RUN=1"], 1),
    (["STUB_RUN=1", "STUB_RUN=2; STUB_NO_FINDINGS=1", "STUB_RUN=0"], 2),
    (["STUB_UP=1", "STUB_RUN=1", "STUB_RUN=2; STUB_NO_FINDINGS=1"], 3),
])
def test_batch_exits_with_the_worst_outcome(box, outcomes, worst):
    for i, outcome in enumerate(outcomes):
        box.add(f"p{i}")
        box.outcome(f"p{i}", outcome)
    proc = box.cli("project", "scan", "--all", "--json")
    assert proc.returncode == worst, proc.stderr
    assert json.loads(proc.stdout)["exit_code"] == worst


def test_one_failure_does_not_stop_the_rest(box, monkeypatch):
    box.add("a-git", URL)
    box.add("b")
    box.add("c")
    box.outcome("b", "STUB_UP=1")
    monkeypatch.setenv("STUB_GIT_FAIL", "1")
    proc = box.cli("project", "scan", "--all", "--json")
    outcome = json.loads(proc.stdout)
    assert proc.returncode == 3
    assert {r["project"]: r["exit_code"] for r in outcome["projects"]} == {"a-git": 3, "b": 3, "c": 0}
    assert "c" in box.cli("project", "list").stdout


def test_a_broken_definition_counts_and_does_not_stop_the_batch(box):
    box.add("ok")
    box.definition("ok").with_name("broken.yml").write_text("target: ext::sh\n")
    proc = box.cli("project", "scan", "--all", "--json")
    outcome = json.loads(proc.stdout)
    assert proc.returncode == 2
    assert {r["project"]: r["exit_code"] for r in outcome["projects"]} == {"ok": 0, "broken": 2}


def test_batch_with_no_projects_is_not_a_pass(box):
    assert box.cli("project", "scan", "--all").returncode == 2


def test_scan_takes_a_name_or_all(box):
    box.add("p")
    assert box.cli("project", "scan").returncode == 2
    assert box.cli("project", "scan", "p", "--all").returncode == 2
    assert box.cli("project", "scan", "--all", "--jobs", "0").returncode == 2


def test_batch_runs_in_parallel_when_asked(box):
    for name in ("a", "b", "c"):
        box.add(name)
    proc = box.cli("project", "scan", "--all", "--jobs", "3", "--json")
    assert proc.returncode == 0, proc.stderr
    assert len(json.loads(proc.stdout)["projects"]) == 3


def test_batch_survives_a_crash_in_one_project(box, monkeypatch):
    for name in ("a", "b"):
        box.add(name)
    real = runner.scan_project

    def explode_on_a(name, *args, **kw):
        if name == "a":
            raise RuntimeError("boom")
        return real(name, *args, **kw)
    monkeypatch.setattr(runner, "scan_project", explode_on_a)
    outcome = batch.run_batch()
    assert outcome["exit_code"] == 3
    assert [r["exit_code"] for r in outcome["projects"]] == [3, 0]


def test_index_is_self_contained_with_all_the_columns(box):
    box.add("clean")
    box.add("dirty")
    box.findings("dirty", {
        "severity_counts": {"critical": 1, "high": 4}, "policy": {"breaching": 5},
        "components": [{"package": "lodash@1.0.0", "severity": "high", "vulnerabilities": 3,
                        "upgrade_to": "4.17.21", "malicious": False}]})
    box.outcome("dirty", "STUB_RUN=1")
    assert box.cli("project", "scan", "--all").returncode == 1
    index = (box.state / "appsec-compose" / "index.html").read_text()
    assert "1 critical, 4 high" in index and "lodash@1.0.0 -&gt; 4.17.21" in index
    assert 'href="projects/dirty/reports/summary.html"' in index
    assert (box.state / "appsec-compose" / "projects/dirty/reports/summary.html").exists()
    assert "<script" not in index and "http://" not in index and "https://" not in index
    assert "default-src 'none'" in index


def test_index_escapes_everything(box):
    evil = '<script>alert(1)</script>"\'&'
    box.add("p")
    box.findings("p", {"severity_counts": {"high": 1},
                       "components": [{"package": evil, "severity": "high", "vulnerabilities": 1,
                                       "upgrade_to": evil}]})
    # A definition file whose very name is hostile: listed as broken, escaped, no link.
    box.definition("p").with_name('<img src=x onerror=alert(2)>.yml').write_text("target: /x\n")
    box.cli("project", "scan", "--all")
    index = (box.state / "appsec-compose" / "index.html").read_text()
    assert "<script>alert" not in index and "<img src" not in index
    assert "&lt;script&gt;alert(1)" in index and "&lt;img src=x" in index


def test_no_link_when_the_last_run_left_no_report(box):
    box.add("p")
    box.cli("project", "scan", "--all")
    box.outcome("p", "STUB_UP=1")
    box.cli("project", "scan", "--all")
    assert "summary.html" not in (box.state / "appsec-compose" / "index.html").read_text()


# ---- cron --------------------------------------------------------------------

def at(text):
    return datetime.strptime(text, "%Y-%m-%d %H:%M")


# 2026-11-04 is a Wednesday.
@pytest.mark.parametrize("expr,when,expected", [
    ("* * * * *", "2026-11-04 12:34", True),
    ("34 12 * * *", "2026-11-04 12:34", True),
    ("35 12 * * *", "2026-11-04 12:34", False),
    ("*/15 * * * *", "2026-11-04 12:30", True),
    ("*/15 * * * *", "2026-11-04 12:31", False),
    ("0-10/5 * * * *", "2026-11-04 12:05", True),
    ("0-10/5 * * * *", "2026-11-04 12:06", False),
    ("5/20 * * * *", "2026-11-04 12:45", True),
    ("1,2,34 * * * *", "2026-11-04 12:34", True),
    ("0 0 1 1 *", "2026-01-01 00:00", True),
    ("0 0 * jan *", "2026-01-15 00:00", True),
    ("0 0 * FEB *", "2026-01-15 00:00", False),
    ("0 0 * * wed", "2026-11-04 00:00", True),
    ("0 0 * * mon-fri", "2026-11-07 00:00", False),     # a Saturday
    ("0 0 * * 0", "2026-11-08 00:00", True),            # Sunday as 0
    ("0 0 * * 7", "2026-11-08 00:00", True),            # Sunday as 7
    ("0 0 * * 5-7", "2026-11-08 00:00", True),
    ("0 0 * * 1", "2026-11-08 00:00", False),
    ("0 0 13 * fri", "2026-11-13 00:00", True),         # both: either matches
    ("0 0 13 * fri", "2026-11-06 00:00", True),         # a Friday, not the 13th
    ("0 0 13 * fri", "2026-11-05 00:00", False),
    ("0 0 */2 * fri", "2026-11-05 00:00", False),       # `*/2` counts as unrestricted: both
    ("0 0 */2 * fri", "2026-11-13 00:00", True),
])
def test_cron_matching(expr, when, expected):
    assert cron.parse(expr).matches(at(when)) is expected


@pytest.mark.parametrize("expr", [
    "", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * 32 * *",
    "* * * 0 *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *",
    "@daily", "* * * * *\nMAILTO=x", "* * * * * %", "1,,2 * * * *", "- * * * *", "1- * * * *",
    "; * * * *", "$(id) * * * *", "* * * mon *",
])
def test_cron_rejects(expr):
    with pytest.raises(UsageError):
        cron.parse(expr)


def test_cron_schedule_is_stored_normalized(box):
    box.add("p")
    assert box.cli("project", "schedule", "p", "0   3 * * *").returncode == 0
    assert yaml.safe_load(box.definition("p").read_text())["schedule"] == "0 3 * * *"
    assert box.cli("project", "schedule", "p", "nonsense").returncode == 2
    assert box.cli("project", "schedule", "p").returncode == 2
    assert box.cli("project", "schedule", "p", "0 3 * * *", "--off").returncode == 2
    assert box.cli("project", "schedule", "p", "--off").returncode == 0
    assert "schedule" not in yaml.safe_load(box.definition("p").read_text())


def test_project_cron_prints_lines_and_installs_nothing(box):
    crontab = box.bin / "crontab"
    crontab.write_text(f'#!/bin/sh\ntouch "{box.dump}/crontab-called"\n')
    crontab.chmod(0o755)
    box.add("a")
    box.add("b")
    box.add("c")
    box.cli("project", "schedule", "a", "0 3 * * *")
    box.cli("project", "schedule", "c", "*/5 * * * mon")
    proc = box.cli("project", "cron")
    lines = proc.stdout.strip().splitlines()
    assert proc.returncode == 0 and len(lines) == 2
    assert lines[0].startswith("0 3 * * * ") and "project scan a" in lines[0]
    assert lines[1].startswith("*/5 * * * mon ") and "project scan c" in lines[1]
    assert f"XDG_STATE_HOME={box.state}" in lines[0]     # cron would not have it
    assert "PATH=" in lines[0] and "Nothing was installed" in proc.stderr
    assert not (box.dump / "crontab-called").exists()
    # A checkout's path may hold a space: every word arrives whole through cron's shell.
    words = shlex.split(lines[0].split(" ", 5)[5].replace(r"\%", "%"))
    assert words[-5:-2] == ["project", "scan", "a"] and Path(words[-6]).name == "appsec-compose"


def test_crontab_lines_quote_and_escape(box, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", "/tmp/a b%c")
    box.add("a")
    box.cli("project", "schedule", "a", "0 3 * * *")
    line = jobs.crontab_lines()[0]
    assert r"'XDG_CACHE_HOME=/tmp/a b\%c'" in line
    assert line.count("\n") == 0


def test_project_cron_with_no_schedules(box):
    box.add("a")
    proc = box.cli("project", "cron")
    assert proc.returncode == 0 and proc.stdout == "" and "No project has a schedule" in proc.stderr


class FakeScans:
    def __init__(self):
        self.started = []

    def start(self, name, trigger="manual"):
        self.started.append((name, trigger))
        return True


def test_scheduler_starts_what_is_due_once_per_minute(box):
    box.add("every")
    box.add("nightly")
    box.add("off")
    box.cli("project", "schedule", "every", "* * * * *")
    box.cli("project", "schedule", "nightly", "0 3 * * *")
    now = [at("2026-11-04 02:58")]
    scans = FakeScans()
    scheduler = jobs.Scheduler(scans, clock=lambda: now[0])
    assert scheduler.tick() == []                        # the start-up minute is not re-run
    now[0] = at("2026-11-04 02:59")
    assert scheduler.tick() == ["every"]
    assert scheduler.tick() == []                        # same minute: nothing twice
    now[0] += timedelta(seconds=30)
    assert scheduler.tick() == []
    now[0] = at("2026-11-04 03:00")
    assert scheduler.tick() == ["every", "nightly"]
    assert all(trigger == "schedule" for _, trigger in scans.started)


def test_scheduler_catches_up_a_stall_but_not_a_night(box):
    box.add("nightly")
    box.cli("project", "schedule", "nightly", "0 3 * * *")
    now = [at("2026-11-04 02:58")]
    scans = FakeScans()
    scheduler = jobs.Scheduler(scans, clock=lambda: now[0])
    now[0] = at("2026-11-04 03:02")                      # a stall across 03:00
    assert scheduler.tick() == ["nightly"]
    now[0] = at("2026-11-05 03:30")                      # asleep all night
    assert scheduler.tick() == []


def test_scans_never_queue_one_project_twice(box):
    import threading
    box.add("p")
    release = threading.Event()
    entered = threading.Event()

    def slow(name, trigger="manual", on_start=None):
        entered.set()
        release.wait(5)
    scans = jobs.Scans(scan=slow)
    assert scans.start("p") is True
    assert entered.wait(5)
    assert scans.start("p") is False and scans.state("p") == "running"
    release.set()
    for _ in range(100):
        if scans.state("p") == "idle":
            break
        threading.Event().wait(0.02)
    assert scans.state("p") == "idle"
    assert scans.start("p") is True


def test_scans_defer_to_a_scan_in_another_process(box):
    box.add("p")
    scans = jobs.Scans(scan=lambda *a, **k: pytest.fail("must not run"))
    with runs.project_lock("p"):
        assert scans.start("p") is False and scans.state("p") == "running"


def test_a_stopped_queue_starts_nothing(box):
    box.add("p")
    scans = jobs.Scans(scan=lambda *a, **k: pytest.fail("must not run"))
    scans.stop()
    assert scans.start("p") is False


# ---- launcher ----------------------------------------------------------------

def test_help_mentions_the_optional_commands(box):
    out = box.cli("help").stdout
    assert "project <subcommand>" in out and "serve [--port 8787]" in out


def test_xdg_defaults_fall_under_home(box, monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.delenv("XDG_STATE_HOME")
    box.add("p")
    assert (box.home / ".config/appsec-compose/projects/p.yml").exists()
    assert box.cli("project", "scan", "p").returncode == 0
    assert (box.home / ".local/state/appsec-compose/projects/p/reports/findings.json").exists()


def test_no_shell_anywhere_in_the_package():
    for path in (ROOT / "manager").glob("*.py"):
        text = path.read_text()
        assert "shell=True" not in text and "os.system" not in text and "os.popen" not in text, path
        assert "eval(" not in text and "exec(" not in text, path


def test_fetch_swaps_a_finished_clone_into_place(box):
    dest = box.tmp / "dest"
    targets.fetch(URL, dest)
    assert (dest / "app.py").exists() and os.path.isdir(dest / ".git")
    assert not dest.with_name("dest.new").exists()


def test_no_repo_config_is_stored_and_survives_an_update(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    from manager import store
    target = tmp_path / "t"
    target.mkdir()
    store.add_project("third", str(target), repo_config=False)
    assert store.load_project("third").repo_config is False
    store.update_project("third", str(target), None, {}, None)
    assert store.load_project("third").repo_config is False
    store.add_project("mine", str(target))
    assert store.load_project("mine").repo_config is True


def test_a_quoted_path_from_a_terminal_is_accepted(tmp_path):
    from manager import targets
    folder = tmp_path / "my project"
    folder.mkdir()
    expected = str(folder.resolve())
    assert targets.normalize(f"'{folder}'") == expected
    assert targets.normalize(f'"{folder}"') == expected
    assert targets.normalize(f"  {folder}  ") == expected
