"""orchestrator/projectprofile.py: what a repo is made of, and what fits it."""
import json
import subprocess
import sys
from pathlib import Path

import projectprofile as pp

ROOT = Path(__file__).resolve().parent.parent


def tree(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return str(root)


def keys(recs):
    return {".".join(r.path): r.value for r in recs}


def test_a_python_service_without_a_lock_file(tmp_path):
    repo = tree(tmp_path, {**{f"app/m{i}.py": "x = 1\n" for i in range(12)},
                           "pyproject.toml": '[project]\ndependencies = ["fastapi>=0.1"]\n',
                           "requirements.txt": "Django>=4\n"})
    prof = pp.scan(repo)
    assert prof.languages == [("Python", 12)]
    assert prof.frameworks == ["django", "fastapi"]
    assert prof.unpinned == ["requirements.txt"]
    recs = keys(pp.recommend(prof))
    assert recs["scanners.semgrep.rules"] == ["default", "auto"]
    assert recs["scanners.osv.enabled"] is True
    assert recs["scanners.zizmor.enabled"] is False          # no workflows


def test_three_helper_scripts_do_not_make_a_python_project(tmp_path):
    repo = tree(tmp_path, {**{f"src/c{i}.ts": "" for i in range(40)},
                           **{f"tools/s{i}.py": "" for i in range(3)},
                           "package.json": '{"dependencies": {"express": "^4"}}',
                           "package-lock.json": "{}",
                           ".github/workflows/ci.yml": "on: push\n"})
    prof = pp.scan(repo)
    assert prof.frameworks == ["express"] and "github_actions" in prof.iac
    assert pp.recommend(prof) == []                          # the defaults fit


def test_exact_pins_are_their_own_lock(tmp_path):
    repo = tree(tmp_path, {"requirements.txt": "flask==3.0.0\nrequests==2.32.0\n",
                           ".github/workflows/ci.yml": "on: push\n"})
    assert "scanners.osv.enabled" not in keys(pp.recommend(pp.scan(repo)))


def test_excluded_paths_are_not_profiled(tmp_path):
    repo = tree(tmp_path, {"vendor/lib/main.tf": "", "vendor/package.json": "{}"})
    prof = pp.scan(repo, ["vendor"])
    assert prof.iac == [] and prof.manifests == {}


def test_write_creates_an_overlay_and_never_overwrites(tmp_path):
    repo = tree(tmp_path, {"package.json": '{"dependencies": {}}'})
    script = str(ROOT / "orchestrator" / "projectprofile.py")
    out = subprocess.run([sys.executable, script, repo, "--json", "--write"],
                         capture_output=True, text=True, check=True)
    doc = json.loads(out.stdout)
    written = Path(doc["written"])
    import yaml
    cfg = yaml.safe_load(written.read_text())
    assert cfg == {"scanners": {"osv": {"enabled": True}, "zizmor": {"enabled": False}}}
    sys.path.insert(0, str(ROOT / "orchestrator"))
    import schema
    assert schema.validate(cfg, known_scanners={"osv", "zizmor", "semgrep"}) == []
    written.write_text("# mine\n")
    again = subprocess.run([sys.executable, script, repo, "--write"], capture_output=True, text=True)
    assert again.returncode == 0 and "not overwritten" in again.stderr
    assert written.read_text() == "# mine\n"


def test_default_excludes_match_the_renderer():
    import importlib.util
    spec = importlib.util.spec_from_file_location("renv", ROOT / "scripts" / "render-env.py")
    renv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renv)
    assert pp.DEFAULT_EXCLUDES == renv.DEFAULT_EXCLUDES


def test_history_is_advised_once_and_a_shallow_clone_is_called_out(tmp_path):
    import subprocess
    import projectprofile as pp
    run = lambda *a: subprocess.run(["git", "-C", str(tmp_path), *a], check=True,
                                    capture_output=True)
    assert pp.git_history(str(tmp_path)) is None and pp.run_once(None) == []
    run("init", "-q")
    for n in range(2):
        (tmp_path / "f").write_text(str(n))
        run("add", "f")
        run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", f"c{n}")
    history = pp.git_history(str(tmp_path))
    assert history == {"commits": 2, "shallow": False}
    assert "--secrets-history" in pp.run_once(history)[0]
    assert "shallow clone" in pp.run_once({"commits": 5, "shallow": True})[0]
    assert pp.run_once({"commits": 1, "shallow": False}) == []
