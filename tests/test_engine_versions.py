"""Engine versions live in three places, and the updater moves all three."""
import importlib.util
import json
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


up = load("update_engines", "scripts/update-engines.py")
cmp = load("bench_compare", "benchmark/compare.py")


def versions_everywhere(root=ROOT):
    config = yaml.safe_load((root / "scan-config.yml").read_text())["scanners"]
    renderer = {n: (r, v) for n, r, v in re.findall(
        r'"(\w+)": \("([^"]+)", "([^"]+)", "[A-Z]+"\)', (root / "scripts/render-env.py").read_text())}
    compose = (root / "docker-compose.yml").read_text()
    return config, renderer, compose


def test_the_three_places_agree():
    config, renderer, compose = versions_everywhere()
    assert set(renderer) == set(up.ENGINES) == set(config)
    for name, (repo, version) in renderer.items():
        assert str(config[name]["version"]) == version, name
        assert f"{repo}:{version}}}" in compose, name


NOW = datetime(2026, 11, 7, tzinfo=timezone.utc)


def rel(tag, days_old, **kw):
    return {"tag_name": tag, "published_at": (NOW - timedelta(days=days_old)).isoformat(),
            "html_url": f"https://example/{tag}", **kw}


def test_the_newest_aged_stable_release_is_chosen():
    listings = {repo: [] for repo, _ in up.ENGINES.values()}
    listings["semgrep/semgrep"] = [rel("v1.190.0", 1), rel("v1.189.0", 3, prerelease=True),
                                   rel("v1.185.0", 8), rel("v1.184.0", 15)]
    listings["gitleaks/gitleaks"] = [rel("v9.0.0", 30)]
    seen = []
    plan = {c["engine"]: c for c in up.plan(NOW, check_image=lambda ref: seen.append(ref) or True,
                                            release=lambda repo: listings[repo])}
    assert plan["semgrep"]["to"] == "1.185.0" and not plan["semgrep"]["major"]
    assert plan["gitleaks"]["to"] == "v9.0.0" and plan["gitleaks"]["major"]   # flagged
    assert "semgrep/semgrep:1.185.0" in seen
    assert plan["trivy"]["to"] is None and plan["trivy"]["note"] == "up to date"


def test_a_young_or_imageless_release_waits():
    listings = {repo: [] for repo, _ in up.ENGINES.values()}
    listings["semgrep/semgrep"] = [rel("v1.190.0", 2)]
    listings["aquasecurity/trivy"] = [rel("v0.99.0", 30)]
    plan = {c["engine"]: c for c in up.plan(NOW, check_image=lambda ref: "trivy" not in ref,
                                            release=lambda repo: listings[repo])}
    assert plan["semgrep"]["to"] is None and "none 7 days old" in plan["semgrep"]["note"]
    assert plan["trivy"]["to"] is None and "not in the registry" in plan["trivy"]["note"]


def test_apply_moves_all_three_places_or_none(tmp_path, monkeypatch):
    for rel_path in ("scan-config.yml", "scripts/render-env.py", "docker-compose.yml"):
        (tmp_path / rel_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel_path, tmp_path / rel_path)
    monkeypatch.setattr(up, "ROOT", tmp_path)
    up.apply([{"engine": "semgrep", "from": "1.174.0", "to": "1.185.0"},
              {"engine": "hadolint", "from": "v2.15.1-alpine", "to": "v2.16.0-alpine"}])
    config, renderer, compose = versions_everywhere(tmp_path)
    assert config["semgrep"]["version"] == "1.185.0" and renderer["semgrep"][1] == "1.185.0"
    assert "semgrep/semgrep:1.185.0}" in compose and "hadolint/hadolint:v2.16.0-alpine}" in compose
    assert config["trivy"]["version"] == "0.74.0"                    # neighbours untouched
    before = (tmp_path / "scan-config.yml").read_text()
    try:
        up.apply([{"engine": "trivy", "from": "0.0.1", "to": "0.0.2"}])
    except SystemExit:
        pass
    assert (tmp_path / "scan-config.yml").read_text() == before        # nothing half-applied


def test_compare_flags_a_drop():
    old = {"suites": {"secrets": {"runs": {"default": {"score": {"merged": {"recall": .88, "precision": .95}}}}}}}
    new = {"suites": {"secrets": {"runs": {"default": {"score": {"merged": {"recall": .80, "precision": .96}}}}}}}
    rows = {r["metric"]: r for r in cmp.compare(old, new)}
    assert rows["Secrets recall"]["worse"] and not rows["Secrets precision"]["worse"]
    assert "| Secrets recall | 88.0% | 80.0% | worse |" in cmp.markdown(cmp.compare(old, new))


def test_compare_flags_a_longer_brief():
    run = lambda tokens: {"suites": {"sca": {"runs": {"default": {
        "brief": {"approx_tokens": tokens}, "score": {"recall": .9}}}}}}
    rows = {r["metric"]: r for r in cmp.compare(run(1000), run(1500))}
    assert rows["sca brief ~tokens"]["worse"] and not rows["SCA recall"]["worse"]
