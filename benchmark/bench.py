#!/usr/bin/env python3
"""appsec-compose public benchmark — one command, reproducible numbers.

    python3 benchmark/bench.py                    # everything (~10 min warm)
    python3 benchmark/bench.py --suite sast       # one suite
    python3 benchmark/bench.py --profile default  # only the shipped defaults
    python3 benchmark/bench.py --rescore          # re-score the last run's reports

For every suite it (1) materialises a pinned corpus into a cache directory
outside the repository, (2) runs ./run.sh over it with a benchmark config
derived from the shipped scan-config.yml, (3) scores reports/findings.json
against the corpus' ground truth and (4) writes benchmark/results.json and the
generated section of benchmark/RESULTS.md.

Corpora are pinned: OWASP Benchmark by commit SHA (downloaded as that commit's
archive, so no git is needed), the secrets and SCA corpora by the generator
code in this directory plus a recorded tree digest.

Needs what run.sh needs (Docker, Python 3.9+, PyYAML) and network access.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import net                      # noqa: E402
import report                   # noqa: E402
import sca_corpus               # noqa: E402
import scoring                  # noqa: E402
import synthetic_secrets        # noqa: E402

CORPORA = json.loads((HERE / "corpora.json").read_text())
TRUTH_FILE = HERE / "sca_truth.json"
RESULTS_JSON = HERE / "results.json"
RESULTS_MD = HERE / "RESULTS.md"
DEFAULT_CACHE = Path(os.environ.get("APPSEC_BENCH_CACHE")
                     or Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
                     / "appsec-compose-bench")

# What each suite runs. `default` is always the engine set the shipped
# scan-config.yml uses for that category; anything else is an opt-in
# alternative and is labelled as such everywhere it is reported.
SUITES = {
    "sast": {
        "default": {"enable": ["semgrep"],
                    "label": "Semgrep, p/default (shipped default)"},
        "auto": {"enable": ["semgrep"], "semgrep_rules": ["default", "auto"],
                 "label": "Semgrep, p/default + `auto` stack packs (opt-in)"},
    },
    "secrets": {
        # Trivy runs `--scanners vuln,secret` by default, so it is part of the
        # default secret coverage too.
        "default": {"enable": ["gitleaks", "trivy"],
                    "label": "Gitleaks + Trivy (shipped default)"},
        "trufflehog": {"enable": ["gitleaks", "trivy", "trufflehog"],
                       "label": "Gitleaks + Trivy + TruffleHog (opt-in)"},
    },
    "sca": {
        "default": {"enable": ["trivy"], "sbom": True,
                    "label": "Trivy (shipped default)"},
        "all": {"enable": ["trivy", "grype", "osv"], "sbom": True,
                "label": "Trivy + Grype + OSV-Scanner (opt-in)"},
    },
}


def log(msg: str) -> None:
    print(f"[bench] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Corpora
# ---------------------------------------------------------------------------

def tree_digest(root: Path) -> str:
    """sha256 over (relative path, file sha256) of every file, sorted."""
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            h.update(p.relative_to(root).as_posix().encode() + b"\0")
            h.update(hashlib.sha256(p.read_bytes()).hexdigest().encode() + b"\n")
    return h.hexdigest()


def _safe_extract(archive: Path, dest: Path) -> None:
    # Every member is checked to stay inside dest before anything is extracted.
    with tarfile.open(archive) as tar:  # nosemgrep: tarfile-extractall-traversal
        if sys.version_info >= (3, 12):
            tar.extractall(dest, filter="data")
            return
        for m in tar.getmembers():
            target = (dest / m.name).resolve()
            # is_relative_to, not a string prefix: "/cache/x" prefixes "/cache/x-evil".
            if not target.is_relative_to(dest.resolve()) or m.issym() or m.islnk():
                raise RuntimeError(f"refusing archive member {m.name}")
        tar.extractall(dest)


def fetch_github_commit(repo_url: str, commit: str, cache: Path, name: str) -> Path:
    """Materialise `repo_url` at exactly `commit` under cache/corpora/<name>-<sha12>."""
    dest = cache / "corpora" / f"{name}-{commit[:12]}"
    marker = cache / "corpora" / f".{name}-{commit[:12]}.ok"
    if marker.exists() and dest.is_dir():
        return dest
    owner_repo = repo_url.removeprefix("https://github.com/").rstrip("/")
    archive = cache / "downloads" / f"{name}-{commit}.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        log(f"downloading {owner_repo}@{commit[:12]}")
        net.fetch(f"https://codeload.github.com/{owner_repo}/tar.gz/{commit}", out=str(archive))
    staging = cache / "downloads" / f"{name}-{commit}.x"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir()
    _safe_extract(archive, staging)
    tops = list(staging.iterdir())
    # GitHub names the archive's top directory <repo>-<full sha>: proof that
    # what we unpacked is the commit we asked for.
    if len(tops) != 1 or not tops[0].name.endswith(commit):
        raise RuntimeError(f"unexpected archive layout for {owner_repo}@{commit}: {tops}")
    shutil.rmtree(dest, ignore_errors=True)
    tops[0].rename(dest)
    shutil.rmtree(staging)
    marker.write_text(commit + "\n")
    return dest


def write_tree(dest: Path, files: dict[str, str]) -> Path:
    shutil.rmtree(dest, ignore_errors=True)
    for rel, content in files.items():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return dest


def prepare(suite: str, cache: Path) -> tuple[Path, dict, object]:
    """Return (corpus dir, corpus metadata, ground truth) for a suite."""
    if suite == "sast":
        meta = CORPORA["owasp_benchmark_java"]
        path = fetch_github_commit(meta["repo"], meta["commit"], cache, "benchmarkjava")
        truth = scoring.parse_expected_results((path / meta["expected_results"]).read_text())
        return path, {**meta, "tree_sha256": tree_digest(path)}, truth
    if suite == "secrets":
        files, labels = synthetic_secrets.build()
        path = write_tree(cache / "corpora" / f"secrets-synthetic-v{synthetic_secrets.GENERATOR_VERSION}", files)
        meta = {**CORPORA["secrets_synthetic"], "seed": synthetic_secrets.SEED,
                "generator_version": synthetic_secrets.GENERATOR_VERSION,
                "files": len(files),
                "secrets": sum(lab["label"] == "secret" for lab in labels),
                "decoys": sum(lab["label"] == "decoy" for lab in labels),
                "tree_sha256": tree_digest(path)}
        return path, meta, labels
    if suite == "sca":
        snapshot = json.loads(TRUTH_FILE.read_text())
        path = write_tree(cache / "corpora" / "sca-pinned-v1", sca_corpus.manifests())
        meta = {**CORPORA["sca_pinned"], "osv_snapshot": snapshot["taken"],
                "packages": len(snapshot["packages"]),
                "manifests": sorted(sca_corpus.MANIFEST.values()),
                "tree_sha256": tree_digest(path)}
        return path, meta, snapshot["packages"]
    raise ValueError(suite)


# ---------------------------------------------------------------------------
# Running appsec-compose
# ---------------------------------------------------------------------------

def bench_config(profile: dict) -> dict:
    """The shipped scan-config.yml, narrowed to this profile's engines.

    Derived at run time rather than committed, so the benchmark follows the
    shipped engine versions and defaults instead of drifting from them.
    """
    import yaml  # run.sh needs PyYAML anyway; only this step does here.
    cfg = yaml.safe_load((ROOT / "scan-config.yml").read_text())
    for name, block in cfg["scanners"].items():
        block["enabled"] = name in profile["enable"]
    if profile.get("semgrep_rules"):
        cfg["scanners"]["semgrep"]["rules"] = profile["semgrep_rules"]
    cfg["sbom"] = bool(profile.get("sbom", False))
    cfg["fail_on"] = "none"           # report-only: we want every finding
    cfg["baseline"] = False
    cfg["ignore"] = []
    cfg["offline"] = False
    cfg.setdefault("enrich", {}).setdefault("cve_paas", {})["enabled"] = False
    return cfg


def _db_dates_on_disk() -> dict[str, str]:
    """The vulnerability DB dates actually in cache/ after a scan."""
    dates = {}
    try:
        dates["trivy"] = json.loads((ROOT / "cache/trivy/db/metadata.json").read_text())["UpdatedAt"]
    except (OSError, KeyError, ValueError):
        pass
    for meta in sorted((ROOT / "cache/grype").glob("*/metadata.json")):
        try:
            dates["grype"] = json.loads(meta.read_text()).get("built", "")
        except (OSError, ValueError):
            pass
    # Grype DB schema v6 (grype >= 0.88) has no metadata.json; the build time
    # is only in the archive name recorded in import.json.
    for imp in sorted((ROOT / "cache/grype").glob("*/import.json")):
        try:
            m = re.search(r"_(\d{4}-\d\d-\d\dT[\d:]+Z)_", json.loads(imp.read_text()).get("source", ""))
        except (OSError, ValueError):
            m = None
        if m:
            dates["grype"] = m.group(1)
    return dates


def run_scan(suite: str, name: str, profile: dict, corpus: Path, corpus_digest: str,
             cache: Path, keep_images: bool) -> dict:
    run_dir = cache / "runs" / f"{suite}-{name}"
    reports = run_dir / "reports"
    shutil.rmtree(run_dir, ignore_errors=True)
    reports.mkdir(parents=True)
    config = run_dir / "scan-config.yml"
    # JSON is YAML; no need to round-trip comments that nobody reads here.
    config.write_text(json.dumps(bench_config(profile), indent=2))
    slug = f"bench-{suite}-{name}"
    cmd = [str(ROOT / "run.sh"), str(corpus), "--config", str(config),
           "--reports", str(reports), "--baseline", str(run_dir / "baseline.json"),
           "--name", slug, "--fail-on", "none"]
    log(f"{suite}/{name}: scanning {corpus.name} ({profile['label']})")
    started = time.monotonic()
    with open(run_dir / "run.log", "w") as out:
        code = subprocess.call(cmd, stdout=out, stderr=subprocess.STDOUT, cwd=ROOT)
    runtime = round(time.monotonic() - started, 1)
    if not keep_images:
        subprocess.call(["docker", "image", "rm", "-f", f"appsec-{slug}-collector"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if code != 0:
        raise RuntimeError(f"run.sh exited {code} for {suite}/{name}; see {run_dir / 'run.log'}")
    meta = {"label": profile["label"], "engines_enabled": profile["enable"],
            "semgrep_rules": profile.get("semgrep_rules", ["default"]) if "semgrep" in profile["enable"] else None,
            "runtime_seconds": runtime, "corpus_tree_sha256": corpus_digest,
            "db_dates_on_disk_after_run": _db_dates_on_disk()}
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    return meta


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _semgrep_rules_loaded(reports: Path) -> dict:
    try:
        sarif = json.loads((reports / "native/semgrep.sarif").read_text())
        driver = sarif["runs"][0]["tool"]["driver"]
        return {"rules": len(driver.get("rules") or []),
                "semgrep_version": driver.get("semanticVersion", "")}
    except (OSError, KeyError, IndexError, ValueError):
        return {}


def score(suite: str, truth, findings_doc: dict, reports: Path) -> dict:
    findings = findings_doc["findings"]
    if suite == "sast":
        result = scoring.score_owasp_benchmark(truth, findings)
        result.update(_semgrep_rules_loaded(reports))
        sast = [f for f in findings if f["category"] == "sast"]
        result["sast_findings"] = len(sast)
        result["sast_findings_by_severity"] = _count(f["severity"] for f in sast)
        return result
    if suite == "secrets":
        result = {"merged": scoring.score_secrets(truth, findings)}
        tools = sorted({t for f in findings if f["category"] == "secrets" for t in f["tools"]})
        result["per_tool"] = {t: scoring.score_secrets(truth, findings, tool=t) for t in tools}
        # Trivy's secret scanner writes into trivy-fs.sarif, which the collector
        # files under `sca`. A vulnerability finding always names a package; a
        # secret finding never does — that is how they are told apart here.
        stray = [f for f in findings if f["category"] == "sca" and not f.get("package")]
        if stray:
            result["trivy_secrets_filed_as_sca"] = scoring.score_secrets(truth, stray, category="sca")
        return result
    if suite == "sca":
        result = scoring.score_sca(truth, findings)
        result["coverage_warnings"] = [w["message"] for w in findings_doc["coverage"]["warnings"]]
        return result
    raise ValueError(suite)


def _count(values) -> dict:
    out: dict = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _cmd(args: list[str]) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, cwd=ROOT,
                              timeout=60).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def refresh_truth() -> None:
    log("querying OSV for the SCA ground truth")
    packages = sca_corpus.fetch_truth()
    TRUTH_FILE.write_text(json.dumps({
        "taken": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "https://api.osv.dev/v1 (querybatch + vulns/{id}); withdrawn advisories dropped",
        "packages": packages}, indent=2) + "\n")
    n = sum(len(p["advisories"]) for p in packages)
    log(f"wrote {TRUTH_FILE.relative_to(ROOT)}: {len(packages)} packages, {n} advisories")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cache", type=Path, default=DEFAULT_CACHE,
                    help=f"corpora + run reports (default {DEFAULT_CACHE})")
    ap.add_argument("--suite", action="append", choices=sorted(SUITES),
                    help="run only this suite (repeatable; default: all)")
    ap.add_argument("--profile", choices=["default", "all"], default="all",
                    help="'default' runs only the shipped-default engines")
    ap.add_argument("--rescore", action="store_true",
                    help="score the reports of the last run without scanning again")
    ap.add_argument("--refresh-sca-truth", action="store_true",
                    help="re-query OSV and rewrite sca_truth.json, then exit")
    ap.add_argument("--keep-images", action="store_true",
                    help="keep the appsec-bench-* collector images")
    ap.add_argument("--no-write", action="store_true",
                    help="print results; do not update results.json / RESULTS.md")
    args = ap.parse_args(argv)

    if args.refresh_sca_truth:
        refresh_truth()
        return 0

    cache = args.cache.expanduser().resolve()
    ignored = HERE / ".cache"           # the one in-repo location .gitignore covers
    inside = cache == ROOT or ROOT in cache.parents
    if inside and not (cache == ignored or ignored in cache.parents):
        # The corpora hold vulnerable code and fake credentials: inside the repo
        # they would be committed by accident and fail the repo's own scan.
        ap.error("--cache must be outside the repository (or under benchmark/.cache)")
    cache.mkdir(parents=True, exist_ok=True)

    previous = json.loads(RESULTS_JSON.read_text()) if RESULTS_JSON.exists() else {}
    results = {
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "appsec_compose": (ROOT / "VERSION").read_text().strip(),
        "appsec_compose_commit": _cmd(["git", "rev-parse", "HEAD"]),
        "host": {"platform": platform.platform(), "machine": platform.machine(),
                 "docker": _cmd(["docker", "version", "--format", "{{.Server.Version}}"])},
        "suites": dict(previous.get("suites", {})),
    }

    for suite in args.suite or list(SUITES):
        corpus, meta, truth = prepare(suite, cache)
        runs = {}
        for name, profile in SUITES[suite].items():
            if args.profile == "default" and name != "default":
                continue
            run_dir = cache / "runs" / f"{suite}-{name}"
            if args.rescore:
                run_meta = json.loads((run_dir / "meta.json").read_text())
                # Scoring old reports against a regenerated corpus would pair
                # findings with lines they were never reported on.
                if run_meta.get("corpus_tree_sha256") != meta["tree_sha256"]:
                    raise RuntimeError(f"{suite}/{name}: corpus changed since the scan; "
                                       "run without --rescore")
            else:
                run_meta = run_scan(suite, name, profile, corpus, meta["tree_sha256"],
                                    cache, args.keep_images)
            doc = json.loads((run_dir / "reports/findings.json").read_text())
            if doc.get("reports_missing") or doc.get("reports_errored"):
                raise RuntimeError(f"{suite}/{name}: engines failed to report: "
                                   f"{doc.get('reports_missing')} {doc.get('reports_errored')}")
            runs[name] = {**run_meta, "provenance": doc["provenance"],
                          "score": score(suite, truth, doc, run_dir / "reports")}
            log(f"{suite}/{name}: {report.headline(suite, runs[name]['score'])}")
        results["suites"][suite] = {"corpus": meta, "runs": runs}

    text = json.dumps(results, indent=2) + "\n"
    if args.no_write:
        print(text)
        return 0
    RESULTS_JSON.write_text(text)
    report.update_markdown(RESULTS_MD, results)
    log(f"wrote {RESULTS_JSON.relative_to(ROOT)} and {RESULTS_MD.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
