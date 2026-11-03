#!/usr/bin/env python3
"""How long appsec-compose takes — a full scan and a diff scan, per engine.

    python3 benchmark/speed.py                 # every corpus, 3 runs each
    python3 benchmark/speed.py --runs 5 --corpus django

Precision and recall have ground truth; speed has noise. So each measurement
is repeated and the median is reported, after one warm-up run that downloads
the databases and builds the collector image (a first run on a fresh machine
pays that once, and it is not what a scan costs). Every run uses the shipped
scan-config.yml as a user gets it. Engine durations come from the scan's own
findings.json (provenance.timings), so the benchmark measures exactly what
every report already records.

Diff mode is measured on a change an agent would make: one existing source
file edited and one new file added, uncommitted, scanned with --diff HEAD.

The machine matters as much as the code — engines run side by side and
compete for CPU — so the CPU count, Docker's memory and the load average at
the start are recorded with the numbers. --isolate also times each default
engine running alone: the gap between that and the parallel run is the cost
of contention, which is what decides whether trimming one engine speeds up
the others. Results: benchmark/SPEED.md and
benchmark/speed.json.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bench                    # noqa: E402  (corpus fetching, cache layout, log)

ROOT = HERE.parent
SPEED_JSON = HERE / "speed.json"
SPEED_MD = HERE / "SPEED.md"

# corpora.json key -> the edit a diff run makes: an existing file to append to
# and a new file, both in the corpus' main language.
CORPORA = {
    "juice-shop": {"key": "speed_juice_shop", "edit": "routes/login.ts",
                   "new": ("routes/benchChange.ts",
                           "import { exec } from 'child_process'\n"
                           "export function run (cmd: string) { exec(cmd) }\n")},
    "django": {"key": "speed_django", "edit": "django/core/handlers/base.py",
               "new": ("django/bench_change.py",
                       "import subprocess\n\n\ndef run(cmd):\n"
                       "    return subprocess.call(cmd, shell=True)\n")},
}

_GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "bench", "GIT_AUTHOR_EMAIL": "bench@localhost",
            "GIT_COMMITTER_NAME": "bench", "GIT_COMMITTER_EMAIL": "bench@localhost",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, env=_GIT_ENV, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def git_repo(src: Path, dest: Path) -> Path:
    """The corpus as a one-commit git repository, so diff mode has a base."""
    shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(src, dest, symlinks=True)
    _git(dest, "init", "-q")
    _git(dest, "add", "-A")
    _git(dest, "commit", "-qm", "corpus")
    return dest


def make_change(repo: Path, spec: dict) -> None:
    with open(repo / spec["edit"], "a") as fh:
        fh.write("\n// appsec-compose speed benchmark: edited line\n"
                 if spec["edit"].endswith(".ts") else
                 "\n# appsec-compose speed benchmark: edited line\n")
    path, body = spec["new"]
    (repo / path).write_text(body)


def scan(target: Path, work: Path, slug: str, *extra: str) -> dict:
    reports = work / "reports"
    shutil.rmtree(reports, ignore_errors=True)
    cmd = [str(ROOT / "run.sh"), str(target), "--reports", str(reports),
           "--baseline", str(work / "baseline.json"), "--name", slug,
           "--fail-on", "none", "--json", *extra]
    started = time.monotonic()
    with open(work / "run.log", "a") as log:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=log, text=True, cwd=ROOT)
    wall = round(time.monotonic() - started, 1)
    result = json.loads(proc.stdout.strip().splitlines()[-1]) if proc.stdout.strip() else {}
    if result.get("verdict") not in ("pass", "fail"):
        raise RuntimeError(f"scan of {target} ended {result.get('verdict')!r}; see {work / 'run.log'}")
    doc = json.loads(Path(result["findings_json"]).read_text())
    timings = (doc.get("provenance") or {}).get("timings") or {}
    return {"wall_s": wall, "total_s": timings.get("total_s"),
            "scanners_s": timings.get("scanners_s"), "engines": timings.get("engines") or {},
            "findings": len(doc.get("findings") or []),
            "files_in_scope": ((doc.get("provenance") or {}).get("scope") or {}).get("files")}


def _median(values):
    values = [v for v in values if v is not None]
    return round(statistics.median(values), 1) if values else None


def summarize(runs: list[dict]) -> dict:
    engines = sorted({e for r in runs for e in r["engines"]})
    per_engine = {e: _median([r["engines"].get(e) for r in runs]) for e in engines}
    return {"runs": len(runs), "wall_s": _median([r["wall_s"] for r in runs]),
            "scanners_s": _median([r["scanners_s"] for r in runs]),
            "wall_s_range": [min(r["wall_s"] for r in runs), max(r["wall_s"] for r in runs)],
            "engines": dict(sorted(per_engine.items(), key=lambda kv: -(kv[1] or 0))),
            "findings": runs[-1]["findings"], "files_in_scope": runs[-1]["files_in_scope"]}


def default_engines() -> list[str]:
    import yaml
    cfg = yaml.safe_load((ROOT / "scan-config.yml").read_text())
    return [n for n, b in cfg["scanners"].items() if (b or {}).get("enabled")]


def isolated(repo: Path, work: Path, slug: str) -> dict[str, float]:
    """Each default engine on its own (one run each, after the warm-up)."""
    out = {}
    for engine in default_engines():
        overlay = work / f"only-{engine}.yml"
        overlay.write_text(json.dumps({"scanners": {e: {"enabled": e == engine}
                                                    for e in default_engines()}}))
        bench.log(f"speed: {engine} alone")
        out[engine] = scan(repo, work, slug, "--config", str(overlay))["engines"].get(engine)
    return out


def machine() -> dict:
    info = {"platform": platform.platform(), "cpus": os.cpu_count(),
            "load_average_at_start": [round(x, 2) for x in os.getloadavg()]}
    try:
        out = subprocess.run(["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}}"],
                             capture_output=True, text=True, timeout=20).stdout.split()
        info["docker_cpus"], info["docker_mem_gb"] = int(out[0]), round(int(out[1]) / 2**30, 1)
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        pass
    return info


def count_files(root: Path) -> int:
    return sum(1 for p in root.rglob("*") if p.is_file() and ".git" not in p.parts)


def render_md(doc: dict) -> str:
    m = doc["machine"]
    lines = [
        "# Speed", "",
        "How long appsec-compose takes on real codebases with the shipped defaults: "
        "median of repeated runs after a warm-up (databases cached, collector image "
        "built). Engines run in parallel, so a scan costs what its slowest engine "
        "costs. Re-run with `python3 benchmark/speed.py`; method in its docstring.", "",
        f"appsec-compose {doc['version']} · {doc['generated']} · {m.get('platform')} · "
        f"{m.get('cpus')} CPUs (Docker: {m.get('docker_cpus', '?')} CPUs, "
        f"{m.get('docker_mem_gb', '?')} GB) · load average at start "
        f"{', '.join(map(str, m.get('load_average_at_start', [])))}", "",
        "| Corpus | Files | Mode | Median | Range | Scanners | Slowest engines |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, c in doc["corpora"].items():
        for mode in ("full", "diff"):
            s = c[mode]
            slow = ", ".join(f"{e} {v:g} s" for e, v in list(s["engines"].items())[:3]) or "—"
            files = f"{c['files']:,}" if mode == "full" else f"{s['files_in_scope']} changed"
            lines.append(f"| {name} @ `{c['commit'][:12]}` | {files} | {mode} | "
                         f"**{s['wall_s']} s** | {s['wall_s_range'][0]}–{s['wall_s_range'][1]} s | "
                         f"{s['scanners_s']} s | {slow} |")
    lines += ["", "Per engine (median seconds):", ""]
    engines = sorted({e for c in doc["corpora"].values() for m_ in ("full", "diff")
                      for e in c[m_]["engines"]})
    lines.append("| Corpus | Mode | " + " | ".join(engines) + " |")
    lines.append("|---|---|" + "---|" * len(engines))
    for name, c in doc["corpora"].items():
        for mode in ("full", "diff"):
            row = [str(c[mode]["engines"].get(e, "—")) for e in engines]
            lines.append(f"| {name} | {mode} | " + " | ".join(row) + " |")
    if any("alone" in c for c in doc["corpora"].values()):
        lines += ["", "Each engine alone vs. side by side in the full scan (seconds):", "",
                  "| Corpus | Engine | Alone | In the full scan |", "|---|---|---|---|"]
        for name, c in doc["corpora"].items():
            for e, t in (c.get("alone") or {}).items():
                lines.append(f"| {name} | {e} | {t} | {c['full']['engines'].get(e, '—')} |")
    lines += ["", "Numbers from one machine under its own load; compare runs from the same "
              "machine, not across machines. Diff mode: one existing file edited and one "
              "new file added, uncommitted, `--diff HEAD`.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cache", type=Path, default=bench.DEFAULT_CACHE)
    ap.add_argument("--corpus", action="append", choices=sorted(CORPORA))
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--no-write", action="store_true", help="print, do not update SPEED.md")
    ap.add_argument("--isolate", action="store_true",
                    help="also time each default engine running alone")
    args = ap.parse_args(argv)

    corpora_meta = json.loads((HERE / "corpora.json").read_text())
    doc = {"version": (ROOT / "VERSION").read_text().strip(),
           "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "machine": machine(), "corpora": {}}
    for name in args.corpus or list(CORPORA):
        spec = CORPORA[name]
        meta = corpora_meta[spec["key"]]
        src = bench.fetch_github_commit(meta["repo"], meta["commit"], args.cache, name)
        work = args.cache / "speed" / name
        work.mkdir(parents=True, exist_ok=True)
        repo = git_repo(src, work / "repo")
        slug = f"bench-speed-{name}"
        bench.log(f"speed/{name}: warm-up")
        scan(repo, work, slug)
        full = []
        for i in range(args.runs):
            bench.log(f"speed/{name}: full {i + 1}/{args.runs}")
            full.append(scan(repo, work, slug))
        alone = isolated(repo, work, slug) if args.isolate else None
        make_change(repo, spec)
        diff = []
        for i in range(args.runs):
            bench.log(f"speed/{name}: diff {i + 1}/{args.runs}")
            diff.append(scan(repo, work, slug, "--diff", "HEAD"))
        doc["corpora"][name] = {"commit": meta["commit"], "repo": meta["repo"],
                                "files": count_files(src),
                                "full": summarize(full), "diff": summarize(diff),
                                **({"alone": alone} if alone else {}),
                                "raw": {"full": full, "diff": diff}}
    md = render_md(doc)
    if args.no_write:
        print(md)
    else:
        SPEED_JSON.write_text(json.dumps(doc, indent=2) + "\n")
        SPEED_MD.write_text(md)
        bench.log(f"wrote {SPEED_MD.relative_to(ROOT)} and {SPEED_JSON.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
