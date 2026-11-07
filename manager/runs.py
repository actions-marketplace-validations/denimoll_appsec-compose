"""A project's run history, and the lock that keeps it to one scan at a time.

The lock is flock(2) on a file in the project's state directory, so it holds
across everything that can start a scan (the CLI, cron, `serve`) and the kernel
drops it if the holder dies: there is no stale lock to clean up, and "is it
running?" is answered by the lock itself rather than a status file that a crash
would leave lying.

History keeps the last N runs' summaries, not their reports: enough for a trend,
without keeping N copies of quoted source code around. The reports directory
always holds the latest run.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import time

from .paths import private_dir, project_state, reports_dir, write_atomic

DEFAULT_KEEP = 20
_LOCK_TRIES = 3
SEVERITIES = ["critical", "high", "medium", "low", "info"]
_RANK = {name: rank for rank, name in enumerate(reversed(SEVERITIES))}
_SPARK = "▁▂▃▄▅▆▇█"


class ProjectBusy(RuntimeError):
    """Another scan of this project holds the lock."""


@contextlib.contextmanager
def project_lock(name: str):
    state = private_dir(project_state(name))
    fd = os.open(state / ".lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        # A few tries: is_running() holds the lock for an instant when it probes.
        for attempt in range(_LOCK_TRIES):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if attempt == _LOCK_TRIES - 1:
                    raise ProjectBusy(name) from exc
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


def is_running(name: str) -> bool:
    path = project_state(name) / ".lock"
    try:
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    finally:
        os.close(fd)
    return False


def keep_runs() -> int:
    try:
        return max(1, int(os.environ.get("APPSEC_COMPOSE_KEEP_RUNS", DEFAULT_KEEP)))
    except ValueError:
        return DEFAULT_KEEP


def _history(name: str):
    return project_state(name) / "runs.json"


def read_runs(name: str) -> list[dict]:
    """Oldest first. An unreadable history reads as none: it is a convenience, not a verdict."""
    try:
        with open(_history(name), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def latest(name: str) -> dict | None:
    history = read_runs(name)
    return history[-1] if history else None


def record(name: str, entry: dict) -> None:
    """Called under the project's lock, the history's only writer."""
    history = (read_runs(name) + [entry])[-keep_runs():]
    write_atomic(_history(name), json.dumps(history, indent=1))


def _top_component(components: object) -> str | None:
    """The one upgrade worth naming: a malicious package first, then the worst severity,
    then the most vulnerabilities. Values come from the scanned repo: escape on output."""
    entries = [c for c in components if isinstance(c, dict)] if isinstance(components, list) else []
    if not entries:
        return None
    top = max(entries, key=lambda c: (bool(c.get("malicious")), _RANK.get(c.get("severity"), -1),
                                      c["vulnerabilities"] if isinstance(c.get("vulnerabilities"), int) else 0))
    package = str(top.get("package") or top.get("name") or "?")[:120]
    if top.get("malicious"):
        return f"remove {package} (malicious)"
    upgrade = top.get("upgrade_to")
    return f"{package} -> {str(upgrade)[:40]}" if upgrade else f"{package} (no single fix)"


def summarize(findings_json: object) -> dict:
    """What a run's history entry keeps from findings.json. Tolerates any shape."""
    empty = {"severity_counts": None, "breaching": None, "top_component": None, "attention": [],
             "slowest_engine": None, "brief_tokens": None}
    if not findings_json:
        return empty
    try:
        with open(str(findings_json), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return empty
    if not isinstance(data, dict):
        return empty
    counts = data.get("severity_counts")
    policy = data.get("policy") if isinstance(data.get("policy"), dict) else {}
    breaching = policy.get("breaching")
    return {
        "severity_counts": {s: counts.get(s, 0) if isinstance(counts.get(s, 0), int) else 0
                            for s in SEVERITIES} if isinstance(counts, dict) else None,
        "breaching": breaching if isinstance(breaching, int) else None,
        "top_component": _top_component(data.get("components")),
        "attention": _attention(data),
        **_cost(data),
    }


def _cost(data: dict) -> dict:
    """Where a run's time went and what its brief costs to read (metrics, 1.5)."""
    metrics = data.get("metrics") if isinstance(data.get("metrics"), dict) else {}
    engines = ((metrics.get("time_s") or {}).get("engines") or {}) if isinstance(
        metrics.get("time_s"), dict) else {}
    slowest = next(((str(k), v) for k, v in engines.items()
                    if isinstance(v, (int, float))), None) if isinstance(engines, dict) else None
    tokens = (metrics.get("brief") or {}).get("approx_tokens") if isinstance(
        metrics.get("brief"), dict) else None
    return {"slowest_engine": f"{slowest[0]} {slowest[1]:g} s" if slowest else None,
            "brief_tokens": tokens if isinstance(tokens, int) else None}


def _attention(data: dict) -> list[str]:
    """What makes this result less than it looks: a count of findings says
    nothing about dependencies no engine resolved or a report that came back
    incomplete, and "no findings there" is easy to read as clean."""
    out: list[str] = []
    coverage = data.get("coverage") if isinstance(data.get("coverage"), dict) else {}
    for warning in coverage.get("warnings") or []:
        if isinstance(warning, dict):
            out.append(f"{warning.get('message', '')} {warning.get('advice', '')}".strip())
    out += [f"Incomplete or unreadable report: {e}" for e in data.get("reports_errored") or []]
    out += [f"No report from: {r}" for r in data.get("reports_missing") or []]
    prov = data.get("provenance") if isinstance(data.get("provenance"), dict) else {}
    repo = prov.get("repo_config")
    if isinstance(repo, dict):
        out.append(f"The scanned repository's own {repo.get('file', 'config')} set: "
                   f"{', '.join(map(str, repo.get('applied') or [])) or 'nothing'}.")
    return [str(x)[:400] for x in out[:8]]


def attention_of(name: str, run: dict | None) -> list[str]:
    """A run's warnings. Runs recorded before the field: from the latest report."""
    if not run:
        return []
    if isinstance(run.get("attention"), list):
        return [str(x) for x in run["attention"]]
    if not run.get("has_reports"):
        return []
    return summarize(reports_dir(name) / "findings.json")["attention"]


_SPOT_MARKUP = str.maketrans("", "", "*`")


def blind_spots(name: str) -> list[str]:
    """The review brief's blind-spot bullets, as plain text."""
    try:
        with open(reports_dir(name) / "review-brief.md", encoding="utf-8") as fh:
            text = fh.read(256 * 1024)
    except OSError:
        return []
    _, found, rest = text.partition("## Blind spots")
    if not found:
        return []
    section = rest.split("\n## ", 1)[0]
    # These two are already in `attention`, above them on the page.
    return [line[2:].translate(_SPOT_MARKUP) for line in section.splitlines()
            if line.startswith("- ") and not line.startswith(("- **SCA coverage:", "- **Incomplete report:"))]


def total(run: dict | None) -> int | None:
    counts = (run or {}).get("severity_counts")
    if not isinstance(counts, dict):
        return None
    return sum(v for v in counts.values() if isinstance(v, int))


def trend(history: list[dict], points: int = 10) -> dict:
    """Findings over the runs that reached a verdict; a broken scan says nothing about them."""
    totals = [t for t in (total(r) for r in history) if t is not None][-points:]
    if not totals:
        return {"totals": [], "spark": "", "delta": None}
    high = max(totals) or 1
    spark = "".join(_SPARK[(t * (len(_SPARK) - 1)) // high] for t in totals)
    return {"totals": totals, "spark": spark,
            "delta": totals[-1] - totals[-2] if len(totals) > 1 else None}
