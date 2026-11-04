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

from .paths import private_dir, project_state, write_atomic

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
    empty = {"severity_counts": None, "breaching": None, "top_component": None}
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
    }


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
