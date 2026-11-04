"""One scan of one project: fetch the source, call the launcher, record the outcome.

Goes through `bin/appsec-compose scan --json` like any other caller, so the
launcher's conventions (the target's `.appsec-compose.yml` and
`.appsec-baseline.json`) apply as they do by hand, and the exit-code contract is
the launcher's. Engine output goes to a private log and is never rendered: only
run.sh's own `Error:` lines are surfaced.

The compose project is `appsec-project-<name>` rather than the launcher's default
(the directory name), because run.sh starts with `compose down --remove-orphans`:
sharing a name with a by-hand `scan ~/src/<name>` would stop that scan.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from . import runs, store, targets
from .paths import (LAUNCHER, UsageError, private_dir, profile_file, project_state,
                    reports_dir, source_dir)

VERDICTS = {0: "pass", 1: "fail", 2: "usage_error", 3: "scan_error"}
_ERROR_LINE = re.compile(r"(Error|ERROR):? ")


def _result(name: str, code: int, error: str | None = None, **extra) -> dict:
    return {"project": name, "exit_code": code, "verdict": VERDICTS.get(code, "scan_error"),
            "reports_dir": None, "findings_json": None, "review_brief": None,
            "severity_counts": None, "breaching": None, "baseline": None, "error": error, **extra}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_file(name: str) -> Path:
    return project_state(name) / "scan.log"


def _errors_from(log: Path) -> str | None:
    """run.sh's own error lines and their indented details, not the engines' output."""
    found: list[str] = []
    try:
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    keep = False
    for line in lines:
        keep = bool(_ERROR_LINE.match(line)) or (keep and line.startswith("  "))
        if keep:
            found.append(line)
    return "\n".join(found)[:1000] or None


def _invoke(argv: list[str], name: str, on_start) -> tuple[int, dict]:
    log = log_file(name)
    log.touch(mode=0o600)
    with open(log, "w", encoding="utf-8") as fh:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=fh, stdin=subprocess.DEVNULL,
                                cwd=project_state(name), text=True,
                                start_new_session=on_start is not None)
        if on_start:
            on_start(name, proc)
        stdout, _ = proc.communicate()
    try:
        parsed = json.loads(stdout)
    except ValueError:
        parsed = {}
    code = proc.returncode if proc.returncode in VERDICTS else 3
    return code, parsed if isinstance(parsed, dict) else {}


def _scan_under_lock(project: store.Project, extra: list[str], on_start) -> dict:
    name = project.name
    target = project.target
    args: list[str] = [] if project.repo_config else ["--no-repo-config"]
    if project.is_git:
        target = str(source_dir(name))
        targets.fetch(project.target, Path(target))
        # A clone is replaced freely, so its baseline lives beside it (the
        # launcher would otherwise take one committed in the repo, if any).
        baseline = project_state(name) / "baseline.json"
        # Its own, from our own earlier snapshot: not the repo's, so kept either way.
        if baseline.exists() or "--update-baseline" in extra:
            args += ["--baseline", str(baseline)]
    if project.profile:
        profile = profile_file(project.profile)
        if not profile.is_file():
            raise UsageError(f"project '{name}' uses profile '{project.profile}', which does not exist")
        args += ["--profile", str(profile)]
    reports = reports_dir(name)
    argv = [str(LAUNCHER), "scan", target, "--reports", str(reports),
            "--name", f"project-{name}", "--json", *args, *extra]
    code, parsed = _invoke(argv, name, on_start)
    return _result(name, code, None if code in (0, 1) else _errors_from(log_file(name)), **{
        k: parsed.get(k) for k in ("reports_dir", "findings_json", "review_brief",
                                   "severity_counts", "breaching", "baseline")})


def scan_project(name: str, extra: list[str] | None = None, trigger: str = "manual",
                 on_start=None) -> dict:
    """Never raises for a failed scan: the result carries the exit code, 0-3."""
    try:
        project = store.load_project(name)
    except UsageError as exc:
        return _result(name, 2, str(exc))
    try:
        with runs.project_lock(name):
            started, began = _now(), time.time()
            try:
                result = _scan_under_lock(project, list(extra or []), on_start)
            except targets.CloneError as exc:
                result = _result(name, 3, str(exc))
            except UsageError as exc:
                result = _result(name, 2, str(exc))
            except OSError as exc:
                result = _result(name, 3, f"could not run the scan: {exc.strerror or exc}")
            summary = runs.summarize(result["findings_json"])
            runs.record(name, {
                "started": started, "finished": _now(), "duration_s": round(time.time() - began),
                "trigger": trigger, "exit_code": result["exit_code"], "verdict": result["verdict"],
                "severity_counts": summary["severity_counts"], "breaching": summary["breaching"],
                "top_component": summary["top_component"],
                "attention": summary["attention"],
                "has_reports": bool(result["findings_json"]), "error": result["error"]})
            return result
    except runs.ProjectBusy:
        return _result(name, 3, "another scan of this project is running")
    except OSError as exc:
        return _result(name, 3, f"could not use the project's state directory: {exc.strerror or exc}")
