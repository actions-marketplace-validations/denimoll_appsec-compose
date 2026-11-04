"""What `serve` runs in the background: scans on demand, and the schedules that are due.

Scans queue on a semaphore (one at a time by default, as a batch does) and each
project is on the queue at most once. runs.project_lock remains the real
guarantee against two scans of a project, and also covers a CLI or crontab scan
this process knows nothing about.
"""
from __future__ import annotations

import os
import shlex
import shutil
import signal
import sys
import threading
from datetime import datetime, timedelta

from . import cron, runner, runs, store
from .paths import LAUNCHER, UsageError

MAX_CATCH_UP_MINUTES = 5


class Scans:
    def __init__(self, jobs: int = 1, scan=runner.scan_project):
        self._scan, self._slots = scan, threading.BoundedSemaphore(max(1, jobs))
        self._lock = threading.Lock()
        self._active: dict[str, str] = {}
        self._procs: dict = {}
        self._stopping = False

    def state(self, name: str) -> str:
        """idle, queued or running (here, or by another process)."""
        with self._lock:
            active = self._active.get(name)
        return active or ("running" if runs.is_running(name) else "idle")

    def start(self, name: str, trigger: str = "manual") -> bool:
        """Queue a scan; False if this project already has one, wherever it runs."""
        with self._lock:
            if self._stopping or name in self._active or runs.is_running(name):
                return False
            self._active[name] = "queued"
        threading.Thread(target=self._run, args=(name, trigger), daemon=True).start()
        return True

    def _started(self, name: str, proc) -> None:
        with self._lock:
            self._procs[name] = proc

    def _run(self, name: str, trigger: str) -> None:
        try:
            with self._slots:
                with self._lock:
                    if self._stopping:
                        return
                    self._active[name] = "running"
                self._scan(name, trigger=trigger, on_start=self._started)
        except Exception as exc:  # the thread's last chance to say so
            print(f"scan of {name} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        finally:
            with self._lock:
                self._active.pop(name, None)
                self._procs.pop(name, None)

    def stop(self) -> None:
        """Queued scans never start; running ones get SIGTERM, in their own process group."""
        with self._lock:
            self._stopping = True
            procs = list(self._procs.values())
        for proc in procs:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                pass


def due(projects: list[store.Project], minute: datetime) -> list[str]:
    names = []
    for project in projects:
        if project.schedule and cron.parse(project.schedule).matches(minute):
            names.append(project.name)
    return names


class Scheduler(threading.Thread):
    """Checks once per wall-clock minute. A short stall is caught up; a laptop that slept
    all night does not replay the night, the same as cron."""

    def __init__(self, scans: Scans, clock=datetime.now):
        super().__init__(daemon=True)
        self.scans, self.clock = scans, clock
        self.halted = threading.Event()
        self.last = self._minute()

    def _minute(self) -> datetime:
        return self.clock().replace(second=0, microsecond=0)

    def tick(self) -> list[str]:
        now = self._minute()
        started = []
        if now <= self.last:
            return started
        if now - self.last > timedelta(minutes=MAX_CATCH_UP_MINUTES):
            self.last = now - timedelta(minutes=1)
        projects, _ = store.list_projects()
        while self.last < now:
            self.last += timedelta(minutes=1)
            for name in due(projects, self.last):
                if self.scans.start(name, trigger="schedule"):
                    started.append(name)
        return started

    def run(self) -> None:
        while not self.halted.wait(1):
            try:
                self.tick()
            except Exception as exc:  # e.g. a definition being edited: try again next minute
                print(f"scheduler: {type(exc).__name__}: {exc}", file=sys.stderr)


# ---- crontab lines -----------------------------------------------------------

def _environment() -> list[str]:
    """What cron will not have: the PATH that finds docker, and where the state lives."""
    folders = []
    for tool in ("docker", "python3", "git"):
        found = shutil.which(tool)
        if found and os.path.dirname(found) not in folders:
            folders.append(os.path.dirname(found))
    folders += [f for f in ("/usr/bin", "/bin") if f not in folders]
    env = [f"PATH={':'.join(folders)}"]
    for variable in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "ASS_CACHE_DIR",
                     "DOCKER_HOST"):
        if os.environ.get(variable):
            env.append(f"{variable}={os.environ[variable]}")
    return env


def crontab_lines() -> list[str]:
    """One line per scheduled project. `%` is a newline to cron, so it is escaped."""
    projects, broken = store.list_projects()
    if broken:
        raise UsageError("cannot read: " + ", ".join(stem for stem, _ in broken))
    lines = []
    for project in projects:
        if not project.schedule:
            continue
        words = [*_environment(), str(LAUNCHER), "project", "scan", project.name]
        command = " ".join(shlex.quote(w) for w in words).replace("%", r"\%")
        lines.append(f"{project.schedule} {command} >/dev/null 2>&1")
    return lines
