"""Project and profile definitions: one YAML file each, read and validated on every use.

Files, not a database, so a definition can be read, edited and versioned by
hand. For the same reason nothing read back is trusted: a hand-edited
`target: ext::sh -c ...` is rejected on load exactly as `project add` rejects it.

A profile is the same format as a project config, checked by the same
orchestrator/schema.py as `run.sh` checks it, only earlier: when it is saved,
not minutes into a nightly batch.
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
from dataclasses import dataclass, field

import yaml

from . import cron, runs, targets
from .paths import (ROOT, UsageError, check_name, private_dir, profile_file, profiles_dir,
                    project_file, project_state, projects_dir, write_atomic)

_PROJECT_KEYS = {"name", "target", "profile", "meta", "schedule"}
_META_KEY = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_META_VALUE = 500
_RESERVED = {"new"}


@dataclass
class Project:
    name: str
    target: str
    profile: str | None = None
    meta: dict = field(default_factory=dict)
    schedule: str | None = None

    @property
    def is_git(self) -> bool:
        return targets.is_git_url(self.target)

    def to_dict(self) -> dict:
        data = {"name": self.name, "target": self.target}
        if self.profile:
            data["profile"] = self.profile
        if self.meta:
            data["meta"] = self.meta
        if self.schedule:
            data["schedule"] = self.schedule
        return data


def check_meta(meta: object) -> dict:
    if meta is None:
        return {}
    if not isinstance(meta, dict):
        raise UsageError("meta: expected a mapping of key: value")
    out = {}
    for key, value in meta.items():
        if not (isinstance(key, str) and _META_KEY.fullmatch(key)):
            raise UsageError(f"meta key {key!r}: use letters, digits, '_', '.', '-'")
        value = "" if value is None else str(value)
        if len(value) > MAX_META_VALUE or _CONTROL.search(value):
            raise UsageError(f"meta value of '{key}': too long, or holds a control character")
        out[key] = value
    return out


def parse_meta(pairs: list[str]) -> dict:
    """`k=v` strings, from the command line or the UI's text box."""
    meta = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep:
            raise UsageError(f"meta '{pair}': expected key=value")
        meta[key.strip()] = value.strip()
    return check_meta(meta)


def _from_dict(stem: str, data: object) -> Project:
    if not isinstance(data, dict):
        raise UsageError(f"{stem}.yml: expected a mapping")
    unknown = sorted(str(k) for k in data if k not in _PROJECT_KEYS)
    if unknown:
        raise UsageError(f"{stem}.yml: unknown key(s) {', '.join(unknown)}")
    if data.get("name", stem) != stem:
        raise UsageError(f"{stem}.yml: its name must match the file name")
    profile = data.get("profile")
    schedule = data.get("schedule")
    return Project(
        name=check_name(stem),
        target=targets.check_stored(data.get("target")),
        profile=check_name(profile, "profile") if profile else None,
        meta=check_meta(data.get("meta")),
        schedule=cron.normalize(schedule) if schedule else None)


def load_project(name: str) -> Project:
    path = project_file(name)
    try:
        return _from_dict(name, yaml.safe_load(path.read_text(encoding="utf-8")))
    except FileNotFoundError as exc:
        raise UsageError(f"no project named '{name}'") from exc
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise UsageError(f"{path.name}: cannot be read: {exc}") from exc


def list_projects() -> tuple[list[Project], list[tuple[str, str]]]:
    """Every project, plus the files that are not one, as (stem, why): one bad file
    must not hide the rest, and must not pass for nothing being there."""
    good, broken = [], []
    folder = projects_dir()
    for path in sorted(folder.glob("*.yml")) if folder.is_dir() else []:
        try:
            good.append(load_project(check_name(path.stem)))
        except UsageError as exc:
            broken.append((path.stem, str(exc)))
    return good, broken


def save_project(project: Project) -> None:
    _from_dict(project.name, project.to_dict())   # the same rules as a load
    write_atomic(project_file(project.name), yaml.safe_dump(project.to_dict(), sort_keys=False))


def add_project(name: str, target: str, profile: str | None = None, meta: dict | None = None,
                schedule: str | None = None) -> Project:
    check_name(name)
    if name in _RESERVED:
        raise UsageError(f"'{name}' is reserved by the UI's URLs")
    profile = profile or None
    if profile:
        read_profile(profile)
    project = Project(name, targets.normalize(target), profile, check_meta(meta),
                      cron.normalize(schedule) if schedule else None)
    _from_dict(name, project.to_dict())
    private_dir(projects_dir())
    # 'x': two simultaneous adds of one name cannot both succeed.
    try:
        with open(project_file(name), "x", encoding="utf-8") as fh:
            os.fchmod(fh.fileno(), 0o600)
            yaml.safe_dump(project.to_dict(), fh, sort_keys=False)
    except FileExistsError as exc:
        raise UsageError(f"project '{name}' already exists") from exc
    return project


def update_project(name: str, target: str, profile: str | None, meta: dict,
                   schedule: str | None) -> Project:
    load_project(name)
    if profile:
        read_profile(profile)
    project = Project(name, targets.normalize(target), profile or None, check_meta(meta),
                      cron.normalize(schedule) if schedule else None)
    save_project(project)
    return project


def set_schedule(name: str, schedule: str | None) -> Project:
    project = load_project(name)
    project.schedule = cron.normalize(schedule) if schedule else None
    save_project(project)
    return project


def delete_project(name: str, keep_state: bool = False) -> None:
    """Remove the definition and what we stored for it. A local target is never touched."""
    check_name(name)
    if not project_file(name).exists():
        raise UsageError(f"no project named '{name}'")
    state = project_state(name)
    if keep_state or not state.exists():
        project_file(name).unlink()
        return
    if state.is_symlink():
        raise UsageError(f"{state} is a symlink; remove it by hand")
    try:
        with runs.project_lock(name):
            project_file(name).unlink()
            shutil.rmtree(state)
    except runs.ProjectBusy as exc:
        raise UsageError(f"project '{name}' is being scanned; try again when it finishes") from exc
    except OSError as exc:
        raise UsageError(f"could not remove {state}: {exc.strerror or exc}") from exc


# ---- profiles ----------------------------------------------------------------

def _schema():
    spec = importlib.util.spec_from_file_location("ass_schema", ROOT / "orchestrator" / "schema.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _known_scanners() -> set:
    with open(ROOT / "scan-config.yml", encoding="utf-8") as fh:
        return set((yaml.safe_load(fh) or {}).get("scanners") or {})


def check_profile_text(text: str, label: str = "profile") -> None:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise UsageError(f"{label} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise UsageError(f"{label} must be a mapping of settings")
    problems = _schema().validate(data, known_scanners=_known_scanners())
    if problems:
        raise UsageError(f"invalid {label}:\n  " + "\n  ".join(
            p.replace("scan-config.yml", label) for p in problems))


def list_profiles() -> list[str]:
    folder = profiles_dir()
    names = []
    for path in sorted(folder.glob("*.yml")) if folder.is_dir() else []:
        try:
            names.append(check_name(path.stem, "profile"))
        except UsageError:
            continue
    return names


def read_profile(name: str) -> str:
    try:
        return profile_file(name).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise UsageError(f"no profile named '{name}' ({profile_file(name)})") from exc


def save_profile(name: str, text: str, create: bool = False) -> None:
    check_name(name, "profile")
    exists = profile_file(name).exists()
    if create and exists:
        raise UsageError(f"profile '{name}' already exists")
    if not create and not exists:
        raise UsageError(f"no profile named '{name}'")
    text = text.replace("\r\n", "\n")   # what a browser's text box submits
    check_profile_text(text, f"{name}.yml")
    write_atomic(profile_file(name), text)


def delete_profile(name: str) -> None:
    check_name(name, "profile")
    if not profile_file(name).exists():
        raise UsageError(f"no profile named '{name}'")
    users = [p.name for p in list_projects()[0] if p.profile == name]
    if users:
        raise UsageError(f"profile '{name}' is used by: {', '.join(users)}")
    profile_file(name).unlink()
