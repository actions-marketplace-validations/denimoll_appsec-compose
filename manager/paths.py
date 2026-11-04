"""Where projects live, and the one rule that keeps a name inside them.

Definitions are configuration (`$XDG_CONFIG_HOME`), reports and clones are state
(`$XDG_STATE_HOME`). Every path below is built from a name that passed
`check_name`, so a project called `../../etc` cannot exist: the pattern admits
no separator and no leading dot. fullmatch, not match with `$`, which would
accept a trailing newline.
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "bin" / "appsec-compose"

_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
MAX_NAME = 63


class UsageError(ValueError):
    """Bad input from the user or a definition file: exit 2."""


def check_name(name: object, kind: str = "project") -> str:
    if not (isinstance(name, str) and len(name) <= MAX_NAME and _NAME.fullmatch(name)):
        raise UsageError(f"invalid {kind} name {name!r}: use lower-case letters, digits and "
                         f"dashes, starting with a letter or digit (at most {MAX_NAME})")
    return name


def _xdg(variable: str, fallback: str) -> Path:
    return Path(os.environ.get(variable) or Path.home() / fallback) / "appsec-compose"


def config_home() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config")


def state_home() -> Path:
    return _xdg("XDG_STATE_HOME", ".local/state")


def projects_dir() -> Path:
    return config_home() / "projects"


def profiles_dir() -> Path:
    return config_home() / "profiles"


def project_file(name: str) -> Path:
    return projects_dir() / f"{check_name(name)}.yml"


def profile_file(name: str) -> Path:
    return profiles_dir() / f"{check_name(name, 'profile')}.yml"


def project_state(name: str) -> Path:
    return state_home() / "projects" / check_name(name)


def reports_dir(name: str) -> Path:
    return project_state(name) / "reports"


def source_dir(name: str) -> Path:
    return project_state(name) / "source"


def index_file() -> Path:
    return state_home() / "index.html"


def private_dir(path: Path) -> Path:
    """Create a directory only its owner can enter: reports quote the flagged code."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def write_atomic(path: Path, text: str) -> None:
    """Replace a file whole, so a crash or a concurrent reader never sees half of it."""
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
