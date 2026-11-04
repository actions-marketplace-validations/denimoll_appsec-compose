"""A project's target: a local directory, or a git URL fetched shallowly.

A git URL is an attack surface before anything is scanned: `ext::sh -c ...` runs
a command, a leading dash becomes an option, `file://` reads the local disk, and
`https://user:token@host` would put a credential in a file the UI renders. So
only plain https and ssh pass, git gets the URL after `--` in an argv list, and
GIT_ALLOW_PROTOCOL holds for whatever a redirect or a submodule suggests.

A clone's content is untrusted: `core.symlinks=false` stops a repo from planting
`.appsec-compose.yml -> ~/.ssh/id_rsa` for the host-side config step to read, and
hooks stay off (a clone brings none, the user's own templates must not run).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from .paths import UsageError

GIT_TIMEOUT = 900   # seconds; a hung remote must not hold a batch forever
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_UNSAFE_IN_URL = re.compile(r"[\x00-\x20\x7f\\]")
_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")
_USER = re.compile(r"[A-Za-z0-9._][A-Za-z0-9._-]*")
_SCP = re.compile(r"([^@/:]+)@([^/:]+):(.+)")
_HELPER = re.compile(r"[A-Za-z0-9+.-]+::")
_GIT_HARDENING = ["-c", "core.symlinks=false", "-c", "core.hooksPath=/dev/null"]
_GIT_ENV_DROP = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                 "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_PREFIX", "GIT_COMMON_DIR")


class CloneError(RuntimeError):
    """The source could not be fetched: the scan did not complete (exit 3)."""


def is_git_url(raw: str) -> bool:
    """Anything that looks remote goes to the URL check, which then decides."""
    return bool(raw.startswith("-") or "://" in raw or _HELPER.match(raw) or _SCP.fullmatch(raw))


def check_git_url(url: str) -> str:
    bad = f"git URL {url!r} is not allowed:"
    if url.startswith("-"):
        raise UsageError(f"{bad} it starts with a dash")
    if _UNSAFE_IN_URL.search(url):
        raise UsageError(f"{bad} it contains whitespace, a control character or a backslash")
    if _HELPER.match(url):
        raise UsageError(f"{bad} transport helpers (ext::, fd::, ...) can run commands")
    if "://" not in url:
        match = _SCP.fullmatch(url)
        if not match:
            raise UsageError(f"{bad} use https://, ssh:// or user@host:path")
        user, host, path = match.groups()
        if not (_USER.fullmatch(user) and _HOST.fullmatch(host)) or path.startswith("-"):
            raise UsageError(f"{bad} malformed user, host or path")
        return url
    try:
        parts = urlsplit(url)
        parts.port   # raises on a malformed port
    except ValueError as exc:
        raise UsageError(f"{bad} {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("https", "ssh"):
        raise UsageError(f"{bad} only https and ssh are accepted, not {parts.scheme or 'this'}")
    if not (parts.hostname and _HOST.fullmatch(parts.hostname)):
        raise UsageError(f"{bad} malformed host")
    if parts.path in ("", "/") or parts.query or parts.fragment:
        raise UsageError(f"{bad} it needs a repository path and no query or fragment")
    if parts.password is not None or (scheme == "https" and parts.username is not None):
        raise UsageError(f"{bad} no credentials in the URL (it is stored and displayed); "
                         "use a git credential helper or ssh")
    if parts.username is not None and not _USER.fullmatch(parts.username):
        raise UsageError(f"{bad} malformed user")
    return url


def check_path(raw: str) -> str:
    if _CONTROL.search(raw):
        raise UsageError(f"target path {raw!r} contains a control character")
    if not raw.startswith("/"):
        raise UsageError(f"target path {raw!r} must be absolute")
    return raw


def check_stored(target: object) -> str:
    """A target read back from a definition file: same rules, the directory may be gone."""
    if not (isinstance(target, str) and target):
        raise UsageError("target: expected a path or a git URL")
    return check_git_url(target) if is_git_url(target) else check_path(target)


def normalize(raw: str) -> str:
    """A target given by the user: a URL as it is, a path absolute and existing."""
    raw = (raw or "").strip()
    # A path copied from a terminal or dragged from a file manager comes quoted.
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        raw = raw[1:-1].strip()
    if not raw:
        raise UsageError("a target is required: a directory, or an https/ssh git URL")
    if is_git_url(raw):
        return check_git_url(raw)
    if _CONTROL.search(raw):
        raise UsageError(f"target path {raw!r} contains a control character")
    path = Path(raw).expanduser().resolve()
    if not path.is_dir():
        raise UsageError(f"target '{raw}' is not a directory")
    return check_path(str(path))


def _env() -> dict:
    env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV_DROP}
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https:ssh",
                "GIT_LFS_SKIP_SMUDGE": "1"})
    # A batch run has nobody to answer a passphrase or host-key prompt.
    env.setdefault("GIT_SSH_COMMAND", "ssh -oBatchMode=yes")
    return env


def _git(*args: str, capture: bool = False) -> str:
    try:
        proc = subprocess.run(["git", *_GIT_HARDENING, *args], env=_env(), text=True,
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=GIT_TIMEOUT)
    except FileNotFoundError as exc:
        raise CloneError("git is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise CloneError(f"git timed out after {GIT_TIMEOUT} s") from exc
    if proc.returncode:
        detail = " ".join(proc.stderr.split())[-500:]
        verb = args[2] if args[0] == "-C" else args[0]
        raise CloneError(f"git {verb} failed: {detail or f'exit {proc.returncode}'}")
    return proc.stdout.strip() if capture else ""


def fetch(url: str, dest: Path) -> None:
    """Bring `dest` to the remote's HEAD: clone if new or re-pointed, else update in place."""
    check_git_url(url)
    if (dest / ".git").is_dir():
        try:
            if _git("-C", str(dest), "remote", "get-url", "origin", capture=True) == url:
                _git("-C", str(dest), "fetch", "--quiet", "--depth", "1",
                     "--no-recurse-submodules", "--", "origin", "HEAD")
                _git("-C", str(dest), "reset", "--quiet", "--hard", "FETCH_HEAD")
                _git("-C", str(dest), "clean", "-qffdx")
                return
        except CloneError:
            pass   # a clone gone bad locally must not block; a dead remote fails below too
    # Clone beside it and swap, so a failed clone leaves no half-tree to scan.
    fresh = dest.with_name(dest.name + ".new")
    shutil.rmtree(fresh, ignore_errors=True)
    try:
        _git("clone", "--quiet", "--depth", "1", "--no-recurse-submodules", "--template=",
             "-c", "core.symlinks=false", "--", url, str(fresh))
    except CloneError:
        shutil.rmtree(fresh, ignore_errors=True)
        raise
    shutil.rmtree(dest, ignore_errors=True)
    fresh.rename(dest)
