"""Targets, per-target state, and driving the appsec-compose CLI.

Everything here is independent of MCP so it can be tested without a client:
server.py only maps these functions onto tools.

A scan's reports live outside the scanned tree, in a per-target directory under
the user cache. Writing them into the target would put them in the next scan's
input, and in the user's `git status`. The last scan of each target is recorded
there too, so findings/finding/brief/suppress work without scanning again.
"""
from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import os
import re
import signal
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

TOOL_DIR = Path(os.environ.get("APPSEC_COMPOSE_DIR")
                or Path(__file__).resolve().parent.parent).resolve()

# The project-local convention: a scan-config and a baseline in the target root.
PROJECT_CONFIG = ".appsec-compose.yml"
PROJECT_BASELINE = ".appsec-baseline.json"

SEVERITIES = ["info", "low", "medium", "high", "critical"]   # lowest -> highest
THRESHOLDS = [*SEVERITIES, "none"]
CATEGORIES = ["sast", "sca", "secrets", "iac"]

# The CLI's exit codes (run.sh): each one names what the caller has to fix.
VERDICTS = {0: "pass", 1: "fail", 2: "usage_error", 3: "scan_error"}

# A scan pulls images and vulnerability DBs on first run; minutes are normal.
SCAN_TIMEOUT = float(os.environ.get("APPSEC_MCP_SCAN_TIMEOUT", "3600"))


class UserError(Exception):
    """A problem with the request the agent can fix; shown to it verbatim."""


# ---- Targets -----------------------------------------------------------------

def resolve_target(path: str) -> Path:
    """The scan target as a real, absolute directory — or a UserError.

    An agent passes whatever path it has in mind; a typo or an empty string
    must not turn into a scan of the whole home directory. Symlinks are
    resolved first, so the checks apply to what would actually be read.
    """
    if not isinstance(path, str) or not path.strip():
        raise UserError("path is required: the repository directory to scan")
    if "\x00" in path:
        raise UserError("path contains a NUL byte")
    p = Path(path.strip()).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    try:
        p = p.resolve(strict=True)
    except (OSError, RuntimeError):
        raise UserError(f"path does not exist: {path}") from None
    if not p.is_dir():
        raise UserError(f"path is not a directory: {p}")

    # Too broad to be a project: the filesystem root and its direct children
    # (/usr, /home, /Users …), the home directory and anything above it.
    home = Path.home().resolve()
    if len(p.parts) <= 2 or p == home or home.is_relative_to(p):
        raise UserError(f"refusing to scan {p}: pass a project directory, "
                        "not the filesystem root or a home directory")

    allowed = [Path(a).expanduser().resolve()
               for a in os.environ.get("APPSEC_MCP_ALLOWED_ROOTS", "").split(os.pathsep)
               if a.strip()]
    if allowed and not any(p.is_relative_to(a) for a in allowed):
        raise UserError(f"{p} is outside APPSEC_MCP_ALLOWED_ROOTS")
    if p.is_relative_to(state_root()):
        raise UserError(f"{p} is the MCP server's own report store")
    return p


# ---- Per-target state ----------------------------------------------------------

def state_root() -> Path:
    explicit = os.environ.get("APPSEC_MCP_STATE_DIR")
    if explicit:
        return Path(explicit).expanduser().resolve()
    cache = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return (Path(cache).expanduser() / "appsec-compose" / "mcp").resolve()


def _target_id(target: Path) -> str:
    return hashlib.sha256(str(target).encode()).hexdigest()[:12]


def state_dir(target: Path) -> Path:
    """<state>/<name>-<hash>: readable in a listing, unique per absolute path."""
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", target.name).strip("-.") or "target"
    return state_root() / f"{slug[:40]}-{_target_id(target)}"


def _last_scan_file(target: Path) -> Path:
    return state_dir(target) / "last-scan.json"


def load_last_scan(target: Path) -> dict:
    try:
        return json.loads(_last_scan_file(target).read_text())
    except FileNotFoundError:
        raise UserError(f"{target} has not been scanned through this server yet: "
                        "call scan(path) first") from None
    except (OSError, ValueError) as exc:
        raise UserError(f"cannot read the last scan record for {target}: {exc}") from None


def _save_last_scan(target: Path, record: dict) -> None:
    f = _last_scan_file(target)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, indent=2))
    os.replace(tmp, f)


# ---- The CLI ------------------------------------------------------------------

@dataclass
class Cli:
    """How to invoke appsec-compose from this checkout.

    `bin/appsec-compose scan` is the installable entry point with a JSON
    contract on stdout. Until it exists, run.sh takes the same flags; whether a
    given run.sh already understands --json / --diff is read from its own
    argument parser rather than assumed.
    """
    argv: list[str]
    kind: str                  # "cli" | "run.sh"
    supports_json: bool
    supports_diff: bool


def detect_cli(tool_dir: Path | None = None) -> Cli:
    tool_dir = tool_dir or TOOL_DIR
    cli = tool_dir / "bin" / "appsec-compose"
    if cli.is_file() and os.access(cli, os.X_OK):
        return Cli([str(cli), "scan"], "cli", True, True)
    run_sh = tool_dir / "run.sh"
    if not run_sh.is_file():
        raise UserError(f"appsec-compose not found in {tool_dir} "
                        "(neither bin/appsec-compose nor run.sh)")
    text = run_sh.read_text(errors="replace")
    return Cli(["bash", str(run_sh)], "run.sh",
               supports_json=bool(re.search(r"^\s*--json\)", text, re.M)),
               supports_diff=bool(re.search(r"^\s*--diff\)", text, re.M)))


# A git revision as the agent would type it; never something that could be
# read as an option. git's own refname rules forbid "..", spaces and controls.
_REF = re.compile(r"^[A-Za-z0-9_@][A-Za-z0-9_./@{}~^:+-]{0,199}$")


def validate_diff_base(ref: str | None) -> str | None:
    if ref is None or not str(ref).strip():
        return None
    ref = str(ref).strip()
    if not _REF.match(ref) or ".." in ref:
        raise UserError(f"diff_base {ref!r} is not a plain git ref "
                        "(e.g. origin/main, HEAD~1, a commit SHA)")
    return ref


def validate_fail_on(level: str | None) -> str | None:
    if level is None or not str(level).strip():
        return None
    level = str(level).strip().lower()
    if level not in THRESHOLDS:
        raise UserError(f"fail_on must be one of {THRESHOLDS}")
    return level


CONFIDENCES = ("low", "medium", "high")


def validate_min_confidence(level: str | None) -> str | None:
    if level is None or not str(level).strip():
        return None
    level = str(level).strip().lower()
    if level not in CONFIDENCES:
        raise UserError(f"min_confidence must be one of {list(CONFIDENCES)}")
    return level


def build_argv(cli: Cli, target: Path, reports_dir: Path, *,
               diff_base: str | None = None, fail_on: str | None = None,
               no_repo_config: bool = False,
               min_confidence: str | None = None,
               secrets_history: bool = False) -> list[str]:
    """An argv list — never a shell string, so no path or ref is ever parsed
    by a shell."""
    argv = [*cli.argv, str(target), "--reports", str(reports_dir)]
    # Not --config: a scanned repo's own file is held to project policy only.
    config = target / PROJECT_CONFIG
    if no_repo_config:
        argv.append("--no-repo-config")
    elif config.is_file():
        argv += ["--repo-config", str(config)]
    # Only an existing baseline: run.sh would otherwise create the file inside
    # the target, and scanning must not write into the scanned tree.
    baseline = target / PROJECT_BASELINE
    if baseline.is_file() and not no_repo_config:
        argv += ["--baseline", str(baseline)]
    if fail_on:
        argv += ["--fail-on", fail_on]
    if min_confidence:
        argv += ["--min-confidence", min_confidence]
    if secrets_history:
        argv.append("--secrets-history")
    if diff_base:
        if not cli.supports_diff:
            raise UserError("diff mode needs a newer appsec-compose "
                            "(bin/appsec-compose, or run.sh with --diff); "
                            "scan without diff_base instead")
        argv += ["--diff", diff_base]
    if cli.supports_json:
        argv.append("--json")
    if cli.kind == "run.sh":
        # Namespace the containers per target, so scans of two targets (or
        # this server and a terminal) never share compose service names.
        prefix = re.sub(r"[^a-z0-9-]+", "-",
                        os.environ.get("APPSEC_MCP_COMPOSE_PREFIX", "mcp").lower())
        argv += ["--name", f"{prefix}-{_target_id(target)[:8]}"]
    return argv


# ---- Running a scan --------------------------------------------------------------

LineSink = Callable[[str], Awaitable[None]]

_locks: dict[str, asyncio.Lock] = {}


def target_lock(target: Path) -> asyncio.Lock:
    return _locks.setdefault(str(target), asyncio.Lock())


@dataclass
class Outcome:
    exit_code: int
    payload: dict | None              # the CLI's --json object, if any
    log_tail: list[str] = field(default_factory=list)
    timed_out: bool = False


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    """Stop run.sh and the docker compose it started (one process group)."""
    for sig, grace in ((signal.SIGTERM, 30), (signal.SIGKILL, 5)):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            await asyncio.wait_for(proc.wait(), grace)
            return
        except asyncio.TimeoutError:
            continue


async def run_cli(argv: list[str], on_line: LineSink | None = None,
                  json_stdout: bool = True, timeout: float = SCAN_TIMEOUT) -> Outcome:
    proc = await asyncio.create_subprocess_exec(
        *argv, cwd=str(TOOL_DIR), stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=True, limit=1 << 20)
    tail: deque[str] = deque(maxlen=40)
    stdout_chunks: list[bytes] = []

    async def pump(stream: asyncio.StreamReader, collect: bool) -> None:
        while True:
            try:
                raw = await stream.readline()
            except ValueError:            # a line over the limit: skip it
                continue
            if not raw:
                return
            if collect:
                stdout_chunks.append(raw)
                continue
            line = raw.decode(errors="replace").rstrip()
            if line:
                tail.append(line)
                if on_line:
                    await on_line(line)

    pumps = asyncio.gather(pump(proc.stdout, json_stdout), pump(proc.stderr, False))
    timed_out = False
    try:
        await asyncio.wait_for(asyncio.shield(pumps), timeout)
        await proc.wait()
    except asyncio.TimeoutError:
        timed_out = True
        await _terminate(proc)
    except asyncio.CancelledError:
        # The client gave up on the call; do not leave scanners running.
        await _terminate(proc)
        raise
    finally:
        if not pumps.done():
            pumps.cancel()

    payload = None
    if json_stdout:
        text = b"".join(stdout_chunks).decode(errors="replace").strip()
        payload = _parse_json_object(text)
        if payload is None and text:
            tail.extend(text.splitlines()[-10:])
    code = proc.returncode if proc.returncode is not None else 3
    return Outcome(3 if timed_out else code, payload, list(tail), timed_out)


def _parse_json_object(text: str) -> dict | None:
    """The CLI prints exactly one JSON object; tolerate stray lines around it."""
    if not text:
        return None
    candidates = [text] + [l for l in reversed(text.splitlines()) if l.startswith("{")]
    for c in candidates:
        try:
            obj = json.loads(c)
        except ValueError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def _brief_blind_spots(brief: Path) -> list[str]:
    try:
        text = brief.read_text(errors="replace")
    except OSError:
        return []
    spots, inside = [], False
    for line in text.splitlines():
        if line.startswith("## "):
            inside = line[3:].strip().lower().startswith("blind spots")
            continue
        if inside and line.startswith("- "):
            spots.append(line[2:].replace("**", "").strip()[:400])
    return spots


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


async def scan(target: Path, *, diff_base: str | None = None,
               fail_on: str | None = None, on_line: LineSink | None = None,
               cli: Cli | None = None, no_repo_config: bool = False,
               min_confidence: str | None = None, secrets_history: bool = False) -> dict:
    """Run one scan and return the compact result handed to the agent."""
    cli = cli or detect_cli()
    sdir = state_dir(target)
    reports = sdir / "reports"
    if reports.resolve().is_relative_to(target):
        raise UserError("the report store is inside the target; "
                        "set APPSEC_MCP_STATE_DIR to a directory outside it")
    (reports / "native").mkdir(parents=True, exist_ok=True)
    os.chmod(sdir, 0o700)  # nosemgrep: insecure-file-permissions -- owner only
    argv = build_argv(cli, target, reports, diff_base=diff_base, fail_on=fail_on,
                      no_repo_config=no_repo_config, min_confidence=min_confidence,
                      secrets_history=secrets_history)

    # Another server process (a second agent session) scanning the same target
    # would share this reports dir and compose project name.
    with open(sdir / ".lock", "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise UserError(f"a scan of {target} is already running in another "
                            "process; wait for it to finish") from None
        # A run rejected before it starts (a config typo) leaves the previous
        # reports in place; they must not be read as this run's result.
        for name in ("findings.json", "review-brief.md", "summary.md", "summary.html"):
            (reports / name).unlink(missing_ok=True)
        started = datetime.now(timezone.utc)
        outcome = await run_cli(argv, on_line, json_stdout=cli.supports_json)
    p = outcome.payload or {}

    reports_dir = Path(p.get("reports_dir") or reports)
    findings_json = Path(p.get("findings_json") or reports_dir / "findings.json")
    review_brief = Path(p.get("review_brief") or reports_dir / "review-brief.md")
    verdict = p.get("verdict") or VERDICTS.get(outcome.exit_code, "scan_error")
    # Only a verdict comes with findings; anything else is not a result.
    doc = _read_json(findings_json) if verdict in ("pass", "fail") else None
    if verdict in ("pass", "fail") and doc is None:
        verdict = "scan_error"           # a verdict always leaves findings.json

    record = {
        "target": str(target),
        "scanned_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verdict": verdict,
        "exit_code": outcome.exit_code,
        "diff_base": diff_base,
        "fail_on": fail_on,
        "cli": cli.kind,
        "reports_dir": str(reports_dir),
        "findings_json": str(findings_json) if doc is not None else None,
        "review_brief": str(review_brief) if review_brief.is_file() else None,
    }
    _save_last_scan(target, record)
    return summarize(record, doc, p, outcome)


def summarize(record: dict, doc: dict | None, payload: dict, outcome: Outcome) -> dict:
    """Small enough to sit in an agent's context; detail is one call away."""
    out: dict = {"target": record["target"], "verdict": record["verdict"],
                 "exit_code": record["exit_code"]}
    if record.get("diff_base"):
        out["diff_base"] = record["diff_base"]

    if doc is None:
        out["error"] = ("the scan timed out" if outcome.timed_out else
                        "the scan did not produce findings.json; no verdict was reached"
                        if record["verdict"] != "usage_error" else
                        "appsec-compose rejected the invocation or the config")
        out["log_tail"] = outcome.log_tail[-25:]
        return out

    policy = doc.get("policy") or {}
    counts = payload.get("severity_counts") or doc.get("severity_counts") or {}
    out["findings"] = len(doc.get("findings") or [])
    out["gating"] = payload.get("breaching", policy.get("breaching", 0))
    out["severity_counts"] = {s: counts[s] for s in reversed(SEVERITIES) if counts.get(s)}
    if doc.get("category_counts"):
        out["category_counts"] = doc["category_counts"]
    by_cat = policy.get("fail_on_by_category") or {}
    out["gate"] = (", ".join(f"{c}={l}" for c, l in sorted(by_cat.items()))
                   + f", default={policy.get('fail_on')}" if by_cat
                   else policy.get("fail_on", "high"))
    if policy.get("fail_on_exploitable"):
        out["gate"] += " + exploitable"
    if policy.get("min_confidence") not in (None, "low"):
        out["gate"] += f"; rules of {policy['min_confidence']} confidence and above"
    brief_size = ((doc.get("metrics") or {}).get("brief") or {})
    if brief_size.get("approx_tokens") is not None:
        # What reading the brief costs, before anyone opens it.
        out["brief_tokens"] = brief_size["approx_tokens"]

    base = payload.get("baseline") or doc.get("baseline") or {}
    if base.get("enabled"):
        out["baseline"] = {k: base[k] for k in ("new", "known", "fixed") if k in base}
    scope = (doc.get("provenance") or {}).get("scope")
    if scope:
        out["scope"] = scope
    if doc.get("suppressed_count"):
        out["suppressed"] = doc["suppressed_count"]
    expired = [e.get("selectors", "") for e in doc.get("expired_suppressions") or []]
    if expired:
        out["expired_suppressions"] = expired
    problems = ([f"no report from {r}" for r in doc.get("reports_missing") or []]
                + [f"unreadable report: {r}" for r in doc.get("reports_errored") or []])
    if problems:
        out["incomplete"] = problems

    brief = Path(record["review_brief"]) if record.get("review_brief") else None
    out["blind_spots"] = _brief_blind_spots(brief) if brief else []
    out["reports"] = {"dir": record["reports_dir"], "findings_json": record["findings_json"],
                      "review_brief": record["review_brief"]}
    out["next"] = (
        "Call findings(path, gating_only=true) to triage what fails the gate; "
        "finding(path, fingerprint) for code context; brief(path) for the full "
        "review brief. Fix real issues; suppress(...) only false positives or "
        "accepted risks, with a reason. Then scan again."
        if out["gating"] else
        "Gate passes. Review blind_spots (what the tools cannot see) and "
        "findings(path) below the gate if time allows.")
    return out
