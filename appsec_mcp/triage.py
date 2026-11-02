"""Record a triage verdict as an `ignore:` entry in the project's config.

The verdict goes where a human reviewer will see it: `<target>/.appsec-compose.yml`,
next to the code, as a fingerprint with a reason and an expiry. The file is the
user's, so it is edited as text — an entry is inserted into the existing
`ignore:` list and nothing else moves; a PyYAML dump would drop every comment
and reorder the file. The result is then parsed back and checked: everything
but `ignore` must be unchanged, `ignore` must have gained exactly this entry,
and the collector's schema must accept it. Anything unexpected and nothing is
written.

A project without the file gets one copied from the tool's scan-config.yml.
run.sh reads a `--config` file *instead of* scan-config.yml, not on top of it;
a file holding only `ignore:` would enable no scanners at all (render-env
derives the enabled list from `scanners:`), and one holding only defaults would
quietly drop whatever the user had set in the tool's own config. A copy keeps
the next scan identical to the last, plus one suppression.
"""
from __future__ import annotations

import json
import os
import re
import stat
from datetime import date, timedelta
from pathlib import Path

import yaml

from . import core
from ._orchestrator import normalize, schema, suppress as collector_suppress
from .views import Report, location

DEFAULT_DAYS = 90
MAX_DAYS = int(os.environ.get("APPSEC_MCP_MAX_SUPPRESS_DAYS", "365"))
_MIN_REASON = 10
_MAX_REASON = 500

_IGNORE_KEY = re.compile(r"^ignore\s*:")
# `ignore:`, `ignore: []`, `ignore: ~`, `ignore: null` — each with an optional comment.
_IGNORE_EMPTY = re.compile(r"^ignore\s*:\s*(?:\[\s*\]|~|null)?\s*(?P<comment>#.*)?$")
_IGNORE_BLOCK = re.compile(r"^ignore\s*:\s*(?P<comment>#.*)?$")


def _header(version: str) -> str:
    return (
        "# appsec-compose scan config for this project.\n"
        "#\n"
        "# Created by the appsec-compose MCP server to record a triage verdict.\n"
        f"# It starts as a copy of the tool's scan-config.yml (appsec-compose {version}),\n"
        "# because a project config replaces that file rather than overlaying it:\n"
        "# the scanners and the gate stay exactly as they were. Edit freely.\n"
        "\n")


def _tool_version() -> str:
    try:
        return (core.TOOL_DIR / "VERSION").read_text().strip()
    except OSError:
        return "unknown"


def validate_reason(reason: str) -> str:
    reason = " ".join(str(reason or "").split())
    if len(reason) < _MIN_REASON:
        raise core.UserError(
            "reason is required: say why this finding is a false positive or an "
            "accepted risk in this codebase (e.g. 'input is a constant; no user "
            "data reaches the shell'), so a reviewer can check the decision")
    if len(reason) > _MAX_REASON:
        raise core.UserError(f"reason is over {_MAX_REASON} characters; summarise it")
    return reason


def validate_expires(expires: str | None, today: date | None = None) -> date:
    today = today or date.today()
    if expires is None or not str(expires).strip():
        return today + timedelta(days=DEFAULT_DAYS)
    try:
        when = date.fromisoformat(str(expires).strip())
    except ValueError:
        raise core.UserError("expires must be a date, YYYY-MM-DD") from None
    if when <= today:
        raise core.UserError("expires must be in the future")
    if when > today + timedelta(days=MAX_DAYS):
        raise core.UserError(
            f"expires is more than {MAX_DAYS} days away; an accepted risk should be "
            "re-argued, not inherited (APPSEC_MCP_MAX_SUPPRESS_DAYS sets the limit)")
    return when


def _comment_safe(text: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(text))[:160]


def _entry_lines(indent: int, fingerprint: str, reason: str, expires: date,
                 note: str) -> list[str]:
    pad = " " * indent
    # Quoted: an all-digit fingerprint would otherwise load as an integer.
    # JSON string syntax is valid YAML double-quoted scalar syntax.
    return [f"{pad}# {_comment_safe(note)}",
            f'{pad}- fingerprint: "{fingerprint}"',
            f"{pad}  reason: {json.dumps(reason, ensure_ascii=False)}",
            f"{pad}  expires: {expires.isoformat()}"]


def _load(text: str, what: str) -> dict:
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise core.UserError(f"{what} is not valid YAML; fix it first: {exc}") from None
    if not isinstance(raw, dict):
        raise core.UserError(f"{what} must be a mapping of settings")
    return raw


def insert_entry(text: str, raw: dict, fingerprint: str, reason: str,
                 expires: date, note: str) -> str:
    """Return `text` with the entry appended to its top-level `ignore:` list."""
    nl = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    key_at = next((i for i, l in enumerate(lines) if _IGNORE_KEY.match(l)), None)
    current = raw.get("ignore")
    unsupported = core.UserError(
        "the `ignore:` in this config is laid out in a way that cannot be edited "
        "safely (flow style or unusual nesting); add the entry by hand:\n"
        + "\n".join(["ignore:", *_entry_lines(2, fingerprint, reason, expires, note)]))

    if "ignore" not in raw:
        body = lines + ([""] if lines and lines[-1].strip() else [])
        body += ["ignore:", *_entry_lines(2, fingerprint, reason, expires, note)]
    elif key_at is None:
        raise unsupported
    elif not current:
        m = _IGNORE_EMPTY.match(lines[key_at])
        if not m:
            raise unsupported
        comment = m.group("comment")
        lines[key_at] = "ignore:" + (f"  {comment}" if comment else "")
        body = (lines[:key_at + 1] + _entry_lines(2, fingerprint, reason, expires, note)
                + lines[key_at + 1:])
    elif isinstance(current, list) and _IGNORE_BLOCK.match(lines[key_at]):
        # The list runs until the next top-level key; insert after its last
        # content line, so comments that introduce the next section stay put.
        last, indent = key_at, None
        for i in range(key_at + 1, len(lines)):
            line = lines[i]
            stripped = line.lstrip()
            top_level = line[:1] not in ("", " ", "\t", "#", "-") or line.startswith(("---", "..."))
            if top_level:
                break
            if stripped and not stripped.startswith("#"):
                last = i
                if indent is None and stripped.startswith("-"):
                    indent = len(line) - len(stripped)
        if indent is None:
            raise unsupported
        body = (lines[:last + 1] + _entry_lines(indent, fingerprint, reason, expires, note)
                + lines[last + 1:])
    else:
        raise unsupported
    return nl.join(body) + nl


def _check(old: dict, new: dict, entry: dict) -> None:
    """Parsed back, the edit must be exactly one added entry, and valid."""
    rest_old = {k: v for k, v in old.items() if k != "ignore"}
    rest_new = {k: v for k, v in new.items() if k != "ignore"}
    if rest_old != rest_new or new.get("ignore") != [*(old.get("ignore") or []), entry]:
        raise core.UserError("editing the config as text did not produce the expected "
                             "result, so nothing was written; add the entry by hand")
    problems = schema.validate(new, known_scanners=set(normalize.SCANNER_FILES))
    if problems:
        raise core.UserError("the config would not be valid, so nothing was written:\n  "
                             + "\n  ".join(problems))
    try:
        for e in new["ignore"]:
            if isinstance(e, dict) and e.get("expires") is not None:
                collector_suppress._parse_expiry(e["expires"])
    except ValueError as exc:
        raise core.UserError(f"the config has an invalid ignore entry: {exc}") from None


def _write(path: Path, text: str, create: bool) -> None:
    """Write the one file, never through a symlink: a scanned repo is not
    trusted, and `.appsec-compose.yml -> ~/.bashrc` must not be followed."""
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= (os.O_CREAT | os.O_EXCL) if create else os.O_TRUNC
    fd = os.open(path, flags, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def suppress(report: Report, fingerprint: str, reason: str,
             expires: str | None = None, today: date | None = None) -> dict:
    finding, status = report.resolve(fingerprint)
    fp = finding["fingerprint"]
    where = {"rule": finding.get("rule_id"), "location": location(finding)}
    reason = validate_reason(reason)
    when = validate_expires(expires, today)
    if status == "suppressed":
        return {"status": "already_suppressed", "fingerprint": fp, **where,
                "by_reason": report.scrub(finding, finding.get("reason", "")),
                "note": "an ignore rule already covers this finding; nothing written"}

    target = report.target
    path = target / core.PROJECT_CONFIG
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise core.UserError(f"{path} is a symlink or not a regular file; "
                             "refusing to write through it")

    create = st is None
    if create:
        template = core.TOOL_DIR / "scan-config.yml"
        try:
            text = _header(_tool_version()) + template.read_text()
        except OSError as exc:
            raise core.UserError(f"cannot read the tool's {template}: {exc}") from None
    else:
        text = path.read_text(encoding="utf-8")
    old = _load(text, str(path) if not create else "the tool's scan-config.yml")

    for e in old.get("ignore") or []:
        if isinstance(e, dict) and str(e.get("fingerprint", "")).lower() == fp:
            return {"status": "already_present", "fingerprint": fp, **where,
                    "config": str(path), "entry": {k: str(v) for k, v in e.items()},
                    "note": "this fingerprint is already in the config (the last scan "
                            "predates it); rescan to see it suppressed. Edit the file "
                            "by hand to change its reason or expiry"}

    note = (f"triaged {date.today().isoformat()} via appsec-compose MCP: "
            f"{where['rule']} at {where['location']}")
    new_text = insert_entry(text, old, fp, reason, when, note)
    entry = {"fingerprint": fp, "reason": reason, "expires": when}
    _check(old, _load(new_text, "the edited config"), entry)
    _write(path, new_text, create)

    return {"status": "added", "fingerprint": fp, **where, "config": str(path),
            "created": create,
            "entry": {"fingerprint": fp, "reason": reason, "expires": when.isoformat()},
            "next": "scan(path) again: the finding moves to `suppressed` and stops "
                    "counting towards the gate. Commit the config so the decision "
                    "is reviewed with the code."}
