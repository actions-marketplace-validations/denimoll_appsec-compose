"""appsec-compose as an MCP server (stdio): scan, triage, record verdicts.

The tools follow the review loop an agent should run — scan, read what fails
the gate and what the tools cannot see, fix or suppress with a reason, scan
again — and their descriptions say when to reach for each one. Outputs are
compact JSON: a scan result is a summary plus paths, findings come a page at a
time, and code only for the one finding being looked at.
"""
from __future__ import annotations

import json
import time
from typing import Annotated, Literal

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import core, triage, views

Severity = Literal["info", "low", "medium", "high", "critical"]
Threshold = Literal["info", "low", "medium", "high", "critical", "none"]
Category = Literal["sast", "sca", "secrets", "iac"]

PathArg = Annotated[str, Field(
    description="Absolute path of the repository (project directory). Relative "
                "paths resolve against the server's working directory.")]
FingerprintArg = Annotated[str, Field(
    description="Finding fingerprint as listed by findings(): the 12-character "
                "prefix shown there, or the full 40-character value.")]

INSTRUCTIONS = """\
appsec-compose runs open-source security scanners (Semgrep SAST, Trivy SCA/IaC,
Gitleaks secrets, Checkov IaC) over a local repository in Docker and hands the
results over for review.

Workflow: scan(path) -> read `blind_spots` and the gate -> components(path) for
dependencies (one upgrade per package) and findings(path, gating_only=true) for
the rest -> finding(path, fp) for each, decide if it is real -> fix the code,
or suppress(path, fp, reason) a false positive / accepted risk -> scan again
(with diff_base to check just your change). A scan takes minutes; the
other tools read the last scan and are instant. Never paste secret values: the
tools mask them, keep it that way."""

mcp = MCPServer(name="appsec-compose", instructions=INSTRUCTIONS,
                version=triage._tool_version())


def _json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def _target(path: str):
    try:
        return core.resolve_target(path)
    except core.UserError as exc:
        raise ToolError(str(exc)) from None


def _report(path: str) -> views.Report:
    try:
        return views.load_report(_target(path))
    except core.UserError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool(
    annotations=ToolAnnotations(title="Run a security scan", read_only_hint=False,
                                destructive_hint=False, idempotent_hint=True,
                                open_world_hint=True),
    structured_output=False)
async def scan(
    path: PathArg,
    ctx: Context,
    diff_base: Annotated[str | None, Field(
        description="Git ref to diff against (e.g. origin/main, HEAD~1) to scan only "
                    "what changed since it — much faster; use it to re-check your own "
                    "fix. Omit for a full scan.")] = None,
    no_repo_config: Annotated[bool, Field(
        description="Ignore the repository's own .appsec-compose.yml and baseline. Set "
                    "it when the code is not the user's: otherwise its authors decide "
                    "what counts.")] = False,
    fail_on: Annotated[Threshold | None, Field(
        description="Override the gate threshold for this run (default: the project "
                    "config, normally `high`). `none` reports without gating.")] = None,
    min_confidence: Annotated[Literal["low", "medium", "high"] | None, Field(
        description="Gate only on findings from rules at least this confident "
                    "(`medium` drops Semgrep's LOW-confidence rules from the gate; "
                    "they are still reported). Default: the project config, "
                    "normally `low` = everything gates.")] = None,
) -> str:
    """Scan a repository for security issues (SAST, vulnerable dependencies,
    secrets, IaC misconfigurations). Use it first, before reviewing a codebase or
    a change for security, and again after fixing or suppressing findings.

    Takes minutes (Docker; the first run also pulls images and vulnerability
    databases). Returns the verdict (pass / fail / usage_error / scan_error),
    severity counts, how many findings fail the gate, the blind spots of this
    scan (what the tools could not check — review those yourself) and where the
    reports are. The result is remembered per repository, so findings(),
    finding(), brief() and suppress() work on it without rescanning. Reports are
    kept outside the repository; nothing in it is modified."""
    target = _target(path)
    try:
        diff_base = core.validate_diff_base(diff_base)
        fail_on = core.validate_fail_on(fail_on)
        min_confidence = core.validate_min_confidence(min_confidence)
    except core.UserError as exc:
        raise ToolError(str(exc)) from None

    lock = core.target_lock(target)
    if lock.locked():
        raise ToolError(f"a scan of {target} is already running; wait for it to finish")
    started = time.monotonic()
    last_sent = [0.0]
    lines = [0]

    async def on_line(line: str) -> None:
        # Throttled: compose prints thousands of lines on a first image pull.
        lines[0] += 1
        now = time.monotonic()
        if now - last_sent[0] < 2.0:
            return
        last_sent[0] = now
        await ctx.report_progress(round(now - started), None,
                                  f"{round(now - started)}s: {line[:160]}")

    async with lock:
        await ctx.report_progress(0, None, f"scanning {target}")
        try:
            result = await core.scan(target, diff_base=diff_base, fail_on=fail_on,
                                     no_repo_config=no_repo_config,
                                     min_confidence=min_confidence,
                                     on_line=on_line)
        except core.UserError as exc:
            raise ToolError(str(exc)) from None
    result["duration_s"] = round(time.monotonic() - started)
    return _json(result)


@mcp.tool(annotations=ToolAnnotations(title="List findings", read_only_hint=True),
          structured_output=False)
def findings(
    path: PathArg,
    severity_min: Annotated[Severity | None, Field(
        description="Only findings at or above this severity.")] = None,
    category: Annotated[Category | None, Field(
        description="sast (code), sca (dependencies), secrets, iac (Docker/Terraform/K8s).")] = None,
    file: Annotated[str | None, Field(
        description="Repo-relative file, directory, or glob (e.g. src/api, '*.py').")] = None,
    new_only: Annotated[bool, Field(
        description="Only findings not in the project's baseline (baseline mode).")] = False,
    gating_only: Annotated[bool, Field(
        description="Only findings that fail the gate — start triage here.")] = False,
    include_suppressed: Annotated[bool, Field(
        description="Also list findings already suppressed by ignore rules, with their reason.")] = False,
    limit: Annotated[int, Field(ge=1, le=200, description="Page size.")] = 50,
    offset: Annotated[int, Field(ge=0, description="Start of the page; use next_offset.")] = 0,
) -> str:
    """List the findings of the last scan of a repository, one line each:
    fingerprint, severity, category, rule, file:line, short message (plus
    package and fixed version for dependencies). Ordered gating first, then by
    severity. Paginated: follow `next_offset` until it is null. Use it after
    scan() to pick what to triage; call finding() for the code and details."""
    report = _report(path)
    try:
        return _json(views.list_findings(
            report, severity_min=severity_min, category=category, file=file,
            new_only=new_only, gating_only=gating_only,
            include_suppressed=include_suppressed, limit=limit, offset=offset))
    except core.UserError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool(annotations=ToolAnnotations(title="Profile a repository", read_only_hint=True),
          structured_output=False)
def profile(path: PathArg) -> str:
    """What a repository is made of — languages, frameworks from its manifests,
    IaC and CI files, dependency manifests and whether they have lock files —
    and the few config changes that fit it, each with its reason (e.g. enable
    OSV-Scanner when dependencies have no lock file). Instant, no containers.
    Use it before the first scan to plan the review, or to explain a gap;
    record a recommendation only with the user's agreement."""
    from dataclasses import asdict
    from ._orchestrator import projectprofile as pp
    target = _target(path)
    prof = pp.scan(str(target), pp.DEFAULT_EXCLUDES)
    recs = pp.recommend(prof)
    return _json({"profile": {**asdict(prof), "ci": prof.ci},
                  "recommendations": [asdict(r) for r in recs],
                  "config": pp.overlay(recs) if recs else None})


@mcp.tool(annotations=ToolAnnotations(title="List vulnerable components", read_only_hint=True),
          structured_output=False)
def components(
    path: PathArg,
    gating_only: Annotated[bool, Field(
        description="Only components with at least one finding that fails the gate.")] = False,
    limit: Annotated[int, Field(ge=1, le=200, description="Page size.")] = 50,
    offset: Annotated[int, Field(ge=0, description="Start of the page; use next_offset.")] = 0,
) -> str:
    """Dependencies of the last scan grouped by package: severity, how many
    vulnerabilities, the version to upgrade to (the lowest that fixes them
    all, when it can be derived), and the findings inside with their
    fingerprints. Use it for SCA instead of paging through one finding per
    CVE: one upgrade usually resolves a whole component. Malicious packages
    come first; they are removed, not upgraded."""
    report = _report(path)
    try:
        return _json(views.list_components(report, gating_only=gating_only,
                                           limit=limit, offset=offset))
    except core.UserError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool(annotations=ToolAnnotations(title="Show one finding", read_only_hint=True),
          structured_output=False)
def finding(
    path: PathArg,
    fingerprint: FingerprintArg,
    context_lines: Annotated[int, Field(
        ge=0, le=30, description="Lines of code shown either side of the flagged region.")] = 5,
) -> str:
    """Full detail of one finding from the last scan: rule, CWE, the scanner's
    explanation, advisory link, fixed version for dependencies, whether it fails
    the gate, and the flagged code (`>` marks the flagged lines) read from the
    repository. Use it to decide whether a finding is real before fixing or
    suppressing it. Secret values are always masked."""
    report = _report(path)
    try:
        return _json(views.detail(report, fingerprint, context_lines))
    except core.UserError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool(annotations=ToolAnnotations(title="Read the review brief", read_only_hint=True),
          structured_output=False)
def brief(
    path: PathArg,
    section: Annotated[str | None, Field(
        description="Return one section only: 'Scope', 'Blind spots', 'Findings' "
                    "or 'Recording a verdict' (prefix match).")] = None,
    max_chars: Annotated[int, Field(ge=1000, le=200000,
                                    description="Truncate longer text.")] = 24000,
) -> str:
    """The review brief of the last scan (Markdown), written for a reviewer:
    what was scanned with which engines, the blind spots the tools cannot cover
    (authorization, business logic, cross-file data flow…), every finding with
    code context, and how to record a verdict. Read 'Blind spots' to plan the
    manual part of a review; prefer findings()/finding() for triage, which page
    and cost less context."""
    report = _report(path)
    try:
        return views.brief(report, section, max_chars)
    except core.UserError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool(
    annotations=ToolAnnotations(title="Suppress a finding", read_only_hint=False,
                                destructive_hint=False, idempotent_hint=True,
                                open_world_hint=False),
    structured_output=False)
def suppress(
    path: PathArg,
    fingerprint: FingerprintArg,
    reason: Annotated[str, Field(
        description="Why this is a false positive or an accepted risk HERE — specific "
                    "enough for a reviewer to check (e.g. 'value is a hard-coded "
                    "constant; no request data reaches the query').")],
    expires: Annotated[str | None, Field(
        description="YYYY-MM-DD after which the suppression lapses and the finding "
                    "counts again. Default: 90 days from today.")] = None,
) -> str:
    """Record a triage verdict: suppress one finding (by fingerprint) as a false
    positive or an accepted risk, with a reason and an expiry. Writes an
    `ignore:` entry into <repo>/.appsec-compose.yml (created from the tool's
    defaults if missing; existing content and comments are preserved) and
    nothing else. Use it only after reading the finding with finding() and
    concluding it is not exploitable here — real issues should be fixed in code
    instead. Takes effect on the next scan()."""
    report = _report(path)
    try:
        return _json(triage.suppress(report, fingerprint, reason, expires))
    except core.UserError as exc:
        raise ToolError(str(exc)) from None


@mcp.prompt(title="Security review of a repository")
def security_review(
    path: Annotated[str, Field(description="Repository to review.")],
    diff_base: Annotated[str | None, Field(
        description="Git ref the change is based on, to focus on what changed.")] = None,
) -> str:
    """Run a full security review of a repository with appsec-compose."""
    scope = (f" Focus on the change since `{diff_base}`: pass diff_base=\"{diff_base}\" "
             "to scan()." if diff_base else "")
    return f"""Perform a security review of the repository at `{path}` using the appsec-compose tools.{scope}

1. Call `scan(path="{path}"{f', diff_base="{diff_base}"' if diff_base else ''})`. If the verdict is
   `usage_error` or `scan_error`, report the error and `log_tail` and stop: there is no verdict.
2. Read `blind_spots` in the result. These are things the scanners did not or could not check
   (e.g. authorization, business logic, cross-file data flow). Plan to review them yourself.
3. Call `findings(path, gating_only=true)` and page through it. For each finding call
   `finding(path, fingerprint)` and decide from the code whether it is real and reachable here.
4. Real issue: fix it in the code (for dependencies, upgrade to the fixed version).
   Not exploitable here, or a deliberate accepted risk: call `suppress(path, fingerprint,
   reason, expires)` with a specific, checkable reason. Never suppress to make the gate pass.
   A real secret must be rotated, not only removed or suppressed.
5. Re-run `scan` (with `diff_base` to check just your changes) until the gate passes, or
   explain what remains and why.
6. Review the blind spots by reading the relevant code.

Report: verdict before and after, each finding with your decision (fixed / suppressed with
reason / left open with justification), and what you found in the blind spots. Never quote
secret values."""


def main() -> None:
    mcp.run("stdio")
