"""Review brief: the scan handed over to whoever reviews the code next.

summary.html is for reading results; this is for acting on them. A reviewer,
human or AI agent, gets what was checked, what could not be, the findings with
the code they point at, and how to record a verdict. The blind spots matter as
much as the findings: a scanner's silence about authorization or business
logic is not evidence, and a reviewer told so spends their time where the
tools cannot.

Written as Markdown so it can be pasted, or read, into an agent's context as is.
Secret values never appear: their lines are shown masked.
"""
from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

from baseline import _Source, _mask_secret
from components import group
from dedup import _norm_file
from normalize import _SEVERITY_RANK, Finding
from policy import breaches

# Findings shown with code; the rest are counted, so a large legacy backlog
# does not crowd the new and gating ones out of a reader's context.
MAX_DETAILED = 150
_CONTEXT = 2           # lines of code either side of a SAST/IaC finding
# A finding can span a whole file (Checkov's OpenAPI checks flag lines 1-437,
# zizmor's permissions a whole workflow); showing all of it made one brief
# 2,800 lines long. The first lines locate it; the file has the rest.
_MAX_FLAGGED = 8
_MAX_LINE = 240        # minified code makes for useless context

_LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".java": "Java",
    ".kt": "Kotlin", ".scala": "Scala", ".rb": "Ruby", ".php": "PHP", ".cs": "C#",
    ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".rs": "Rust", ".swift": "Swift", ".m": "Objective-C", ".sh": "Shell",
    ".tf": "Terraform", ".sql": "SQL", ".ex": "Elixir", ".exs": "Elixir",
    ".dart": "Dart", ".lua": "Lua", ".pl": "Perl", ".vue": "Vue",
}
_MAX_WALK = 20_000

_CATEGORY_NAMES = {"sast": "SAST", "sca": "SCA", "secrets": "Secrets", "iac": "IaC"}
_ENGINE_CATEGORIES = {
    "semgrep": {"sast"}, "trivy": {"sca", "iac"}, "grype": {"sca"}, "osv": {"sca"},
    "gitleaks": {"secrets"}, "trufflehog": {"secrets"},
    "checkov": {"iac"}, "hadolint": {"iac"}, "zizmor": {"iac"},
}


def _languages(code_dir: str, excludes: set[str],
               paths: list[str] | None = None) -> list[tuple[str, int]]:
    counts: Counter = Counter()
    if paths is not None:                  # diff mode: the changed files only
        counts.update(l for l in (_LANGUAGES.get(Path(p).suffix.lower())
                                  for p in paths) if l)
        return counts.most_common()
    walked = 0
    for root, dirs, files in os.walk(code_dir):
        dirs[:] = [d for d in dirs if d not in excludes and not d.startswith(".")]
        for name in files:
            walked += 1
            lang = _LANGUAGES.get(Path(name).suffix.lower())
            if lang:
                counts[lang] += 1
        if walked > _MAX_WALK:
            break
    return counts.most_common()


def _diff_spots(scope) -> list[str]:
    """What a diff scan leaves out — first, because it is the biggest gap."""
    spots = [
        f"**Unchanged code was not scanned:** this is a diff scan of the "
        f"{len(scope.files)} file(s) changed since `{scope.base}` (merge-base "
        f"`{scope.merge_base[:12]}`). Findings anywhere else in the codebase, "
        f"old or new, are not in this report; a full scan covers them.",
        "**Cross-file effects of the change are not covered:** a change can make "
        "code it did not touch exploitable — a new call into an existing unsafe "
        "function, a removed check that a caller relied on, a changed signature, "
        "config value or data format consumed elsewhere. Only the changed files "
        "were analysed, so review the callers and dependents of what changed.",
    ]
    if scope.skipped("sca"):
        spots.append("**Dependencies (SCA) were not checked:** no dependency "
                     "manifest or lock file changed, so the SCA engines did not run.")
    if scope.skipped("iac") and scope.files:
        spots.append("**IaC was not checked:** no IaC file changed.")
    if scope.commits and not scope.history_scanned:
        note = f" ({scope.history_note})" if scope.history_note else ""
        spots.append(f"**Branch commits:** the {scope.commits} commit(s) since the "
                     f"merge-base were not searched for secrets{note}; a secret "
                     f"committed on the branch and removed again is not covered.")
    return spots


def _workflow_spots(enabled: set[str], code_dir: str) -> list[str]:
    """CI/CD workflows are code that runs with the repo's secrets; say when
    they went unchecked, or were checked without the audits that need GitHub."""
    if not Path(code_dir, ".github", "workflows").is_dir():
        return []
    if "zizmor" not in enabled:
        return ["**CI/CD workflows:** `.github/workflows` exists but zizmor is "
                "disabled, so script injection, `pull_request_target` misuse and "
                "over-broad tokens in the pipeline were not checked."]
    if os.environ.get("ASS_ZIZMOR_ONLINE") != "1":
        return ["**CI/CD online audits:** zizmor ran offline. Impostor commits, "
                "known-vulnerable or archived actions and ref confusion need the "
                "GitHub API (export `ZIZMOR_GITHUB_TOKEN` to enable them)."]
    return []


def _blind_spots(enabled: set[str], cfg, coverage, image_mode: bool,
                 scope=None, code_dir: str = "") -> list[str]:
    covered = set().union(*(_ENGINE_CATEGORIES.get(e, set()) for e in enabled))
    spots = [f"**{_CATEGORY_NAMES[c]} was not run** — no engine for it is enabled."
             for c in ("sast", "sca", "secrets", "iac") if c not in covered]
    if scope:
        spots = _diff_spots(scope) + spots
        # A category skipped because the change did not touch it is reported
        # above; it was not run, so its run-time caveats do not apply.
        covered = {c for c in covered if not scope.skipped(c)}
    spots += [f"**SCA coverage:** {w.message} {w.advice}" for w in coverage.warnings]
    if image_mode:
        spots.append("**Image scan:** only the image's packages were checked; "
                     "no source code, secrets or IaC.")
        return spots
    if "sast" in covered:
        spots.append("**Cross-file data flow:** Semgrep CE follows taint within one "
                     "file. Input that crosses a module boundary before reaching "
                     "a sink was not traced.")
    if "secrets" in covered and not cfg.secrets_history and not scope:
        spots.append("**Git history:** secrets were searched in the working tree "
                     "only; a credential committed and later deleted is not covered.")
    if "sca" in covered:
        spots.append("**Reachability:** a vulnerable dependency is reported whether "
                     "or not the vulnerable code path is ever called.")
    if code_dir:
        spots += _workflow_spots(enabled, code_dir)
    spots.append("**Logic the tools cannot model:** authentication and "
                 "authorization (IDOR, missing checks, privilege boundaries), "
                 "business rules, race conditions, and how secrets and crypto "
                 "are used in context. Static rules match patterns; these need "
                 "a reader who knows what the code is for.")
    return spots


def _snippet(f: Finding, source: _Source,
             secrets: dict[tuple[str, int], Finding]) -> str | None:
    """The flagged lines with context. Any line a secret finding points at is
    masked wherever it appears — including inside another finding's context,
    which is where a credential next to, say, an insecure call would leak."""
    if f.category == "sca" or not f.line:
        return None
    if f.category == "secrets":
        text = source.line(f.file, f.line)
        return None if text is None else f"{f.line:>5} | {_mask_secret(f, text)[:_MAX_LINE]}"
    last = max(f.end_line or f.line, f.line)
    cut = last - (f.line + _MAX_FLAGGED - 1)
    if cut > 0:
        last = f.line + _MAX_FLAGGED - 1
    rows = []
    for n in range(max(1, f.line - _CONTEXT), last + (0 if cut > 0 else _CONTEXT) + 1):
        text = source.line(f.file, n)
        if text is None:
            break
        secret = secrets.get((_norm_file(f.file), n))
        if secret is not None:
            text = _mask_secret(secret, text)
        mark = ">" if f.line <= n <= last else " "
        rows.append(f"{mark}{n:>4} | {text[:_MAX_LINE]}")
    if cut > 0 and rows:
        rows.append(f"  … {cut} more flagged line(s), to {_norm_file(f.file)}:{last + cut}")
    return "\n".join(rows) or None


def _labels(f: Finding, gating: bool, new: bool | None) -> str:
    tags = [f.severity.upper()]
    if gating:
        tags.append("GATING")
    if new:
        tags.append("NEW")
    elif new is False:
        tags.append("baseline")
    if getattr(f, "on_changed_line", None):
        tags.append("CHANGED LINE")
    if f.malicious:
        tags.append("MALICIOUS PACKAGE")
    if f.exploitable:
        tags.append("EXPLOITABLE")
    return " · ".join(tags)


def _finding(f: Finding, gating: bool, new: bool | None, source: _Source,
             secrets: dict[tuple[str, int], Finding]) -> list[str]:
    where = f"{_norm_file(f.file)}:{f.line}" if f.line else _norm_file(f.file) or "(no file)"
    out = [f"#### `{where}` — {f.rule_id}", "",
           f"- **{_labels(f, gating, new)}** · {f.category} · "
           f"{', '.join(f.tools)}" + (f" · {', '.join(f.cwe)}" if f.cwe else ""),
           f"- fingerprint: `{f.fingerprint}`"]
    if f.package:
        fix = f" → fixed in {f.fixed_version}" if f.fixed_version else " → no fixed version known"
        out.append(f"- package: `{f.package}`{fix}")
    message = " ".join(f.message.split())
    if message:
        out.append(f"- {message[:400]}")
    if f.url:
        out.append(f"- {f.url}")
    snippet = _snippet(f, source, secrets)
    if snippet:
        out += ["", "```", snippet, "```"]
    return out + [""]


MAX_COMPONENTS = 60


def _components(comps, gates, is_new) -> list[str]:
    """One entry per vulnerable package: what to upgrade, and what is in it."""
    comps = sorted(comps, key=lambda c: (not any(gates(f) for f in c.findings),
                                         not any(is_new(f) for f in c.findings)))
    out = ["### Vulnerable components", "",
           f"{sum(len(c.findings) for c in comps)} SCA finding(s) in {len(comps)} "
           "package(s). Each vulnerability still gates and is suppressed on its own "
           "fingerprint.", ""]
    for c in comps[:MAX_COMPONENTS]:
        tags = [c.severity.upper()]
        if c.malicious:
            tags.append("MALICIOUS PACKAGE")
        if any(gates(f) for f in c.findings):
            tags.append("GATING")
        if any(is_new(f) for f in c.findings):
            tags.append("NEW")
        if c.exploitable and not c.malicious:
            tags.append("EXPLOITABLE")
        counts = ", ".join(f"{n} {s}" for s, n in c.counts.items())
        if c.upgrade_to:
            fix = (f"upgrade to **{c.upgrade_to}** — the lowest version that fixes "
                   f"all {len(c.findings)}")
        elif c.fixed_in:
            fix = "no single upgrade version can be derived; per-vulnerability fixes below"
        else:
            fix = "no fix known"
        if c.unfixed and c.fixed_in:
            fix += f" ({c.unfixed} without a fix)"
        out += [f"#### `{c.package}` — {len(c.findings)} vulnerabilit"
                f"{'y' if len(c.findings) == 1 else 'ies'} ({counts})", "",
                f"- **{' · '.join(tags)}** · declared in {', '.join(c.files) or '(unknown)'}",
                f"- {fix}"]
        for f in c.findings:
            extra = "".join([" · KEV" if f.kev else "", " · MALICIOUS" if f.malicious else ""])
            fixed = f" → {f.fixed_version}" if f.fixed_version else ""
            aliases = f" ({', '.join(f.aliases)})" if f.aliases else ""
            out.append(f"  - {f.severity} `{f.rule_id}`{aliases}{fixed}{extra} · "
                       f"fingerprint `{f.fingerprint}`")
        out.append("")
    if len(comps) > MAX_COMPONENTS:
        out += [f"…and {len(comps) - MAX_COMPONENTS} more component(s); all are in "
                "findings.json (`components`).", ""]
    return out


def render(out_dir: str, findings: list[Finding], cfg, enabled: set[str],
           coverage, provenance: dict, code_dir: str, excludes: set[str],
           image_mode: bool, new_fps: set[str] | None, scope=None,
           license_stats=None) -> None:
    source = _Source(None if image_mode else code_dir)
    secrets = {(_norm_file(f.file), f.line): f for f in findings
               if f.category == "secrets" and f.line}

    def is_new(f: Finding) -> bool | None:
        return None if new_fps is None else f.fingerprint in new_fps

    def gates(f: Finding) -> bool:
        return breaches(f, cfg) and is_new(f) is not False

    # SCA is listed per component below; this ordering covers the rest.
    ordered = sorted((f for f in findings if f.category != "sca"), key=lambda f: (
        not gates(f), not is_new(f), not getattr(f, "on_changed_line", None),
        -_SEVERITY_RANK.get(f.severity, 0),
        f.category, _norm_file(f.file), f.line or 0))
    shown, rest = ordered[:MAX_DETAILED], ordered[MAX_DETAILED:]
    gating = sum(1 for f in findings if gates(f))

    engines = provenance.get("engines") or {}
    lines = [
        "# Security review brief", "",
        f"appsec-compose {provenance.get('appsec_compose', 'unknown')} · "
        f"{provenance.get('generated', '')} · target: {provenance.get('target', '')}"
        + (" · offline" if provenance.get("offline") else "")
        + (f" · **{scope.label()}**" if scope else ""), "",
        "Scanner results for this codebase, prepared for a reviewer — a person or "
        "an AI agent. The tools have done the pattern matching; use this to "
        "verify their findings and to spend the review on what they cannot see.",
        "",
        "## Scope", "",
        f"- Engines: {', '.join(sorted(enabled)) or 'none'}",
    ]
    if scope:
        lines[-1] = f"- Engines: {', '.join(sorted(enabled - set(scope.skipped_engines))) or 'none'}"
        lines += [f"  - {name} not run: {reason}"
                  for name, reason in sorted(scope.skipped_engines.items())]
    lines += [f"  - {name}: `{ref}`" for name, ref in sorted(engines.items())]
    if provenance.get("databases"):
        lines.append("- Databases: " + ", ".join(
            f"{k} {v}" for k, v in sorted(provenance["databases"].items())))
    if scope:
        shown_paths = ", ".join(f"`{p}`" for p in scope.files[:20])
        more = f" and {len(scope.files) - 20} more" if len(scope.files) > 20 else ""
        lines.append(f"- Diff: {len(scope.files)} file(s) changed since `{scope.base}` "
                     f"(merge-base `{scope.merge_base[:12]}`, {scope.commits} "
                     f"commit(s)), including uncommitted and untracked files. "
                     f"Only these were scanned and gated"
                     + (f": {shown_paths}{more}" if scope.files else "") + ".")
    if not image_mode:
        langs = _languages(code_dir, excludes, scope.files if scope else None)
        if langs:
            lines.append("- Languages (files): " + ", ".join(f"{l} ({n})" for l, n in langs))
        if excludes:
            lines.append("- Not scanned (excluded): " + ", ".join(f"`{e}`" for e in sorted(excludes)))
    fws = provenance.get("checkov_frameworks")
    if "checkov" in enabled and isinstance(fws, list):
        lines.append("- Checkov frameworks (the IaC kinds found in the repo): "
                     + (", ".join(fws) or "none"))
    lines += [f"- Gate: fail_on {cfg.threshold_label()}"
              + (" + exploitable" if cfg.fail_on_exploitable else "")
              + (" (new findings only)" if new_fps is not None else ""), ""]

    lines += ["## Blind spots", "",
              "What this scan did not or could not check. Absence of findings here "
              "is not evidence of absence.", ""]
    spots = _blind_spots(enabled, cfg, coverage, image_mode, scope, code_dir)
    if license_stats and license_stats.unlicensed:
        spots.insert(0, f"**License policy:** {license_stats.unlicensed} of "
                     f"{license_stats.packages} dependencies carry no license data "
                     f"({', '.join(license_stats.unlicensed_ecosystems)} manifests do not "
                     "record one), so the policy could not judge them.")
    lines += [f"- {s}" for s in spots]

    counts = Counter(f.category for f in findings)
    lines += ["", f"## Findings ({len(findings)}, {gating} gating)", ""]
    if counts:
        lines.append(" · ".join(f"{_CATEGORY_NAMES.get(c, c)} {n}"
                                for c, n in sorted(counts.items())))
        lines.append("")
    lines.append("Ordered gating first, then new, then by severity. For each one, "
                 "decide whether it is real in this codebase; code shown is the "
                 "flagged region (`>`) with context.")
    if scope:
        lines.append("")
        lines.append("Diff scan: a finding in a changed file gates whether or not "
                     "its own line changed — a change often makes an unchanged "
                     "line exploitable (e.g. new input reaching an old sink). "
                     "`CHANGED LINE` marks the ones on a line the change wrote; "
                     "start there.")
    lines.append("")
    comps = group(findings)
    if comps:
        lines += _components(comps, gates, is_new)
        if shown:
            lines += ["### Code, secrets and IaC", ""]
    for f in shown:
        lines += _finding(f, gates(f), is_new(f), source, secrets)
    if rest:
        left = Counter((f.category, f.severity) for f in rest)
        lines += [f"…and {len(rest)} more, not detailed here "
                  f"({', '.join(f'{n} {s} {c}' for (c, s), n in sorted(left.items()))}). "
                  "All of them are in findings.json.", ""]

    lines += [
        "## Recording a verdict", "",
        "A finding confirmed as real is fixed in code. A false positive or an "
        "accepted risk is recorded in `scan-config.yml` by its fingerprint, with "
        "the reasoning and an expiry, so the next run excludes it and the "
        "decision is reviewable:", "",
        "```yaml",
        "ignore:",
        "  - fingerprint: <fingerprint>",
        "    reason: \"<why this is not exploitable here>\"",
        "    expires: <YYYY-MM-DD>",
        "```", "",
    ]
    Path(out_dir, "review-brief.md").write_text("\n".join(lines))
