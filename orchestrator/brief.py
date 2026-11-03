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
from dedup import _norm_file
from normalize import _SEVERITY_RANK, Finding
from policy import breaches

# Findings shown with code; the rest are counted, so a large legacy backlog
# does not crowd the new and gating ones out of a reader's context.
MAX_DETAILED = 150
_CONTEXT = 2           # lines of code either side of a SAST/IaC finding
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
    "checkov": {"iac"}, "hadolint": {"iac"},
}


def _languages(code_dir: str, excludes: set[str]) -> list[tuple[str, int]]:
    counts: Counter = Counter()
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


def _blind_spots(enabled: set[str], cfg, coverage, image_mode: bool) -> list[str]:
    covered = set().union(*(_ENGINE_CATEGORIES.get(e, set()) for e in enabled))
    spots = [f"**{_CATEGORY_NAMES[c]} was not run** — no engine for it is enabled."
             for c in ("sast", "sca", "secrets", "iac") if c not in covered]
    spots += [f"**SCA coverage:** {w.message} {w.advice}" for w in coverage.warnings]
    if image_mode:
        spots.append("**Image scan:** only the image's packages were checked; "
                     "no source code, secrets or IaC.")
        return spots
    if "sast" in covered:
        spots.append("**Cross-file data flow:** Semgrep CE follows taint within one "
                     "file. Input that crosses a module boundary before reaching "
                     "a sink was not traced.")
    if "secrets" in covered and not cfg.secrets_history:
        spots.append("**Git history:** secrets were searched in the working tree "
                     "only; a credential committed and later deleted is not covered.")
    if "sca" in covered:
        spots.append("**Reachability:** a vulnerable dependency is reported whether "
                     "or not the vulnerable code path is ever called.")
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
    rows = []
    for n in range(max(1, f.line - _CONTEXT), last + _CONTEXT + 1):
        text = source.line(f.file, n)
        if text is None:
            break
        secret = secrets.get((_norm_file(f.file), n))
        if secret is not None:
            text = _mask_secret(secret, text)
        mark = ">" if f.line <= n <= last else " "
        rows.append(f"{mark}{n:>4} | {text[:_MAX_LINE]}")
    return "\n".join(rows) or None


def _labels(f: Finding, gating: bool, new: bool | None) -> str:
    tags = [f.severity.upper()]
    if gating:
        tags.append("GATING")
    if new:
        tags.append("NEW")
    elif new is False:
        tags.append("baseline")
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


def render(out_dir: str, findings: list[Finding], cfg, enabled: set[str],
           coverage, provenance: dict, code_dir: str, excludes: set[str],
           image_mode: bool, new_fps: set[str] | None) -> None:
    source = _Source(None if image_mode else code_dir)
    secrets = {(_norm_file(f.file), f.line): f for f in findings
               if f.category == "secrets" and f.line}

    def is_new(f: Finding) -> bool | None:
        return None if new_fps is None else f.fingerprint in new_fps

    def gates(f: Finding) -> bool:
        return breaches(f, cfg) and is_new(f) is not False

    ordered = sorted(findings, key=lambda f: (
        not gates(f), not is_new(f), -_SEVERITY_RANK.get(f.severity, 0),
        f.category, _norm_file(f.file), f.line or 0))
    shown, rest = ordered[:MAX_DETAILED], ordered[MAX_DETAILED:]
    gating = sum(1 for f in findings if gates(f))

    engines = provenance.get("engines") or {}
    lines = [
        "# Security review brief", "",
        f"appsec-compose {provenance.get('appsec_compose', 'unknown')} · "
        f"{provenance.get('generated', '')} · target: {provenance.get('target', '')}"
        + (" · offline" if provenance.get("offline") else ""), "",
        "Scanner results for this codebase, prepared for a reviewer — a person or "
        "an AI agent. The tools have done the pattern matching; use this to "
        "verify their findings and to spend the review on what they cannot see.",
        "",
        "## Scope", "",
        f"- Engines: {', '.join(sorted(enabled)) or 'none'}",
    ]
    lines += [f"  - {name}: `{ref}`" for name, ref in sorted(engines.items())]
    if provenance.get("databases"):
        lines.append("- Databases: " + ", ".join(
            f"{k} {v}" for k, v in sorted(provenance["databases"].items())))
    if not image_mode:
        langs = _languages(code_dir, excludes)
        if langs:
            lines.append("- Languages (files): " + ", ".join(f"{l} ({n})" for l, n in langs))
        if excludes:
            lines.append("- Not scanned (excluded): " + ", ".join(f"`{e}`" for e in sorted(excludes)))
    lines += [f"- Gate: fail_on {cfg.threshold_label()}"
              + (" + exploitable" if cfg.fail_on_exploitable else "")
              + (" (new findings only)" if new_fps is not None else ""), ""]

    lines += ["## Blind spots", "",
              "What this scan did not or could not check. Absence of findings here "
              "is not evidence of absence.", ""]
    lines += [f"- {s}" for s in _blind_spots(enabled, cfg, coverage, image_mode)]

    counts = Counter(f.category for f in findings)
    lines += ["", f"## Findings ({len(findings)}, {gating} gating)", ""]
    if counts:
        lines.append(" · ".join(f"{_CATEGORY_NAMES.get(c, c)} {n}"
                                for c, n in sorted(counts.items())))
        lines.append("")
    lines.append("Ordered gating first, then new, then by severity. For each one, "
                 "decide whether it is real in this codebase; code shown is the "
                 "flagged region (`>`) with context.")
    lines.append("")
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
