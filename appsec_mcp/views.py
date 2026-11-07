"""Read-side views over the last scan: finding lists, one finding, the brief.

Agents have little context to spare, so lists are one line per finding and
paginated, and detail is fetched one finding at a time.

Secret values never leave this module. A finding's code is read from the
target with the collector's own reader (confined to the target root) and every
line that a secret-like finding points at is masked with the collector's own
`_mask_secret` — not only the secret finding's own snippet, but any context
window that happens to include that line. Messages of secret-like findings are
scrubbed of whatever the masking removed from their line, in case an engine
echoed the value it matched.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from types import SimpleNamespace

from . import core
from ._orchestrator import baseline, dedup

_RANK = {s: i for i, s in enumerate(core.SEVERITIES)}
_CONFIDENCE = list(core.CONFIDENCES)
_MAX_LINE = 240
_FP_PREFIX = re.compile(r"^[0-9a-f]{8,40}$")

# Rules and weaknesses that point at a credential even outside the secrets
# category (a SAST "hardcoded password" rule, Trivy's secret scanner).
_CREDENTIAL_CWES = {"CWE-798", "CWE-259", "CWE-321", "CWE-522", "CWE-256", "CWE-312"}
_CREDENTIAL_RULE = re.compile(
    r"secret|passw|credential|token|api[-_.]?key|private[-_.]?key|access[-_.]?key|"
    r"\bpat\b|-pat$", re.I)


def norm_file(path: str | None) -> str:
    return dedup._norm_file(path or "")


def location(f: dict) -> str:
    path = norm_file(f.get("file")) or "(no file)"
    return f"{path}:{f['line']}" if f.get("line") else path


def is_secret_like(f: dict) -> bool:
    """Conservative: a false positive here only costs a masked line."""
    if f.get("category") == "secrets":
        return True
    # A dependency finding always names its package; one without is Trivy's
    # secret scanner, which reports under the filesystem (SCA) run.
    if f.get("category") == "sca" and not f.get("package"):
        return True
    if _CREDENTIAL_CWES & set(f.get("cwe") or []):
        return True
    return bool(_CREDENTIAL_RULE.search(str(f.get("rule_id") or "")))


def _span(f: dict, first_line: bool) -> SimpleNamespace:
    """What baseline._mask_secret reads off a Finding; positions only on the
    flagged line itself — continuation lines are masked as a whole."""
    if not first_line:
        return SimpleNamespace(line=None, column=None, end_column=None, end_line=None)
    return SimpleNamespace(line=f.get("line"), column=f.get("column"),
                           end_column=f.get("end_column"), end_line=f.get("end_line"))


@dataclass
class Report:
    target: Path
    last: dict
    doc: dict
    findings: list[dict]
    suppressed: list[dict]
    source: object = field(repr=False, default=None)
    # (file, line) -> the secret-like findings located there
    _secret_lines: dict = field(default_factory=dict, repr=False)

    def __post_init__(self):
        self.source = baseline._Source(str(self.target))
        for f in [*self.findings, *self.suppressed]:
            if not (is_secret_like(f) and f.get("line")):
                continue
            path = norm_file(f.get("file"))
            last = max(f.get("end_line") or f["line"], f["line"])
            for n in range(f["line"], last + 1):
                self._secret_lines.setdefault((path, n), []).append(
                    _span(f, n == f["line"]))

    # ---- policy, as the collector applies it ----

    @property
    def policy(self) -> dict:
        return self.doc.get("policy") or {}

    @property
    def baseline_on(self) -> bool:
        return bool((self.doc.get("baseline") or {}).get("enabled"))

    def gates(self, f: dict) -> bool:
        """policy.breaches(), plus baseline mode's 'new findings only'."""
        if f.get("new") is False:
            return False
        p = self.policy
        if p.get("fail_on_exploitable") and f.get("exploitable"):
            return True
        threshold = (p.get("fail_on_by_category") or {}).get(
            f.get("category"), p.get("fail_on", "high"))
        if threshold == "none" or threshold not in _RANK:
            return False
        # min_confidence: a rule less sure than asked reports but does not gate.
        conf, floor = f.get("confidence") or "", p.get("min_confidence") or "low"
        if conf in _CONFIDENCE and _CONFIDENCE.index(conf) < _CONFIDENCE.index(
                floor if floor in _CONFIDENCE else "low"):
            return False
        return _RANK.get(f.get("severity"), 0) >= _RANK[threshold]

    def order(self, items: list[dict]) -> list[dict]:
        """The brief's order: gating, then new, then severity."""
        return sorted(items, key=lambda f: (
            not self.gates(f), not f.get("new"), -_RANK.get(f.get("severity"), 0),
            f.get("category", ""), norm_file(f.get("file")), f.get("line") or 0))

    # ---- code and secret masking ----

    def code_line(self, path: str, n: int) -> str | None:
        text = self.source.line(path, n)
        if text is None:
            return None
        for span in self._secret_lines.get((path, n), ()):
            text = baseline._mask_secret(span, text)
        return text[:_MAX_LINE]

    def scrub(self, f: dict, text: str) -> str:
        """Remove from a secret-like finding's text anything the masking would
        have removed from its line. Unreadable line: mask the text itself."""
        if not text or not is_secret_like(f):
            return text
        raw = self.source.line(f.get("file"), f.get("line"))
        if raw is None:
            return baseline._mask_secret(_span(f, False), text)
        candidates = set()
        col, end = f.get("column"), f.get("end_column")
        if col and end and end > col:
            candidates.add(raw[col - 1:end - 1])
        for m in baseline._QUOTED.finditer(raw):
            candidates.add(m.group(0)[1:-1])
        for m in baseline._TOKEN.finditer(raw):
            token = m.group(0)
            candidates.add(token)
            # KEY=value, user:pass@host — the value alone may be what is echoed.
            candidates.update(re.split(r"[=:@]", token))
        for c in sorted((c for c in candidates if len(c) >= 4), key=len, reverse=True):
            text = text.replace(c, "*")
        return text

    def resolve(self, fingerprint: str) -> tuple[dict, str]:
        """A full fingerprint or a unique prefix (>= 8 hex chars), like git."""
        fp = str(fingerprint or "").strip().lower()
        if not _FP_PREFIX.match(fp):
            raise core.UserError("fingerprint must be 8-40 hex characters, "
                                 "as listed by findings()")
        hits = [(f, "open") for f in self.findings if f.get("fingerprint", "").startswith(fp)]
        hits += [(f, "suppressed") for f in self.suppressed
                 if f.get("fingerprint", "").startswith(fp)]
        if not hits:
            raise core.UserError(f"no finding {fp} in the last scan of {self.target} "
                                 f"(scanned {self.last.get('scanned_at')}); rescan or "
                                 "list them with findings()")
        if len({h[0]["fingerprint"] for h in hits}) > 1:
            raise core.UserError(f"fingerprint prefix {fp} is ambiguous; use more characters")
        return hits[0]


def load_report(target: Path) -> Report:
    last = core.load_last_scan(target)
    path = last.get("findings_json")
    if not path:
        raise core.UserError(f"the last scan of {target} ended in {last.get('verdict')} "
                             "without findings; fix that and scan again")
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise core.UserError(f"cannot read {path}: {exc}; scan again") from None
    return Report(target, last, doc, list(doc.get("findings") or []),
                  list(doc.get("suppressed") or []))


def _one_line(text: str, limit: int = 160) -> str:
    text = " ".join(str(text or "").split())
    # Trivy prefixes every message with Artifact/Type/Severity headers.
    if "Message: " in text:
        text = text.split("Message: ", 1)[1].split(" Link: ", 1)[0]
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _summary_line(report: Report, f: dict) -> str:
    if f.get("package") and f.get("description"):
        return _one_line(report.scrub(f, f["description"]))
    return _one_line(report.scrub(f, f.get("message", "")))


def _file_matches(f: dict, pattern: str) -> bool:
    path, pattern = norm_file(f.get("file")), norm_file(pattern).rstrip("/")
    if any(c in pattern for c in "*?["):
        return fnmatch(path, pattern)
    return path == pattern or path.startswith(pattern + "/")


def list_findings(report: Report, *, severity_min: str | None = None,
                  category: str | None = None, file: str | None = None,
                  new_only: bool = False, gating_only: bool = False,
                  include_suppressed: bool = False,
                  limit: int = 50, offset: int = 0) -> dict:
    if severity_min and severity_min not in _RANK:
        raise core.UserError(f"severity_min must be one of {core.SEVERITIES}")
    if category and category not in core.CATEGORIES:
        raise core.UserError(f"category must be one of {core.CATEGORIES}")
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))

    notes = []
    pool = [(f, "open") for f in report.order(report.findings)]
    if include_suppressed:
        pool += [(f, "suppressed") for f in report.order(report.suppressed)]
    if new_only and not report.baseline_on:
        notes.append("baseline mode is off, so every finding counts as new; "
                     "new_only had no effect")
    selected = [
        (f, status) for f, status in pool
        if (not severity_min or _RANK.get(f.get("severity"), 0) >= _RANK[severity_min])
        and (not category or f.get("category") == category)
        and (not file or _file_matches(f, file))
        and (not new_only or not report.baseline_on or f.get("new"))
        and (not gating_only or (status == "open" and report.gates(f)))
    ]
    page = selected[offset:offset + limit]
    items = []
    for f, status in page:
        item = {"fingerprint": f["fingerprint"][:12], "severity": f.get("severity"),
                "category": f.get("category"), "rule": f.get("rule_id"),
                "location": location(f)}
        if f.get("package"):
            item["package"] = f["package"]
            item["fixed_in"] = f.get("fixed_version") or "no fix known"
        item["message"] = _summary_line(report, f)
        if status == "open" and report.gates(f):
            item["gating"] = True
        if f.get("new"):
            item["new"] = True
        if f.get("exploitable"):
            item["exploitable"] = True
        if status == "suppressed":
            item["suppressed"] = report.scrub(f, f.get("reason", ""))
        items.append(item)

    nxt = offset + len(page)
    out = {"target": str(report.target), "scanned_at": report.last.get("scanned_at"),
           "total": len(selected), "returned": len(items),
           "next_offset": nxt if nxt < len(selected) else None,
           "findings": items}
    if notes:
        out["notes"] = notes
    return out


def list_components(report: Report, *, gating_only: bool = False,
                    limit: int = 50, offset: int = 0) -> dict:
    """Dependencies grouped by package: what to upgrade, and what it fixes."""
    comps = report.doc.get("components")
    if comps is None:
        raise core.UserError("this scan predates the component view (findings.json "
                             "schema < 1.2); scan again")
    by_fp = {f.get("fingerprint"): f for f in report.findings}
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    items = []
    for c in comps:
        inner = [by_fp[fp] for fp in c.get("findings", []) if fp in by_fp]
        gating = any(report.gates(f) for f in inner)
        if gating_only and not gating:
            continue
        item = {"package": c["package"], "severity": c["severity"],
                "vulnerabilities": c["vulnerabilities"], "counts": c["counts"],
                "upgrade_to": c.get("upgrade_to") or (
                    "no fix known" if not c.get("fixed_in") else "no single version"),
                "declared_in": c["files"],
                "findings": [{"fingerprint": f["fingerprint"][:12], "severity": f.get("severity"),
                              "rule": f.get("rule_id"),
                              "fixed_in": f.get("fixed_version") or "no fix known"}
                             for f in inner]}
        if c.get("unfixed"):
            item["unfixed"] = c["unfixed"]
        if gating:
            item["gating"] = True
        if c.get("malicious"):
            item["malicious"] = True
        elif c.get("exploitable"):
            item["exploitable"] = True
        items.append(item)
    page = items[offset:offset + limit]
    nxt = offset + len(page)
    return {"target": str(report.target), "scanned_at": report.last.get("scanned_at"),
            "total": len(items), "returned": len(page),
            "next_offset": nxt if nxt < len(items) else None, "components": page}


def detail(report: Report, fingerprint: str, context_lines: int = 5) -> dict:
    f, status = report.resolve(fingerprint)
    context_lines = max(0, min(int(context_lines), 30))
    out: dict = {"fingerprint": f["fingerprint"], "status": status}
    if status == "suppressed":
        out["suppressed_reason"] = report.scrub(f, f.get("reason", ""))
    else:
        out["gating"] = report.gates(f)
    if "new" in f:
        out["new"] = f["new"]
    out.update({
        "severity": f.get("severity"), "category": f.get("category"),
        "rule": f.get("rule_id"), "location": location(f),
        "tools": f.get("tools") or [f.get("tool")],
    })
    for key in ("aliases", "cwe"):
        if f.get(key):
            out[key] = f[key]
    if f.get("package"):
        out["package"] = f["package"]
        out["fixed_version"] = f.get("fixed_version") or "no fixed version known"
    for key in ("priority", "epss", "kev", "poc", "nuclei", "exploitable", "scanner_severity"):
        if f.get(key):
            out[key] = f[key]
    out["message"] = report.scrub(f, " ".join(str(f.get("message", "")).split()))
    description = report.scrub(f, str(f.get("description") or "").strip())
    if description and description != out["message"]:
        out["description"] = description[:2000]
    if f.get("url"):
        out["url"] = f["url"]

    line = f.get("line")
    if line:
        path = norm_file(f.get("file"))
        last = max(f.get("end_line") or line, line)
        last = min(last, line + 60)          # a whole-file span is not context
        rows = []
        for n in range(max(1, line - context_lines), last + context_lines + 1):
            text = report.code_line(path, n)
            if text is None:
                break
            mark = ">" if line <= n <= last else " "
            rows.append(f"{mark}{n:>5} | {text}")
        if rows:
            out["code"] = rows
        else:
            out["code_note"] = f"{path} could not be read from the target (moved, deleted, or outside it)"
    if is_secret_like(f):
        out["secret_note"] = ("secret values are masked (*); rotate the credential if "
                              "it is real, removing it from the code does not revoke it")
    return out


_BRIEF_HEADING = re.compile(r"^#### `(?P<where>.+?)` — ")
_BRIEF_ROW = re.compile(r"^(?P<lead>[> ]\s*(?P<n>\d+) \| )(?P<text>.*)$")


def _mask_brief(report: Report, text: str) -> str:
    """The brief shows context around SAST/IaC findings; a secret one line away
    from such a finding would sit in that context unmasked. Re-mask every
    code row whose line a secret-like finding points at."""
    out, path, fenced = [], None, False
    for row in text.splitlines():
        heading = _BRIEF_HEADING.match(row)
        if heading:
            where = heading.group("where")
            file_part, _, line_part = where.rpartition(":")
            path = norm_file(file_part if line_part.isdigit() else where)
        elif row.startswith("```"):
            fenced = not fenced
        elif fenced and path:
            m = _BRIEF_ROW.match(row)
            if m and (path, int(m.group("n"))) in report._secret_lines:
                masked = report.code_line(path, int(m.group("n")))
                row = m.group("lead") + (masked if masked is not None else "*")
        out.append(row)
    return "\n".join(out)


def brief(report: Report, section: str | None = None, max_chars: int = 24000) -> str:
    path = report.last.get("review_brief")
    if not path:
        raise core.UserError("the last scan produced no review-brief.md")
    try:
        text = _mask_brief(report, Path(path).read_text(errors="replace"))
    except OSError as exc:
        raise core.UserError(f"cannot read {path}: {exc}") from None
    if section:
        parts = re.split(r"(?m)^(?=## )", text)
        names = [p.splitlines()[0][3:].strip() for p in parts if p.startswith("## ")]
        wanted = section.strip().lower()
        match = next((p for p in parts if p.startswith("## ")
                      and p[3:].strip().lower().startswith(wanted)), None)
        if match is None:
            raise core.UserError(f"no section {section!r}; sections: {names}")
        text = match
    max_chars = max(1000, min(int(max_chars), 200_000))
    if len(text) > max_chars:
        text = (text[:max_chars] + f"\n\n[truncated: {len(text) - max_chars} more "
                "characters. Ask for one section, or use findings()/finding() to page "
                "through the findings.]")
    return text
