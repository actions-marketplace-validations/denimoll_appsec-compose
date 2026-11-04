"""Escape by default. Findings, package names and meta come from scanned repos or files.

`h("<td>{}</td>", value)` escapes every argument unless it is already `Safe`, the
type only `h`, `esc`, `join` and `url` return. So forgetting to escape takes
effort, and nested fragments are not escaped twice. Templates are literals in
this package and never hold user data.

Used by both the batch index and the UI; the shared bits of how a verdict and its
counts look live here too.
"""
from __future__ import annotations

import html
from urllib.parse import quote

CSS = """
:root { color-scheme: light dark; --line: #8884; --dim: #888; }
* { box-sizing: border-box; }
body { font: 14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0 auto;
       max-width: 1200px; padding: 16px; }
nav a { margin-right: 16px; }
h1 { font-size: 20px; } h2 { font-size: 16px; margin-top: 24px; }
table { border-collapse: collapse; width: 100%; display: block; overflow-x: auto; }
th, td { border-bottom: 1px solid var(--line); padding: 6px 10px 6px 0; text-align: left;
         vertical-align: top; }
th { color: var(--dim); font-weight: 600; white-space: nowrap; }
code, pre, textarea { font: 13px/1.4 ui-monospace, Menlo, Consolas, monospace; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; }
input[type=text], textarea, select { width: 100%; max-width: 640px; padding: 6px; }
textarea { min-height: 200px; }
textarea.short { min-height: 70px; }
.hint { margin: 2px 0 6px; max-width: 640px; font-size: 13px; opacity: .75; }
label { display: block; margin: 12px 0 4px; font-weight: 600; }
button { padding: 4px 10px; cursor: pointer; }
form.inline { display: inline; }
.dim { color: var(--dim); }
.error { border: 1px solid #c33; padding: 8px 12px; white-space: pre-wrap; overflow-wrap: anywhere; }
.badge { border-radius: 4px; padding: 1px 7px; font-weight: 600; color: #fff; white-space: nowrap; }
.pass { background: #1a7f37; } .fail { background: #c62828; }
.scan_error, .usage_error { background: #b45309; } .none { background: #777; }
.running, .queued { background: #1f6feb; }
"""


class Safe(str):
    """Text that is already HTML."""
    __slots__ = ()


def esc(value: object) -> Safe:
    if isinstance(value, Safe):
        return value
    return Safe(html.escape("" if value is None else str(value), quote=True))


def h(template: str, *args: object, **kwargs: object) -> Safe:
    return Safe(template.format(*[esc(a) for a in args], **{k: esc(v) for k, v in kwargs.items()}))


def join(items, separator: str = "") -> Safe:
    return Safe(separator.join(esc(item) for item in items))


def url(segment: object) -> Safe:
    """One path segment of a link."""
    return esc(quote(str(segment), safe=""))


# Only these class names reach an attribute; a verdict read from a file does not.
_VERDICT_CLASS = {"pass": "pass", "fail": "fail", "scan_error": "scan_error",
                  "usage_error": "usage_error", "running": "running", "queued": "queued"}


def badge(verdict: object) -> Safe:
    key = verdict if isinstance(verdict, str) else ""
    return h('<span class="badge {cls}">{text}</span>',
             cls=_VERDICT_CLASS.get(key, "none"), text=verdict or "no run")


def counts_text(counts: object) -> str:
    """`1 critical, 4 high`, or an em dash when the run reached no verdict."""
    if not isinstance(counts, dict):
        return "—"
    parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info")
             if isinstance(counts.get(s), int) and counts[s]]
    return ", ".join(parts) or "no findings"
