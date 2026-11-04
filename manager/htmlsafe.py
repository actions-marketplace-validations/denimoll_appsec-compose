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

# On top of Pico (manager/static), which styles the semantic HTML: only what it
# has no idea about, and a denser table than its reading-sized defaults.
CSS = """
:root { --pico-font-size: 93.75%; --pico-form-element-spacing-vertical: .55rem; }
body > main, body > header { max-width: 1280px; }
body > header { padding-block: .5rem; border-bottom: 1px solid var(--pico-muted-border-color); }
main { padding-block: 1.5rem; }
h1 { font-size: 1.5rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
.tablewrap { overflow-x: auto; }
table { font-size: .9rem; }
th { color: var(--pico-muted-color); white-space: nowrap; }
td { vertical-align: top; }
form.inline { display: inline; margin: 0; }
form.inline button { width: auto; margin: 0; padding: .2rem .8rem; font-size: .875rem; }
form > p > button { width: auto; }
.hint { margin: -.6rem 0 1.1rem; font-size: .8rem; color: var(--pico-muted-color); }
textarea.short { min-height: 5rem; }
form { max-width: 720px; }
button.danger { background: #c62828; border-color: #c62828; }
.dim { color: var(--pico-muted-color); }
.error { border: 1px solid #c62828; border-radius: var(--pico-border-radius); padding: .6rem .9rem;
         margin-bottom: 1rem; white-space: pre-wrap; overflow-wrap: anywhere; }
.badge { border-radius: 999px; padding: .1rem .6rem; font-size: .75rem; font-weight: 600;
         color: #fff; white-space: nowrap; vertical-align: middle; }
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
