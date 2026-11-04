"""Scan every project and write one page across them.

Sequential by default: the engines are heavy, and a laptop running a batch should
stay usable. One project failing never stops the rest; the batch exits with the
worst outcome, and the numbering of the contract already orders them
(3 scan did not complete > 2 config error > 1 policy fail > 0 pass).

index.html is self-contained, opens from disk, and runs no script. Its values
come from findings in scanned repos, so all of them go through htmlsafe.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import runner, runs, store
from .htmlsafe import CSS, Safe, badge, counts_text, h, join, url
from .paths import index_file, reports_dir, write_atomic


def _scan_safely(name: str, extra: list[str], on_begin) -> dict:
    if on_begin:
        on_begin(name)
    try:
        return runner.scan_project(name, extra, trigger="batch")
    except Exception as exc:  # one project's bug must not cost the others their scan
        return runner._result(name, 3, f"{type(exc).__name__}: {exc}")


def run_batch(extra: list[str] | None = None, jobs: int = 1, on_begin=None) -> dict:
    projects, broken = store.list_projects()
    names = [p.name for p in projects]
    extra = list(extra or [])
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        results = list(pool.map(lambda n: _scan_safely(n, extra, on_begin), names))
    results += [runner._result(stem, 2, why) for stem, why in broken]
    write_atomic(index_file(), render_index())
    return {"exit_code": max((r["exit_code"] for r in results), default=2),
            "index_html": str(index_file()), "projects": results}


def _row(project: store.Project) -> Safe:
    run = runs.latest(project.name)
    link: Safe | str = "—"
    if run and run.get("has_reports") and (reports_dir(project.name) / "summary.html").is_file():
        link = h('<a href="projects/{}/reports/summary.html">summary</a>', url(project.name))
    return h("<tr><td>{name}</td><td>{verdict}</td><td>{counts}</td><td>{top}</td>"
             "<td>{when}</td><td>{link}</td></tr>",
             name=project.name, verdict=badge((run or {}).get("verdict")),
             counts=counts_text((run or {}).get("severity_counts")),
             top=(run or {}).get("top_component") or "—",
             when=(run or {}).get("finished") or "never", link=link)


def render_index() -> str:
    projects, broken = store.list_projects()
    rows = [_row(p) for p in projects]
    rows += [h('<tr><td>{}</td><td>{}</td><td colspan="4">{}</td></tr>',
               stem, badge("usage_error"), why) for stem, why in broken]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return h("""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>appsec-compose projects</title><style>{css}</style></head>
<body><h1>appsec-compose projects</h1><p class="dim">Generated {generated}.</p>
<table><thead><tr><th>Project</th><th>Verdict</th><th>Severity</th><th>Top component to upgrade</th>
<th>Last run</th><th>Report</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>
""", css=Safe(CSS), generated=generated, rows=join(rows))
