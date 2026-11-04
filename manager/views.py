"""The UI's pages: server-rendered, no script, everything through htmlsafe.

Each function returns a body fragment; `page` wraps it. Every value below may be
attacker-controlled (a finding's package name, a hand-edited definition), so the
one way to put a value into a page is an `h()` argument. A state-changing action
is always a form POST carrying the CSRF token, and links only ever read.
"""
from __future__ import annotations

from . import runs, store
from .htmlsafe import Safe, badge, counts_text, h, join, url
from .paths import reports_dir
from .reports import listed_reports


def page(title: str, body: Safe, refresh: bool = False) -> bytes:
    meta = Safe('<meta http-equiv="refresh" content="5">') if refresh else Safe("")
    return h("""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">{meta}
<title>{title} - appsec-compose</title>
<link rel="stylesheet" href="/pico.css"><link rel="stylesheet" href="/app.css"></head>
<body><header><nav><ul><li><strong>appsec-compose</strong></li></ul>
<ul><li><a href="/">Projects</a></li><li><a href="/profiles">Profiles</a></li></ul></nav></header>
<main>{body}</main></body></html>
""", meta=meta, title=title, body=body).encode("utf-8")


def _csrf(token: str) -> Safe:
    return h('<input type="hidden" name="csrf" value="{}">', token)


def _action(path: Safe, label: str, token: str) -> Safe:
    return h('<form class="inline" method="post" action="{}">{}<button>{}</button></form>',
             path, _csrf(token), label)


def _error(message: str | None) -> Safe:
    return h('<div class="error">{}</div>', message) if message else Safe("")


def _trend(history: list[dict]) -> str:
    info = runs.trend(history)
    if not info["totals"]:
        return "—"
    delta = info["delta"]
    change = "" if delta is None else f" ({delta:+d})"
    return f"{info['spark']} {info['totals'][-1]}{change}"


def _status_badge(state: str, run: dict | None) -> Safe:
    return badge(state) if state != "idle" else badge((run or {}).get("verdict"))


def dashboard(scans, token: str, error: str | None = None) -> bytes:
    projects, broken = store.list_projects()
    rows = []
    for project in projects:
        history = runs.read_runs(project.name)
        run = history[-1] if history else None
        link = h('/projects/{}', url(project.name))
        report: Safe | str = "—"
        if run and run.get("has_reports") and (reports_dir(project.name) / "summary.html").is_file():
            report = h('<a href="{}/reports/summary.html">summary</a>', link)
        rows.append(h(
            '<tr><td><a href="{link}">{name}</a></td><td>{status}</td><td>{counts}</td>'
            '<td>{trend}</td><td>{top}</td><td>{when}</td><td><code>{schedule}</code></td>'
            '<td>{report}</td><td>{scan}</td></tr>',
            link=link, name=project.name, status=_status_badge(scans.state(project.name), run),
            counts=counts_text((run or {}).get("severity_counts")), trend=_trend(history),
            top=(run or {}).get("top_component") or "—", when=(run or {}).get("finished") or "never",
            schedule=project.schedule or "—", report=report,
            scan=_action(h("{}/scan", link), "Scan", token)))
    rows += [h('<tr><td>{}</td><td>{}</td><td colspan="7">{}</td></tr>',
               stem, badge("usage_error"), why) for stem, why in broken]
    table = h("""<div class="tablewrap"><table><thead><tr><th>Project</th><th>Status</th><th>Severity</th><th>Trend</th>
<th>Top component to upgrade</th><th>Last run</th><th>Schedule</th><th>Report</th><th></th></tr></thead>
<tbody>{}</tbody></table></div>""", join(rows)) if rows else Safe("<p>No projects yet.</p>")
    body = h('<h1>Projects</h1>{}{}<p><a href="/projects/new" role="button">Add a project</a></p>',
             _error(error), table)
    return page("Projects", body)


def _profile_options(selected: str | None) -> Safe:
    options = [h('<option value="">(shipped defaults)</option>')]
    for name in store.list_profiles():
        chosen = Safe(" selected") if name == selected else Safe("")
        options.append(h('<option value="{name}"{chosen}>{name}</option>', name=name, chosen=chosen))
    return join(options)


def _project_fields(values: dict) -> Safe:
    meta = "\n".join(f"{k}={v}" for k, v in (values.get("meta") or {}).items()) \
        if isinstance(values.get("meta"), dict) else values.get("meta") or ""
    return h("""<label for="target">Target</label>
<input type="text" id="target" name="target" value="{target}" required>
<p class="hint">A folder on this machine (<code>/Users/me/src/api</code>) or a git URL
(<code>https://github.com/org/repo.git</code>, ssh too). A repository is cloned, and
refreshed before each scan.</p>
<label for="profile">Profile</label><select id="profile" name="profile">{options}</select>
<p class="hint">Scan settings shared between projects: engines, the gate, exclusions.
Without one the shipped defaults apply. Create them under Profiles.</p>
<label for="meta">Metadata (optional)</label>
<textarea id="meta" name="meta" class="short" rows="3">{meta}</textarea>
<p class="hint">Your own notes about the project, one <code>key=value</code> per line, such as
<code>owner=team-payments</code> or <code>env=prod</code>. Kept with the project; the scan
does not use them.</p>
<label for="schedule">Schedule (optional)</label>
<input type="text" id="schedule" name="schedule" value="{schedule}">
<p class="hint">Cron: minute hour day month weekday. <code>0 3 * * 1</code> is Mondays at
03:00. Runs while <code>appsec-compose serve</code> is up; to run without it, install the
lines from <code>appsec-compose project cron</code>.</p>""",
             target=values.get("target"), options=_profile_options(values.get("profile")),
             meta=meta, schedule=values.get("schedule"))


def new_project(token: str, values: dict | None = None, error: str | None = None) -> bytes:
    values = values or {}
    body = h("""<h1>Add a project</h1>{error}<form method="post" action="/projects">{csrf}
<label for="name">Name</label>
<input type="text" id="name" name="name" value="{name}" required>
<p class="hint">Lowercase letters, digits and hyphens, such as <code>payments-api</code>.</p>
{fields}<p><button>Add</button></p></form>""",
             error=_error(error), csrf=_csrf(token), name=values.get("name"),
             fields=_project_fields(values))
    return page("Add a project", body)


def project_page(project: store.Project, scans, token: str, error: str | None = None) -> bytes:
    name = project.name
    link = h("/projects/{}", url(name))
    history = runs.read_runs(name)
    run = history[-1] if history else None
    state = scans.state(name)
    report_links = join((h('<a href="{}/reports/{}">{}</a>', link, url(f), f)
                         for f in listed_reports(name)), " · ")
    rows = join(h("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                  r.get("finished"), badge(r.get("verdict")), counts_text(r.get("severity_counts")),
                  r.get("trigger"), f"{r.get('duration_s')} s", r.get("error") or "")
                for r in reversed(history))
    body = h("""<h1>{name} {status}</h1>{error}
<p>{scan} <a href="{link}/status.json">status.json</a></p>
<p>Trend: {trend}</p>
<h2>Latest reports</h2><p>{reports}</p>
<h2>Runs</h2><div class="tablewrap"><table><thead><tr><th>Finished</th><th>Verdict</th><th>Severity</th><th>Trigger</th>
<th>Took</th><th>Error</th></tr></thead><tbody>{rows}</tbody></table></div>
<h2>Edit</h2><form method="post" action="{link}">{csrf}{fields}<p><button>Save</button></p></form>
<h2>Delete</h2><form method="post" action="{link}/delete">{csrf}
<label><input type="checkbox" name="confirm" value="1" required> Also deletes this project's reports,
clone and history. A local target is not touched.</label>
<p><button class="danger">Delete</button></p></form>""",
             name=name, status=_status_badge(state, run), error=_error(error),
             scan=_action(h("{}/scan", link), "Scan now", token), link=link,
             trend=_trend(history), reports=report_links or "None yet.", rows=rows,
             csrf=_csrf(token), fields=_project_fields(project.to_dict()))
    return page(name, body, refresh=state != "idle")


def profiles_page(token: str) -> bytes:
    items = join(h('<li><a href="/profiles/{}">{}</a></li>', url(n), n) for n in store.list_profiles())
    body = h("""<h1>Profiles</h1>
<p>A profile is laid over the shipped defaults; a repo's own <code>.appsec-compose.yml</code>
is laid over the profile, so its suppressions keep working.</p>
<ul>{items}</ul><h2>New profile</h2>
<form method="post" action="/profiles">{csrf}<label for="name">Name</label>
<input type="text" id="name" name="name" required>
<p class="hint">Lowercase letters, digits and hyphens.</p>
<label for="yaml">Settings (YAML)</label>
<textarea id="yaml" name="yaml"></textarea>
<p class="hint">Only what differs from the defaults, for example:<br>
<code>fail_on: critical</code><br><code>exclude: [vendor, fixtures]</code><br>
<code>scanners: {{zizmor: {{enabled: false}}}}</code></p>
<p><button>Create</button></p></form>""",
             items=items, csrf=_csrf(token))
    return page("Profiles", body)


def profile_page(name: str, text: str, token: str, error: str | None = None) -> bytes:
    link = h("/profiles/{}", url(name))
    body = h("""<h1>Profile {name}</h1>{error}
<form method="post" action="{link}">{csrf}
<label for="yaml">YAML, same format as a project config</label>
<textarea id="yaml" name="yaml">{text}</textarea><p><button>Save</button></p></form>
<h2>Delete</h2><form method="post" action="{link}/delete">{csrf}
<p><button class="danger">Delete</button></p></form>""",
             name=name, error=_error(error), link=link, csrf=_csrf(token), text=text)
    return page(f"Profile {name}", body)


def message(title: str, text: str) -> bytes:
    return page(title, h("<h1>{}</h1><p>{}</p>", title, text))
