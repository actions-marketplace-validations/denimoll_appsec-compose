"""`appsec-compose project ...` and `appsec-compose serve`.

Exit codes are the scanner's: 0 pass, 1 policy fail, 2 usage/config error, 3 the
scan did not complete. With --json, stdout is one JSON object whatever happens,
usage errors included; everything for people goes to stderr.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import batch, jobs, runner, runs, store, targets
from .htmlsafe import counts_text
from .paths import UsageError, profile_file, project_state, reports_dir


class _Parser(argparse.ArgumentParser):
    """A bad flag answers like every other usage error, --json callers included."""

    def error(self, message):
        raise UsageError(message)


def _parser() -> argparse.ArgumentParser:
    root = _Parser(prog="appsec-compose", allow_abbrev=False)
    top = root.add_subparsers(dest="command", required=True, parser_class=_Parser)

    project = top.add_parser("project", help="named projects", allow_abbrev=False)
    sub = project.add_subparsers(dest="action", required=True, parser_class=_Parser)

    add = sub.add_parser("add", help="define a project", allow_abbrev=False)
    add.add_argument("name")
    add.add_argument("target", help="a directory, or an https/ssh git URL")
    add.add_argument("--profile", help="a profile's name")
    add.add_argument("--meta", action="append", default=[], metavar="K=V")
    add.add_argument("--no-repo-config", action="store_true",
                     help="ignore the repo's own config and baseline (code that isn't yours)")
    add.add_argument("--json", action="store_true")

    listing = sub.add_parser("list", help="projects and their latest verdict", allow_abbrev=False)
    listing.add_argument("--json", action="store_true")

    show = sub.add_parser("show", help="a project's definition and runs", allow_abbrev=False)
    show.add_argument("name")
    show.add_argument("--json", action="store_true")

    rm = sub.add_parser("rm", help="delete a definition, its reports and clone", allow_abbrev=False)
    rm.add_argument("name")
    rm.add_argument("--keep-state", action="store_true", help="keep reports, clone and history")
    rm.add_argument("--json", action="store_true")

    scan = sub.add_parser("scan", help="scan one project, or --all", allow_abbrev=False)
    scan.add_argument("name", nargs="?")
    scan.add_argument("--all", action="store_true", help="every project, then write index.html")
    scan.add_argument("--jobs", type=int, default=1, help="with --all: projects at once (default 1)")
    scan.add_argument("--fail-on", metavar="L")
    scan.add_argument("--min-confidence", metavar="L")
    scan.add_argument("--strict", action="store_true")
    scan.add_argument("--require-pinned", action="store_true")
    scan.add_argument("--update-baseline", action="store_true")
    scan.add_argument("--json", action="store_true")

    schedule = sub.add_parser("schedule", help="set or clear a project's cron", allow_abbrev=False)
    schedule.add_argument("name")
    schedule.add_argument("cron", nargs="?", help='5 fields, e.g. "0 3 * * *"')
    schedule.add_argument("--off", action="store_true")
    schedule.add_argument("--json", action="store_true")

    sub.add_parser("cron", help="print crontab lines to install; changes nothing",
                   allow_abbrev=False)

    serve = top.add_parser("serve", help="local web UI", allow_abbrev=False)
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--allow-remote", action="store_true",
                       help="permit a non-loopback --host; there is no login")
    serve.add_argument("--public-host", action="append", default=[], metavar="NAME",
                       help="a name clients reach a non-loopback bind by (Host check)")
    serve.add_argument("--jobs", type=int, default=1, help="scans at once (default 1)")
    return root


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _out(args, payload: dict, text: str | None = None) -> None:
    if getattr(args, "json", False):
        print(json.dumps(payload))
    elif text is not None:
        print(text)


def _extra(args) -> list[str]:
    extra = []
    if args.fail_on:
        extra += ["--fail-on", args.fail_on]
    if args.min_confidence:
        extra += ["--min-confidence", args.min_confidence]
    extra += [flag for flag, on in (("--strict", args.strict),
                                    ("--require-pinned", args.require_pinned),
                                    ("--update-baseline", args.update_baseline)) if on]
    return extra


def _line(result: dict) -> str:
    line = f"{result['project']}: {result['verdict']} ({counts_text(result['severity_counts'])})"
    return f"{line}: {result['error']}" if result.get("error") else line


def _scan(args) -> int:
    if args.all == bool(args.name):
        raise UsageError("project scan needs a project name or --all, not both")
    if args.jobs < 1:
        raise UsageError("--jobs must be at least 1")
    if args.all:
        projects, broken = store.list_projects()
        if not projects and not broken:
            raise UsageError("no projects to scan: add one with `appsec-compose project add`")
        outcome = batch.run_batch(_extra(args), args.jobs,
                                  on_begin=lambda n: _say(f"{n}: scanning (log: {runner.log_file(n)})"))
        code = outcome["exit_code"]
        for result in outcome["projects"]:
            _say(_line(result))
        _say(f"Index: {outcome['index_html']}")
        _out(args, {"verdict": runner.VERDICTS[code], **outcome})
        return code
    store.load_project(args.name)
    _say(f"{args.name}: scanning (log: {runner.log_file(args.name)})")
    result = runner.scan_project(args.name, _extra(args))
    _say(_line(result))
    if result["reports_dir"]:
        _say(f"Reports: {result['reports_dir']}/summary.html")
    _out(args, result)
    return result["exit_code"]


def _list(args) -> int:
    projects, broken = store.list_projects()
    rows = []
    for project in projects:
        history = runs.read_runs(project.name)
        run = history[-1] if history else {}
        rows.append({"name": project.name, "target": project.target, "profile": project.profile,
                     "schedule": project.schedule, "verdict": run.get("verdict"),
                     "severity_counts": run.get("severity_counts"), "last_run": run.get("finished"),
                     "trend": runs.trend(history)})
    if getattr(args, "json", False):
        print(json.dumps({"projects": rows, "broken": [{"name": s, "error": w} for s, w in broken]}))
        return 2 if broken else 0
    for row in rows:
        print(f"{row['name']}\t{row['verdict'] or 'no run'}\t{counts_text(row['severity_counts'])}\t"
              f"{row['last_run'] or 'never'}\t{row['profile'] or '-'}\t{row['schedule'] or '-'}\t{row['target']}")
    for stem, why in broken:
        _say(f"{stem}: {why}")
    if not rows and not broken:
        _say("No projects yet: appsec-compose project add <name> <path-or-git-url>")
    return 2 if broken else 0


def _show(args) -> int:
    project = store.load_project(args.name)
    history = runs.read_runs(project.name)
    payload = {**project.to_dict(), "state_dir": str(project_state(project.name)),
               "reports_dir": str(reports_dir(project.name)), "running": runs.is_running(project.name),
               "runs": history, "trend": runs.trend(history)}
    if project.profile:
        payload["profile_file"] = str(profile_file(project.profile))
    lines = [f"{key}: {value}" for key, value in payload.items() if key not in ("runs", "trend")]
    lines += [f"{r.get('finished')}  {r.get('verdict')}  {counts_text(r.get('severity_counts'))}"
              for r in history]
    _out(args, payload, "\n".join(lines))
    return 0


def _dispatch(args) -> int:
    if args.command == "serve":
        from .web import serve   # the server's imports stay out of every other command
        return serve(args.host, args.port, args.public_host, args.allow_remote, args.jobs)
    action = args.action
    if action == "add":
        project = store.add_project(args.name, args.target, args.profile, store.parse_meta(args.meta),
                                    repo_config=not args.no_repo_config)
        kind = "git URL, cloned at scan time" if targets.is_git_url(project.target) else "local path"
        _out(args, project.to_dict(), f"Added {project.name}: {project.target} ({kind})")
    elif action == "list":
        return _list(args)
    elif action == "show":
        return _show(args)
    elif action == "rm":
        store.delete_project(args.name, args.keep_state)
        _out(args, {"removed": args.name}, f"Removed {args.name}")
    elif action == "scan":
        return _scan(args)
    elif action == "schedule":
        if args.off == bool(args.cron):
            raise UsageError('project schedule needs a cron expression or --off, not both')
        project = store.set_schedule(args.name, None if args.off else args.cron)
        _out(args, project.to_dict(), f"{project.name}: schedule {project.schedule or 'off'}")
        if project.schedule and not getattr(args, "json", False):
            _say("It runs while `appsec-compose serve` is up, or from cron: see `appsec-compose project cron`.")
    elif action == "cron":
        lines = jobs.crontab_lines()
        for line in lines:
            print(line)
        _say("Nothing was installed. To add these: (crontab -l; appsec-compose project cron) | crontab -"
             if lines else "No project has a schedule.")
    return 0


def main(argv: list[str]) -> int:
    wants_json = "--json" in argv
    try:
        return _dispatch(_parser().parse_args(argv))
    except UsageError as exc:
        _say(f"Error: {exc}")
        if wants_json:
            print(json.dumps({"exit_code": 2, "verdict": "usage_error", "error": str(exc),
                              "reports_dir": None, "findings_json": None, "review_brief": None,
                              "severity_counts": None, "breaching": None, "baseline": None}))
        return 2
    except OSError as exc:   # the definitions or state directory, not a scan
        _say(f"Error: {exc}")
        if wants_json:
            print(json.dumps({"exit_code": 2, "verdict": "usage_error", "error": str(exc)}))
        return 2
