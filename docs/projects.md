# Projects, batch runs, schedules and the local UI

An optional layer over `appsec-compose scan`, for someone looking after several
repositories. Back to the [README](../README.md).

The scanner stays stateless: a plain `scan` reads none of this and writes none of
it. Everything below lives in the `manager/` package and in your XDG directories,
and needs nothing beyond what a scan already needs (Python with PyYAML, Docker;
`git` for git targets).

A **project** is a name + a target (a directory or a git URL) + an optional
**profile** + metadata.

## Quick start

```bash
appsec-compose project add api ~/src/api --meta owner=platform
appsec-compose project add web https://github.com/acme/web.git --profile strict
appsec-compose project scan api           # one project: exit 0/1/2/3 as ever
appsec-compose project scan --all         # all of them, then an index.html
appsec-compose serve                      # the same in a browser, on 127.0.0.1:8787
```

| Command | Does |
|---|---|
| `project add <name> <path-or-git-url> [--profile P] [--meta k=v]...` | define a project; a git URL is cloned at scan time |
| `project list`, `project show <name>` | latest verdict and history (`--json` on either) |
| `project rm <name> [--keep-state]` | delete the definition, and the reports, clone and history unless kept; a local target is never touched |
| `project scan <name> \| --all [--jobs N]` | scan; takes `--fail-on`, `--strict`, `--require-pinned`, `--update-baseline`, `--json` |
| `project schedule <name> "<cron>"` / `--off` | set or clear a schedule |
| `project cron` | print crontab lines; installs nothing |
| `serve [--port 8787]` | the local UI, which also runs due schedules |

Names are lower-case letters, digits and dashes, starting with a letter or digit.
They become file names, so nothing else is accepted. `new` is reserved.

## Where things live

```
${XDG_CONFIG_HOME:-~/.config}/appsec-compose/
├── projects/<name>.yml        # name, target, profile, meta, schedule: edit by hand if you like
└── profiles/<name>.yml        # same format as a project config
${XDG_STATE_HOME:-~/.local/state}/appsec-compose/
├── index.html                 # written by `project scan --all`
└── projects/<name>/
    ├── reports/               # the latest run's reports
    ├── source/                # the shallow clone (git targets)
    ├── baseline.json          # the baseline (git targets)
    ├── runs.json              # the last 20 runs' summaries (APPSEC_COMPOSE_KEEP_RUNS)
    ├── scan.log               # the latest run's engine output
    └── .lock
```

The state must sit somewhere Docker can bind-mount: anything under `$HOME` is
shared with Docker Desktop and Colima by default. Project and state directories
are private to your user, because reports quote the flagged code.

History keeps each run's verdict, severity counts, top component and time, not
its reports: enough for a trend, without keeping old copies of quoted source.

## Profiles

A named overlay in the [project config](configuration.md) format, validated by
the same schema. It is checked when saved in the UI and again by every scan; a
mistake is exit 2 naming the file. The precedence is:

**shipped defaults < profile < the repo's own `.appsec-compose.yml`**

Mappings merge key by key; a list or a scalar is replaced whole. So a repo's own
`ignore:` keeps working, and if a repo has one it replaces a profile's `ignore:`
rather than adding to it.

```yaml
# ~/.config/appsec-compose/profiles/strict.yml
fail_on: { secrets: low, default: medium }
strict: true
scanners:
  osv: { enabled: true }
```

`scan` and `run.sh` take a profile as a file too: `--profile path/to/strict.yml`.

## Git targets

Only `https://`, `ssh://` and `user@host:path` are accepted. `ext::`, `fd::`,
`file://`, `http://`, a leading dash and credentials in the URL are refused; use a
git credential helper or ssh keys for a private repository. Git runs from an argv
list with the URL after `--`, prompts off (`GIT_TERMINAL_PROMPT=0`, ssh in batch
mode) and `GIT_ALLOW_PROTOCOL=https:ssh`, no submodules, no symlinks checked out.

Every scan brings the clone to the remote's `HEAD` with a shallow fetch. A clone
or fetch that fails is exit 3 for that project: there is no result, and a stale
tree is not scanned.

**A cloned repository's own config applies, as it does when you scan any checkout
by hand.** That is what keeps a repo's suppressions working, but it also means a
repository you do not trust can suppress its own findings. For third-party code,
read its `.appsec-compose.yml` before believing a pass. Its `enrich.cve_paas.url`
could also point the optional enrichment elsewhere, sending your
`CVE_PAAS_API_KEY` if you have one exported.

## Baselines

The same convention as a plain scan. For a local target that is
`<target>/.appsec-baseline.json`, in the repo where it can be committed. A clone is
replaced freely, so a git target's baseline lives beside it in the state directory
(a baseline committed in the repo is used until you make your own). Either way:
`project scan <name> --update-baseline`.

## Batch

`project scan --all` runs one project at a time unless you pass `--jobs N`. One
project failing never stops the rest, a definition file that cannot be read counts
as exit 2, and the batch exits with the worst outcome: 3 > 2 > 1 > 0. With no
projects at all it is exit 2, not a pass.

`index.html` is self-contained and opens from disk: project, verdict, severity
counts, the top component to upgrade, last run, and a link to its `summary.html`.
`--all --json` gives `exit_code`, `verdict`, `index_html` and one `scan --json` object
per project (plus `project` and `error`).

A second scan of a project that is already running is refused with exit 3, whether
it came from the CLI, cron or the UI.

## Schedules

`project schedule api "0 3 * * *"` stores a standard 5-field expression: lists,
ranges, steps, `jan`-`dec`, `sun`-`sat`, and 0 or 7 for Sunday. When both day fields
are restricted, either may match, as in cron. `@daily` and friends are not accepted.

Nothing edits your crontab. Either keep `appsec-compose serve` running, which fires
what is due, or install the printed lines:

```bash
appsec-compose project cron                                     # look first
(crontab -l; appsec-compose project cron) | crontab -           # then add them
```

Each line carries the `PATH` that finds Docker and any XDG override, since cron has
neither. Both can run together: the project lock stops a second scan. `serve` catches
up a stall of a few minutes but does not replay a night the laptop was asleep.

## The local UI

```bash
appsec-compose serve [--port 8787]
```

Python's standard library only, server-rendered, no JavaScript. List projects with
their latest verdict and trend, create, edit and delete projects and profiles, set
schedules, start a scan, follow its status and open its reports.
`/projects/<name>/status.json` gives the status to a script. `--jobs N` lets N scans
run at once (default 1; further ones queue).

### Security

The server reads local files and starts scans, and any web page you visit can send
requests to a port on your machine. What it does about that:

- **Loopback only by default.** Any other address needs `--allow-remote` and prints
  a warning, because **there is no login**: anyone who can reach the port can read
  reports, add projects (including any directory readable by your user as a target)
  and start scans. Put an authenticating proxy or SSH tunnel in front instead if you
  can. `0.0.0.0` also needs `--public-host NAME`, the names clients will use.
- **Host header checked**, against the bound address and port (`localhost` too on
  loopback), which defeats DNS rebinding.
- **Every state change is a POST** with a per-process random CSRF token, a same-origin
  `Origin` and `Sec-Fetch-Site` when the browser sends them, and a form content type.
  GET changes nothing.
- **Reports are served from an allowlist**: `summary.html`, `summary.md`,
  `review-brief.md`, `findings.json` and `sbom.*.json` from that project's own
  reports directory, with no symlink followed. `native/` is never served: it is raw
  engine output, and `native/trufflehog.json` holds the secret values the other
  reports mask. Neither is the scan log rendered, only run.sh's own error lines.
- **Findings are attacker-controlled** through scanned repositories. All output is
  escaped by default, every response has `nosniff` and a strict CSP with no script.
  `summary.html` runs only its own filter script, allowed by hash, in a sandbox that
  gives it no access to the UI's origin.
- **No shell**: scans and git run from argv lists.

It speaks plain HTTP. That is fine on loopback; off it, reports travel in clear.
