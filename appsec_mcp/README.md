# appsec-compose MCP server

Lets an AI agent (Claude Code, Cursor, any MCP client) run an appsec-compose
scan and triage it: read what fails the gate, look at the flagged code, and
record a verdict — a fix in code, or a suppression with a reason and an expiry
that a human reviews with the diff.

It is a thin layer over the same CLI and the same
[`findings.json` contract](../schemas/findings.schema.json); the scanners still
run in Docker. Transport: stdio.

## Install

Needs Python 3.10+ and Docker, as for any scan. With the [CLI installed](../README.md#install-and-run-locally-no-clone):

```bash
appsec-compose mcp --setup
```

That creates a private venv (`${XDG_DATA_HOME:-~/.local/share}/appsec-compose/mcp-venv`)
with the pinned [requirements](requirements.txt); re-run it after an upgrade
when the server asks you to. Nothing is installed into your own Python.

## Register it

**Claude Code** — available in every project (`--scope user`), or just the
current one (default, `local`):

```bash
claude mcp add --scope user appsec-compose -- appsec-compose mcp
```

**Any MCP client** (Cursor `~/.cursor/mcp.json`, Claude Desktop, …):

```json
{
  "mcpServers": {
    "appsec-compose": { "command": "appsec-compose", "args": ["mcp"] }
  }
}
```

From a checkout without the CLI, install `requirements.txt` into a venv and
run `<venv>/bin/python /path/to/appsec-compose/appsec_mcp` instead.

## Tools

| Tool | When | Returns |
|---|---|---|
| `scan(path, diff_base?, fail_on?)` | first; again after fixing | verdict (`pass` / `fail` / `usage_error` / `scan_error`), severity counts, gating count, **blind spots**, report paths |
| `findings(path, severity_min?, category?, file?, new_only?, gating_only?, include_suppressed?, limit=50, offset=0)` | pick what to triage | one line per finding, gating first; page with `next_offset` |
| `components(path, gating_only?, limit=50, offset=0)` | dependencies: what to upgrade | one entry per vulnerable package — severity, count, **version to upgrade to**, the findings inside |
| `finding(path, fingerprint, context_lines=5)` | decide if one finding is real | rule, CWE, explanation, advisory, fixed version, flagged code with context |
| `brief(path, section?)` | plan the manual review | `review-brief.md`, or one section (`Blind spots`, `Scope`, …) |
| `suppress(path, fingerprint, reason, expires?)` | false positive / accepted risk | the `ignore:` entry written to `<repo>/.appsec-compose.yml` |

Plus a `security_review(path, diff_base?)` prompt that walks an agent through
the whole loop.

A scan takes minutes (the first one also pulls images and vulnerability DBs);
the server streams progress while it runs. The other tools read the last scan of
that repository and are instant. Fingerprints may be given as the 12-character
prefix `findings()` prints.

## Recommended agent workflow

1. `scan(path)`. On `usage_error` / `scan_error` there is no verdict — report
   `log_tail` and stop.
2. Read `blind_spots`: what the tools did not check (authorization, business
   logic, cross-file data flow, …). Those need reading the code.
3. `findings(path, gating_only=true)`, then `finding(path, fp)` for each.
4. Real → fix the code (dependencies: upgrade to the fixed version; secrets:
   rotate, not just delete). Not exploitable here → `suppress` with a specific
   reason a reviewer can check.
5. `scan(path, diff_base="origin/main")` to re-check the change, until the gate
   passes or what remains is explained.

## Where things are written

- **Reports** go to a per-repository directory under the user cache
  (`~/.cache/appsec-compose/mcp/<name>-<hash>/`), never into the scanned tree.
  Docker bind-mounts it, so it must be a path Docker can share (anything
  under your home directory is, by default, on Docker Desktop too).
- **`suppress`** writes exactly one file, `<repo>/.appsec-compose.yml`. An
  existing file is edited as text — the entry is inserted into `ignore:`,
  comments and layout are kept — then parsed back and validated against the
  collector's schema before anything is written. A missing file is created holding
  only the `ignore:` list: a project config is laid over the tool's
  `scan-config.yml`, so the engines and the gate stay as shipped.
- If `<repo>/.appsec-compose.yml` or `<repo>/.appsec-baseline.json` exist, every
  scan uses them.

## Safety

- `path` must be an existing directory; `/`, its direct children and your home
  directory (or anything above it) are refused. `APPSEC_MCP_ALLOWED_ROOTS`
  narrows it further.
- The CLI is run from an argv list — no shell — and `diff_base` must look like a
  git ref, never an option.
- No secret value is returned by any tool: code is masked with the collector's
  own `_mask_secret`, on every line a secret-like finding points at (including
  when it falls in another finding's context), and secret findings' messages
  are scrubbed of the matched value.
- `suppress` requires a reason, defaults the expiry to 90 days, caps it, and
  refuses to write through a symlink.

## Settings (environment)

| Variable | Default | |
|---|---|---|
| `APPSEC_MCP_STATE_DIR` | `$XDG_CACHE_HOME/appsec-compose/mcp` | where reports and the last-scan record live |
| `APPSEC_MCP_ALLOWED_ROOTS` | (any) | `:`-separated directories targets must be inside |
| `APPSEC_MCP_SCAN_TIMEOUT` | `3600` | seconds before a scan is stopped |
| `APPSEC_MCP_MAX_SUPPRESS_DAYS` | `365` | latest allowed `expires` |
| `APPSEC_MCP_COMPOSE_PREFIX` | `mcp` | compose project prefix when driving `run.sh` |
| `APPSEC_COMPOSE_DIR` | this checkout | the appsec-compose to drive |
