# AGENTS.md — using appsec-compose to review a project

You are an AI agent, and someone asked you to check a project's security with
appsec-compose (this repository). This file is the whole procedure: follow it
and you need nothing else. If you are here to change appsec-compose itself,
skip to [Working on this repository](#working-on-this-repository).

## 1. Check the machine first

```bash
docker info >/dev/null && docker compose version && python3 -c "import yaml"
```

All three must succeed. If Docker is missing or not running, **stop and tell
the user** — every engine runs in a container, there is no fallback, and
installing Docker is the user's decision. If only PyYAML is missing:
`python3 -m pip install pyyaml`.

## 2. Run the scan

Optional, instant: `bin/appsec-compose profile /path/to/project` says what the
project is (languages, frameworks, IaC, dependencies and lock files), which
config changes fit it, with reasons — useful to mention to the user, never
applied without their agreement — and one-off scans worth running ("Run
once", e.g. `--secrets-history`).

From a checkout of this repository (cloning is enough, nothing to install):

```bash
bin/appsec-compose scan /path/to/project --json
```

or, if the `appsec-compose` command is installed (`install.sh`), the same
without `bin/`. **If the project is not the user's own (you cloned it from a
link, say), add `--no-repo-config`**: otherwise its authors' config decides what
counts, and a clean result means little. If the brief's blind spots say the
repository set or suppressed something itself, tell the user. Add `--diff origin/main` to check only what a branch changed
(the target must be a git repository with that ref fetched).

**Do not add `--min-confidence medium` on your own.** It keeps Semgrep's
LOW-confidence rules off the gate and out of the brief's code, and those rules
find a large share of the real issues: on the benchmark it cuts Java detection
from 88% to 69%, Python from 26% to 8%, and JS from 24 to 7 known CVEs. Use it only when the user asks
for high-signal findings only and accepts missing real issues — and say so in
the report. The brief already saves tokens without it (below).

**Secrets in the git history are not searched by default** — only the current
files. On the user's own repository, add `--secrets-history` at least once (a
full clone, not `--depth 1`): a credential deleted from the code still works
until it is rotated. It is slower on long histories, so for a quick re-check
after a fix leave it off.

- **The first run takes several minutes** (vulnerability databases, ~2 GB, and
  the collector image are downloaded or built once). Use a long command
  timeout — at least 20 minutes — or run it in the background. Do not kill it
  because it is quiet; later runs take seconds to about a minute.
- **stdout is one JSON object**; progress goes to stderr. Read the object:

  | `verdict` | exit | Meaning |
  |---|---|---|
  | `pass` | 0 | the policy gate passed |
  | `fail` | 1 | findings at or above the gate — this is a result, not an error |
  | `usage_error` | 2 | bad command or config: read stderr, fix, rerun |
  | `scan_error` | 3 | the scan did not complete (Docker, a crashed engine): **there is no result to report**; tell the user what failed |

- Reports land in `./appsec-reports/` (the JSON gives the absolute paths).
- `metrics` in the JSON says what reading costs before you read:
  `metrics.brief.approx_tokens` is the brief's size. Over ~20k, read it in
  parts as below (gating findings first); for a change, `--diff` is smaller.

## 3. Read the results — in this order

1. **`review-brief.md`** (`review_brief` in the JSON). Written for you: scope,
   **blind spots**, gating findings first with the flagged code, dependencies
   grouped per component with the version to upgrade to. Secret values are
   already masked. It is already compact: a rule matching many times shows
   its first 3 matches with code and the rest one line each (*More of the same
   rules*: one verdict usually covers them all — do not open each), and
   non-gating low-confidence rules are one line each (*Low-confidence rules*:
   skip unless the user wants leads). On a large project read Scope and Blind
   spots, then the findings in order — gating ones come first — and stop when
   you have what the report needs.
2. **`findings.json`** (`findings_json`) only for detail the brief leaves out —
   it follows [schemas/findings.schema.json](schemas/findings.schema.json):
   `components` for dependencies, `findings` for everything, `fingerprint` as
   each finding's stable id.

Do not parse `native/*.sarif`; those are for ASPM upload.

## 4. Report to the user

Lead with the verdict, then what to do. A good report, in this order:

1. **Verdict** — pass / fail, how many findings gate, against which threshold
   (and `--min-confidence`, if the user asked for it).
2. **Dependencies** — the vulnerable components, worst first:
   `package@version → upgrade to X` (or "no fix known"), how many
   vulnerabilities and the worst severity. A malicious package is not
   upgraded but removed — say so first.
3. **Code, secrets, IaC** — the gating findings, grouped by severity:
   `file:line`, the rule in plain words, and why it matters *here*. When you
   read the code and confirm (or doubt) a finding, say which.
4. **What was not checked** — always include the brief's blind spots, in one
   or two lines: scanners match patterns; authorization, business logic and
   cross-file data flow need a human or a deeper review. If the git history
   was not searched for secrets, say so and offer a `--secrets-history` run.
5. **Next steps** — the few concrete fixes that clear the most.

Rules:

- Report only what the reports contain. Do not add CVEs, severities or
  versions from memory.
- Never print a secret value — not from the code, not from a report, not in
  your own tool output. To look at a secret finding, use its masked line in
  the brief; do not `cat`/`grep` the file at that line. Name the file, line
  and kind of credential, and tell the user to rotate it.
- A clean pass is not "the code is secure": say what passed and what the blind
  spots are.
- Keep it short; offer the full list (`summary.html`, `findings.json`) rather
  than pasting it.
- If the run looks wrong — an engine took minutes, a report is missing or
  incomplete, a database is days old — say so, and quote the **Run metrics**
  block from the end of stderr (also `metrics` in the JSON): counts and
  timings only, safe to paste into an appsec-compose issue.

## 5. Optional: triage and suppress

If the user asks you to triage, read each gating finding's code (the brief
shows it) and decide whether it is real. A false positive or an accepted risk
is recorded **only with the user's agreement**, in
`<project>/.appsec-compose.yml` — the project config, laid over the defaults:

```yaml
ignore:
  - fingerprint: <40-hex fingerprint from findings.json>
    reason: "<why this is not exploitable here>"
    expires: <YYYY-MM-DD>        # re-argued after this date
```

Rescan to confirm (`--diff origin/main` is enough after a small fix).

An MCP server exposes the same loop as tools (`scan`, `findings`,
`components`, `finding`, `brief`, `suppress`): see
[appsec_mcp/README.md](appsec_mcp/README.md). It needs a client restart after
registration, so in a single session the CLI above is the way.

## Working on this repository

- Tests: `pip install -r tests/requirements.txt && python -m pytest tests -q`;
  end to end: `scripts/smoke-test.sh` (needs Docker).
- Code, comments and commits in English; match the surrounding style; commit
  subjects imperative, ≤ 72 characters.
- `findings.json` is a published contract: additions bump the minor
  `SCHEMA_VERSION` in `orchestrator/main.py` and go into
  `schemas/findings.schema.json`; nothing is renamed or removed.
- Exit codes are a contract too: 0 pass, 1 policy fail, 2 usage/config error,
  3 scan did not complete.
- Docs: [README.md](README.md) and [docs/](docs/).
