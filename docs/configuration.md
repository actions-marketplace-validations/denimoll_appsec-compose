# Configuration and policy

scan-config.yml, project configs, the gate, suppressions and baselines. Back to the [README](../README.md).

## Configuration — one file

Everything lives in [`scan-config.yml`](../scan-config.yml): which checks run, the
pinned tool **versions** (bump here to upgrade), the policy gate and the offline
switch. `run.sh` renders it into `.env` (which Compose loads) and runs only the
enabled scanners.

```yaml
scanners:
  semgrep:  { enabled: true, version: "1.183.0" }    # SAST
  trivy:    { enabled: true, version: "0.76.1" }     # SCA + IaC + SBOM
  gitleaks: { enabled: true, version: "v8.30.1" }    # secrets
  checkov:  { enabled: true, version: "3.4.0" }     # IaC

sbom: true                 # SBOM via Trivy
sbom_formats: [cyclonedx]  # any of: cyclonedx, spdx
fail_on: high              # critical|high|medium|low|none (none = report-only)
unknown_severity: medium
strict: false              # a scanner with no readable report fails the run
offline: false             # use ./preload.sh cache, no network during scan
```

A **project config** (`--config`, or `<target>/.appsec-compose.yml` with the
CLI) is laid over these defaults, not swapped in for them, so it states only
what differs:

```yaml
# .appsec-compose.yml — everything else stays as shipped
fail_on: { secrets: low, default: high }
scanners:
  zizmor: { enabled: false }
ignore:
  - rule: CVE-2018-1000656
    reason: "no fix available, mitigated at the proxy"
```

Mappings merge key by key (`scanners.zizmor.enabled` leaves zizmor's version
and every other engine alone); lists such as `ignore:` and `exclude:` and plain
values replace the default whole. A project config therefore keeps following
the shipped defaults across upgrades — a new default engine reaches it —
instead of freezing a copy. To turn a default engine off, say so with
`enabled: false`. Mistakes are reported against the project file and key.

Disable a check by setting `enabled: false` — that scanner won't run and the
collector won't expect its report. Upgrade a tool by changing its `version`.
Set `secrets_history: true` (or pass `--secrets-history` for one run) to have
Gitleaks also scan the full **git history** — a second pass, so the working
tree, uncommitted files included, is still read. A credential deleted from the
code stays in the history and keeps working until it is rotated, so run it at
least once on your own repository. It needs a `.git`: without one the run says
so and searches the files only. In CI that is usually
more than you need — `secrets_history_range: "origin/main..HEAD"` limits it to
the branch's own commits, which is orders of magnitude faster and still catches
a secret that was committed and then removed within the branch.

## A repository's own config

`.appsec-compose.yml` in the scanned repository is written by whoever controls
that repository, not by whoever runs the scan, so it is not trusted like a
`--config` or `--profile` you pass yourself. Only project policy applies from it:
`fail_on`, `unknown_severity`, `strict`, `dedup`, `baseline`, `exclude`, `ignore`,
`sbom`, `sbom_formats`, `secrets_history`, `licenses`, `offline`, `require_pinned`,
`scanners.<engine>.enabled` and `scanners.semgrep.rules: [default, auto]`.

Everything else is refused with a warning: image `version`s, `enrich` (its URL
would receive `CVE_PAAS_API_KEY`), TruffleHog `verify` (it would send found
secrets out), Checkov `frameworks`/`guidelines`, other Semgrep rule refs and
`secrets_history_range`. To use them in your own project, pass the file
explicitly: `--config .appsec-compose.yml`.

Policy can still hide findings, so what the repository set is recorded
(`provenance.repo_config`, the console, the review brief's blind spots) together
with how many findings it suppresses, in-code comments included. **For code that
is not yours, scan with `--no-repo-config`**: its config and baseline are ignored.
Engine-level ignore files it carries (`.semgrepignore`, `zizmor.yml`) still
apply, and in-code suppressions are still honoured and counted.

## Custom & auto Semgrep rules

By default Semgrep runs the curated `p/default` pack. Point it at your own rules
or let it pick rules for the repo's stack via `scanners.semgrep.rules`:

```yaml
scanners:
  semgrep:
    enabled: true
    version: "1.183.0"
    rules:
      - default                      # the curated p/default pack
      - auto                         # detect the stack -> matching registry packs
      - "p/python"                   # any Semgrep registry ref
      - "/semgrep-rules/custom.yml"  # a file from ./semgrep-rules
```

- **`auto`** scans the repo for languages/manifests (`.py`, `.go`, `.tf`,
  `Dockerfile`, …) and adds the matching `p/<lang>` packs (online only; offline
  falls back to the cached default pack).
- Any `*.yml`/`*.yaml` you drop into **`./semgrep-rules/`** is mounted at
  `/semgrep-rules` and auto-included — no config needed.

## Scan scope (`exclude:`)

Every engine skips the same set of directories, so vendored dependencies and
build output don't bury the real findings (or dominate the runtime). Omit the
key for the recommended defaults — `.git`, `node_modules`, `vendor`, `dist`,
`build`, `target`, `.venv`, `venv`, `__pycache__`, `.gradle`, `.tox`,
`.mypy_cache` — or set it to replace them:

```yaml
exclude:
  - node_modules
  - vendor
  - "docs/**"      # path globs work too
```

An explicit empty list (`exclude: []`) scans everything. Entries are translated
into each engine's own mechanism (`--exclude`, `--skip-dirs`, `--skip-path`, a
generated Gitleaks allowlist, a TruffleHog regex file, a pruned input list for
zizmor, …), so one list covers all ten.

### What git ignores (`respect_gitignore`)

In a git repository, untracked paths that its `.gitignore` covers — caches,
virtualenvs, local databases, build output, a local `.env` — are skipped too,
on top of `exclude:`. They are not the repository: Semgrep already looked only
at tracked files, while Gitleaks, Trivy and Checkov walked the whole working
tree, and one ignored 1.7 GB cache once turned a 16-second scan into an
11-minute one, full of "secrets" from a vulnerability database.

Only untracked paths qualify, so a repository cannot hide a committed file
this way; a path whose name a tracked file shares (an ignored `build/` next to
a tracked `src/build/`) is scanned anyway, since an exclude entry matches its
name anywhere. The brief lists what was skipped. To scan the whole working
tree — say, to check local `.env` files for live credentials:

```yaml
respect_gitignore: false
```

## Policy per category

`fail_on` may be a single level or a map, so each practice gets the gate it
deserves — a leaked credential is not the same event as a medium IaC lint:

```yaml
fail_on:
  secrets: low        # any credential fails the build
  sca: high
  sast: critical
  iac: none           # report-only
  default: high       # categories not listed above
```

Each finding is compared against the threshold for its own category.
`./run.sh --fail-on <level>` overrides the whole map with a single level.

## Rule confidence (`min_confidence`)

Rule authors say how often their rule is right. Semgrep marks each rule
`HIGH`, `MEDIUM` or `LOW` confidence — about 40% of its default rules are
`LOW`: a pattern worth a look, often a false positive — and zizmor rates each
result. Every finding carries that as `confidence` (`""` when its engine
states none).

```yaml
min_confidence: medium   # low (default) | medium | high
```

Findings from rules less sure than `min_confidence` are still reported, in
every report, but **do not gate**; the review brief lists the non-gating
low-confidence ones one line each, without code. A finding whose engine states
no confidence (Gitleaks, Trivy, Checkov) always gates — a missing signal never
takes a finding off the gate. `--min-confidence L` sets it for one run.

It is a trade, and a steep one: Semgrep's LOW-confidence rules find a large
share of the real issues. On the [benchmark](../benchmark/RESULTS.md#reading-cost)
`medium` cuts Java detection from 88% to 69% while the false-positive rate
barely moves (44% → 42%), Python from 26% to 8%, and JS from 24 to 7 known CVEs. Leave it at `low` unless you want only the
findings rules are sure of and accept missing real ones — a legacy backlog
gate, say; the brief folds non-gating low-confidence findings either way.

## Failing loudly (`strict`)

Scanners always exit `0`, so a crashed engine would otherwise look like a clean
result. With `strict: true` (or `--strict`) the run fails with exit `3` — rather
than counting as "0 findings" — when either:

- a scanner that was expected to report produced nothing readable, or
- the [SCA coverage check](engines.md#sca-coverage-check) found dependency manifests that
  no engine resolved.

Off by default, since a flaky engine then breaks the build rather than degrading
the scan.

## Policy / exit codes

The **collector** decides pass/fail; scanners themselves always exit `0`, so a
noisy finding never breaks the scan phase — only the policy does. Each exit
code tells the caller — a person, a CI job, an AI agent — what to fix:

| Code | Meaning | What to do |
|---|---|---|
| `0` | the policy gate passed | — |
| `1` | the gate failed: findings at/above `fail_on` | fix or triage the findings |
| `2` | usage or configuration error (bad flag, invalid `scan-config.yml`, missing target, `require_pinned` unmet, `offline` without a cache, a `--build` target that does not build) | fix the invocation or config |
| `3` | the scan did not complete (Docker unavailable, a collector crash, a missing or unreadable report under `strict`, an image that could not be pulled) | fix the environment; there is no verdict to trust |

`1` means exactly one thing: a verdict was reached and it is "fail". Compose
and bash both report their own failures as `1`, so `run.sh` checks that the
collector actually wrote a verdict and maps everything else to `3`.

## Suppressions

Drop known/accepted findings from the gate and counts via an `ignore:` list in
`scan-config.yml`. An entry matches when every field present matches; `rule` is
a glob over the finding's ID **and its aliases** (so a single CVE entry also
catches the equivalent GHSA):

```yaml
ignore:
  - rule: CVE-2018-1000656
    reason: "no fix available, mitigated at the proxy"
  - file: "tests/**"
    reason: "test fixtures"
  - rule: "generic.*"
    category: secrets
    reason: "false positives in sample data"
  - fingerprint: 3f9a…                  # exactly one finding, from findings.json
    reason: "triaged: input is a constant"
```

`fingerprint` pins one finding rather than a pattern — the right selector for a
triage verdict on a single result, whether a person or an agent made it.

An engine's own in-code suppression — `# nosemgrep`, a Checkov skip comment,
anything the engine reports as a SARIF `suppressions` entry — is honoured the
same way, with the reason `suppressed in source`; one whose status is
`rejected` or `underReview` is not in effect.

Suppressed findings are excluded from `fail_on` but recorded in `findings.json`
under `suppressed` (with the reason) for the audit trail.

Add `expires:` to make an acceptance temporary — an accepted risk should be
re-argued, not inherited by whoever maintains the repo in two years:

```yaml
ignore:
  - rule: CVE-2018-1000656
    reason: "no fix available, mitigated at the proxy"
    expires: 2026-12-01
```

Past that date the entry stops suppressing anything, its findings count towards
the gate again, and the run reports which entries lapsed (console, both
summaries, and `expired_suppressions` in `findings.json`).

## Baseline (gate on new findings)

Accept the current findings and fail only on **new** ones thereafter:

```bash
# 1. set `baseline: true` in scan-config.yml, then snapshot the accepted state:
./run.sh /path/to/repo --update-baseline      # writes appsec-baseline.json
# 2. commit appsec-baseline.json; subsequent runs gate on new findings only:
./run.sh /path/to/repo
```

Each finding gets a fingerprint anchored on **what** was flagged, not where it
sits, so adding a line above a known finding does not make it new:

| Category | Identity |
|---|---|
| SAST, IaC | rule + file + the flagged line's code (whitespace-normalized) |
| IaC with a cross-engine equivalent | policy class + file |
| Secrets | file + the line with the secret masked out — no secret material is ever hashed |
| SCA | vulnerability (CVE preferred over aliases) + package name + manifest |

Identical code flagged twice in one file is told apart by order of appearance.
SCA ignores the installed version on purpose: bumping to a version that is still
vulnerable is the same accepted risk. When the source cannot be read (image
mode, a file over 5 MB) the line number stands in.

Baselines from earlier releases (no `version` field) used line numbers. They are still honoured with
the old scheme, and the run asks you to re-snapshot with `--update-baseline`.

Runs report `new` / `known` / `fixed` counts (in the console, summary and
`findings.json`), and `fail_on` applies to **new** findings only. Re-run
`--update-baseline` to re-accept the current state.

## Configuration errors

Unknown keys are rejected before a single container starts, with a suggestion:

```
ERROR: invalid scan-config.yml:
  scan-config.yml: unknown key 'fail_on_severity' — did you mean 'fail_on'?
  scan-config.yml: unknown key 'strickt' — did you mean 'strict'?
```

A mistyped key used to be ignored in silence, which meant the gate quietly ran
at its default while the config said otherwise. Every problem in the file is
reported at once.
