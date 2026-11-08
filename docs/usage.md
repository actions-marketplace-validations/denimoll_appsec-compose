# Usage

Running scans: install, flags, diff mode, images, offline, pinning, several projects. Back to the [README](../README.md).

## Requirements

On the host running the scan:

| | |
|---|---|
| **Docker** + **Docker Compose v2** | every engine runs as a one-shot container |
| **Python 3.9+** with **PyYAML** | `run.sh` renders `scan-config.yml` into `.env` via `scripts/render-env.py`; `pin.sh` and `preload.sh` use it too |
| **Bash** | `run.sh`, `pin.sh`, `preload.sh` |

```bash
python3 -m pip install pyyaml     # or: apt install python3-yaml / brew install pyyaml
```

Nothing else is installed on the host — the scanners and the collector are all
containers, and no `docker.sock` is mounted into them.

## Install and run locally (no clone)

The main way to use appsec-compose: install the `appsec-compose` command once,
then scan any directory — by hand or as the first step of an AI agent's review.

```bash
curl -fsSL https://raw.githubusercontent.com/denimoll/appsec-compose/main/install.sh | bash
# or, reading it first / pinning a version:
curl -fsSLO https://raw.githubusercontent.com/denimoll/appsec-compose/main/install.sh
bash install.sh --ref v.1.6.0          # or APPSEC_COMPOSE_VERSION=v.1.6.0 bash install.sh
```

[`install.sh`](../install.sh) checks the [requirements](#requirements) and names
every missing one (nothing is installed until they are met), downloads the
latest release (or `--ref` tag / branch / commit; `--from <dir>` installs a
local checkout) into `${XDG_DATA_HOME:-~/.local/share}/appsec-compose/<version>`
and links `~/.local/bin/appsec-compose`. No sudo; re-running is safe. It prints
the uninstall commands at the end (remove the link, the data dir and,
optionally, the cache dir).

```bash
appsec-compose scan                    # the current directory
appsec-compose scan ~/src/api --fail-on critical
appsec-compose scan --image nginx:1.27
appsec-compose preload                 # once, with network, for offline use
appsec-compose version                 # tool + engine versions, install and cache paths
```

`scan` takes every `run.sh` flag. Per-project conventions are picked up
automatically; an explicit flag always wins:

| Convention | Used as | When |
|---|---|---|
| `<target>/.appsec-compose.yml` | `--config` | present (same format as `scan-config.yml`) |
| `<target>/.appsec-baseline.json` | `--baseline` | present, or created with `--update-baseline` |
| `./appsec-reports` (current dir) | `--reports` | always; created with a `.gitignore` of `*` |
| target directory name | `--name` | always, so scans of different projects can overlap |

When the reports directory lies inside the scanned target (e.g. `scan .`), it
is excluded from the scan — see [Scan scope](configuration.md#scan-scope-exclude).

State stays out of the install directory: the vulnerability databases live in
`${XDG_CACHE_HOME:-~/.cache}/appsec-compose` (`ASS_CACHE_DIR`), shared by every
project and kept across upgrades. Only the per-run `.run/` directory is created
inside the install directory — Docker has to bind-mount it, and a path under
`$HOME` is shared with Docker Desktop and Colima by default — and it is removed
when the run exits.

### Machine-readable result (`--json`)

For agents and tools (the MCP server shells out to
`appsec-compose scan <path> … --json`). With `--json` — on `run.sh` or the CLI —
everything human-readable (progress, compose and engine output, the summary)
goes to **stderr**, and **stdout carries exactly one JSON object**, on a single
line, written on exit for **every** exit code, usage errors included:

```json
{"exit_code": 1, "verdict": "fail",
 "reports_dir": "/home/me/src/api/appsec-reports",
 "findings_json": "/home/me/src/api/appsec-reports/findings.json",
 "review_brief": "/home/me/src/api/appsec-reports/review-brief.md",
 "severity_counts": {"info": 0, "low": 2, "medium": 8, "high": 4, "critical": 1},
 "breaching": 5, "baseline": null,
 "metrics": {"time_s": {"total": 41}, "brief": {"approx_tokens": 12300}, "...": "..."}}
```

| Field | Type | Meaning |
|---|---|---|
| `exit_code` | int | the process exit code, `0`–`3` ([exit codes](configuration.md#policy--exit-codes)) |
| `verdict` | string | `pass` (0), `fail` (1), `usage_error` (2), `scan_error` (3) |
| `reports_dir` | string \| null | absolute reports directory (where reports were, or would have been, written); `null` only if the launcher failed before resolving it |
| `findings_json` | string \| null | absolute path to this run's `findings.json`, `null` if the run produced none |
| `review_brief` | string \| null | absolute path to this run's `review-brief.md`, or `null` |
| `severity_counts` | object \| null | `findings.json`'s `severity_counts` (gating view: after suppressions), or `null` |
| `breaching` | int \| null | `findings.json`'s `policy.breaching`: findings at/above `fail_on` |
| `baseline` | object \| null | `findings.json`'s `baseline` (`enabled`, `new`, `known`, `fixed`, `legacy_format`) when a baseline was in force, else `null` |
| `metrics` | object \| null | `findings.json`'s [`metrics`](reports.md#run-metrics): time, reports, how findings were reduced, the brief's size (`brief.approx_tokens`), database age |

A path is only ever this run's: reports left by an earlier run are never
reported (an early usage error yields `null`s). Fields are only added, never
renamed or removed; ignore ones you do not know. Everything else is in
`findings.json` itself ([contract](reports.md#findingsjson-contract)). `--version` is not
a scan and answers in text even with `--json`.

## Usage

```bash
./run.sh /path/to/your/repo
# default fails (exit 1) on high+ findings; override per run:
./run.sh /path/to/your/repo --fail-on critical

# scan a container image instead of a repo (Trivy / Grype / Syft):
./run.sh --image nginx:1.27
# a private image (or set REGISTRY_USER / REGISTRY_PASS in the env):
./run.sh --image ghcr.io/me/app:1.0 --registry-user me --registry-pass "$TOKEN"
# build from a Dockerfile and scan the result:
./run.sh --build ./path/to/context [--dockerfile Dockerfile.prod]

# fail if an enabled scanner produced no readable report:
./run.sh /path/to/your/repo --strict
# refuse to run unless every scanner is pinned by digest:
./run.sh /path/to/your/repo --require-pinned
# scan only what the current branch changed (see "Diff mode"):
./run.sh /path/to/your/repo --diff origin/main
```

Out of the box one engine per category runs (Semgrep, Trivy, Gitleaks, Checkov),
plus zizmor for the CI/CD workflows nothing else reads,
and the gate fails on `high`+ — that is the recommended setup, not a minimum.
The alternative engines and everything below are opt-in for when you want more.

**Collector image.** Releases publish the collector to GHCR as
`ghcr.io/denimoll/appsec-compose-collector:v.<VERSION>`, labelled with a hash of
`orchestrator/`. Before scanning, `run.sh` picks the image deterministically
([`scripts/collector-image.sh`](../scripts/collector-image.sh)): a local build of
this exact `orchestrator/` content if one exists, else the published image if
it is present or pullable (never pulled when `offline: true`) **and** its label
matches this checkout, else a local build tagged
`appsec-compose-collector:local-<hash>`. An installed release therefore skips
the build; a development checkout — unreleased `VERSION`, or edits on top of a
released one — always runs its own code. Set `ASS_COLLECTOR_IMAGE` to force an
image (e.g. a registry mirror).

## Project profile

```bash
appsec-compose profile ~/src/api            # instant: one walk, no containers
appsec-compose profile ~/src/api --write    # create .appsec-compose.yml from it
```

Reports the languages, the frameworks the manifests declare (Django, Flask,
FastAPI, Express, React, Spring, Rails, Laravel, Gin, ASP.NET Core, …), the IaC
and CI files, and each dependency manifest with its lock file — then the few
config changes that fit, each with its reason:

- Python is a main language → `semgrep.rules: [default, auto]`, which adds
  `p/python` — the one pack the [benchmark](../benchmark/RESULTS.md) found
  worth adding; framework packs added nothing measurable, so none is proposed.
- dependencies without a lock file, or `requirements.txt` with ranges →
  enable OSV-Scanner, which resolves ranges (it sends dependency names and
  versions to osv.dev; committing a lock file is the better fix).
- no GitHub workflows, actions or dependabot config → zizmor off.
- generated or vendored directories the default `exclude:` misses
  (`.next`, `coverage`, `third_party`, …) → named for you to review.

Then, under **Run once**, scans worth running once rather than settings to
keep: a git repository with history gets `--secrets-history` (scans search the
current files only, and a deleted credential still works until it is
rotated); a shallow clone is told that its history is mostly not there.

`--write` creates `.appsec-compose.yml` with only those changes and their
reasons as comments; an existing file is never overwritten. `--json` gives the
same as one object. The scan uses the same detection: it picks Checkov's
frameworks, and the review brief names the languages and frameworks.

## Diff mode (scan only what a change touched)

A developer or an AI agent iterating on a branch wants the verdict on *their
change*, quickly — not a full scan on every edit:

```bash
./run.sh /path/to/repo --diff origin/main
```

The changed set is every file that differs between `merge-base(origin/main,
HEAD)` and the **working tree** — committed, uncommitted and untracked (but not
git-ignored) files alike, since an agent's edits are usually uncommitted.
Deleted files are not scanned; `exclude:` still applies. It is computed on the
host with git, so the target must be a git repository and the ref must exist
locally (fetch it first); otherwise the run exits `2`.

Each engine gets only its part of the change:

| | in diff mode |
|---|---|
| SAST (Semgrep) | the changed files only |
| Secrets (Gitleaks, TruffleHog) | the changed files, plus Gitleaks walks the commits `merge-base..HEAD` (`gitleaks-history.sarif`), so a secret committed and removed again on the branch is still reported |
| IaC (Checkov, Trivy config, Hadolint) | the changed IaC files, plus the Terraform files beside a changed one (a module is evaluated as a whole); not run if no IaC file changed |
| SCA (Trivy, Grype, OSV, Syft) | only if a dependency manifest or lock file changed — then over the whole repo; otherwise not run, and the run says so |

Findings are reported and gated for the changed files only. **The gate is per
changed file, not per changed line**: a change is often dangerous through a line
it did not touch — new input reaching an existing sink, a removed check above
an unchanged call — and Semgrep reports the sink, so a line-level gate would pass
exactly those. Instead every finding carries `on_changed_line` (marked `Δ` in
the summaries, `CHANGED LINE` in the brief) so a reviewer can start with the
lines the change wrote. Combine with [baseline mode](configuration.md#baseline-gate-on-new-findings)
to stop pre-existing findings in a touched file from gating.

The scope is recorded in `findings.json` (`provenance.scope`: base, merge-base,
files, skipped engines), printed on the console and shown in both summaries;
`review-brief.md` lists as blind spots that unchanged code was not scanned and
that the change's effects on unchanged code are not covered.

- `strict` does not count a skipped engine's report as missing, and the [SCA
  coverage check](engines.md#sca-coverage-check) is not run when SCA was skipped.
- In baseline mode `fixed` is not reported (findings outside the change were
  not looked for), and `--update-baseline` refuses `--diff`: a snapshot of a
  partial scan would forget everything outside it.
- `--diff` with `--image`/`--build` is a usage error.
- Branch commits are only walked when the target is the repository root (not a
  subdirectory, not a linked worktree); otherwise the run says so.

## Scanning a container image

`./run.sh --image <ref>` scans a container image instead of a repo. Only the
image-capable tools run — **Trivy** and **Grype** (OS + language package
vulnerabilities) and **Syft** (SBOM); source-only scanners (Semgrep, Checkov,
Gitleaks, Hadolint, zizmor) are skipped. Dedup, suppressions, baseline, SBOM formats and
the policy gate all work the same way.

- **Private registries** — pass `--registry-user/--registry-pass` (or set
  `REGISTRY_USER`/`REGISTRY_PASS`). The scanners pull the image themselves using
  a generated docker auth config; no Docker socket is mounted.
- **Build & scan** — `./run.sh --build <context> [--dockerfile <path>]` builds
  the image with the host Docker, exports it to a tar (`docker save`) and scans
  that archive — so locally-built images are scanned without a registry or a
  Docker socket in the scanner containers.

## Offline / air-gapped

Run once **with** network to snapshot DBs and rulesets into `./cache/` (the
CLI: `~/.cache/appsec-compose`; any location via `ASS_CACHE_DIR`):

```bash
./preload.sh           # Semgrep ruleset, Trivy + Grype DBs, the collector image
appsec-compose preload # the same, for an installed copy
```

Then set `offline: true` in `scan-config.yml`. Scans now run with no network
access (Semgrep uses the cached ruleset; Trivy uses the cached DB with
`--skip-db-update --offline-scan`). Gitleaks, Checkov and zizmor bundle their
rules in the image, so they need no preload; zizmor runs with `--offline`.

> JVM note: Trivy's Java DB downloads on demand. To scan JVM projects offline,
> run one JVM scan online first to populate `cache/trivy`.

## Reproducible / pinned images

By default scanners run from their pinned **tags** (versions in
`scan-config.yml`). For tamper-evident, fully reproducible runs, pin them to
immutable digests:

```bash
./pin.sh        # resolves each repo:tag -> repo@sha256:... into image-digests.lock
```

Commit `image-digests.lock`; `render-env.py` then runs every scanner by digest.
Re-run `./pin.sh` after bumping a version (a bumped version with no matching
lock entry safely falls back to its tag). Delete the lock to go back to tags.

To pin a **single** tool by hand, put a digest in its `version` field instead of
a tag — `version: "sha256:abc..."` resolves to `repo@sha256:abc...`.

A lock that no longer covers every enabled scanner (someone bumped a `version`
and forgot to re-pin) prints a warning. Set `require_pinned: true` — or pass
`--require-pinned` — to make that an error instead, so a supply-chain-sensitive
pipeline can never silently fall back to a mutable tag.

## Scanning several projects from one clone

State can live outside the tool directory, so one checkout can serve many
projects:

```bash
./run.sh /src/api   --name api   --config profiles/api.yml \
                    --reports /var/appsec/api   --baseline /var/appsec/api/baseline.json
./run.sh /src/front --name front --config profiles/front.yml \
                    --reports /var/appsec/front --baseline /var/appsec/front/baseline.json
```

Or let appsec-compose keep the list: [projects](projects.md) gives each one a name,
a profile, a run history, batch runs and schedules.

`--name` namespaces the containers (`COMPOSE_PROJECT_NAME`), and `cache/` stays
shared on purpose — the vulnerability databases are the same for every project.

Runs can **overlap**: each one renders its `.env` and `excludes/` (plus a built
image tar or registry credentials) into a private directory under `.run/`, which
is removed when the run exits. Give concurrent runs distinct `--name` and
`--reports` — the containers and the report directory are what they would
otherwise share.
