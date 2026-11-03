# appsec-compose

One-command, OSS AppSec static scan for any code repository. Runs **SAST, SCA,
secret scanning and IaC** checks via proven open-source engines, then collects
the results into native reports plus a human-readable summary and a CycloneDX
SBOM — ready to read yourself or upload to an ASPM/ASOC (DefectDojo,
DependencyTrack, …).

It is a **thin, stateless orchestrator**: no database, no web UI, no workers.
Each scanner runs as a one-shot Docker Compose service; a small Python collector
aggregates the reports and produces a CI-meaningful exit code.

What's planned (multi-project profiles, scheduling, a minimal UI, ASPM push) is
tracked in [ROADMAP.md](ROADMAP.md).

## Engines

| Category | Tool | Default | Output |
|---|---|---|---|
| SAST | [Semgrep](https://semgrep.dev) | on | `semgrep.sarif` |
| SCA | [Trivy](https://trivy.dev) | on | `trivy-fs.sarif` |
| SCA (alt) | [Grype](https://github.com/anchore/grype) | off | `grype.sarif` |
| SCA (alt) | [OSV-Scanner](https://github.com/google/osv-scanner) | off | `osv.sarif` (needs network) |
| IaC | [Trivy config](https://trivy.dev) | on | `trivy-config.sarif` |
| IaC | [Checkov](https://www.checkov.io) | on | `checkov.sarif` |
| IaC (alt) | [Hadolint](https://github.com/hadolint/hadolint) | off | `hadolint.sarif` (Dockerfiles) |
| IaC — CI/CD | [zizmor](https://docs.zizmor.sh) | on | `zizmor.sarif` (GitHub Actions workflows) |
| Secrets | [Gitleaks](https://github.com/gitleaks/gitleaks) | on | `gitleaks.sarif` |
| Secrets (alt) | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | off | `trufflehog.json` + `trufflehog.sarif`\* |
| SBOM | [Trivy](https://trivy.dev) | on | `sbom.trivy.cdx.json` |
| SBOM (alt) | [Syft](https://github.com/anchore/syft) | off | `sbom.syft.cdx.json` |

Tools covering the same category are **complementary** — enable one or several;
every enabled tool emits its own native report and all are aggregated.

\* TruffleHog has no native SARIF, so the collector keeps its raw JSON **and**
generates a SARIF from it, so SARIF-only ASPM tools can ingest it too. Our
`findings.json` normalization is internal (for the summary); the per-tool native
reports are what you upload to an ASPM.

TruffleHog can check whether a credential is live by calling its issuer's API.
That sends the secret found in your repository to a third party, so it is off
unless you set `scanners.trufflehog.verify: true`; without it, findings are
reported unverified (high), and nothing leaves the machine.

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
bash install.sh --ref v.1.2.0          # or APPSEC_COMPOSE_VERSION=v.1.2.0 bash install.sh
```

[`install.sh`](install.sh) checks the [requirements](#requirements) and names
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
is excluded from the scan — see [Scan scope](#scan-scope-exclude).

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
 "breaching": 5, "baseline": null}
```

| Field | Type | Meaning |
|---|---|---|
| `exit_code` | int | the process exit code, `0`–`3` ([exit codes](#policy--exit-codes)) |
| `verdict` | string | `pass` (0), `fail` (1), `usage_error` (2), `scan_error` (3) |
| `reports_dir` | string \| null | absolute reports directory (where reports were, or would have been, written); `null` only if the launcher failed before resolving it |
| `findings_json` | string \| null | absolute path to this run's `findings.json`, `null` if the run produced none |
| `review_brief` | string \| null | absolute path to this run's `review-brief.md`, or `null` |
| `severity_counts` | object \| null | `findings.json`'s `severity_counts` (gating view: after suppressions), or `null` |
| `breaching` | int \| null | `findings.json`'s `policy.breaching`: findings at/above `fail_on` |
| `baseline` | object \| null | `findings.json`'s `baseline` (`enabled`, `new`, `known`, `fixed`, `legacy_format`) when a baseline was in force, else `null` |

A path is only ever this run's: reports left by an earlier run are never
reported (an early usage error yields `null`s). Fields are only added, never
renamed or removed; ignore ones you do not know. Everything else is in
`findings.json` itself ([contract](#findingsjson-contract)). `--version` is not
a scan and answers in text even with `--json`.

## Use in your project's CI

No need to vendor or clone anything into your repository.

**GitHub Actions** — the repo is a composite action:

```yaml
permissions:
  contents: read
  security-events: write          # for the SARIF upload to code scanning
jobs:
  appsec:
    runs-on: ubuntu-latest        # needs Docker on the runner
    steps:
      - uses: actions/checkout@v5
      - uses: denimoll/appsec-compose@v.1.2.0
        with:
          config: .github/scan-config.yml   # optional; default = shipped config
          # fail-on: critical                # override the config's fail_on
          # strict: true                     # a missing report fails the run
          # baseline: appsec-baseline.json   # with `baseline: true` in the config
          # upload-sarif: false              # skip code scanning
```

It caches the vulnerability DBs, uploads every tool's SARIF to code scanning
(one category per tool), keeps the reports as the `appsec-reports` artifact,
writes the verdict to the job summary and then fails the step on a policy
breach. Outputs: `exit-code`, `findings` (path to `findings.json`),
`reports-dir`. Inputs and details: [`action.yml`](action.yml).

**GitLab CI** — include the template; it fetches the tool at a pinned ref and
scans `$CI_PROJECT_DIR`:

```yaml
include:
  - remote: https://raw.githubusercontent.com/denimoll/appsec-compose/v.1.2.0/templates/gitlab/appsec-compose.yml

appsec-compose:
  variables:
    APPSEC_COMPOSE_REF: v.1.2.0                     # tag or commit SHA
    APPSEC_COMPOSE_CONFIG: .gitlab/scan-config.yml  # optional
    APPSEC_COMPOSE_ARGS: "--fail-on critical"       # optional run.sh flags
```

Reports land in the `appsec-reports/` artifact; the job's exit status is the
verdict. The runner needs the host Docker socket, not dind — see the header of
[`templates/gitlab/appsec-compose.yml`](templates/gitlab/appsec-compose.yml).

**Anywhere else** — clone the tool once and call `run.sh` from your project;
relative paths are resolved against your current directory:

```bash
git clone --depth 1 --branch v.1.2.0 https://github.com/denimoll/appsec-compose ~/appsec-compose
cd /path/to/your/repo && ~/appsec-compose/run.sh . --config scan-config.yml --reports /tmp/appsec-reports
```

A `--reports` directory inside the scanned tree is excluded from the scan
automatically, so the scanners never read their own output.

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
([`scripts/collector-image.sh`](scripts/collector-image.sh)): a local build of
this exact `orchestrator/` content if one exists, else the published image if
it is present or pullable (never pulled when `offline: true`) **and** its label
matches this checkout, else a local build tagged
`appsec-compose-collector:local-<hash>`. An installed release therefore skips
the build; a development checkout — unreleased `VERSION`, or edits on top of a
released one — always runs its own code. Set `ASS_COLLECTOR_IMAGE` to force an
image (e.g. a registry mirror).

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
lines the change wrote. Combine with [baseline mode](#baseline-gate-on-new-findings)
to stop pre-existing findings in a touched file from gating.

The scope is recorded in `findings.json` (`provenance.scope`: base, merge-base,
files, skipped engines), printed on the console and shown in both summaries;
`review-brief.md` lists as blind spots that unchanged code was not scanned and
that the change's effects on unchanged code are not covered.

- `strict` does not count a skipped engine's report as missing, and the [SCA
  coverage check](#sca-coverage-check) is not run when SCA was skipped.
- In baseline mode `fixed` is not reported (findings outside the change were
  not looked for), and `--update-baseline` refuses `--diff`: a snapshot of a
  partial scan would forget everything outside it.
- `--diff` with `--image`/`--build` is a usage error.
- Branch commits are only walked when the target is the repository root (not a
  subdirectory, not a linked worktree); otherwise the run says so.

## Configuration — one file

Everything lives in [`scan-config.yml`](scan-config.yml): which checks run, the
pinned tool **versions** (bump here to upgrade), the policy gate and the offline
switch. `run.sh` renders it into `.env` (which Compose loads) and runs only the
enabled scanners.

```yaml
scanners:
  semgrep:  { enabled: true, version: "1.174.0" }    # SAST
  trivy:    { enabled: true, version: "0.74.0" }     # SCA + IaC + SBOM
  gitleaks: { enabled: true, version: "v8.30.1" }    # secrets
  checkov:  { enabled: true, version: "3.3.13" }     # IaC

sbom: true                 # SBOM via Trivy
sbom_formats: [cyclonedx]  # any of: cyclonedx, spdx
fail_on: high              # critical|high|medium|low|none (none = report-only)
unknown_severity: medium
strict: false              # a scanner with no readable report fails the run
offline: false             # use ./preload.sh cache, no network during scan
```

Disable a check by setting `enabled: false` — that scanner won't run and the
collector won't expect its report. Upgrade a tool by changing its `version`.
Set `secrets_history: true` to have Gitleaks scan the full **git history**
(needs a `.git` in the repo), not just the working tree. In CI that is usually
more than you need — `secrets_history_range: "origin/main..HEAD"` limits it to
the branch's own commits, which is orders of magnitude faster and still catches
a secret that was committed and then removed within the branch.

## Custom & auto Semgrep rules

By default Semgrep runs the curated `p/default` pack. Point it at your own rules
or let it pick rules for the repo's stack via `scanners.semgrep.rules`:

```yaml
scanners:
  semgrep:
    enabled: true
    version: "1.174.0"
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

## CI/CD workflows (zizmor)

A workflow runs with the repository's secrets and a token that can push, so it
is attack surface: `${{ github.event.pull_request.title }}` interpolated into a
`run:` script, `pull_request_target` checking out a fork's code, write-all
tokens, a third-party action pinned to a tag its owner can move.
[zizmor](https://docs.zizmor.sh) audits `.github/workflows/*`, composite
`action.yml` files and `dependabot.yml`; its findings land in the `iac`
category (`rule_id` = `zizmor/<audit>`, e.g. `zizmor/template-injection`), with
zizmor's own severity. When zizmor is unsure it says so, and the message ends in
`(confidence: low)` — shown to the reviewer, never folded into the severity.

On by default, because no other engine covers it: on DVWA's workflows Checkov's
GitHub Actions checks find only the missing `permissions:` blocks, while zizmor
also finds the shell injection via `github.ref`, a `toJSON(secrets)` dump and
the unpinned third-party actions.

**Pinning policy.** Since 1.20 zizmor wants every action pinned to a commit SHA
and rates each tag reference high, so `actions/checkout@v5` alone would fail the
default gate in practically every repository. Unless the repo brings its own
`zizmor.yml` (or `.github/zizmor.yml`, which then wins entirely), the scan uses
zizmor's pre-1.20 policy: GitHub's own `actions/*`, `github/*` and
`dependabot/*` may be tag-pinned, everything else must be hash-pinned. To demand
SHAs everywhere, commit a `zizmor.yml` with `"*": hash-pin`. Inline
`# zizmor: ignore[audit]` comments are honoured as well.

**Online audits.** Some audits ask the GitHub API (impostor commits,
known-vulnerable or archived actions, ref confusion). They run only when a token
is exported on the host — never put one in `scan-config.yml`:

```bash
ZIZMOR_GITHUB_TOKEN="$(gh auth token)" ./run.sh .
```

Without it (and always with `offline: true`) zizmor runs offline, and the review
brief lists the skipped audits as a blind spot.

The reports directory, when it lies inside the target, is appended to the list
for that run (even to `exclude: []`), so no engine reads earlier reports — which
quote the code they flag — as findings. Like any entry it is matched by its path
relative to the target (`appsec-reports` matches a directory of that name at
any depth). `--reports` equal to the target itself is a usage error.

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

## Failing loudly (`strict`)

Scanners always exit `0`, so a crashed engine would otherwise look like a clean
result. With `strict: true` (or `--strict`) the run fails with exit `3` — rather
than counting as "0 findings" — when either:

- a scanner that was expected to report produced nothing readable, or
- the [SCA coverage check](#sca-coverage-check) found dependency manifests that
  no engine resolved.

Off by default, since a flaky engine then breaks the build rather than degrading
the scan.

## Exploitability (CVE-PaaS)

A CVSS score says how bad a vulnerability would be. It does not say whether
anyone is exploiting it — which is why a CVSS-only gate fires on dozens of
theoretical "high" findings and teams learn to ignore the report.

Point the collector at a [CVE-PaaS](https://github.com/denimoll/CVE-PaaS)
instance and every SCA finding carrying a CVE gains the other half of the
picture: CISA KEV listing, EPSS score, public PoC, Nuclei template.

> Use **CVE-PaaS 1.4.0 or newer**. Before that a KEV listing never reached the
> verdict, so a vulnerability actively exploited in the wild but without a
> public PoC came back under-prioritised. Older releases still work — the
> collector reads whichever signals they provide — just less accurately.

```yaml
enrich:
  cve_paas:
    enabled: true
    url: "http://host.docker.internal:8000"
    api_key_env: CVE_PAAS_API_KEY   # env var name; the key is never in this file
    mode: annotate                  # or: reprioritize
    fail_on_exploitable: false
```

- **`annotate`** (default) leaves severity exactly as the scanner reported it
  and adds `priority`, `epss`, `kev`, `poc` to each finding, the console line,
  both summaries and `findings.json`. Nothing about your existing gate changes.
- **`reprioritize`** lets the CVE-PaaS priority replace `severity`, keeping the
  scanner's own in `scanner_severity`. Counts, baseline fingerprints and the
  gate all follow the new value, so expect existing projects to shift.

`fail_on_exploitable: true` adds a gate that is independent of severity: fail on
anything with a KEV listing, a public PoC or a Nuclei template, whatever its
CVSS. Combined with a relaxed severity gate this is the useful shape:

```yaml
fail_on:
  sca: none          # stop failing on theoretical CVSS
enrich:
  cve_paas:
    fail_on_exploitable: true    # fail on what is actually being exploited
```

Lookups are batched 50 at a time and CVE-PaaS caches them, so repeat runs are
cheap. If the service is unreachable the scan continues on the scanners' own
severities and says so; under `strict: true` that becomes a failure instead.
The check is skipped in `offline` mode.

> Only SCA findings that carry a CVE id are affected — SAST, secrets and IaC
> keep the scanners' severities, and a finding known only by a GHSA with no CVE
> alias cannot be looked up.

## Malicious packages

A hijacked or typosquatted release is not a vulnerability waiting for an
exploit — it is the exploit, and it runs at install time. The advisory
databases still ship it as one more "vulnerability", scored like one: Trivy
rates the September 2025 `debug@4.4.2` takeover **HIGH**. So the collector
recognises a malicious-package advisory by what it is — an OpenSSF `MAL-` id,
CWE-506 (Embedded Malicious Code), or GitHub's malware titles ("Malware in X",
"Malicious code in X", "X contains malware…") — and then:

- ranks it **critical** whatever its score (the engine's own level is kept in
  `scanner_severity`), and CVE-PaaS `reprioritize` never lowers it;
- sets `malicious: true` in `findings.json`, prefixes the message with
  `MALICIOUS PACKAGE`, and labels it in both summaries, the review brief and the
  console.

How much each SCA engine knows, measured on 23 hijacked npm releases (the 2025
chalk/debug takeover, Shai-Hulud's `@ctrl/tinycolor`, `nx` 21.5.0, and the
older `flatmap-stream`, `eslint-scope`, `ua-parser-js`), from the lockfile alone:

| Engine | Detected | Source |
|---|---|---|
| Trivy (default) | 11 / 23 | GitHub-*reviewed* malware advisories only |
| Grype (offline DB) | 22 / 23 | all GitHub malware advisories |
| OSV-Scanner (network) | 23 / 23 | the OpenSSF `MAL-` feed |

Out of the box Trivy catches the reviewed ones (`flatmap-stream`, the CVE-
numbered half of the 2025 takeover) and they are handled as above. For real
coverage enable **`osv`** where the scan may reach the network, or **`grype`**
offline (its database is ~3 GB on disk, so it stays opt-in):

```yaml
scanners:
  osv:   { enabled: true }   # broadest: OpenSSF malicious-packages, needs network
  grype: { enabled: true }   # offline alternative: GitHub malware advisories
```

Only a lockfile or exact pin can be matched: a range in `requirements.txt` says
nothing about which release was installed.

## Dependency licenses (opt-in)

```yaml
licenses:
  deny: [AGPL-*, GPL-3.0, SSPL-1.0]   # SPDX ids or globs, case-insensitive
  warn: [LGPL-*]                      # reported at severity info, never gates
  severity: high                      # severity of a denied license (default)
```

With a `deny` or `warn` list, Trivy adds a license-only pass over the same
target (no vulnerability DB lookup; ~2 s on the test repos), written to
`native/trivy-license.json`. Each denied dependency becomes an SCA finding with
`rule_id` `LICENSE:<license>` and its `package`, so `fail_on`, `ignore:`
(`rule: "LICENSE:GPL-*"`) and the baseline treat it like any vulnerability.
The decision is this policy's alone: Trivy's own forbidden/restricted
classification is ignored.

- A plain id covers its spellings: `GPL-3.0` also denies `GPL-3.0-only` and
  `GPL-3.0-or-later` (which Trivy normalises `GPL-3.0` and `GPL-3.0+` to); a
  glob (`GPL-*`) covers a family. `LGPL-3.0` is not matched by `GPL-3.0`.
- A package offered under several licenses (`MIT OR GPL-3.0-only`, or
  composer's license list) is denied only when every alternative is; `MIT AND
  GPL-3.0-only` is denied as soon as one part is. `WITH` exceptions stay part
  of the term: `GPL-2.0-only` does not deny `GPL-2.0-only WITH
  Classpath-exception-2.0`, `GPL-2.0*` does.
- Only application dependencies are judged; in image mode, OS packages are not.

**Where license data exists.** Measured with Trivy 0.74: npm lockfiles (v2+),
`composer.lock` and installed packages (`node_modules`, `site-packages`) carry
licenses; Maven poms only online (Trivy reads the remote pom). Python
`requirements.txt`, poetry/uv lockfiles, `go.mod` and `Cargo.lock` record none,
so those dependencies cannot be judged. They are counted instead of silently
passing — `licenses.unlicensed` in `findings.json`, the console line, and a
blind spot in the review brief — and for those ecosystems this check is no
substitute for a license audit of the installed tree.

## SCA coverage check

The most dangerous result a dependency scanner can produce is *nothing*: an
engine that parsed no manifests looks exactly like a project with no vulnerable
dependencies, and the policy gate cannot tell them apart.

The collector checks for that directly — it compares the manifests the repo
declares against what the engines actually resolved into the SBOM, and says so
when the answer is zero:

```
  ! SCA coverage: requirements.txt specifies version ranges, not exact versions
    — Trivy and Syft resolve a package only from an exact version, so nothing
    was scanned.
    -> Pin the versions (`pkg==1.2.3`), commit a lock file, or enable the `osv`
       scanner, which resolves ranges.
```

The advice names the cause and only an engine that actually solves it — OSV
resolves version ranges, Grype shares Syft's exact-version requirement, so it is
never offered as the answer to that particular gap. An engine you already have
enabled is never suggested. The warning is recorded in `findings.json` under
`coverage`, printed to the console and shown in both summaries. It does **not**
fail the build on its own; with `strict: true` it does.

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

## Output (`./reports/`)

```
reports/
├── native/                 # raw per-tool reports (SARIF) — feed these to ASPM
│   ├── semgrep.sarif
│   ├── trivy-fs.sarif
│   ├── trivy-config.sarif
│   ├── gitleaks.sarif
│   ├── gitleaks-history.sarif  # diff mode: the branch's commits
│   ├── checkov.sarif
│   ├── grype.sarif         # + grype.json (carries CVE/GHSA aliases for dedup)
│   ├── zizmor.sarif        # GitHub Actions workflows / composite actions
│   └── trufflehog.json     # + generated trufflehog.sarif
├── findings.json           # consolidated findings + counts (versioned contract)
├── review-brief.md         # hand-off for a human or AI-agent security review
├── sbom.trivy.cdx.json     # CycloneDX SBOM (Trivy; .spdx.json if enabled)
├── sbom.syft.cdx.json      # Syft SBOM (CycloneDX + SPDX, if enabled)
├── summary.md              # human summary
└── summary.html            # human summary (styled)
```

`summary.html` shows severity cards/bars, per-tool breakdown and a findings
table with **category filters**, expandable **details** (description + advisory
link per finding), and — in baseline mode — a **NEW** flag on findings added
since the accepted snapshot. It is fully self-contained (no external assets).

### `findings.json` contract

`findings.json` is the machine-readable interface for ASPM imports, CI scripts
and AI agents, and it is versioned: `schema_version` (`1.1`) refers to
[`schemas/findings.schema.json`](schemas/findings.schema.json). The major only
changes when a field is removed, renamed or changes meaning; additions bump the
minor, so ignore fields you do not know.

Each finding carries a `fingerprint` (stable across runs, see
[Baseline](#baseline-gate-on-new-findings)), its full location (`line`,
`end_line`, `column`, `end_column`), the `cwe` ids its rule declares, every
engine that reported it (`tools`), whether the severity was stated by an engine
or derived from CVSS (`severity_stated`), and for SCA the `fixed_version` the
engine knows of.

### `review-brief.md` — hand-off to a reviewer

The scan is usually the start of a review, not the end — more and more often
the reviewer is an AI agent. `review-brief.md` is written for that reader,
compact enough to go straight into its context:

- **Scope** — engines and their exact images, DB dates, the languages present,
  what was excluded, the gate in force.
- **Blind spots** — what this run did not or could not check: disabled
  categories, unresolved manifests, git history, cross-file data flow (Semgrep
  CE is intra-file), SCA reachability, and the logic no pattern matcher models
  (authorization, business rules). Silence from the scanners there is not
  evidence, and the reviewer is told so.
- **Findings** — gating first, then new, then by severity, each with its
  fingerprint and the flagged code in context (secrets masked; no secret value
  reaches any of the collector's reports). The first 150 are detailed, the rest
  counted.
- **Recording a verdict** — a false positive or accepted risk goes into
  `ignore:` by fingerprint, with a reason and an expiry.

### Driving it from an AI agent (MCP)

[`appsec_mcp/`](appsec_mcp/README.md) is an MCP server (stdio) over the same
CLI and `findings.json`: an agent calls `scan`, pages through `findings`, reads
one `finding` with its code (secrets masked), and records a verdict with
`suppress` — an `ignore:` entry with a reason and an expiry in the project's
`.appsec-compose.yml`. Install and register it:

```bash
appsec-compose mcp --setup        # once: a private venv with the pinned MCP SDK
claude mcp add --scope user appsec-compose -- appsec-compose mcp
```

Any other MCP client takes the same command (`"command": "appsec-compose",
"args": ["mcp"]`). Details and the recommended agent workflow:
[appsec_mcp/README.md](appsec_mcp/README.md).

## Provenance

Every report records what produced it — the appsec-compose version, each
engine's resolved image ref (the immutable digest when pinned), the
vulnerability-database dates, and whether the scan ran offline. A clean result
from a three-week-old database is not the same as a clean result, and an
artifact heading into an ASPM should say which tool version produced it.

It lands in `findings.json` under `provenance` and at the foot of both
summaries. To see the resolved engines without running a scan:

```bash
./run.sh --version
```

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

## CI/CD

For other repositories, see [Use in your project's CI](#use-in-your-projects-ci):

- **GitHub Action** — [`action.yml`](action.yml) (`uses: denimoll/appsec-compose@v.1.2.0`)
  runs the scan, uploads every SARIF to **code scanning**, keeps the reports as
  an artifact, caches the vuln DBs, and fails the step on a policy breach. This
  repo's own [`.github/workflows/appsec-scan.yml`](.github/workflows/appsec-scan.yml)
  dogfoods it with `uses: ./` after the unit and smoke tests.
- **GitLab CI** — [`templates/gitlab/appsec-compose.yml`](templates/gitlab/appsec-compose.yml)
  fetches the tool at `APPSEC_COMPOSE_REF`, scans the project, exposes the
  CycloneDX SBOM to GitLab Dependency Scanning, and caches DBs. (Needs a runner
  with the host Docker socket — see the file header.) This repo's
  [`.gitlab-ci.yml`](.gitlab-ci.yml) includes the same template.
- **Publish the collector image** — [`.github/workflows/publish-collector.yml`](.github/workflows/publish-collector.yml)
  pushes the collector to GHCR on release, so CI can skip the local build.

## Severity

A finding keeps the severity **its own tool assigned**. Where a report states
one (Trivy tags every rule with its verdict), that wins; only when a tool states
none — OSV-Scanner levels every result the same, so its CVSS score is the only
gradation available — is severity derived from CVSS, and the coarse SARIF level
is the last resort.

That order matters, because a CVSS score and an advisory's own rating routinely
disagree. `CVE-2026-34520` in aiohttp is rated **LOW** by GitHub, who own the
advisory, while the CVSS v3 vector it carries scores **9.1**. Trivy follows the
advisory (`SeveritySource: ghsa`) and reports LOW; reading the number instead
made it the single "critical" line of a report, contradicting the native output
shipped beside it.

The same rule holds across tools. When several engines report one
vulnerability, the merged severity is the highest **among those that assigned
one** — a score-derived level never outranks a verdict. On the example above
Trivy and Grype both say LOW while OSV-Scanner, which states no severity of its
own, derives critical from that 9.1; taking the loudest number would put the
phantom critical straight back.

Severities a tool could not determine are ranked by `unknown_severity` rather
than quietly treated as informational — Trivy emits those with a CVSS of `0.0`,
which is not the same claim as "harmless". Secrets keep their floor regardless:
a credential nobody scored is still a credential.

## De-duplication

When several tools cover the same category they report the same issues. With
`dedup: true` (default) the collector merges duplicates in `findings.json` and
the summary (the raw native reports are left untouched for ASPM import):

- **secrets** — same `(file, line)` is one secret, regardless of tool.
- **SCA** — same `package@version` + file, clustered by overlapping vuln IDs.
  Trivy's `CVE-2018-1000656` and Grype's `GHSA-562c-5r94-xh97` merge because
  Grype's `relatedVulnerabilities` lists that CVE — so CVE/GHSA aliases collapse.
- **IaC** — engines use different ids for the same policy (a Dockerfile with no
  `USER` is Trivy's `DS-0002`, Checkov's `CKV_DOCKER_3` and Hadolint's `DL3002`),
  so findings whose rule maps to a known equivalence class merge per file.
  Unmapped rules keep their own `(rule, file, line)` identity.
- **SAST** — same rule at the same `(file, line)`.

A merged finding keeps the highest severity among the tools that assigned one
(see [Severity](#severity)), records **every tool** that reported it, and lists
the equivalent IDs as aliases. `findings.json` reports
`raw_findings`, `unique_findings` and `duplicates_removed`. Per-tool counts
still reflect each tool's true raw yield.

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

## Scanning several projects from one clone

State can live outside the tool directory, so one checkout can serve many
projects:

```bash
./run.sh /src/api   --name api   --config profiles/api.yml \
                    --reports /var/appsec/api   --baseline /var/appsec/api/baseline.json
./run.sh /src/front --name front --config profiles/front.yml \
                    --reports /var/appsec/front --baseline /var/appsec/front/baseline.json
```

`--name` namespaces the containers (`COMPOSE_PROJECT_NAME`), and `cache/` stays
shared on purpose — the vulnerability databases are the same for every project.

Runs can **overlap**: each one renders its `.env` and `excludes/` (plus a built
image tar or registry credentials) into a private directory under `.run/`, which
is removed when the run exits. Give concurrent runs distinct `--name` and
`--reports` — the containers and the report directory are what they would
otherwise share.

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

## How it works

1. `run.sh` renders `scan-config.yml` → `.env` and bind-mounts the target repo
   **read-only** at `/code`.
2. The enabled scanner services run once (in parallel), each writing a native
   SARIF report into the shared `reports/` volume and exiting `0`.
3. `collector` normalizes every SARIF into one model, writes `findings.json` +
   summaries, and exits with the policy code.

No `docker.sock`, no docker-in-docker.

## Layout

```
bin/appsec-compose      # installed CLI: project conventions over run.sh
install.sh              # no-clone installer (~/.local/share + ~/.local/bin)
docker-compose.yml      # scanners + collector (versions/flags from .env)
run.sh                  # entrypoint: render config, run scanners + collector
scripts/collector-image.sh  # prebuilt-vs-local collector image choice
scripts/scan-result.py  # the --json result object
preload.sh              # offline cache populator
scan-config.yml         # the single file you edit
scripts/render-env.py   # scan-config.yml -> .env
scripts/diff-scope.py   # --diff: the changed set, narrowed per engine
orchestrator/           # Python collector (config, normalize, policy, summary)
appsec_mcp/             # MCP server for AI agents (scan, triage, suppress)
tests/                  # collector unit tests (pytest)
benchmark/              # precision/recall harness + RESULTS.md
```

## Tests

The collector decides what counts as a finding, what merges, what is suppressed
and whether the build fails — so it is unit-tested:

```bash
python3 -m pip install -r tests/requirements.txt
python3 -m pytest tests/ -q
```

Unit tests cannot see the compose wiring, though, and every engine is invoked
through a shell command line that upstream can change underneath us. Gitleaks,
for instance, kept `detect` as a deprecated alias that exits `0` and writes a
valid but **empty** report — so the scan would have gone on reporting zero
secrets, and even `strict` would have been satisfied. The smoke test runs the
whole pipeline over a deliberately vulnerable fixture and asserts that each
engine found the thing planted for it:

```bash
./scripts/smoke-test.sh      # needs Docker; ~2 min
```

Both run on every push in [`appsec-scan.yml`](.github/workflows/appsec-scan.yml),
and the scan job depends on them.

## Benchmark — what it catches and what it misses

A first step of a review is only useful if the reviewer knows what it already
covered. [`benchmark/RESULTS.md`](benchmark/RESULTS.md) measures the default
scan on corpora with known answers — OWASP Benchmark for Java (SAST), a
synthetic labelled secrets set, and pinned vulnerable packages checked against
an OSV snapshot (SCA) — with per-category recall and false-positive rates, the
exact engine digests and DB dates, and a section on where the tool is weak.
IaC has no number yet: no labelled corpus maps onto these engines.

```bash
python3 benchmark/bench.py        # re-run everything (Docker + network; ~10 min)
```

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
