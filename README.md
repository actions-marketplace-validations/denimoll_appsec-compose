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

## Use in your project

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
      - uses: denimoll/appsec-compose@v1
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
  - remote: https://raw.githubusercontent.com/denimoll/appsec-compose/<tag>/templates/gitlab/appsec-compose.yml

appsec-compose:
  variables:
    APPSEC_COMPOSE_REF: <tag>                     # tag or commit SHA
    APPSEC_COMPOSE_CONFIG: .gitlab/scan-config.yml  # optional
    APPSEC_COMPOSE_ARGS: "--fail-on critical"       # optional run.sh flags
```

Reports land in the `appsec-reports/` artifact; the job's exit status is the
verdict. The runner needs the host Docker socket, not dind — see the header of
[`templates/gitlab/appsec-compose.yml`](templates/gitlab/appsec-compose.yml).

**Anywhere else** — clone the tool once and call `run.sh` from your project;
relative paths are resolved against your current directory:

```bash
git clone --depth 1 --branch <tag> https://github.com/denimoll/appsec-compose ~/appsec-compose
cd /path/to/your/repo && ~/appsec-compose/run.sh . --config scan-config.yml --reports /tmp/appsec-reports
```

Keep `--reports` outside the scanned tree, or the scanners read each other's
output while it is being written.

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
```

Out of the box one engine per category runs (Semgrep, Trivy, Gitleaks, Checkov)
and the gate fails on `high`+ — that is the recommended setup, not a minimum.
The alternative engines and everything below are opt-in for when you want more.

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
generated Gitleaks allowlist, a TruffleHog regex file, …), so one list covers
all nine.

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
result. With `strict: true` (or `--strict`) the run fails with exit `2` — rather
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

Run once **with** network to snapshot DBs and rulesets into `./cache/`:

```bash
./preload.sh           # Semgrep ruleset + Trivy vulnerability DB
```

Then set `offline: true` in `scan-config.yml`. Scans now run with no network
access (Semgrep uses the cached ruleset; Trivy uses the cached DB with
`--skip-db-update --offline-scan`). Gitleaks and Checkov bundle their rules in
the image, so they need no preload.

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
│   ├── checkov.sarif
│   ├── grype.sarif         # + grype.json (carries CVE/GHSA aliases for dedup)
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
and AI agents, and it is versioned: `schema_version` (`1.0`) refers to
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

The **collector** decides pass/fail: exit `1` if any finding is at or above
`fail_on`, else `0`. Scanners themselves always exit `0`, so a noisy finding
never breaks the scan phase — only the policy does. `run.sh` propagates the
collector's exit code, which makes this safe to drop into a CI gate.

## CI/CD

For other repositories, see [Use in your project](#use-in-your-project):

- **GitHub Action** — [`action.yml`](action.yml) (`uses: denimoll/appsec-compose@v1`)
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
Gitleaks, Hadolint) are skipped. Dedup, suppressions, baseline, SBOM formats and
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
docker-compose.yml      # scanners + collector (versions/flags from .env)
run.sh                  # entrypoint: render config, run scanners + collector
preload.sh              # offline cache populator
scan-config.yml         # the single file you edit
scripts/render-env.py   # scan-config.yml -> .env
orchestrator/           # Python collector (config, normalize, policy, summary)
tests/                  # collector unit tests (pytest)
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
