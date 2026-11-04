# Engines and coverage

What each engine checks, how findings are ranked and merged. Back to the [README](../README.md).

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

## Checkov: only the IaC the repository has

Checkov walks the whole tree once per framework, whether or not the repository
holds anything of that kind. On django — 7,000 files whose only IaC is GitHub
workflows — the helm framework alone took 49 s, ansible 41 s, and the one that
found anything, github_actions, 11 s. So before the scan, `run.sh` lists the
frameworks the repository has files for and runs only those:

| Framework | Selected when the repo has |
|---|---|
| terraform, terraform_json, terraform_plan | `*.tf`, `*.tf.json`, a plan JSON |
| dockerfile | `Dockerfile*`, `Containerfile*`, `*.dockerfile` |
| kubernetes, helm, kustomize | YAML/JSON with `apiVersion` and `kind`; `Chart.yaml`; `kustomization.yaml` |
| cloudformation, serverless, cdk | `AWSTemplateFormatVersion` or `AWS::` types; `serverless.yml`; `aws-cdk-lib` |
| arm, bicep | an Azure deployment-template schema; `*.bicep` |
| github_actions, gitlab_ci, bitbucket_pipelines, azure_pipelines, circleci_pipelines, argo_workflows | the pipeline files of each |
| openapi, ansible | an `openapi:`/`swagger:` key; plays with `hosts:` and `tasks:`/`roles:` |

Detection errs towards running a framework — an extra one costs seconds, a
missed one would silently drop coverage — respects `exclude:`, and takes a
fraction of a second (0.24 s on django). A repository with no IaC at all does
not start Checkov; its report is an empty SARIF. Frameworks that need a Prisma
API key or platform tokens (`sast_*`, `sca_*`, `*_configuration`) and the
custom-policy-only `json`/`yaml` are never selected; secrets belong to Gitleaks
and Trivy. The frameworks used are recorded in `findings.json`
(`provenance.checkov_frameworks`) and in the review brief. To run them all:

```yaml
scanners:
  checkov: { frameworks: all }      # or an explicit list: [terraform, helm]
```

Checkov also runs with `--skip-download`: otherwise every scan spends about
25 s fetching Prisma Cloud guideline links (and waits out a timeout offline).
The findings and their levels are the same; only the per-finding doc link is
missing. `guidelines: true` brings the links back, online only.

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
- **CI workflows** — one flaw in a workflow, reported by different engines,
  merges where their regions overlap: template injection (zizmor
  `template-injection`, Semgrep `run-shell-injection`, Checkov `CKV_GHA_2`) and
  unpinned actions (zizmor `unpinned-uses`, Semgrep
  `github-actions-mutable-action-tag`). Semgrep flags a whole `run:` step and
  zizmor the expression inside it, so two injections in one step are one thing
  to fix, and two steps stay two findings. The result is an `iac` finding, under
  that category's gate. A finding only one engine reported is left as it is.

A baseline keeps working across this: the merged finding keeps the fingerprint
of the engine that leads it. The absorbed engine's fingerprint counts once as
`fixed`, and an `ignore: fingerprint` naming it should be re-pointed at the
merged finding; `rule:` entries match all its aliases and need no change.

A merged finding keeps the highest severity among the tools that assigned one
(see [Severity](#severity)), records **every tool** that reported it, and lists
the equivalent IDs as aliases. `findings.json` reports
`raw_findings`, `unique_findings` and `duplicates_removed`. Per-tool counts
still reflect each tool's true raw yield.
