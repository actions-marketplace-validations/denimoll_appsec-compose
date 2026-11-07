# appsec-compose

One command runs a full OSS static security scan of a repository — **SAST, SCA,
secrets, IaC and CI/CD workflows** — through proven engines (Semgrep, Trivy,
Gitleaks, Checkov, zizmor, …), merges what they find into one de-duplicated,
fingerprinted result, and gates on it with an exit code that says what to fix.

It is built to be the first step of a security review, by a person or by an AI
agent: every run also writes a **review brief** — what was checked, what could
not be, and the flagged code — and an MCP server lets an agent scan, triage and
record verdicts itself.

**AI agent asked to check a project?** Follow [AGENTS.md](AGENTS.md): how to
run the scan, read the results and report them.

A thin, stateless orchestrator: no database, no workers. Each engine runs as a
one-shot container; a small Python collector does the rest. Looking after several
repositories? An optional layer adds named projects, batch runs, schedules and a
local UI, and a plain `scan` never touches it: [projects](docs/projects.md).

## Install and run locally (no clone)

Needs Docker with Compose v2, Python 3.9+ with PyYAML, and bash.

```bash
curl -fsSL https://raw.githubusercontent.com/denimoll/appsec-compose/main/install.sh | bash
# or pin a release:  bash install.sh --ref v.1.4.0
```

```bash
appsec-compose scan                       # the current directory
appsec-compose scan ~/src/api --fail-on critical
appsec-compose scan . --diff origin/main  # only what your branch changed
appsec-compose scan --image nginx:1.27    # a container image
appsec-compose profile .                  # what the repo is, and the config that fits it
appsec-compose scan . --json              # one JSON object on stdout, for tools and agents
```

Reports land in `./appsec-reports`. The vulnerability databases are cached in
`~/.cache/appsec-compose`; `appsec-compose preload` prepares them for offline
use. More: [usage](docs/usage.md).

## What runs

| Category | On by default | Opt-in |
|---|---|---|
| SAST | Semgrep | — |
| Dependencies (SCA) + SBOM | Trivy | Grype, OSV-Scanner, Syft |
| Secrets | Gitleaks (+ Trivy) | TruffleHog |
| IaC | Checkov, Trivy config | Hadolint |
| CI/CD workflows | zizmor | — |

Malicious packages are ranked critical whatever their score; a dependency
license policy is available as an option. Details, and how findings are ranked
and merged across engines: [engines](docs/engines.md).

## What you get

| File | For |
|---|---|
| `summary.html`, `summary.md` | reading the result — dependencies grouped per vulnerable component, with the version to upgrade to |
| `review-brief.md` | the next reviewer — a person or an AI agent: scope, **blind spots**, findings with code (secrets masked), how to record a verdict |
| `findings.json` | tools and agents: a versioned contract ([schema](schemas/findings.schema.json)), stable fingerprints |
| `native/*.sarif`, `sbom.*.json` | ASPM upload (DefectDojo, Dependency-Track, GitHub code scanning, …) |

Every report records the tool version, engine images and database dates, and
every run ends with a few lines of metrics — where the time went, how far
merging cut the raw output, what the brief costs to read (~tokens).
[Reports](docs/reports.md).

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| `0` | the gate passed | — |
| `1` | findings at or above `fail_on` | fix or triage them |
| `2` | usage or configuration error | fix the command or the config |
| `3` | the scan did not complete | fix the environment; there is no verdict |

## Configure a project

Defaults live in [`scan-config.yml`](scan-config.yml). A project adds
`.appsec-compose.yml` at its root, picked up automatically, and states only
what differs — it is laid over the defaults:

```yaml
fail_on: { secrets: low, default: high }   # gate per category
min_confidence: medium                     # Semgrep's LOW-confidence rules report, but don't gate
exclude: [vendor, fixtures]
ignore:
  - fingerprint: 3f9a…                     # one finding, from findings.json
    reason: "input is a constant from the CLI table"
    expires: 2027-03-01                    # accepted risks get re-argued
```

A file inside the scanned repo is not trusted like one you pass: only project
policy applies from it, and the reports say what it set. **Scanning code that
isn't yours? Add `--no-repo-config`.**

`.appsec-baseline.json` next to it gates on new findings only
(`--update-baseline` to accept the current state). Everything else — engines,
custom Semgrep rules, strict mode, exploitability data from CVE-PaaS:
[configuration](docs/configuration.md).

## With an AI agent

```bash
appsec-compose mcp --setup
claude mcp add --scope user appsec-compose -- appsec-compose mcp
```

The agent gets `scan`, `findings`, `components`, `finding`, `brief` and `suppress`; a
suppression is written to the project config with a reason and an expiry, for
a human to review with the code. [AI agents](docs/ai-agents.md) ·
[MCP server](appsec_mcp/README.md).

## In CI

`uses: denimoll/appsec-compose@v.1.4.0` in GitHub Actions, or an `include:` of
the GitLab template: [CI/CD](docs/ci.md).

## Documentation

- [Usage](docs/usage.md) — install, flags, diff mode, images, offline, pinned images, several projects
- [Projects](docs/projects.md) — optional: named projects and profiles, batch, schedules, the local UI
- [Configuration](docs/configuration.md) — the config file, gate, suppressions, baseline
- [Engines](docs/engines.md) — what each engine checks, severity, de-duplication
- [Reports](docs/reports.md) — every output file and the `findings.json` contract
- [AI agents](docs/ai-agents.md) · [CI/CD](docs/ci.md) · [Development](docs/development.md)
- [Benchmark](benchmark/RESULTS.md) — measured precision and recall, and where it is weak
- [Privacy and network use](PRIVACY.md) — nothing is collected; every connection a scan makes
- [Roadmap](ROADMAP.md)
