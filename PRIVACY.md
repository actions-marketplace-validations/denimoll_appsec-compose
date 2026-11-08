# Privacy and network use

appsec-compose collects nothing. It has no server, no account, no telemetry
and no analytics: the maintainers receive no data of any kind from a scan,
whether it runs locally, in CI or as the GitHub Action.

Your code is read only inside containers on the machine that runs the scan,
and the reports are written there. What follows is every network connection
a scan can make, and what it carries.

## Default configuration

| Connection | Carries | When |
|---|---|---|
| Container registries (Docker Hub, GHCR) | image pulls | first run and after an engine version change |
| Trivy vulnerability DBs (`mirror.gcr.io`, GHCR) | a download request | when the cached DB is due for an update (the Java DB only for JVM projects); never with `offline: true` |
| Semgrep rule registry (`semgrep.dev`) | a download request for the rule pack | every online run; Semgrep's metrics are off (`--metrics off`) |

Telemetry and update checks of the engines are switched off: Trivy runs with
`TRIVY_DISABLE_TELEMETRY` and `TRIVY_SKIP_VERSION_CHECK`, Grype and Syft with
their app-update checks disabled, Semgrep with `--metrics off`, Checkov with
`--skip-download`. KICS (opt-in) needs no network at all — verified by running
it with `--network none`. `offline: true` (after `appsec-compose preload`) makes
a scan use no network at all.

## Only if you turn it on

| Setting | Sends | To |
|---|---|---|
| `scanners.osv.enabled` | the names and versions of your dependencies | `api.osv.dev` (Google OSV) |
| `scanners.grype.enabled` | a DB download request | `grype.anchore.io` |
| `scanners.trufflehog.verify: true` | each candidate secret, to test whether it is live | the secret's issuer (GitHub, AWS, Slack, …) |
| `ZIZMOR_GITHUB_TOKEN` in the environment | workflow `uses:` references | the GitHub API |
| `scanners.checkov.guidelines: true` | a download request | Prisma Cloud (Palo Alto Networks) |
| `enrich.cve_paas.enabled` | CVE ids found in your dependencies | the CVE-PaaS server you configure |
| a git URL as a [project](docs/projects.md) target | a fetch of that repository (`git`, with your credentials if the host asks) | the host in the URL, on each scan of that project |

## GitHub Action

The action runs on your runner and, with `upload-sarif: true` (the default),
uploads the SARIF reports to your repository's code scanning through GitHub's
own `upload-sarif` action, and the reports as a workflow artifact. Both stay in
your repository. Nothing is sent anywhere else.

## What the reports contain

Reports quote the flagged code, so treat them like the code itself. Secret
values are masked in every report the collector writes, and Gitleaks runs with
`--redact`; TruffleHog's raw `native/trufflehog.json` (opt-in engine) is the one
file that can hold a secret value.

Questions: open an issue at https://github.com/denimoll/appsec-compose/issues.
