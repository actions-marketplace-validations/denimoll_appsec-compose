# CI/CD

GitHub Actions, GitLab CI and other pipelines. Back to the [README](../README.md).

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
`reports-dir`. Inputs and details: [`action.yml`](../action.yml).

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
[`templates/gitlab/appsec-compose.yml`](../templates/gitlab/appsec-compose.yml).

**Anywhere else** — clone the tool once and call `run.sh` from your project;
relative paths are resolved against your current directory:

```bash
git clone --depth 1 --branch v.1.2.0 https://github.com/denimoll/appsec-compose ~/appsec-compose
cd /path/to/your/repo && ~/appsec-compose/run.sh . --config scan-config.yml --reports /tmp/appsec-reports
```

A `--reports` directory inside the scanned tree is excluded from the scan
automatically, so the scanners never read their own output.

## CI/CD

For other repositories, see [Use in your project's CI](#use-in-your-projects-ci):

- **GitHub Action** — [`action.yml`](../action.yml) (`uses: denimoll/appsec-compose@v.1.2.0`)
  runs the scan, uploads every SARIF to **code scanning**, keeps the reports as
  an artifact, caches the vuln DBs, and fails the step on a policy breach. This
  repo's own [`.github/workflows/appsec-scan.yml`](../.github/workflows/appsec-scan.yml)
  dogfoods it with `uses: ./` after the unit and smoke tests.
- **GitLab CI** — [`templates/gitlab/appsec-compose.yml`](../templates/gitlab/appsec-compose.yml)
  fetches the tool at `APPSEC_COMPOSE_REF`, scans the project, exposes the
  CycloneDX SBOM to GitLab Dependency Scanning, and caches DBs. (Needs a runner
  with the host Docker socket — see the file header.) This repo's
  [`.gitlab-ci.yml`](../.gitlab-ci.yml) includes the same template.
- **Publish the collector image** — [`.github/workflows/publish-collector.yml`](../.github/workflows/publish-collector.yml)
  pushes the collector to GHCR on release, so CI can skip the local build.
