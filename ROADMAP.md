# Roadmap

## Shipped (on `develop`, pending the 1.0.0 release)

- **Engines** — Semgrep (SAST), Trivy (SCA/IaC/SBOM), Gitleaks (secrets),
  Checkov (IaC) by default; Grype + OSV-Scanner (SCA), TruffleHog (secrets),
  Hadolint (IaC), Syft (SBOM) opt-in. Several tools per category, aggregated.
- **Cross-tool de-duplication** with CVE↔GHSA alias resolution.
- **Suppressions** (`ignore:` rules) and **baseline / delta** (gate only on new).
- **SBOM** in CycloneDX and SPDX.
- **Offline / air-gapped** mode (`preload.sh`).
- **Supply-chain** — pin scanner images by digest (`pin.sh`), or a digest in a
  tool's `version`.
- **Targets** — repo filesystem, container image (public **and private**
  registries), and **build-from-Dockerfile** (scan the built image).
- **Reports** — native SARIF per tool, `findings.json`, CycloneDX/SPDX SBOM, and
  a self-contained HTML summary (severity cards, category filters, per-finding
  details + advisory links, NEW badges in baseline mode).
- **CI/CD** — reusable GitHub Action (`uses: denimoll/appsec-compose@v1`) and an
  includable GitLab template (`templates/gitlab/`) for other projects; GHCR
  collector-image publish.
- **Scan scope** — one `exclude:` list translated into every engine's own
  exclusion mechanism; recommended defaults out of the box.
- **Policy per category** — `fail_on` as a map (secrets/sca/sast/iac), plus
  `strict` (a scanner with no readable report fails the run) and
  `require_pinned` (refuse to run on unpinned images).
- **Cross-tool IaC de-duplication** via a rule equivalence map.
- **SCA coverage check** — warns when the repo declares dependency manifests
  that no engine resolved (the silent-zero failure mode), with advice naming the
  engine that actually fixes the gap.
- **Exploitability enrichment** — optional [CVE-PaaS](https://github.com/denimoll/CVE-PaaS)
  lookup adds KEV / EPSS / PoC / Nuclei data to SCA findings, in `annotate` or
  `reprioritize` mode, plus a `fail_on_exploitable` gate independent of CVSS.
- **Expiring suppressions** — `expires:` on an `ignore` entry.
- **Config schema validation** — unknown keys rejected with a suggestion,
  before any container starts.
- **Provenance** — tool version, resolved engine digests and DB dates in every
  report; `./run.sh --version`.
- **Smoke test** — `scripts/smoke-test.sh` runs the whole pipeline over a
  vulnerable fixture and asserts every engine reported; gates CI.
- **Multi-project primitives** — `--config`, `--baseline`, `--reports`,
  `--name` (per-run `COMPOSE_PROJECT_NAME`), per-run `.env` / `excludes/` so
  runs from one clone can overlap; `cache/` stays shared.
- **Tests** — pytest suite over the collector, gating the CI scan job.

## Release: 1.1.0

- [ ] **Re-validate on a real production project** (gate — must pass before
      tagging). Gate behaviour changed in three places this cycle (per-category
      `fail_on`, `strict`, `exclude:`), so existing projects may shift.
- [ ] Merge `develop` → `main`.
- [ ] Tag `v1.1.0` + GitHub Release (triggers the collector image publish to GHCR).

## Multi-project & UI (primary future direction)

A "project" = a named **profile** (a scan-config) applied to a target entity.

- [ ] **Enabling primitives** (each independently useful):
  - [x] `run.sh --config <path> --baseline <path> --reports <dir>` — decouple
        state from the tool directory.
  - [x] `COMPOSE_PROJECT_NAME=appsec-<slug>` per run — isolate containers/volumes.
  - [x] `render-env.py` accepts a config path.
  - [x] Keep `cache/` (Trivy/Grype/Semgrep DBs) global/shared across projects.
  - [x] Per-run `.env` / `excludes/` so projects can run **concurrently**.
- [ ] **Profiles** — one main profile or several reusable profiles (which
      practices/engines, SBOM formats, policy, etc.).
- [ ] **Projects** — entities with their own name, path/address (repo URL or
      local path) and metadata, each referencing a profile.
- [ ] **Scheduling** — run a project's scan on a **cron** schedule.
- [ ] **Batch** — run many projects; aggregated `reports/index.html` across them.
- [ ] **Minimal UI** — thin backend (e.g. FastAPI/Flask) over `run.sh` to CRUD
      profiles/projects, browse reports, and manage schedules.

## Integrations & extras (backlog)

- [ ] **ASPM/ASOC push** — DefectDojo (API import), DependencyTrack (SBOM upload).
- [ ] Prebuilt collector image consumed by compose (`image:` instead of `build:`).
- [ ] Richer **delta report** in HTML (new/fixed diff beyond the baseline NEW flag).
- [ ] More engines as needed (e.g. KICS).
- [ ] Extend the IaC equivalence map beyond Dockerfile rules (Terraform, K8s).
