# Roadmap

## Shipped

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
- **CI/CD** — reusable GitHub Action (`uses: denimoll/appsec-compose@v.X.Y.Z`) and an
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
- **Content-anchored fingerprints (v2)** — baseline identity follows the flagged
  code, not its line number, so unrelated edits no longer surface known
  findings as new; v1 baselines still honoured. Secret values never hashed.
- **`findings.json` contract** — `schema_version` + JSON Schema
  (`schemas/findings.schema.json`); fingerprint, full span, CWE, fixed version.
- **Review brief** — `review-brief.md` hands the scan to a human or AI-agent
  reviewer: scope, blind spots, findings with code context, verdict format.
  `ignore:` accepts a `fingerprint` for single-finding triage verdicts.
- **Secret-free reports** — Gitleaks runs with `--redact`; no report the run
  produces carries a secret value.
- **Distinct exit codes** — 0 pass, 1 policy breach, 2 usage/config error,
  3 scan did not complete; a compose or bash failure can no longer pass for a
  policy verdict.
- **GitLab security reports** — `scripts/gitlab-reports.py` converts
  `findings.json` into GitLab's native sast / secret_detection /
  dependency_scanning formats (validated against schemas 15.0.7 and 15.2.4);
  the template no longer hands GitLab SARIF it cannot parse.
- **CI/CD workflow scanning** — zizmor (on by default, category `iac`) audits
  GitHub Actions workflows, composite actions and Dependabot config; GitHub's
  own actions may be tag-pinned unless the repo brings a `zizmor.yml`; online
  audits only with a host `ZIZMOR_GITHUB_TOKEN`. Trivy's secret results now
  count as secrets and merge with Gitleaks instead of landing in SCA.
- **Malicious packages** — a MAL- id, CWE-506 or a GitHub malware advisory
  makes an SCA finding `malicious`, critical whatever its score, and labelled
  in every report. Trivy (default) knows only GitHub-reviewed malware (11/23
  hijacked npm releases); `osv` (23/23, network) or `grype` (22/23,
  offline) for real coverage — documented, not enabled by default.
- **Dependency licenses** (opt-in) — `licenses: deny/warn/severity`; Trivy's
  license pass, judged by our policy; denied packages are SCA findings
  (`LICENSE:<id>`) under the usual gate, suppressions and baseline.
  Dependencies whose manifests record no license are counted as unjudged.

## Release: 1.2.0

- [ ] **Re-validate on a real production project** (gate — must pass before
      tagging). Baseline fingerprints changed format (v1 baselines are still
      read, but should be re-snapshotted), and `findings.json` gained a contract.
- [ ] Merge `develop` → `main`.
- [ ] Tag `v.1.2.0` + GitHub Release (triggers the collector image publish to GHCR).

## Primary direction: local and AI-assisted review

The product a person installs and runs on their own machine — by hand, or as
the first step of an AI agent's security review. CI integrations come later.

- [x] **Run without cloning** — `install.sh` + `appsec-compose scan <path>`
      from any directory; project-local config/baseline conventions; DB cache
      in `~/.cache/appsec-compose`; `--json` result object for agents.
- [x] **Prebuilt collector image** — the GHCR image for `v.<VERSION>` when its
      content label matches the checkout, else a local build (also offline).
- [x] **Diff mode** — `./run.sh <path> --diff <base-ref>` scans only the files
      changed since the merge-base (committed, uncommitted and untracked),
      walks the branch's commits for secrets, skips SCA/IaC engines the change
      did not touch, and gates per changed file (`on_changed_line` marks the
      lines the change wrote). `findings.json` 1.1 records the scope.
- [x] **MCP server / agent skill** — `scan`, `findings`, `finding`, `brief`,
      `suppress` over the same CLI and `findings.json` contract
      ([`appsec_mcp/`](appsec_mcp/README.md)).
- [x] **Coverage gaps** — zizmor audits GitHub Actions workflows (on by
      default); malicious packages ranked critical and labelled; an opt-in
      dependency license policy. Malicious-package *coverage* stays engine-bound
      (Trivy 11/23 known hijacks, Grype 22/23, OSV 23/23).
- [x] **Public benchmark** — precision/recall on known-vulnerable projects:
      [`benchmark/RESULTS.md`](benchmark/RESULTS.md), re-runnable with
      `python3 benchmark/bench.py`. SAST on OWASP Benchmark (Java), secrets on
      a synthetic labelled corpus, SCA against an OSV snapshot.
  - [ ] **IaC** — needs a labelled corpus plus a cross-tool rule mapping
        (Checkov/Trivy ids → the corpus' answers); skipped until then.
  - [ ] **Secrets on real data** — CredData-style corpus whose values are not
        replaced by allowlisted provider examples.
  - [ ] More SAST languages (OWASP Benchmark for Python; a JS/TS corpus).

## CI integrations (later — current versions work)

- [ ] Run the GitHub Action and the GitLab template in real pipelines.
- [ ] Optional moving tag (e.g. `v.1`) for the Action, moved by the release
      workflow; until then, pin an exact `v.X.Y.Z` tag or a commit SHA.

## Multi-project & UI (later)

A "project" = a named **profile** (a scan-config) applied to a target entity.
The enabling primitives are done (`--config`/`--baseline`/`--reports`/`--name`,
per-run state, shared `cache/`).

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
- [ ] Richer **delta report** in HTML (new/fixed diff beyond the baseline NEW flag).
- [ ] More engines as needed (e.g. KICS).
- [ ] Extend the IaC equivalence map beyond Dockerfile rules (Terraform, K8s).
