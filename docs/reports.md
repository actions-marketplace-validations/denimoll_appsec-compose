# Reports

What a run writes: native SARIF, findings.json, the summaries, the review brief, provenance. Back to the [README](../README.md).

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

### Vulnerable components

SCA results are shown per **component** — one row per package@version with
every vulnerability found in it — in both summaries, in `review-brief.md` and
as `components` in `findings.json`. A dependency with sixty CVEs is one thing
to upgrade, not sixty rows to read:

| Severity | Component | Vulnerabilities | Upgrade to | Declared in |
|---|---|---|---|---|
| critical | `com.fasterxml.jackson.core:jackson-databind@2.9.8` | 60: 12 critical, 41 high, 7 medium | **2.18.11** | pom.xml |

**Upgrade to** is the lowest version, among those the engines name as fixes,
that fixes every vulnerability listed. Engines name one fix per maintained
branch, so a version counts as fixing a vulnerability when its own branch
(major.minor) has a listed fix at or below it, or when it is above all of that
vulnerability's listed fixes. Only plain numeric versions are compared; with a
pre-release or distro version in play, or a vulnerability that has no fix, the
column says so instead of guessing, and each vulnerability's own fixes are
listed underneath. The findings themselves are unchanged: the gate,
suppressions and the baseline still act on each vulnerability.

### `findings.json` contract

`findings.json` is the machine-readable interface for ASPM imports, CI scripts
and AI agents, and it is versioned: `schema_version` (`1.1`) refers to
[`schemas/findings.schema.json`](../schemas/findings.schema.json). The major only
changes when a field is removed, renamed or changes meaning; additions bump the
minor, so ignore fields you do not know.

Each finding carries a `fingerprint` (stable across runs, see
[Baseline](configuration.md#baseline-gate-on-new-findings)), its full location (`line`,
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
