# Development

How it works inside, the layout, tests and the benchmark. Back to the [README](../README.md).

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
manager/                # optional: projects, batch, schedules, the local UI (docs/projects.md)
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

Both run on every push in [`appsec-scan.yml`](../.github/workflows/appsec-scan.yml),
and the scan job depends on them.

## Benchmark — what it catches and what it misses

A first step of a review is only useful if the reviewer knows what it already
covered. [`benchmark/RESULTS.md`](../benchmark/RESULTS.md) measures the default
scan on corpora with known answers — OWASP Benchmark for Java and for Python
and the OpenSSF CVE Benchmark for JavaScript/TypeScript (SAST, with each
relevant Semgrep rule pack scored as its own profile), a synthetic labelled
secrets set, and pinned vulnerable packages checked against an OSV snapshot
(SCA) — with per-category recall and false-positive rates, the exact engine
digests and DB dates, and a section on where the tool is weak. IaC has no
number yet: no labelled corpus maps onto these engines.

```bash
python3 benchmark/bench.py        # re-run everything (Docker + network; ~40 min)
```
