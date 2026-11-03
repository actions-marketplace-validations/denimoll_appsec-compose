#!/usr/bin/env bash
# appsec-compose — end-to-end smoke test.
#
# The unit tests cover the collector's logic; they cannot see the compose wiring.
# Every engine is invoked through a shell command line in docker-compose.yml, and
# upstream tools change those underneath us.
#
# `strict` is not enough to catch that. Gitleaks kept `detect` as a deprecated
# alias that exits 0 and writes a valid but EMPTY sarif, so the old command line
# would report zero secrets and every structural check would pass. Only asking
# each engine "did you find the thing planted for you?" catches it.
#
# Runs the full pipeline over tests/fixtures/vulnerable-repo and asserts that
# every enabled engine actually produced findings.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

FIXTURE="$SCRIPT_DIR/tests/fixtures/vulnerable-repo"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# All ten engines, report-only: the point is coverage, not the verdict.
# Only the scanners are switched on — enrichment stays off, so the smoke test
# never depends on a CVE-PaaS instance being reachable.
python3 - "$WORK/config.yml" <<'PYCFG'
import sys, pathlib, yaml

cfg = yaml.safe_load(pathlib.Path("scan-config.yml").read_text())
for block in cfg["scanners"].values():
    block["enabled"] = True
cfg["enrich"]["cve_paas"]["enabled"] = False
# The fixture's lockfile declares MIT for flatmap-stream; denying it proves
# Trivy's license pass is wired, not that MIT is a problem.
cfg["licenses"] = {"deny": ["MIT"]}
pathlib.Path(sys.argv[1]).write_text(yaml.safe_dump(cfg, sort_keys=False))
PYCFG

echo "==> Running the full pipeline over the fixture"
./run.sh "$FIXTURE" --config "$WORK/config.yml" --reports "$WORK/reports" \
  --baseline "$WORK/baseline.json" --name "${SMOKE_NAME:-smoke}" --fail-on none --strict

echo "==> Asserting every engine reported"
python3 - "$WORK/reports/findings.json" <<'PY'
import json, sys

data = json.load(open(sys.argv[1]))
failures = []

def check(condition, message):
    if not condition:
        failures.append(message)

check(not data["reports_missing"], f"missing reports: {data['reports_missing']}")
check(not data["reports_errored"], f"unreadable reports: {data['reports_errored']}")

# Each engine must find something in a fixture built to trip it. A silent zero
# here means its command line broke, which is exactly what we are guarding.
tools = data["tool_counts"]
for engine in ("semgrep", "trivy", "gitleaks", "checkov", "hadolint", "osv", "zizmor"):
    check(tools.get(engine, 0) > 0, f"{engine} reported nothing")

# zizmor must read the planted workflow, not merely write an empty SARIF.
rules = {f["rule_id"] for f in data["findings"] if f["tool"] == "zizmor"}
check("zizmor/template-injection" in rules,
      f"zizmor missed the PR-title injection in pr-greeter.yml (saw {sorted(rules)})")

# flatmap-stream@0.1.1 is malware, not a vulnerable release: it must be
# recognised as such from the lockfile alone and ranked critical.
mal = [f for f in data["findings"] if f.get("malicious")]
check(any((f.get("package") or "").startswith("flatmap-stream@") and f["severity"] == "critical"
          for f in mal), f"flatmap-stream not reported as a critical malicious package ({mal})")

# The license pass ran and the policy turned the denied license into SCA.
check(any(f["rule_id"] == "LICENSE:MIT" and f["category"] == "sca"
          for f in data["findings"]), "license policy produced no LICENSE:MIT finding")

# Trivy's secret scanner reports under secrets and merges with Gitleaks.
check(not any(f["category"] == "sca" and not f.get("package") and "trivy" in f["tools"]
              for f in data["findings"]), "a Trivy result without a package landed in sca")

categories = data["category_counts"]
for category in ("sast", "sca", "secrets", "iac"):
    check(categories.get(category, 0) > 0, f"no {category} findings")

# Cross-tool de-duplication must actually collapse the Dockerfile overlaps.
check(data["dedup"]["duplicates_removed"] > 0, "nothing de-duplicated")

# The SBOM must contain the pinned dependencies, not just the root component.
check(data["coverage"]["sbom_components"] != 0,
      "SBOM has no components — SCA resolved nothing")

# Provenance must record what produced the report.
provenance = data["provenance"]
check(provenance["appsec_compose"] != "unknown", "no version recorded")
check(len(provenance["engines"]) >= 6, f"engines not recorded: {provenance['engines']}")

if failures:
    print("SMOKE TEST FAILED:")
    for failure in failures:
        print(f"  - {failure}")
    sys.exit(1)

print(f"  {sum(data['severity_counts'].values())} findings, "
      f"{len(data['reports_found'])} reports, "
      f"{data['dedup']['duplicates_removed']} duplicates merged")
PY

echo "==> Asserting the policy gate still fails on a bad repo"
set +e
./run.sh "$FIXTURE" --config "$WORK/config.yml" --reports "$WORK/reports" \
  --baseline "$WORK/baseline.json" --name "${SMOKE_NAME:-smoke}" --fail-on high >/dev/null 2>&1
code=$?
set -e
[[ "$code" == "1" ]] || { echo "expected exit 1 from the gate, got $code" >&2; exit 1; }

echo "SMOKE TEST PASSED"
