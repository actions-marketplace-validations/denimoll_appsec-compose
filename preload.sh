#!/usr/bin/env bash
# appsec-compose — offline preload.
#
# Run this ONCE with network access. It snapshots everything the scan needs
# from the internet into ./cache/, so later runs with `offline: true` in
# scan-config.yml work fully air-gapped:
#   - Semgrep ruleset (p/default) -> cache/semgrep/default.yaml
#   - Trivy vulnerability DB        -> cache/trivy/
#
# Note: gitleaks, checkov and zizmor ship their rules/policies inside the image,
# so they need no preload (zizmor's online audits are simply skipped offline).
# Trivy's Java DB downloads on demand; if you scan JVM
# projects offline, also run a JVM scan once online to populate cache/trivy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Refresh .env so we use the pinned tool versions from scan-config.yml.
python3 scripts/render-env.py >/dev/null
set -a; . ./.env; set +a

mkdir -p cache/semgrep cache/trivy

echo "==> Snapshotting Semgrep ruleset (p/default)"
curl -fsSL "https://semgrep.dev/c/p/default" -o cache/semgrep/default.yaml
rules=$(grep -cE "^[[:space:]]*- id:" cache/semgrep/default.yaml || true)
echo "    saved cache/semgrep/default.yaml (${rules} rules)"

echo "==> Downloading Trivy vulnerability DB (v${TRIVY_VERSION})"
docker run --rm -v "$SCRIPT_DIR/cache/trivy:/root/.cache/trivy" \
  "aquasec/trivy:${TRIVY_VERSION}" image --download-db-only

echo "==> Downloading Grype vulnerability DB (${GRYPE_VERSION})"
mkdir -p cache/grype
docker run --rm -e GRYPE_DB_CACHE_DIR=/cache/grype \
  -v "$SCRIPT_DIR/cache/grype:/cache/grype" \
  "anchore/grype:${GRYPE_VERSION}" db update

echo
echo "Preload complete. Set 'offline: true' in scan-config.yml to use it."
echo "(gitleaks, checkov, zizmor, semgrep[file], trufflehog, syft need no extra DB.)"
echo "Cache size: $(du -sh cache 2>/dev/null | cut -f1)"
