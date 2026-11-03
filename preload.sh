#!/usr/bin/env bash
# appsec-compose — offline preload.
#
# Run this ONCE with network access. It snapshots everything the scan needs
# from the internet into the cache (./cache/, or $ASS_CACHE_DIR — the
# `appsec-compose` CLI uses ~/.cache/appsec-compose), so later runs with
# `offline: true` in scan-config.yml work fully air-gapped:
#   - Semgrep ruleset (p/default) -> <cache>/semgrep/default.yaml
#   - Trivy vulnerability DB        -> <cache>/trivy/
#   - Grype vulnerability DB        -> <cache>/grype/
#   - the collector image           -> pulled (or built) into the local Docker
#
# Note: gitleaks, checkov and zizmor ship their rules/policies inside the image,
# so they need no preload (zizmor's online audits are simply skipped offline).
# Trivy's Java DB downloads on demand; if you scan JVM
# projects offline, also run a JVM scan once online to populate <cache>/trivy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE="${ASS_CACHE_DIR:-$SCRIPT_DIR/cache}"
[[ "$CACHE" = /* ]] || CACHE="$PWD/$CACHE"
cd "$SCRIPT_DIR"

# Refresh .env so we use the pinned tool versions from scan-config.yml.
python3 scripts/render-env.py >/dev/null
set -a; . ./.env; set +a

mkdir -p "$CACHE/semgrep" "$CACHE/trivy" "$CACHE/grype"

echo "==> Snapshotting Semgrep ruleset (p/default)"
curl -fsSL "https://semgrep.dev/c/p/default" -o "$CACHE/semgrep/default.yaml"
rules=$(grep -cE "^[[:space:]]*- id:" "$CACHE/semgrep/default.yaml" || true)
echo "    saved $CACHE/semgrep/default.yaml (${rules} rules)"

echo "==> Downloading Trivy vulnerability DB (v${TRIVY_VERSION})"
docker run --rm -v "$CACHE/trivy:/root/.cache/trivy" \
  "aquasec/trivy:${TRIVY_VERSION}" image --download-db-only

echo "==> Downloading Grype vulnerability DB (${GRYPE_VERSION})"
docker run --rm -e GRYPE_DB_CACHE_DIR=/cache/grype \
  -v "$CACHE/grype:/cache/grype" \
  "anchore/grype:${GRYPE_VERSION}" db update

# The collector is not a scanner image a `docker compose pull` would fetch: it
# is the published image or a local build (scripts/collector-image.sh), and
# either needs the network once.
echo "==> Preparing the collector image"
scripts/collector-image.sh >/dev/null

echo
echo "Preload complete. Set 'offline: true' in scan-config.yml to use it."
echo "(gitleaks, checkov, zizmor, semgrep[file], trufflehog, syft need no extra DB.)"
echo "Cache size: $(du -sh "$CACHE" 2>/dev/null | cut -f1)"
