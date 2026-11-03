#!/usr/bin/env bash
# appsec-compose — choose the collector image and make sure it exists locally.
#
#   scripts/collector-image.sh [--offline]   # prints the image ref to run
#   scripts/collector-image.sh --hash        # prints the orchestrator/ content hash
#
# Releases publish the collector to GHCR as <repo>:v.<VERSION>, labelled with a
# hash of orchestrator/'s content (.github/workflows/publish-collector.yml). A
# checkout uses that image only when its own orchestrator/ hashes the same: an
# install of a release skips the build, while a development checkout — an
# unreleased VERSION, or local edits on top of a released one — always runs the
# code it actually has. The tag alone cannot tell those apart.
#
# Otherwise the collector is built locally and tagged by the same hash, so it is
# built once per content (and found again offline), and two checkouts with
# different code never run each other's build.
#
# Resolution order, deterministic — compose is never left to build or pull on
# its own:
#   1. ASS_COLLECTOR_IMAGE from the environment (e.g. a mirror), used as is;
#   2. the local build for this content, if present;
#   3. the published image, if present or pullable (no pull with --offline)
#      and its label matches;
#   4. a fresh local build.
# Progress goes to stderr; stdout carries only the image ref.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLISHED_REPO="${ASS_COLLECTOR_REPO:-ghcr.io/denimoll/appsec-compose-collector}"
LABEL="appsec-compose.collector-hash"
LOCAL_REPO="appsec-compose-collector"

content_hash() {
  # Path + length + bytes of every file the Dockerfile's `COPY . .` ships,
  # minus bytecode and dotfiles that a local test run or an editor leaves.
  python3 - "$ROOT/orchestrator" <<'PY'
import hashlib, os, sys
root = sys.argv[1]
digest = hashlib.sha256()
for dirpath, dirs, files in os.walk(root):
    dirs[:] = sorted(d for d in dirs if d != "__pycache__" and not d.startswith("."))
    for name in sorted(files):
        if name.startswith(".") or name.endswith((".pyc", ".pyo")):
            continue
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        with open(path, "rb") as fh:
            data = fh.read()
        digest.update(f"{rel}\0{len(data)}\0".encode())
        digest.update(data)
print(digest.hexdigest())
PY
}

label_of() {
  docker image inspect --format "{{ index .Config.Labels \"$LABEL\" }}" "$1" 2>/dev/null || true
}

OFFLINE=0
case "${1:-}" in
  --hash) content_hash; exit 0 ;;
  --offline) OFFLINE=1 ;;
  "") ;;
  *) echo "Usage: $0 [--offline | --hash]" >&2; exit 2 ;;
esac

if [[ -n "${ASS_COLLECTOR_IMAGE:-}" ]]; then
  echo "Collector: $ASS_COLLECTOR_IMAGE (ASS_COLLECTOR_IMAGE)" >&2
  echo "$ASS_COLLECTOR_IMAGE"; exit 0
fi

hash="$(content_hash)"
local_ref="$LOCAL_REPO:local-${hash:0:12}"
published="$PUBLISHED_REPO:v.$(tr -d '[:space:]' < "$ROOT/VERSION")"

# Each change to orchestrator/ (an upgrade, or editing a checkout) builds a new
# local-<hash>; once a run settles on its image, the superseded local builds
# go, so they don't pile up. Never forced: an image a concurrent run is using
# is refused by Docker and kept. Two checkouts with different collector code
# on one daemon rebuild each other's image when alternating — a cheap build.
use() {
  docker images --format '{{.Repository}}:{{.Tag}}' "$LOCAL_REPO" 2>/dev/null \
    | grep -E ":local-[0-9a-f]{12}$" | grep -vx "$1" \
    | while read -r old; do docker rmi "$old" >/dev/null 2>&1 || true; done || true
  echo "$1"; exit 0
}

if docker image inspect "$local_ref" >/dev/null 2>&1; then
  echo "Collector: $local_ref (local build)" >&2
  use "$local_ref"
fi

if [[ "$(label_of "$published")" == "$hash" ]]; then
  echo "Collector: $published (prebuilt)" >&2
  use "$published"
fi
# Pull only when the image is not here at all: one that is here with another
# label is this release's image under a checkout that has since changed.
if [[ "$OFFLINE" != "1" ]] && ! docker image inspect "$published" >/dev/null 2>&1; then
  if docker pull -q "$published" >/dev/null 2>&1 && [[ "$(label_of "$published")" == "$hash" ]]; then
    echo "Collector: $published (prebuilt, pulled)" >&2
    use "$published"
  fi
fi

echo "Collector: building $local_ref (no prebuilt image matches this checkout)" >&2
docker build --label "$LABEL=$hash" -t "$local_ref" "$ROOT/orchestrator" >&2 || {
  echo "Error: could not build the collector image." >&2
  [[ "$OFFLINE" == "1" ]] && echo "  Offline: run ./preload.sh (appsec-compose preload) once with network." >&2
  exit 1
}
use "$local_ref"
