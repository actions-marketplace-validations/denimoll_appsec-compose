#!/usr/bin/env bash
# appsec-compose installer — no clone, no sudo, nothing outside your home.
#
#   ./install.sh                            # the latest release
#   ./install.sh --ref v.1.6.0              # a release tag (or branch / commit)
#   APPSEC_COMPOSE_VERSION=v.1.6.0 ./install.sh
#   ./install.sh --from /path/to/checkout   # a local checkout, as it is on disk
#
# Documented one-liner (it runs exactly this file — read it first if you like):
#   curl -fsSL https://raw.githubusercontent.com/denimoll/appsec-compose/main/install.sh | bash
#
# Installs into ${XDG_DATA_HOME:-~/.local/share}/appsec-compose/<version> and
# links ~/.local/bin/appsec-compose to it. Idempotent: re-running replaces that
# version's directory as a whole and re-points the link; other installed
# versions are left alone. The vulnerability-DB cache lives separately in
# ${XDG_CACHE_HOME:-~/.cache}/appsec-compose and survives reinstalls.
#
# Exit codes: 0 installed, 1 prerequisites missing or download failed, 2 usage.
set -euo pipefail

REPO="denimoll/appsec-compose"
DATA_ROOT="${XDG_DATA_HOME:-$HOME/.local/share}/appsec-compose"
BIN_DIR="$HOME/.local/bin"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/appsec-compose"

usage() {
  sed -n '2,19p' "${BASH_SOURCE[0]}" 2>/dev/null | sed 's/^# \{0,1\}//' >&2 \
    || echo "Usage: install.sh [--ref <tag|branch|sha>] [--from <dir>] [--skip-checks]" >&2
  exit 2
}

REF="${APPSEC_COMPOSE_VERSION:-}"; FROM=""; SKIP_CHECKS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) REF="${2:-}"; [[ -n "$REF" ]] || usage; shift 2 ;;
    --from) FROM="${2:-}"; [[ -n "$FROM" ]] || usage; shift 2 ;;
    --skip-checks) SKIP_CHECKS=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

say() { echo "$*" >&2; }

# ---- prerequisites ------------------------------------------------------
# Everything is checked and every gap reported at once; nothing is installed
# while one is missing (--skip-checks installs anyway).
missing=()
if ! command -v docker >/dev/null 2>&1; then
  missing+=("docker: install Docker Desktop or Docker Engine — https://docs.docker.com/get-docker/")
elif ! docker compose version >/dev/null 2>&1; then
  missing+=("docker compose v2: the 'docker compose' plugin (the old docker-compose v1 is not enough) — https://docs.docker.com/compose/install/")
fi
if ! command -v python3 >/dev/null 2>&1; then
  missing+=("python3 (3.9+): renders the scan config on the host")
elif ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
  missing+=("python3 3.9+: found $(python3 -c 'import platform; print(platform.python_version())')")
elif ! python3 -c 'import yaml' 2>/dev/null; then
  missing+=("PyYAML for $(command -v python3): python3 -m pip install --user pyyaml  (or: apt install python3-yaml / brew install pyyaml)")
fi
if [[ -z "$FROM" ]] && ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  missing+=("curl or wget: to download the release")
fi
command -v tar >/dev/null 2>&1 || missing+=("tar")

if [[ ${#missing[@]} -gt 0 ]]; then
  say "Missing prerequisites:"
  for m in "${missing[@]}"; do say "  - $m"; done
  if [[ $SKIP_CHECKS != 1 ]]; then
    say "Nothing was installed. Install the above and re-run (or pass --skip-checks)."
    exit 1
  fi
  say "(--skip-checks: installing anyway)"
fi
if command -v docker >/dev/null 2>&1 && ! docker info >/dev/null 2>&1; then
  say "Note: the Docker daemon is not reachable right now; start it before scanning."
fi

fetch() {   # fetch <url> — to stdout
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1"; else wget -qO- "$1"; fi
}

# ---- what to install ----------------------------------------------------
if [[ -n "$FROM" ]]; then
  [[ -f "$FROM/run.sh" ]] || { say "Error: '$FROM' is not an appsec-compose checkout"; exit 2; }
  FROM="$(cd "$FROM" && pwd)"
  VERSION_DIR="local"
  say "Installing from $FROM"
else
  if [[ -z "$REF" ]]; then
    REF="$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
      | python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null)" || REF=""
    [[ -n "$REF" ]] || {
      say "Error: could not look up the latest release (GitHub API unreachable or rate-limited)."
      say "       Pass one explicitly: --ref v.X.Y.Z or APPSEC_COMPOSE_VERSION=v.X.Y.Z"
      exit 1
    }
  fi
  # A ref is a path component here; keep it to one.
  VERSION_DIR="$(printf '%s' "$REF" | tr '/' '-')"
  say "Installing appsec-compose $REF"
fi
DEST="$DATA_ROOT/$VERSION_DIR"

mkdir -p "$DATA_ROOT"
STAGE="$(mktemp -d "$DATA_ROOT/.stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

if [[ -n "$FROM" ]]; then
  # The working tree as it is (uncommitted changes included), minus VCS
  # metadata and everything a scan writes.
  tar -C "$FROM" \
    --exclude=./.git --exclude=./.claude --exclude=./.run --exclude=./cache \
    --exclude=./reports --exclude=./appsec-reports --exclude=./.env \
    --exclude=./excludes --exclude=./.img-empty --exclude=./.img-archive \
    --exclude=./.docker-auth --exclude=.pytest_cache --exclude=__pycache__ \
    -cf - . | tar -C "$STAGE" -xf -
else
  fetch "https://codeload.github.com/$REPO/tar.gz/$REF" | tar -xzf - -C "$STAGE" --strip-components=1 || {
    say "Error: could not download $REPO at '$REF' (no such tag/branch/commit, or no network)."
    exit 1
  }
fi
mkdir -p "$STAGE/reports"

if [[ ! -x "$STAGE/bin/appsec-compose" ]]; then
  say "Error: '$VERSION_DIR' has no bin/appsec-compose — it predates the CLI. Install a newer release."
  exit 1
fi

# Swap the whole directory, so a re-install never mixes two versions' files.
if [[ -e "$DEST" ]]; then
  rm -rf "$DEST.old"
  mv "$DEST" "$DEST.old"
fi
mv "$STAGE" "$DEST"
rm -rf "$DEST.old"
trap - EXIT

mkdir -p "$BIN_DIR"
LINK="$BIN_DIR/appsec-compose"
if [[ -e "$LINK" && ! -L "$LINK" ]]; then
  say "Error: $LINK exists and is not a symlink; move it away and re-run."
  exit 1
fi
ln -sfn "$DEST/bin/appsec-compose" "$LINK"

say ""
say "Installed: $DEST"
say "Command  : $LINK -> $DEST/bin/appsec-compose"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say "Note: $BIN_DIR is not on your PATH. Add it, e.g.:"
     say "        echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.profile" ;;
esac
say ""
say "Try:       appsec-compose scan /path/to/repo"
say "Offline:   appsec-compose preload   (once, with network)"
say ""
say "Uninstall:"
say "  rm $LINK"
say "  rm -rf $DATA_ROOT        # every installed version"
say "  rm -rf $CACHE_DIR        # vulnerability DBs (optional)"
say "  docker image ls 'appsec-compose-collector' ; docker image ls 'ghcr.io/denimoll/appsec-compose-collector'   # then docker image rm the ones you no longer need"
