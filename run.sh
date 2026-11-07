#!/usr/bin/env bash
# appsec-compose — one-command OSS AppSec scan.
#
#   ./run.sh <path-to-repo>  [--fail-on L] [--strict] [--update-baseline]
#   ./run.sh --image <ref>   [--fail-on L]        # scan a container image
#   ./run.sh <path-to-repo>  --diff <base-ref>    # scan only what a change touched
#
# State can be moved out of this directory, so one clone can scan several
# projects: --config, --baseline and --reports. Each run renders its .env and
# excludes/ into a private directory under .run/ (removed on exit), so runs from
# one clone can overlap — give each its own --name and --reports.
#
# --profile <file> lays a named set of settings between the shipped defaults and
# --config, so a repo's own config keeps the last word (docs/projects.md).
#
# Relative paths are resolved against the directory run.sh was invoked from, so
# it can be called from another project's checkout (CI, the GitHub Action).
#
# Reads scan-config.yml, runs the enabled scanners over the target (repo or
# image) and writes reports to ./reports/.
#
# Exit codes — each tells the caller (a person, CI, an agent) what to fix:
#   0  pass
#   1  the policy gate failed: findings at/above fail_on — fix or triage them
#   2  usage or configuration error — fix the invocation or scan-config.yml
#   3  the scan did not complete — a scanner, Docker or the collector failed,
#      so there is no trustworthy verdict
# 1 means exactly one thing: a verdict was reached and it is "fail". Anything
# that goes wrong on the way maps to 3, never to 1.
#
# --json: every human-readable line (ours, compose's, the engines') goes to
# stderr, and stdout carries exactly one JSON object, written on exit whatever
# the exit code (scripts/scan-result.py; the contract is in README.md).
set -Eeuo pipefail
EXIT_PASS=0; EXIT_POLICY=1; EXIT_USAGE=2; EXIT_SCAN=3
ASS_RUN_START="$(date +%s)"; export ASS_RUN_START   # provenance: total run time
# set -e would exit with whatever the failing command returned — usually 1,
# which reads as a policy failure. Docker being down is not a finding.
trap 'echo "Error: scan aborted: \`$BASH_COMMAND\` failed (line $LINENO)" >&2; exit $EXIT_SCAN' ERR

usage() {
  echo "Usage: $0 <path-to-repo> [--fail-on L] [--min-confidence L] [--strict] [--require-pinned] [--update-baseline]" >&2
  echo "       $0 <path-to-repo> --diff <base-ref> [--fail-on L] [--strict]" >&2
  echo "       $0 <path-to-repo> [--profile <file>] [--config <file>] [--baseline <file>] [--reports <dir>] [--name <slug>]" >&2
  echo "       $0 --image <ref> [--registry-user U --registry-pass P] [--fail-on L]" >&2
  echo "       $0 --build <context> [--dockerfile <path>] [--fail-on L]" >&2
  echo "       any of the above with --json: one JSON result on stdout, the rest on stderr" >&2
  exit $EXIT_USAGE
}

# Scanners that can scan a container image (the rest are source-only).
IMAGE_TOOLS=" trivy grype syft "

# Captured before anything changes directory: user paths are relative to it.
CALLER_PWD="$PWD"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Decided before parsing, so even a bad flag gets its JSON answer.
JSON=0
for arg in "$@"; do if [[ "$arg" == "--json" ]]; then JSON=1; fi; done
if [[ $JSON == 1 ]]; then exec 3>&1 1>&2; fi
REPORTS_CLEARED=0
on_exit() {
  local rc=$?
  trap - ERR
  if [[ -n "${RUN_DIR:-}" ]]; then rm -rf "$RUN_DIR"; fi
  if [[ $JSON == 1 ]]; then
    local rdir="${REPORTS:-${REPORTS_DIR:-$SCRIPT_DIR/reports}}"
    [[ "$rdir" = /* ]] || rdir="$CALLER_PWD/$rdir"
    python3 "$SCRIPT_DIR/scripts/scan-result.py" "$rc" "$rdir" "$REPORTS_CLEARED" >&3 \
      || printf '{"exit_code": %d, "verdict": "%s", "reports_dir": null, "findings_json": null, "review_brief": null, "severity_counts": null, "breaching": null, "baseline": null}\n' \
           "$rc" "$(case $rc in 0) echo pass;; 1) echo fail;; 2) echo usage_error;; *) echo scan_error;; esac)" >&3
  fi
  exit $rc
}
trap on_exit EXIT

TARGET=""; IMAGE_REF=""; BUILD_CTX=""; DOCKERFILE=""; FAIL_ON_OVERRIDE=""
CONFIG_FILE=""; PROFILE_FILE=""; REPO_CONFIG_FILE=""; BASELINE_FILE=""; REPORTS_DIR=""; PROJECT_NAME=""; DIFF_BASE=""
REG_USER="${REGISTRY_USER:-}"; REG_PASS="${REGISTRY_PASS:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE_REF="${2:-}"; shift 2 ;;
    --build) BUILD_CTX="${2:-}"; shift 2 ;;
    --dockerfile) DOCKERFILE="${2:-}"; shift 2 ;;
    --registry-user) REG_USER="${2:-}"; shift 2 ;;
    --registry-pass) REG_PASS="${2:-}"; shift 2 ;;
    --config) CONFIG_FILE="${2:-}"; shift 2 ;;
    --profile) PROFILE_FILE="${2:-}"; shift 2 ;;
    --repo-config) REPO_CONFIG_FILE="${2:-}"; shift 2 ;;
    --no-repo-config) shift ;;   # the launcher's: it simply passes no repo files
    --baseline) BASELINE_FILE="${2:-}"; shift 2 ;;
    --reports) REPORTS_DIR="${2:-}"; shift 2 ;;
    --name) PROJECT_NAME="${2:-}"; shift 2 ;;
    --fail-on) FAIL_ON_OVERRIDE="${2:-}"; shift 2 ;;
    --min-confidence) export ASS_MIN_CONFIDENCE="${2:-}"; shift 2 ;;
    --strict) export ASS_STRICT=1; shift ;;
    --require-pinned) export ASS_REQUIRE_PINNED=1; shift ;;
    --update-baseline) export ASS_UPDATE_BASELINE=1; shift ;;
    --json) shift ;;   # handled above
    --diff)
      [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || {
        echo "Error: --diff needs a base ref, e.g. --diff origin/main" >&2; exit $EXIT_USAGE; }
      DIFF_BASE="$2"; shift 2 ;;
    -v|--version)
      here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
      # --version answers in text even with --json: it is not a scan.
      if [[ $JSON == 1 ]]; then exec 1>&3; JSON=0; fi
      echo "appsec-compose $(cat "$here/VERSION" 2>/dev/null || echo unknown)"
      # Re-render so the refs shown are the ones a scan would actually use —
      # into a throwaway dir, so --version never touches any run's state.
      tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
      python3 "$here/scripts/render-env.py" --out-dir "$tmp" >/dev/null 2>&1 || true
      python3 - "$tmp/.env" <<'PYEOF'
import re, sys
try:
    lines = open(sys.argv[1]).read().splitlines()
except OSError:
    sys.exit("  (could not resolve engine versions)")
# ASS_* are runtime settings, not engines.
found = False
for line in lines:
    m = re.match(r"^(?!ASS_)([A-Z]+)_IMAGE='(.*)'$", line)
    if m:
        found = True
        print(f"  {m.group(1).lower()}: {m.group(2)}")
if not found:
    print("  (no engines resolved)")
PYEOF
      exit 0 ;;
    -h|--help) usage ;;
    -*) echo "Unknown argument: $1" >&2; usage ;;
    *) TARGET="$1"; shift ;;
  esac
done

# Resolve every user-supplied path against the caller's directory, then work
# from the tool directory (compose resolves its ./cache etc. relative to it).
abspath() { [[ "$1" = /* ]] && echo "$1" || echo "$CALLER_PWD/$1"; }
[[ -n "$TARGET" ]] && TARGET="$(abspath "$TARGET")"
[[ -n "$BUILD_CTX" ]] && BUILD_CTX="$(abspath "$BUILD_CTX")"
[[ -n "$DOCKERFILE" ]] && DOCKERFILE="$(abspath "$DOCKERFILE")"
[[ -n "$CONFIG_FILE" ]] && CONFIG_FILE="$(abspath "$CONFIG_FILE")"
[[ -n "$PROFILE_FILE" ]] && PROFILE_FILE="$(abspath "$PROFILE_FILE")"
[[ -n "$REPO_CONFIG_FILE" ]] && REPO_CONFIG_FILE="$(abspath "$REPO_CONFIG_FILE")"
[[ -n "$REPORTS_DIR" ]] && REPORTS_DIR="$(abspath "$REPORTS_DIR")"
[[ -n "$BASELINE_FILE" ]] && BASELINE_FILE="$(abspath "$BASELINE_FILE")"
# The vulnerability-DB cache: ./cache by default; the CLI points it at the
# user's cache dir so an installed copy keeps no state of its own.
ASS_CACHE_DIR="$(abspath "${ASS_CACHE_DIR:-$SCRIPT_DIR/cache}")"; export ASS_CACHE_DIR
cd "$SCRIPT_DIR"

# Resolve the per-project state paths (defaults keep the single-project layout).
if [[ -n "$CONFIG_FILE" ]]; then
  [[ -f "$CONFIG_FILE" ]] || { echo "Error: config '$CONFIG_FILE' not found" >&2; exit $EXIT_USAGE; }
fi
if [[ -n "$REPO_CONFIG_FILE" ]]; then
  [[ -f "$REPO_CONFIG_FILE" ]] || { echo "Error: config '$REPO_CONFIG_FILE' not found" >&2; exit $EXIT_USAGE; }
fi
if [[ -n "$PROFILE_FILE" ]]; then
  [[ -f "$PROFILE_FILE" ]] || { echo "Error: profile '$PROFILE_FILE' not found" >&2; exit $EXIT_USAGE; }
fi
if [[ -n "$REPORTS_DIR" ]]; then
  mkdir -p "$REPORTS_DIR/native"
  ASS_REPORTS_DIR="$REPORTS_DIR"; export ASS_REPORTS_DIR
fi
if [[ -n "$BASELINE_FILE" ]]; then
  [[ -f "$BASELINE_FILE" ]] || printf '{"fingerprints": []}' > "$BASELINE_FILE"
  ASS_BASELINE_FILE="$BASELINE_FILE"; export ASS_BASELINE_FILE
fi
# Namespace the containers so two projects never collide on service names.
if [[ -n "$PROJECT_NAME" ]]; then
  slug="$(printf '%s' "$PROJECT_NAME" | tr '[:upper:]' '[:lower:]' | tr -cs '[:alnum:]_-' '-')"
  COMPOSE_PROJECT_NAME="appsec-${slug%-}"
  export COMPOSE_PROJECT_NAME
fi
# Per-run state: the rendered .env, the generated excludes/, a saved image tar
# (build mode) and registry credentials. Private to this run so concurrent runs
# never overwrite each other's config, and removed on exit so credentials don't
# outlive the scan. It sits in the tool directory rather than $TMPDIR because
# Docker must be able to bind-mount it: with a socket-mounted CI runner the
# daemon sees the build dir on the same path, but not the job's /tmp.
mkdir -p .run
RUN_DIR="$(mktemp -d "$SCRIPT_DIR/.run/run.XXXXXX")"   # on_exit removes it
ASS_EXCLUDES_DIR="$RUN_DIR/excludes"; ASS_ARCHIVE_DIR="$RUN_DIR/archive"
export ASS_EXCLUDES_DIR ASS_ARCHIVE_DIR
mkdir -p "$ASS_EXCLUDES_DIR" "$ASS_ARCHIVE_DIR"

# A project config is laid over the shipped defaults rather than replacing
# them, so it states only what differs. Both render-env and the collector read
# the merged result. Overlays apply in order: a profile first, so the project's
# own config (its suppressions, above all) wins over it.
overlays=()
if [[ -n "$PROFILE_FILE" ]]; then overlays+=("$PROFILE_FILE"); fi
if [[ -n "$CONFIG_FILE" ]]; then overlays+=("$CONFIG_FILE"); fi
# The repo's own file is not trusted like the two above: whoever controls the
# scanned repository wrote it, so only project policy applies from it (see
# effective-config.py), and what it did goes into the reports.
if [[ -n "$REPO_CONFIG_FILE" ]]; then overlays+=(--repo "$REPO_CONFIG_FILE"); fi
if [[ ${#overlays[@]} -gt 0 ]]; then
  ASS_REPO_CONFIG="$(python3 scripts/effective-config.py "$SCRIPT_DIR/scan-config.yml" "${overlays[@]}" \
    "$RUN_DIR/scan-config.yml")" || {
    rc=$?; [[ $rc == "$EXIT_USAGE" ]] || rc=$EXIT_SCAN; exit $rc; }
  export ASS_REPO_CONFIG
  ASS_CONFIG_FILE="$RUN_DIR/scan-config.yml"; export ASS_CONFIG_FILE
fi

# Every compose call reads this run's .env, never the tool directory's.
compose() { docker compose --env-file "$RUN_DIR/.env" "$@"; }

# Empty dir for the (unused) /code mount in image mode; in-project so Docker can
# always bind-mount it. Shared: nothing ever writes to it.
mkdir -p .img-empty

# The collector runs non-root; give it the host identity so it can write into
# the bind-mounted reports/ and appsec-baseline.json.
ASS_UID="$(id -u)"; ASS_GID="$(id -g)"
export ASS_UID ASS_GID

# Derive the registry host from an image ref (for the docker auth config key).
registry_of() {
  local ref="$1" first="${1%%/*}"
  if [[ "$ref" == */* && ( "$first" == *.* || "$first" == *:* || "$first" == "localhost" ) ]]; then
    echo "$first"
  else
    echo "https://index.docker.io/v1/"
  fi
}

IMAGE_MODE=0; TARGET_LABEL=""
if [[ -n "$BUILD_CTX" ]]; then
  IMAGE_MODE=1
  [[ -e "$BUILD_CTX" ]] || { echo "Error: build context '$BUILD_CTX' not found" >&2; exit $EXIT_USAGE; }
  tag="appsec-compose-build:scan"
  echo "Building image from $BUILD_CTX ..."
  # A target that does not build is a problem with the input, not the scan.
  build_args=(-t "$tag")
  [[ -n "$DOCKERFILE" ]] && build_args+=(-f "$DOCKERFILE")
  docker build "${build_args[@]}" "$BUILD_CTX" \
    || { echo "Error: could not build $BUILD_CTX" >&2; exit $EXIT_USAGE; }
  docker save "$tag" -o "$ASS_ARCHIVE_DIR/image.tar"
  export ASS_IMAGE_TAR="/archive/image.tar"
  SCAN_TARGET="$SCRIPT_DIR/.img-empty"
  TARGET_LABEL="built image from $BUILD_CTX"
elif [[ -n "$IMAGE_REF" ]]; then
  IMAGE_MODE=1
  export ASS_IMAGE="$IMAGE_REF"
  SCAN_TARGET="$SCRIPT_DIR/.img-empty"
  TARGET_LABEL="image $IMAGE_REF"
  if [[ -n "$REG_USER" && -n "$REG_PASS" ]]; then
    reg="$(registry_of "$IMAGE_REF")"
    b64="$(printf '%s:%s' "$REG_USER" "$REG_PASS" | base64 | tr -d '\n')"
    mkdir -p "$RUN_DIR/docker-auth"
    printf '{"auths":{"%s":{"auth":"%s"}}}' "$reg" "$b64" > "$RUN_DIR/docker-auth/config.json"
    chmod 600 "$RUN_DIR/docker-auth/config.json"
    export ASS_DOCKER_CONFIG="$RUN_DIR/docker-auth"
    echo "Registry auth : configured for $reg"
  fi
elif [[ -n "$TARGET" ]]; then
  [[ -d "$TARGET" ]] || { echo "Error: target '$TARGET' is not a directory" >&2; exit $EXIT_USAGE; }
  SCAN_TARGET="$(cd "$TARGET" && pwd)"
  TARGET_LABEL="$SCAN_TARGET"
else
  usage
fi
export SCAN_TARGET

# Reports written inside the scanned tree would be read back by the scanners —
# this run's while they are being written, and the next run's as findings.
# Exclude the directory through the same `exclude:` machinery (by its path
# relative to the target, so like any entry it matches that name anywhere).
if [[ "$IMAGE_MODE" != "1" ]]; then
  reports_real="$(mkdir -p "${REPORTS_DIR:-$SCRIPT_DIR/reports}" && cd "${REPORTS_DIR:-$SCRIPT_DIR/reports}" && pwd -P)"
  target_real="$(cd "$SCAN_TARGET" && pwd -P)"
  if [[ "$reports_real" == "$target_real" ]]; then
    echo "Error: the reports directory must not be the scan target itself" >&2; exit $EXIT_USAGE
  elif [[ "$reports_real" == "$target_real"/* ]]; then
    ASS_EXTRA_EXCLUDES="${reports_real#"$target_real"/}"; export ASS_EXTRA_EXCLUDES
    echo "Excluded : $ASS_EXTRA_EXCLUDES (the reports directory, inside the target)"
  fi
fi

# Diff mode scans the files a change touched, so it needs a repository, and
# a baseline snapshot of a partial scan would forget every finding outside it.
if [[ -n "$DIFF_BASE" ]]; then
  [[ "$IMAGE_MODE" == "1" ]] && {
    echo "Error: --diff scans a repository's changes; it cannot be combined with --image/--build" >&2
    exit $EXIT_USAGE; }
  [[ "${ASS_UPDATE_BASELINE:-}" == "1" ]] && {
    echo "Error: --update-baseline needs a full scan; drop --diff to snapshot the baseline" >&2
    exit $EXIT_USAGE; }
fi

# Render scan-config.yml -> this run's .env + excludes/ (versions + flags) and
# read the enabled list. render-env reads ASS_IMAGE to pick filesystem vs image
# targets. Command substitution hides a non-zero exit, so capture first and
# propagate: render-env fails deliberately (e.g. require_pinned with an
# incomplete lock).
# render-env exits 2 for a config problem; anything else is a crash.
render_out="$(python3 scripts/render-env.py --out-dir "$RUN_DIR")" || {
  rc=$?; [[ $rc == "$EXIT_USAGE" ]] || rc=$EXIT_SCAN; exit $rc; }
eval "$render_out"
[[ -n "$FAIL_ON_OVERRIDE" ]] && export FAIL_ON="$FAIL_ON_OVERRIDE"

# Cache stays global: the vulnerability DBs are shared across every project.
REPORTS="${ASS_REPORTS_DIR:-$SCRIPT_DIR/reports}"
mkdir -p "$REPORTS/native" "$ASS_CACHE_DIR/semgrep" "$ASS_CACHE_DIR/trivy" \
         "$ASS_CACHE_DIR/grype" semgrep-rules

# Clear last run's native reports. A scanner that is disabled (or that now
# fails) would otherwise leave a stale SARIF behind, which CI's hashFiles()
# guards would happily upload as if it were current.
rm -f "$REPORTS"/native/*.sarif "$REPORTS"/native/*.json
rm -f "$REPORTS"/sbom.*.json
# Same for the consolidated reports: their absence after the collector is how
# a collector that never ran is told apart from one that returned a verdict.
rm -f "$REPORTS"/findings.json "$REPORTS"/summary.md "$REPORTS"/summary.html \
      "$REPORTS"/review-brief.md
REPORTS_CLEARED=1   # from here on, a findings.json in $REPORTS is this run's
# Ensure the baseline file exists so Docker can bind-mount it (empty = no baseline).
BASELINE="${ASS_BASELINE_FILE:-$SCRIPT_DIR/appsec-baseline.json}"
[[ -f "$BASELINE" ]] || echo '{"fingerprints": []}' > "$BASELINE"

# In image mode keep only image-capable scanners.
if [[ "$IMAGE_MODE" == "1" ]]; then
  keep=""
  for s in $ASS_ENABLED; do [[ "$IMAGE_TOOLS" == *" $s "* ]] && keep="$keep $s"; done
  ASS_ENABLED="$(echo "$keep" | xargs || true)"
  [[ -z "$ASS_ENABLED" ]] && { echo "Error: image mode needs trivy/grype/syft enabled" >&2; exit $EXIT_USAGE; }
fi

if [[ -z "${ASS_ENABLED// }" ]]; then
  echo "Error: no scanners enabled in scan-config.yml" >&2; exit $EXIT_USAGE
fi
export ASS_ENABLED   # tell the collector which scanners are configured to run

# Diff mode: work out the changed set on the host and narrow the engines to it
# (scripts/diff-scope.py). Engines with nothing in scope are not started; the
# collector learns which, and why, from the run's diff/scope.json.
RUN_ENGINES="$ASS_ENABLED"; DIFF_SUMMARY=""
if [[ -n "$DIFF_BASE" ]]; then
  diff_out="$(python3 scripts/diff-scope.py --target "$SCAN_TARGET" --base "$DIFF_BASE" \
      --enabled "$ASS_ENABLED" --env-file "$RUN_DIR/.env" --out-dir "$RUN_DIR/diff")" || {
    rc=$?; [[ $rc == "$EXIT_USAGE" ]] || rc=$EXIT_SCAN; exit $rc; }
  eval "$diff_out"
  RUN_ENGINES="$DIFF_RUN_ENGINES"
fi

if [[ "$ASS_OFFLINE" == "1" && "$IMAGE_MODE" != "1" && ! -s "$ASS_CACHE_DIR/semgrep/default.yaml" ]]; then
  echo "Error: offline=true but no cache found in $ASS_CACHE_DIR. Run ./preload.sh first (with network)." >&2
  exit $EXIT_USAGE
fi

# The prebuilt collector when it matches this checkout, else a local build —
# resolved here, before the scanners spend minutes, never by compose itself.
offline_flag=""; [[ "$ASS_OFFLINE" == "1" ]] && offline_flag="--offline"
ASS_COLLECTOR_IMAGE="$(scripts/collector-image.sh $offline_flag)" || exit $EXIT_SCAN
export ASS_COLLECTOR_IMAGE

[[ -n "$PROFILE_FILE" ]] && echo "Profile  : $PROFILE_FILE (over the shipped defaults)"
[[ -n "$CONFIG_FILE" ]] && echo "Config   : $CONFIG_FILE (over the shipped defaults)"
[[ -n "$REPO_CONFIG_FILE" ]] && echo "Config   : $REPO_CONFIG_FILE (the repository's own; project policy only)"
[[ -n "${ASS_REPORTS_DIR:-}" ]] && echo "Reports  : $ASS_REPORTS_DIR"
echo "Target   : $TARGET_LABEL"
echo "Scanners : ${RUN_ENGINES:-none}"
[[ -n "$DIFF_SUMMARY" ]] && echo "$DIFF_SUMMARY"
echo "Mode     : $([[ "$ASS_OFFLINE" == "1" ]] && echo offline || echo online)"
[[ -n "${FAIL_ON_OVERRIDE}" ]] && echo "fail_on  : $FAIL_ON_OVERRIDE (override)"
[[ -n "${ASS_MIN_CONFIDENCE:-}" ]] && echo "gate     : rules of ${ASS_MIN_CONFIDENCE} confidence and above"
[[ "${ASS_STRICT:-}" == "1" ]] && echo "strict   : a missing scanner report fails the run"
[[ "${ASS_UPDATE_BASELINE:-}" == "1" ]] && echo "baseline : updating snapshot"

compose down --remove-orphans >/dev/null 2>&1 || true

# Run the enabled scanners in parallel (one-shot). Plain `up` (no
# --abort-on-container-exit) waits for every listed service to finish.
# A diff that touched nothing any engine reads starts none; the collector still
# runs, so there is a findings.json that says so.
scan_start="$(date +%s)"
if [[ -n "${RUN_ENGINES// }" ]]; then
  # shellcheck disable=SC2086
  compose up --no-deps $RUN_ENGINES
fi
# How long each engine ran, from Docker's own start/finish times — read now,
# before `compose down` removes the one-shot containers. The scanners run in
# parallel, so the slowest one is what a scan costs.
ASS_SCAN_SECONDS="$(( $(date +%s) - scan_start ))"
# shellcheck disable=SC2046,SC2086
ASS_ENGINE_TIMINGS="$(python3 scripts/engine-timings.py \
  $(compose ps -a -q $RUN_ENGINES 2>/dev/null))" || ASS_ENGINE_TIMINGS="{}"
export ASS_SCAN_SECONDS ASS_ENGINE_TIMINGS
# DB dates as of now, for the engines that ran: a scan may have refreshed a DB,
# and a skipped engine's DB says nothing about this report. The shell env
# outranks --env-file in compose interpolation.
# shellcheck disable=SC2086
ASS_DB_DATES="$(python3 scripts/render-env.py --db-dates $RUN_ENGINES)" || ASS_DB_DATES="{}"
export ASS_DB_DATES

# Collector reads the reports and returns the policy exit code. --no-deps so it
# doesn't re-trigger the scanners via depends_on; no --build: the image was
# resolved above.
# `|| code=$?`, not set +e: the ERR trap fires regardless of set -e, and
# would turn a "fail" verdict into a broken scan.
code=0
compose run --rm --no-deps collector || code=$?
# Compose reports its own failures (an image that does not build, a daemon
# that went away) as 1 too. A real verdict always leaves a findings.json,
# except when only the baseline was being snapshotted.
verdict_written=0
[[ -s "$REPORTS/findings.json" || "${ASS_UPDATE_BASELINE:-}" == "1" ]] && verdict_written=1
case "$code" in
  "$EXIT_PASS"|"$EXIT_POLICY")
    if [[ $verdict_written == 0 ]]; then
      echo "Error: the collector did not produce a verdict (exit $code)" >&2
      code=$EXIT_SCAN
    fi ;;
  "$EXIT_USAGE"|"$EXIT_SCAN") ;;
  *) echo "Error: the collector failed (exit $code)" >&2; code=$EXIT_SCAN ;;
esac

compose down --remove-orphans >/dev/null 2>&1 || true

echo
echo "Done. See $REPORTS/summary.md (exit code: $code)"
exit "$code"
