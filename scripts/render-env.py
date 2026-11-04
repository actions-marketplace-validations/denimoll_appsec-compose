#!/usr/bin/env python3
"""Render scan-config.yml into a Docker Compose .env file.

Single source of truth = scan-config.yml. This writes `.env` (which Compose
loads automatically) with the resolved scanner image refs and the online/offline
behaviour flags, and prints a few shell-evalable lines for run.sh to consume:

    ASS_ENABLED='semgrep trivy gitleaks checkov'
    ASS_OFFLINE=0

Image pinning: if image-digests.lock maps a tool's `repo:tag` to a
`repo@sha256:...` digest (written by ./pin.sh), the resolved <TOOL>_IMAGE uses
the digest; otherwise it uses the plain tag. <TOOL>_TAGREF always holds the tag
form (consumed by pin.sh).

Output: `.env` and `excludes/` go to the tool directory by default (what a raw
`docker compose`, pin.sh and preload.sh read). `--out-dir DIR` writes them to
DIR instead — run.sh renders into a private per-run directory so concurrent
runs never overwrite each other.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    # Exit 2 (setup problem), not sys.exit(msg)'s 1, which reads as a verdict.
    print("ERROR: PyYAML is required on the host: pip3 install pyyaml", file=sys.stderr)
    sys.exit(2)


def _load_schema():
    """The collector owns the schema; load it by path so there is one copy."""
    import importlib.util
    path = Path(__file__).resolve().parent.parent / "orchestrator" / "schema.py"
    spec = importlib.util.spec_from_file_location("ass_schema", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "VERSION"
# ASS_CONFIG_FILE (./run.sh --config) lets one clone drive several projects.
CFG = Path(os.environ.get("ASS_CONFIG_FILE") or ROOT / "scan-config.yml")
LOCK = ROOT / "image-digests.lock"

# tool -> (docker repo, default version, env-var prefix)
TOOLS = {
    "semgrep": ("semgrep/semgrep", "1.174.0", "SEMGREP"),
    "trivy": ("aquasec/trivy", "0.74.0", "TRIVY"),
    "gitleaks": ("zricethezav/gitleaks", "v8.30.1", "GITLEAKS"),
    "checkov": ("bridgecrew/checkov", "3.3.13", "CHECKOV"),
    "grype": ("anchore/grype", "v0.117.0", "GRYPE"),
    "trufflehog": ("trufflesecurity/trufflehog", "3.97.0", "TRUFFLEHOG"),
    "syft": ("anchore/syft", "v1.51.0", "SYFT"),
    "hadolint": ("hadolint/hadolint", "v2.15.1-alpine", "HADOLINT"),
    "osv": ("ghcr.io/google/osv-scanner", "v2.5.1", "OSV"),
    "zizmor": ("ghcr.io/zizmorcore/zizmor", "1.31.1", "ZIZMOR"),
}

# Registry pack fetched offline by preload.sh; used as a local file when offline.
SEMGREP_ONLINE_RULES = "p/default"
SEMGREP_OFFLINE_RULES = "/cache/semgrep/default.yaml"
TRIVY_OFFLINE_FLAGS = "--skip-db-update --skip-java-db-update --offline-scan"

# Local drop-in rules dir (mounted into the semgrep container at /semgrep-rules).
SEMGREP_RULES_DIR = "semgrep-rules"

# Stack auto-detect: file extension / name -> Semgrep registry pack.
_EXT_PACKS = {
    ".py": "p/python", ".js": "p/javascript", ".jsx": "p/javascript",
    ".ts": "p/typescript", ".tsx": "p/typescript", ".go": "p/golang",
    ".java": "p/java", ".rb": "p/ruby", ".php": "p/php", ".cs": "p/csharp",
    ".kt": "p/kotlin", ".scala": "p/scala", ".rs": "p/rust", ".tf": "p/terraform",
}
_NAME_PACKS = {"dockerfile": "p/dockerfile"}
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv",
              "venv", "__pycache__", ".idea", ".gradle", "target"}

# Directories excluded from every engine unless scan-config.yml overrides
# `exclude:`. These are build output and dependency trees: scanning them buries
# real findings in vendored noise and dominates the runtime.
DEFAULT_EXCLUDES = [
    ".git", "node_modules", "vendor", "dist", "build", "target",
    ".venv", "venv", "__pycache__", ".gradle", ".tox", ".mypy_cache",
]

# Generated per-engine configs (gitleaks TOML, trufflehog regex list, zizmor's
# fallback policy) live here and are mounted into the containers at /excludes.
EXCLUDES_DIR = "excludes"

# zizmor's policy when the scanned repo brings no zizmor.yml of its own.
# Since zizmor 1.20 `unpinned-uses` demands a commit SHA for *every* action and
# rates each tag reference high, so practically every repository that uses
# GitHub's own actions by tag (`actions/checkout@v5`) fails a `high` gate on
# day one: 19 such findings on this repository, 13 of 28 on DVWA. Tags of
# GitHub-owned actions share a trust root with the runner itself; third-party
# tags are the tj-actions/changed-files risk and stay hash-pin. This is the
# policy zizmor shipped before 1.20 and documents as the opt-out. A repo's own
# `zizmor.yml` / `.github/zizmor.yml` replaces it entirely.
ZIZMOR_DEFAULT_POLICY = """\
rules:
  unpinned-uses:
    config:
      policies:
        actions/*: ref-pin
        github/*: ref-pin
        dependabot/*: ref-pin
        "*": hash-pin
"""


def _path_regex(pattern: str) -> str:
    """A directory name / simple glob as a path regex (checkov, gitleaks, trufflehog)."""
    body = "".join(".*" if ch == "*" else re.escape(ch) for ch in pattern)
    return f"(^|/){body}(/|$)"


def _exclude_flags(patterns: list[str]) -> dict[str, str]:
    """Translate exclude entries into each engine's own exclusion syntax.

    An entry is a directory name ("node_modules") or a path glob ("docs/**").
    Engines that take no exclusion flag (gitleaks, trufflehog) get a generated
    config file instead — see _write_exclude_files.
    """
    semgrep, trivy, checkov, anchore, osv, hadolint = [], [], [], [], [], []
    zizmor: list[str] = []
    # Trivy separates directory and file exclusions; a glob may name either, so
    # a glob entry goes to both lists.
    for raw in patterns:
        pat = str(raw).strip().strip("/")
        if not pat:
            continue
        is_glob = any(c in pat for c in "*?[")
        # No inner quoting: these land in .env (whose parser has no escapes) and
        # are word-split by the container shell, which runs with `set -f` so the
        # glob patterns reach the engine unexpanded.
        semgrep.append(f"--exclude={pat}")
        if is_glob:
            trivy.extend([f"--skip-dirs={pat}", f"--skip-files={pat}"])
        elif "/" in pat:
            trivy.append(f"--skip-dirs={pat}")
        else:
            trivy.append(f"--skip-dirs=**/{pat}")
        checkov.append(f"--skip-path={_path_regex(pat)}")
        anchore.extend([f"./{pat}", f"./**/{pat}"] if is_glob
                       else [f"./{pat}/**", f"./**/{pat}/**"])
        if not is_glob:
            osv.append(f"--experimental-exclude={pat}")
        hadolint.extend(["-not", "-path", f"*/{pat}/*"])
        zizmor.extend(["-not", "-path", f"*/{pat}/*"])
    return {
        "SEMGREP_EXCLUDES": " ".join(semgrep),
        "TRIVY_SKIP_DIRS": " ".join(trivy),
        "CHECKOV_SKIP_PATHS": " ".join(checkov),
        # grype/syft ship no shell, so their exclusions go through the env vars
        # they read (comma-separated) rather than the command line.
        "GRYPE_EXCLUDE": ",".join(anchore),
        "SYFT_EXCLUDE": ",".join(anchore),
        "OSV_EXCLUDES": " ".join(osv),
        "HADOLINT_PRUNE": " ".join(hadolint),
        # zizmor honours .gitignore but takes no exclusion flag, so compose
        # collects its inputs with find and prunes them with these.
        "ZIZMOR_PRUNE": " ".join(zizmor),
    }


def _write_exclude_files(patterns: list[str], out: Path) -> None:
    """Generate the exclude configs for engines that take no exclusion flag."""
    out.mkdir(parents=True, exist_ok=True)
    regexes = [_path_regex(str(p).strip().strip("/")) for p in patterns
               if str(p).strip()]
    header = "# Generated from scan-config.yml by scripts/render-env.py — do not edit.\n"

    # Gitleaks: extend the bundled ruleset with a path allowlist.
    toml = header + "[extend]\nuseDefault = true\n"
    if regexes:
        paths = ",\n".join("    '''" + r + "'''" for r in regexes)
        toml += ('\n[[allowlists]]\ndescription = "appsec-compose exclude:"\n'
                 f"paths = [\n{paths}\n]\n")
    (out / "gitleaks.toml").write_text(toml)

    # TruffleHog: newline-separated regexes of paths to skip.
    (out / "trufflehog.txt").write_text("\n".join(regexes) + ("\n" if regexes else ""))

    # zizmor: not an exclusion list, but per-run engine config all the same.
    (out / "zizmor.yml").write_text(header + ZIZMOR_DEFAULT_POLICY)



# ---- Checkov: run only the frameworks the repository has files for ---------
# Checkov walks the whole tree once per framework, files or not; the detection
# (orchestrator/projectprofile.py, shared with the `profile` command and the
# review brief) errs towards running a framework.

def _load_profile():
    import importlib.util
    path = Path(__file__).resolve().parent.parent / "orchestrator" / "projectprofile.py"
    spec = importlib.util.spec_from_file_location("ass_projectprofile", path)
    module = importlib.util.module_from_spec(spec)
    # Registered first: dataclasses resolve their annotations through it.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _checkov_frameworks(target: str, excludes: list[str]) -> list[str] | None:
    """The Checkov frameworks `target` has files for; None = run them all."""
    return _load_profile().iac_frameworks(target, excludes)


def _checkov_flags(scanners: dict, target: str, excludes: list[str]) -> str:
    """CHECKOV_FRAMEWORKS for compose: a list, "all" (every framework but
    secrets), or "none" (nothing to check: Checkov is not started)."""
    chosen = (scanners.get("checkov") or {}).get("frameworks")
    if chosen is not None:                 # the user decides
        chosen = [chosen] if isinstance(chosen, str) else list(chosen)
        return "all" if "all" in chosen else " ".join(chosen) or "none"
    found = _checkov_frameworks(target, excludes)
    if found is None:
        return "all"
    return " ".join(found) or "none"


def _autodetect_packs() -> list[str]:
    """Detect the repo's stack and map it to Semgrep registry packs."""
    target = os.environ.get("SCAN_TARGET", "")
    if not target or not Path(target).is_dir():
        return []
    packs: list[str] = []
    seen = set()
    scanned = 0
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            scanned += 1
            pack = _NAME_PACKS.get(fn.lower()) or _EXT_PACKS.get(Path(fn).suffix.lower())
            if pack and pack not in seen:
                seen.add(pack)
                packs.append(pack)
        if scanned > 20000 or len(seen) == len(set(_EXT_PACKS.values()) | set(_NAME_PACKS.values())):
            break
    return packs


def _semgrep_configs(scanners: dict, offline: bool) -> str:
    """Build the `--config ...` argument string for semgrep from scan-config."""
    default = SEMGREP_OFFLINE_RULES if offline else SEMGREP_ONLINE_RULES
    rules = (scanners.get("semgrep") or {}).get("rules", None)

    configs: list[str] = []
    if rules is None:
        configs.append(default)                 # default behaviour
    else:
        for r in rules:
            r = str(r).strip()
            if r == "default":
                configs.append(default)
            elif r == "auto":
                configs.extend(_autodetect_packs() if not offline else [default])
            elif r:
                configs.append(r)               # registry ref or container path

    # Local drop-in rules, if any rule files (*.yml/*.yaml) are present.
    rules_dir = ROOT / SEMGREP_RULES_DIR
    if rules_dir.is_dir() and (any(rules_dir.rglob("*.yml")) or any(rules_dir.rglob("*.yaml"))):
        configs.append("/semgrep-rules")

    # De-duplicate (preserve order); never end up with nothing.
    seen, ordered = set(), []
    for c in configs:
        if c and c not in seen:
            seen.add(c)
            ordered.append(c)
    if not ordered:
        ordered.append(default)

    return " ".join(f"--config {c}" for c in ordered)


def _image_ref(repo: str, ver: str) -> str:
    """Build an image ref from a `version` that may be a tag OR a digest.

    `1.97.0`            -> repo:1.97.0
    `sha256:abc...`     -> repo@sha256:abc...
    `@sha256:abc...`    -> repo@sha256:abc...
    """
    ver = ver.strip()
    if ver.startswith("@"):
        return f"{repo}{ver}"
    if ver.startswith("sha256:"):
        return f"{repo}@{ver}"
    return f"{repo}:{ver}"


def _version() -> str:
    try:
        return VERSION_FILE.read_text().strip()
    except OSError:
        return "unknown"


_GRYPE_V6_BUILT = re.compile(r"_(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)_")


def _db_dates(engines: set[str] | None = None) -> dict[str, str]:
    """When each vulnerability database that `engines` used was built.

    A scan is only as current as its DB, so the report should say how old it
    was — a clean result from a three-week-old database is not a clean result.
    run.sh asks again after the scanners ran (--db-dates): an engine that
    refreshed its DB during the scan must report the new date, and an engine
    that did not run must report none.
    """
    dates: dict[str, str] = {}
    # ASS_CACHE_DIR: run.sh's cache location (the CLI keeps it in ~/.cache).
    cache = Path(os.environ.get("ASS_CACHE_DIR") or ROOT / "cache")
    if engines is None or "trivy" in engines:
        try:
            meta = cache / "trivy" / "db" / "metadata.json"
            dates["trivy"] = json.loads(meta.read_text())["UpdatedAt"]
        except (OSError, KeyError, ValueError):
            pass
    if engines is None or "grype" in engines:
        for meta in sorted((cache / "grype").glob("*/metadata.json")):
            try:
                built = json.loads(meta.read_text()).get("built")
                if built:
                    dates["grype"] = built
            except (OSError, ValueError):
                pass
        # DB schema v6 (grype >= 0.88) has no metadata.json; the build time is
        # only in the archive name that import.json records.
        for imp in sorted((cache / "grype").glob("*/import.json")):
            try:
                m = _GRYPE_V6_BUILT.search(json.loads(imp.read_text()).get("source", ""))
            except (OSError, ValueError):
                continue
            if m:
                dates["grype"] = m.group(1)
    return dates


def _load_lock() -> dict[str, str]:
    """Map `repo:tag` -> `repo@sha256:...` from image-digests.lock."""
    pins: dict[str, str] = {}
    if LOCK.exists():
        for line in LOCK.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tag, _, digest = line.partition(" ")
            if tag and digest:
                pins[tag] = digest.strip()
    return pins


def _is_pinned(env: dict[str, str], prefix: str, pins: dict[str, str]) -> bool:
    """True when the resolved image ref is a digest (from the lock or a manual pin)."""
    return "@sha256:" in env.get(f"{prefix}_IMAGE", "")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render scan-config.yml into .env")
    parser.add_argument("--out-dir", type=Path, default=ROOT,
                        help="where to write .env and excludes/ (default: the tool directory)")
    parser.add_argument("--db-dates", nargs="*", metavar="ENGINE",
                        help="print the DB build dates of these engines as JSON and exit")
    args = parser.parse_args(argv)
    if args.db_dates is not None:
        print(json.dumps(_db_dates(set(args.db_dates)), separators=(",", ":")))
        return 0
    out_dir = args.out_dir.resolve()

    try:
        cfg = yaml.safe_load(CFG.read_text()) or {}
    except OSError as exc:
        print(f"ERROR: cannot read {CFG}: {exc.strerror}", file=sys.stderr)
        return 2
    except yaml.YAMLError as exc:
        print(f"ERROR: {CFG.name} is not valid YAML: {exc}", file=sys.stderr)
        return 2
    if not isinstance(cfg, dict):
        print(f"ERROR: {CFG.name} must be a mapping of settings", file=sys.stderr)
        return 2
    # Fail on the host, before a single container starts, and name every problem.
    try:
        _load_schema().check(cfg, known_scanners=set(TOOLS))
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    scanners = cfg.get("scanners", {}) or {}
    offline = bool(cfg.get("offline", False))
    pins = _load_lock()

    # Scan target (set by run.sh): a docker-archive tar (build mode), a registry
    # image ref (--image), or the repo filesystem mounted at /code.
    image = os.environ.get("ASS_IMAGE", "").strip()
    tar = os.environ.get("ASS_IMAGE_TAR", "").strip()
    if tar:
        grype_target = syft_target = f"docker-archive:{tar}"
    elif image:
        grype_target = syft_target = image
    else:
        grype_target = syft_target = "dir:/code"

    sbom_on = bool(cfg.get("sbom", True))
    formats = cfg.get("sbom_formats", ["cyclonedx"]) or []
    formats = [str(f).lower() for f in formats]

    def version(name: str, default: str) -> str:
        return str((scanners.get(name) or {}).get("version", default))

    enabled = [n for n, c in scanners.items() if (c or {}).get("enabled", True)]

    # `exclude:` omitted -> recommended defaults; an explicit (possibly empty)
    # list replaces them entirely.
    raw_excludes = cfg.get("exclude", None)
    excludes = DEFAULT_EXCLUDES if raw_excludes is None else list(raw_excludes or [])
    # Added by run.sh on top of either (one path per line): its own reports
    # directory when that lies inside the target.
    excludes = excludes + [e for e in os.environ.get("ASS_EXTRA_EXCLUDES", "").splitlines()
                           if e.strip() and e not in excludes]
    _write_exclude_files(excludes, out_dir / EXCLUDES_DIR)

    # Gitleaks scans the working tree by default; `secrets_history` walks the
    # full history and `secrets_history_range` narrows it to a commit range
    # (e.g. "origin/main..HEAD" — the PR's own commits instead of everything).
    history_range = str(cfg.get("secrets_history_range", "") or "").strip()
    history = bool(cfg.get("secrets_history", False)) or bool(history_range)

    licenses = cfg.get("licenses") or {}
    license_policy = bool(licenses.get("deny") or licenses.get("warn"))
    if license_policy and "trivy" not in enabled:
        print("warning: licenses: is set but trivy is disabled, so no license "
              "is checked", file=sys.stderr)

    env: dict[str, str] = {}
    for tool, (repo, default_ver, prefix) in TOOLS.items():
        ver = version(tool, default_ver)
        # `version` may already be a digest (manual per-tool pin); honour it.
        tagref = _image_ref(repo, ver)
        env[f"{prefix}_VERSION"] = ver
        env[f"{prefix}_TAGREF"] = tagref
        env[f"{prefix}_IMAGE"] = pins.get(tagref, tagref)   # lock digest if pinned

    env.update({
        "SEMGREP_CONFIGS": _semgrep_configs(scanners, offline),
        "CHECKOV_FRAMEWORKS": _checkov_flags(scanners, os.environ.get("SCAN_TARGET", ""),
                                             excludes),
        # Prisma Cloud guideline links: ~25 s of network per run for a doc URL
        # on each finding. Opt-in, and never offline.
        "CHECKOV_DOWNLOAD": "" if ((scanners.get("checkov") or {}).get("guidelines")
                                   and not offline) else "--skip-download",
        "TRIVY_DB_FLAGS": TRIVY_OFFLINE_FLAGS if offline else "",
        "GRYPE_DB_AUTO_UPDATE": "false" if offline else "true",
        # zizmor's online audits (impostor commits, known-vulnerable actions,
        # ref confusion, ...) need a GitHub token, which only ever comes from
        # the host's ZIZMOR_GITHUB_TOKEN, never from scan-config.yml. Without
        # one zizmor stays offline on its own; `offline: true` forces it even
        # when a token is present.
        "ZIZMOR_FLAGS": "--offline" if offline else "",
        "ASS_ZIZMOR_ONLINE": "1" if (not offline and
                                     os.environ.get("ZIZMOR_GITHUB_TOKEN", "").strip()) else "",
        # Gitleaks subcommand: `git` walks the history, `dir` the working tree.
        "GITLEAKS_CMD": "git" if history else "dir",
        # Verification sends each candidate credential to its issuer's API:
        # an outbound disclosure the user must opt into, never a default.
        "TRUFFLEHOG_VERIFY": "" if (scanners.get("trufflehog") or {}).get("verify")
                             else "--no-verification",
        "GITLEAKS_LOG_OPTS": f"--log-opts={history_range}" if (history and history_range) else "",
        "ASS_SBOM_CDX": "1" if sbom_on and "cyclonedx" in formats else "0",
        "ASS_SBOM_SPDX": "1" if sbom_on and "spdx" in formats else "0",
        # Opt-in license policy: Trivy adds a license-only pass (no DB lookup).
        "ASS_LICENSES": "1" if license_policy else "0",
        "ASS_IMAGE": image,
        "ASS_IMAGE_TAR": tar,
        "ASS_GRYPE_TARGET": grype_target,
        "ASS_SYFT_TARGET": syft_target,
        # Scalar policies pass through .env; a per-category map is read by the
        # collector straight from the mounted scan-config.yml (an FAIL_ON here
        # would be an override and would flatten the map).
        "FAIL_ON": "" if isinstance(cfg.get("fail_on"), dict) else str(cfg.get("fail_on", "high")),
        # All tag refs (for ./pin.sh to resolve to digests).
        "ASS_TAGREFS": " ".join(env[f"{p}_TAGREF"] for _, _, p in TOOLS.values()),
    })
    env.update(_exclude_flags(excludes))

    # Provenance: what produced this report, so it can be audited and reproduced.
    env["ASS_VERSION"] = _version()
    env["ASS_ENGINE_IMAGES"] = json.dumps(
        {tool: env[f"{TOOLS[tool][2]}_IMAGE"] for tool in enabled if tool in TOOLS},
        separators=(",", ":"))
    env["ASS_DB_DATES"] = json.dumps(_db_dates(), separators=(",", ":"))
    # The collector prunes its manifest walk with the same list.
    env["ASS_EXCLUDES"] = " ".join(str(e).strip().strip("/") for e in excludes
                                   if str(e).strip())

    # Single-quote every value: several of them contain spaces (SEMGREP_CONFIGS,
    # TRIVY_DB_FLAGS, ASS_TAGREFS) and pin.sh/preload.sh `.` this file as shell.
    # Compose's own .env parser strips the surrounding quotes.
    def q(v: str) -> str:
        v = str(v)
        if "'" in v:      # the .env parser has no escapes; keep values quote-free
            raise ValueError(f"config value must not contain a single quote: {v!r}")
        return f"'{v}'"

    # Supply chain: a lock that doesn't cover every enabled scanner means those
    # run from a mutable tag. Warn always; fail when `require_pinned` is set.
    unpinned = [tool for tool in enabled
                if tool in TOOLS and not _is_pinned(env, TOOLS[tool][2], pins)]
    if pins and unpinned:
        print(f"warning: not pinned by image-digests.lock: {', '.join(sorted(unpinned))} "
              f"(re-run ./pin.sh)", file=sys.stderr)
    require_pinned = (os.environ.get("ASS_REQUIRE_PINNED", "").strip() == "1"
                      or bool(cfg.get("require_pinned", False)))
    if require_pinned and unpinned:
        print(f"ERROR: require_pinned is set but these scanners have no digest in "
              f"image-digests.lock: {', '.join(sorted(unpinned))}. Run ./pin.sh.",
              file=sys.stderr)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / ".env").write_text(
        "# Generated from scan-config.yml by scripts/render-env.py — do not edit.\n"
        + "".join(f"{k}={q(v)}\n" for k, v in env.items())
    )

    # Shell-consumable summary for run.sh.
    print(f"ASS_ENABLED='{' '.join(enabled)}'")
    print(f"ASS_OFFLINE={'1' if offline else '0'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
