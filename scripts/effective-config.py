#!/usr/bin/env python3
"""Lay a project's config over the tool's scan-config.yml defaults.

A project config says only what differs. `--config` used to *replace* the
defaults, so a file holding just an `ignore:` list ran no scanners at all, and
every project had to carry a full copy of scan-config.yml that silently went
stale on upgrade — a new default engine never reached it.

Mappings merge key by key, all the way down: `scanners: {zizmor: {enabled:
false}}` turns one engine off and leaves the rest as shipped. Anything else — a
list such as `ignore:` or `exclude:`, a scalar, or a key whose type differs
(`fail_on: high` in the defaults, a per-category map in the project) — is
replaced whole. To switch a default engine off, say so: `enabled: false`.

    effective-config.py <defaults.yml> [--repo <repo.yml>] <overlay.yml>... <out.yml>

Overlays apply in the order given, each over the result so far: `run.sh` passes
a named profile first and the project's own config last, so a repo's
suppressions outrank the profile it is scanned with.

A `--repo` overlay is the `.appsec-compose.yml` found in the scanned repository,
which whoever controls that repository wrote, not whoever runs the scan. It goes
last, and only `apply_repo_policy`'s allowlist survives: project policy may
come from the repo, but nothing that picks what executes, what leaves the
machine or where a key is sent — no image versions, no `enrich.cve_paas.url`
(it would receive CVE_PAAS_API_KEY), no TruffleHog `verify` (it would send found
secrets out). stdout carries what was applied and dropped, as JSON.

Each overlay is validated before merging, so a mistake is reported against the
file and key the user wrote. Exits 2 on any config problem.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required on the host: pip3 install pyyaml", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parent.parent


def merge(base, over):
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for key, value in over.items():
            out[key] = merge(base[key], value) if key in base else value
        return out
    return over


def _schema():
    spec = importlib.util.spec_from_file_location("ass_schema", ROOT / "orchestrator" / "schema.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"{path.name} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must be a mapping of settings")
    return data


# What a repository may decide about its own scan. Default-deny: a new setting
# stays out of reach of a scanned repo until someone argues it belongs here.
_REPO_POLICY_KEYS = {"fail_on", "unknown_severity", "min_confidence", "respect_gitignore", "strict", "dedup", "baseline", "exclude",
                     "ignore", "sbom", "sbom_formats", "secrets_history", "licenses",
                     "offline", "require_pinned"}
_REPO_SEMGREP_RULES = {"default", "auto"}
# Exclude entries reach engine command lines word-split: one word, no options.
_SAFE_EXCLUDE = re.compile(r"^[\w.*/@+-]+$")


def apply_repo_policy(overlay: dict) -> tuple[dict, list[str]]:
    """The part of a repo-supplied config that may apply, and the dropped keys."""
    kept: dict = {}
    dropped: list[str] = []
    for key, value in overlay.items():
        if key == "scanners" and isinstance(value, dict):
            for name, block in value.items():
                out = {}
                for opt, val in (block or {}).items():
                    if opt == "enabled" or (name == "semgrep" and opt == "rules"
                                            and set(val or []) <= _REPO_SEMGREP_RULES):
                        out[opt] = val
                    else:
                        dropped.append(f"scanners.{name}.{opt}")
                if out:
                    kept.setdefault("scanners", {})[name] = out
        elif key not in _REPO_POLICY_KEYS:
            dropped.append(key)
        elif key == "exclude" and isinstance(value, list):
            safe = [e for e in value if isinstance(e, str) and not e.startswith("-")
                    and _SAFE_EXCLUDE.match(e)]
            if len(safe) != len(value):
                dropped.append("exclude (unsafe entries)")
            kept[key] = safe
        else:
            kept[key] = value
    return kept, dropped


def main(argv: list[str]) -> int:
    args = argv[1:]
    repo_path = None
    if "--repo" in args:
        at = args.index("--repo")
        repo_path = Path(args[at + 1]) if at + 1 < len(args) else None
        del args[at:at + 2]
    if len(args) < 2 or ("--repo" in argv and repo_path is None):
        print("usage: effective-config.py <defaults.yml> [--repo <repo.yml>] <overlay.yml>... <out.yml>",
              file=sys.stderr)
        return 2
    defaults_path, overlay_paths, out = Path(args[0]), [Path(a) for a in args[1:-1]], Path(args[-1])
    if repo_path:
        overlay_paths.append(repo_path)        # last: a repo's suppressions win
    if not overlay_paths:
        print("usage: effective-config.py <defaults.yml> needs at least one overlay", file=sys.stderr)
        return 2
    try:
        defaults = _load(defaults_path)
        overlays = [_load(path) for path in overlay_paths]
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    known = set((defaults.get("scanners") or {}))
    validate = _schema().validate
    failed = False
    for path, overlay in zip(overlay_paths, overlays):
        problems = validate(overlay, known_scanners=known)
        if problems:
            failed = True
            print(f"ERROR: invalid {path.name}:\n  " + "\n  ".join(
                p.replace("scan-config.yml", path.name) for p in problems), file=sys.stderr)
    if failed:
        return 2
    report = None
    if repo_path:
        overlays[-1], dropped = apply_repo_policy(overlays[-1])
        report = {"file": repo_path.name, "applied": sorted(overlays[-1]), "dropped": dropped}
        if dropped:
            print(f"warning: ignored from {repo_path.name} (a scanned repository may not set "
                  f"these; pass the file with --config to trust it): {', '.join(dropped)}",
                  file=sys.stderr)
    merged = defaults
    for overlay in overlays:
        merged = merge(merged, overlay)
    out.write_text(
        f"# Effective config: {defaults_path} overlaid with "
        + ", then ".join(str(p) for p in overlay_paths) + ".\n"
        "# Generated per run by scripts/effective-config.py — do not edit.\n"
        + yaml.safe_dump(merged, sort_keys=False))
    if report:
        print(json.dumps(report, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
