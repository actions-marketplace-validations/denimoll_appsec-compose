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

    effective-config.py <defaults.yml> <overlay.yml>... <out.yml>

Overlays apply in the order given, each over the result so far: `run.sh` passes
a named profile first and the project's own config last, so a repo's
suppressions outrank the profile it is scanned with.

Each overlay is validated before merging, so a mistake is reported against the
file and key the user wrote. Exits 2 on any config problem.
"""
from __future__ import annotations

import importlib.util
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


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: effective-config.py <defaults.yml> <overlay.yml>... <out.yml>", file=sys.stderr)
        return 2
    defaults_path, overlay_paths, out = Path(argv[1]), [Path(a) for a in argv[2:-1]], Path(argv[-1])
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
    merged = defaults
    for overlay in overlays:
        merged = merge(merged, overlay)
    out.write_text(
        f"# Effective config: {defaults_path} overlaid with "
        + ", then ".join(str(p) for p in overlay_paths) + ".\n"
        "# Generated per run by scripts/effective-config.py — do not edit.\n"
        + yaml.safe_dump(merged, sort_keys=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
