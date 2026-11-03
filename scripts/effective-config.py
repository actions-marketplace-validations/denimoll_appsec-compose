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

    effective-config.py <defaults.yml> <project.yml> <out.yml>

The project file is validated before merging, so a mistake is reported
against the file and key the user wrote. Exits 2 on any config problem.
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
    if len(argv) != 4:
        print("usage: effective-config.py <defaults.yml> <project.yml> <out.yml>", file=sys.stderr)
        return 2
    defaults_path, project_path, out = Path(argv[1]), Path(argv[2]), Path(argv[3])
    try:
        defaults, project = _load(defaults_path), _load(project_path)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    known = set((defaults.get("scanners") or {}))
    problems = _schema().validate(project, known_scanners=known)
    if problems:
        print(f"ERROR: invalid {project_path.name}:\n  " + "\n  ".join(
            p.replace("scan-config.yml", project_path.name) for p in problems), file=sys.stderr)
        return 2
    out.write_text(
        f"# Effective config: {defaults_path} overlaid with {project_path}.\n"
        "# Generated per run by scripts/effective-config.py — do not edit.\n"
        + yaml.safe_dump(merge(defaults, project), sort_keys=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
