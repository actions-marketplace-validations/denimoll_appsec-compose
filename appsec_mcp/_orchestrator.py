"""The collector's own modules, loaded by path.

The MCP server must mask secrets exactly the way the collector does and read
the same config schema, so it reuses orchestrator/ rather than copying it. Those
modules import each other by flat name (`from dedup import ...`, as inside the
collector image), and the names are generic enough — `schema`, `config`,
`normalize` — that putting orchestrator/ on sys.path for the server's lifetime
could shadow, or be shadowed by, an installed package. So they are imported with
orchestrator/ first on the path, and then every flat name is taken back out of
sys.modules: the module objects stay usable through the references held here,
and nothing else in the process sees them under those names.

Only the stdlib-only modules are loaded (normalize, dedup, baseline, schema,
suppress); nothing that needs the collector image's Jinja.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

ORCHESTRATOR_DIR = Path(__file__).resolve().parent.parent / "orchestrator"

# Dependency order: each only imports names earlier in the list.
_MODULES = ("normalize", "dedup", "baseline", "schema", "suppress")


def _load() -> dict[str, ModuleType]:
    if not (ORCHESTRATOR_DIR / "baseline.py").is_file():
        raise ImportError(f"appsec-compose collector not found at {ORCHESTRATOR_DIR}; "
                          "run the MCP server from the tool checkout")
    saved = {n: sys.modules.pop(n) for n in _MODULES if n in sys.modules}
    sys.path.insert(0, str(ORCHESTRATOR_DIR))
    try:
        return {n: importlib.import_module(n) for n in _MODULES}
    finally:
        sys.path.remove(str(ORCHESTRATOR_DIR))
        for n in _MODULES:
            sys.modules.pop(n, None)
        sys.modules.update(saved)


_mods = _load()
normalize: ModuleType = _mods["normalize"]
dedup: ModuleType = _mods["dedup"]
baseline: ModuleType = _mods["baseline"]
schema: ModuleType = _mods["schema"]
suppress: ModuleType = _mods["suppress"]
