"""The scan-config.yml schema, in one place.

Both entry points read the same config: scripts/render-env.py on the host and
config.py inside the collector. Keeping the accepted keys in one module means a
typo cannot be silently accepted by one of them, and neither drifts from the
documented file.

A mistyped key used to be ignored in silence — `fail_on_severity:` next to a
`fail_on:` default left the gate quietly at its default. Everything here exists
to make that impossible.
"""
from __future__ import annotations

from difflib import get_close_matches

CATEGORIES = ["sast", "sca", "secrets", "iac"]

TOP_LEVEL = {
    "scanners", "sbom", "sbom_formats", "secrets_history",
    "secrets_history_range", "exclude", "enrich", "fail_on",
    "unknown_severity", "dedup", "strict", "require_pinned", "baseline",
    "ignore", "offline", "licenses",
}
SCANNER = {"enabled", "version", "rules", "verify", "frameworks", "guidelines"}
ENRICH = {"cve_paas"}
CVE_PAAS = {"enabled", "url", "api_key_env", "mode", "timeout",
            "fail_on_exploitable"}
IGNORE = {"rule", "file", "package", "category", "fingerprint", "reason", "expires"}
FAIL_ON = set(CATEGORIES) | {"default"}
LICENSES = {"deny", "warn", "severity"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _suggest(key: str, allowed: set[str]) -> str:
    """Closest accepted key.

    A near-identical key is a misspelling (`secrets_history_rage`), but a merely
    similar one that the typo is built out of is an invented variant
    (`fail_on_severity` is a suffixed `fail_on`, not a misspelt
    `unknown_severity`) — so try a strict spelling match first, then containment.
    """
    options = sorted(allowed)
    misspelling = get_close_matches(key, options, n=1, cutoff=0.85)
    if misspelling:
        return misspelling[0]
    contained = sorted((k for k in options if key.startswith(k) or k.startswith(key)),
                       key=len, reverse=True)
    if contained:
        return contained[0]
    loose = get_close_matches(key, options, n=1, cutoff=0.6)
    return loose[0] if loose else ""


def _unknown(where: str, keys, allowed: set[str]) -> list[str]:
    problems = []
    for key in keys:
        if key in allowed:
            continue
        hint = _suggest(str(key), allowed)
        suggestion = f" — did you mean '{hint}'?" if hint else ""
        problems.append(f"{where}: unknown key '{key}'{suggestion}")
    return problems


def validate(raw: dict, known_scanners: set[str] | None = None) -> list[str]:
    """Return every problem found, so one run reports them all."""
    if not isinstance(raw, dict):
        return ["scan-config.yml: expected a mapping at the top level"]

    problems = _unknown("scan-config.yml", raw, TOP_LEVEL)

    scanners = raw.get("scanners")
    if scanners is not None:
        if not isinstance(scanners, dict):
            problems.append("scanners: expected a mapping of tool -> settings")
        else:
            if known_scanners:
                problems += _unknown("scanners", scanners, known_scanners)
            for name, block in scanners.items():
                if isinstance(block, dict):
                    problems += _unknown(f"scanners.{name}", block, SCANNER)

    enrich = raw.get("enrich")
    if isinstance(enrich, dict):
        problems += _unknown("enrich", enrich, ENRICH)
        cve_paas = enrich.get("cve_paas")
        if isinstance(cve_paas, dict):
            problems += _unknown("enrich.cve_paas", cve_paas, CVE_PAAS)

    fail_on = raw.get("fail_on")
    if isinstance(fail_on, dict):
        problems += _unknown("fail_on", fail_on, FAIL_ON)

    ignore = raw.get("ignore")
    if isinstance(ignore, list):
        for i, entry in enumerate(ignore):
            if isinstance(entry, dict):
                problems += _unknown(f"ignore[{i}]", entry, IGNORE)

    licenses = raw.get("licenses")
    if licenses is not None:
        if not isinstance(licenses, dict):
            problems.append("licenses: expected a mapping with deny / warn / severity")
        else:
            problems += _unknown("licenses", licenses, LICENSES)
            for key in ("deny", "warn"):
                value = licenses.get(key)
                if value is not None and not (isinstance(value, list)
                                              and all(isinstance(v, str) for v in value)):
                    problems.append(f"licenses.{key}: expected a list of SPDX ids or globs")
            severity = licenses.get("severity")
            if severity is not None and str(severity).lower() not in SEVERITIES:
                problems.append(f"licenses.severity: '{severity}' is not one of "
                                f"{', '.join(sorted(SEVERITIES))}")

    exclude = raw.get("exclude")
    if exclude is not None and not isinstance(exclude, list):
        problems.append("exclude: expected a list of directory names or globs")

    return problems


def check(raw: dict, known_scanners: set[str] | None = None) -> None:
    """Raise with every problem at once, rather than one per run."""
    problems = validate(raw, known_scanners)
    if problems:
        raise ValueError("invalid scan-config.yml:\n  " + "\n  ".join(problems))
