"""Apply ignore/suppression rules from scan-config.yml.

An ignore entry may specify any of: `rule` (glob, matched against the finding's
rule_id OR any alias), `file` (glob on the path), `package` (glob on
name@version), `category`, `fingerprint` (exact; one specific finding, as
reported in findings.json). A finding is suppressed when EVERY field present in
the entry matches. Suppressed findings are removed from the gate and the
summary counts, but recorded with their reason for the audit trail.

An entry may also carry `expires: YYYY-MM-DD`. Past that date it stops
suppressing anything — an accepted risk should be re-argued, not inherited
forever — and the run reports which entries lapsed.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from fnmatch import fnmatch

from normalize import Finding

_SELECTORS = ("rule", "file", "package", "category", "fingerprint")


@dataclass
class Suppressed:
    finding: Finding
    reason: str


@dataclass
class Expired:
    entry: dict
    expires: str

    @property
    def label(self) -> str:
        selectors = ", ".join(f"{k}={self.entry[k]}" for k in _SELECTORS
                              if self.entry.get(k))
        return selectors or "(no selector)"


def _parse_expiry(value) -> date:
    """`expires` is an ISO date; YAML may already have parsed it into a date."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError as exc:
        raise ValueError(
            f"Invalid ignore expires={value!r}; expected YYYY-MM-DD"
        ) from exc


def _matches(entry: dict, f: Finding) -> bool:
    rule = entry.get("rule")
    if rule:
        ids = [f.rule_id, *f.aliases]
        if not any(fnmatch(i.upper(), str(rule).upper()) for i in ids):
            return False
    if entry.get("file") and not fnmatch(f.file or "", str(entry["file"])):
        return False
    if entry.get("package") and not fnmatch(f.package or "", str(entry["package"])):
        return False
    if entry.get("category") and f.category != entry["category"]:
        return False
    if entry.get("fingerprint") and f.fingerprint != str(entry["fingerprint"]):
        return False
    # An empty entry (no selectors) must not match everything.
    return any(entry.get(k) for k in _SELECTORS)


def apply(findings: list[Finding], ignore: list[dict],
          today: date | None = None) -> tuple[list[Finding], list[Suppressed], list[Expired]]:
    if not ignore:
        return list(findings), [], []

    today = today or date.today()
    active: list[dict] = []
    expired: list[Expired] = []
    for entry in ignore:
        if not isinstance(entry, dict):
            continue
        raw_expiry = entry.get("expires")
        if raw_expiry is None:
            active.append(entry)
            continue
        expiry = _parse_expiry(raw_expiry)
        if expiry < today:
            expired.append(Expired(entry, expiry.isoformat()))
        else:
            active.append(entry)

    kept: list[Finding] = []
    suppressed: list[Suppressed] = []
    for f in findings:
        entry = next((e for e in active if _matches(e, f)), None)
        if entry is None:
            kept.append(f)
        else:
            suppressed.append(Suppressed(f, str(entry.get("reason", "")).strip()))
    return kept, suppressed, expired
