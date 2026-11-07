"""Load and validate scan configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

import enrich
import licenses
import schema

# Severity ordering, lowest -> highest. `unknown` is resolved to a real level
# via `unknown_severity` before any comparison.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_VALID_FAIL_ON = set(SEVERITY_ORDER) | {"none"}

# Rule confidence, lowest -> highest (see normalize.Finding.confidence).
CONFIDENCE_ORDER = ["low", "medium", "high"]

# Finding categories a per-category `fail_on` may address.
CATEGORIES = ["sast", "sca", "secrets", "iac"]


@dataclass
class Config:
    fail_on: str = "high"                 # default gate threshold
    fail_on_by_category: dict = field(default_factory=dict)   # category -> level
    unknown_severity: str = "medium"
    # Findings whose rule states a lower confidence are reported but do not
    # gate. "low" (the default) gates on everything, as before.
    min_confidence: str = "low"
    dedup: bool = True
    baseline: bool = False
    strict: bool = False
    offline: bool = False
    secrets_history: bool = False
    ignore: list = field(default_factory=list)
    scanners: dict = field(default_factory=dict)
    enrich: dict = field(default_factory=dict)   # enrich.cve_paas block
    licenses: licenses.Policy = field(default_factory=licenses.Policy)

    @property
    def fail_on_exploitable(self) -> bool:
        """Gate on real-world exploitability, independent of the severity gate."""
        return bool(self.enrich.get("enabled") and
                    self.enrich.get("fail_on_exploitable"))

    @property
    def enabled_scanners(self) -> set[str]:
        return {name for name, cfg in self.scanners.items()
                if cfg.get("enabled", True)}

    def threshold_for(self, category: str) -> str:
        """Gate threshold that applies to a finding of this category."""
        return self.fail_on_by_category.get(category, self.fail_on)

    def threshold_label(self) -> str:
        """Human-readable rendering of the whole gate policy."""
        if not self.fail_on_by_category:
            return self.fail_on
        parts = [f"{c}={l}" for c, l in sorted(self.fail_on_by_category.items())]
        return ", ".join(parts + [f"default={self.fail_on}"])


def _parse_fail_on(raw_value) -> tuple[str, dict]:
    """`fail_on` is either a level ("high") or a map of category -> level.

    The map may carry a `default:` key for categories it doesn't mention.
    """
    if isinstance(raw_value, dict):
        per = {str(k).lower(): str(v).lower() for k, v in raw_value.items()}
        default = per.pop("default", "high")
        return default, per
    return str(raw_value).lower(), {}


def load_config(path: str = "/app/scan-config.yml") -> Config:
    raw = {}
    p = Path(path)
    if p.exists():
        raw = yaml.safe_load(p.read_text()) or {}

    schema.check(raw)
    fail_on, per_category = _parse_fail_on(raw.get("fail_on", "high"))

    cfg = Config(
        fail_on=fail_on,
        fail_on_by_category=per_category,
        unknown_severity=str(raw.get("unknown_severity", "medium")).lower(),
        min_confidence=str(raw.get("min_confidence", "low")).lower(),
        dedup=bool(raw.get("dedup", True)),
        baseline=bool(raw.get("baseline", False)),
        strict=bool(raw.get("strict", False)),
        offline=bool(raw.get("offline", False)),
        secrets_history=bool(raw.get("secrets_history", False)),
        ignore=raw.get("ignore", []) or [],
        scanners=raw.get("scanners", {}) or {},
        enrich=enrich.config_from(raw),
        licenses=licenses.policy_from(raw),
    )

    # Environment override (set via compose, e.g. ./run.sh --fail-on) is a single
    # level and deliberately replaces any per-category policy.
    env_fail_on = os.environ.get("FAIL_ON", "").strip().lower()
    if env_fail_on:
        cfg.fail_on = env_fail_on
        cfg.fail_on_by_category = {}

    env_confidence = os.environ.get("ASS_MIN_CONFIDENCE", "").strip().lower()
    if env_confidence:
        cfg.min_confidence = env_confidence

    # run.sh exports what render-env decided (config or --secrets-history,
    # off for a target without .git): the brief must not claim more.
    if "ASS_SECRETS_HISTORY" in os.environ:
        cfg.secrets_history = os.environ["ASS_SECRETS_HISTORY"].strip() == "1"

    env_strict = os.environ.get("ASS_STRICT", "").strip()
    if env_strict:
        cfg.strict = env_strict == "1"

    for level in [cfg.fail_on, *cfg.fail_on_by_category.values()]:
        if level not in _VALID_FAIL_ON:
            raise ValueError(
                f"Invalid fail_on={level!r}; expected one of {sorted(_VALID_FAIL_ON)}"
            )
    unknown_cats = set(cfg.fail_on_by_category) - set(CATEGORIES)
    if unknown_cats:
        raise ValueError(
            f"Unknown fail_on category/categories {sorted(unknown_cats)}; "
            f"expected one of {CATEGORIES} (or 'default')"
        )
    if cfg.unknown_severity not in set(SEVERITY_ORDER):
        raise ValueError(
            f"Invalid unknown_severity={cfg.unknown_severity!r}; "
            f"expected one of {SEVERITY_ORDER}"
        )
    if cfg.min_confidence not in CONFIDENCE_ORDER:
        raise ValueError(
            f"Invalid min_confidence={cfg.min_confidence!r}; "
            f"expected one of {CONFIDENCE_ORDER}"
        )
    return cfg
