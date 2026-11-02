"""appsec-compose collector entrypoint.

Runs after every scanner service has finished. Loads native SARIF reports,
normalizes them, writes a consolidated findings.json + summary.{md,html} and
exits with a CI-meaningful code derived from the configured fail_on policy.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

import yaml

import baseline as bl
import brief
import coverage as cov
import enrich as enr
from config import load_config
from converters import trufflehog_json_to_sarif
from dedup import merge
from normalize import load_findings, finding_to_dict, expected_reports
from policy import evaluate, resolve_unknown
from summary import render
from suppress import apply as apply_ignore

REPORTS_DIR = "/reports"
NATIVE_DIR = f"{REPORTS_DIR}/native"
CODE_DIR = "/code"
BASELINE_PATH = "/app/appsec-baseline.json"

# Version of the findings.json contract (schemas/findings.schema.json). Bump
# the major for anything a consumer could break on: a removed or renamed field,
# a changed meaning; the minor for additions.
SCHEMA_VERSION = "1.0"

# Exit codes, shared with run.sh. 1 is reserved for a verdict of "fail": every
# way of not reaching a verdict maps elsewhere, so a caller never mistakes a
# broken scan for findings, or a clean exit for a clean codebase.
EXIT_PASS = 0      # the policy gate passed
EXIT_POLICY = 1    # the policy gate failed
EXIT_USAGE = 2     # invalid configuration: fix scan-config.yml
EXIT_SCAN = 3      # the scan is incomplete or unreadable: no trustworthy verdict


def _provenance(cfg, image_mode: bool) -> dict:
    """What produced this report — the engines, their DBs, and the target."""
    def _json_env(name: str) -> dict:
        try:
            return json.loads(os.environ.get(name) or "{}")
        except json.JSONDecodeError:
            return {}

    target = (os.environ.get("ASS_IMAGE")
              or ("docker-archive" if os.environ.get("ASS_IMAGE_TAR") else "")
              or "filesystem")
    return {
        "appsec_compose": os.environ.get("ASS_VERSION", "unknown"),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target if image_mode else "filesystem",
        "offline": cfg.offline,
        "engines": _json_env("ASS_ENGINE_IMAGES"),
        "databases": _json_env("ASS_DB_DATES"),
    }


def main() -> int:
    try:
        cfg = load_config()
    except (ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE

    # Generate SARIF for tools that have no native SARIF (keeps the raw report).
    trufflehog_json_to_sarif(Path(NATIVE_DIR, "trufflehog.json"),
                             Path(NATIVE_DIR, "trufflehog.sarif"))

    # Use the scanners that actually ran (run.sh passes the filtered list in
    # image mode); fall back to everything enabled in the config.
    env_enabled = os.environ.get("ASS_ENABLED", "").split()
    enabled = set(env_enabled) if env_enabled else cfg.enabled_scanners

    image_mode = bool(os.environ.get("ASS_IMAGE") or os.environ.get("ASS_IMAGE_TAR"))
    expected = expected_reports(enabled)
    if image_mode:
        expected.discard("trivy-config.sarif")   # no IaC config scan in image mode
    result = load_findings(NATIVE_DIR, expected=expected)

    # In image mode, a vuln scanner that ran but produced no report means the
    # image could not be pulled/loaded — fail loudly instead of "0 findings".
    if image_mode and ({"trivy", "grype"} & enabled) and not result.reports_found:
        target = os.environ.get("ASS_IMAGE") or "the built image"
        print(f"ERROR: failed to pull or scan {target}. "
              f"Check the image reference and registry credentials.", file=sys.stderr)
        return EXIT_SCAN

    # strict: a scanner that was expected to report but didn't (crashed, OOM,
    # wrote unparseable output) must not pass as "0 findings".
    if cfg.strict and (result.reports_missing or result.reports_errored):
        if result.reports_missing:
            print(f"ERROR: strict mode — no report from: "
                  f"{', '.join(sorted(result.reports_missing))}", file=sys.stderr)
        if result.reports_errored:
            print(f"ERROR: strict mode — unreadable report(s): "
                  f"{'; '.join(result.reports_errored)}", file=sys.stderr)
        return EXIT_SCAN

    # Blind-spot check: an SCA engine that resolved nothing looks exactly like a
    # project with no vulnerable dependencies, and the gate cannot tell them apart.
    excludes = set(os.environ.get("ASS_EXCLUDES", "").split())
    sca_found = sum(1 for f in result.findings if f.category == "sca")
    coverage = cov.analyse(CODE_DIR, REPORTS_DIR, enabled, excludes,
                           image_mode=image_mode, sca_findings=sca_found)
    if cfg.strict and coverage.warnings:
        for warning in coverage.warnings:
            print(f"ERROR: strict mode — {warning.message} {warning.advice}",
                  file=sys.stderr)
        return EXIT_SCAN

    # Tools that could not determine a severity are ranked by the user's
    # `unknown_severity`, before anything merges or compares them.
    unknown_count = resolve_unknown(result.findings, cfg.unknown_severity)

    merged, stats = merge(result.findings, enabled=cfg.dedup)
    # Fingerprints exist before suppression, so an ignore entry can name one.
    bl.assign(merged, CODE_DIR)
    try:
        kept, suppressed, expired = apply_ignore(merged, cfg.ignore)
    except ValueError as exc:            # e.g. a malformed `expires`
        print(f"ERROR: invalid ignore entry: {exc}", file=sys.stderr)
        return EXIT_USAGE

    # Exploitability enrichment runs after the merge, so each CVE is looked up
    # once and the alias set is at its widest.
    enrichment = enr.EnrichResult(verdicts={})
    if cfg.enrich.get("enabled"):
        if cfg.offline:
            enrichment.error = "skipped: offline mode is on"
        else:
            enrichment = enr.apply(
                kept, cfg.enrich["url"], cfg.enrich["api_key"],
                cfg.enrich["timeout"],
                reprioritize=cfg.enrich["mode"] == "reprioritize")
        if enrichment.error and cfg.strict:
            print(f"ERROR: strict mode — CVE-PaaS enrichment failed "
                  f"({enrichment.error})", file=sys.stderr)
            return EXIT_SCAN

    # --update-baseline: snapshot current findings as the accepted state, no gate.
    if os.environ.get("ASS_UPDATE_BASELINE") == "1":
        n = bl.save(BASELINE_PATH, kept)
        print(f"Baseline updated: {n} fingerprint(s) -> appsec-baseline.json")
        return EXIT_PASS

    # Baseline mode: gate only on findings new since the accepted baseline.
    delta = None
    if cfg.baseline:
        delta = bl.classify(kept, bl.load(BASELINE_PATH))
    gate_findings = delta.new if delta is not None else None
    policy = evaluate(kept, cfg, raw_findings=result.findings, gate_findings=gate_findings)
    new_fps = {f.fingerprint for f in delta.new} if delta else set()
    for f in kept:                       # transient flag for the HTML report
        f.is_new = bool(delta) and f.fingerprint in new_fps

    # Machine-readable consolidated output (for ASPM/ASOC ingestion).
    consolidated = {
        "schema_version": SCHEMA_VERSION,
        "provenance": _provenance(cfg, image_mode),
        "policy": {
            "fail_on": policy.threshold,
            "fail_on_by_category": policy.thresholds,
            "fail_on_exploitable": cfg.fail_on_exploitable,
            "strict": cfg.strict,
            "breaching": policy.breaching,
            "exploitable_breaching": policy.exploitable_breaching,
            "exit_code": policy.exit_code,
        },
        "dedup": {
            "enabled": cfg.dedup,
            "raw_findings": stats.raw,
            "unique_findings": stats.unique,
            "duplicates_removed": stats.removed,
        },
        "suppressed_count": len(suppressed),
        "expired_suppressions": [{"selectors": e.label, "expires": e.expires}
                                 for e in expired],
        "enrichment": {
            "enabled": bool(cfg.enrich.get("enabled")),
            "mode": cfg.enrich.get("mode"),
            "requested": enrichment.requested,
            "resolved": enrichment.resolved,
            "reprioritized": enrichment.reprioritized,
            "exploitable": enrichment.exploitable,
            "error": enrichment.error,
        },
        "baseline": {
            "enabled": cfg.baseline,
            "new": len(delta.new) if delta else None,
            "known": len(delta.known) if delta else None,
            "fixed": delta.fixed if delta else None,
            "legacy_format": delta.legacy if delta else None,
        },
        "coverage": {
            "manifests": coverage.manifests,
            "ecosystems": coverage.ecosystems,
            "sbom_components": coverage.sbom_components,
            "warnings": [{"kind": w.kind, "message": w.message, "advice": w.advice}
                         for w in coverage.warnings],
        },
        "severity_counts": policy.severity_counts,
        "category_counts": policy.category_counts,
        "tool_counts": policy.tool_counts,
        "reports_found": result.reports_found,
        "reports_missing": result.reports_missing,
        "reports_errored": result.reports_errored,
        "findings": [{**finding_to_dict(f),
                      **({"new": f.fingerprint in new_fps} if delta else {})}
                     for f in kept],
        "suppressed": [{**finding_to_dict(s.finding), "reason": s.reason}
                       for s in suppressed],
    }
    Path(REPORTS_DIR, "findings.json").write_text(json.dumps(consolidated, indent=2))

    provenance = consolidated["provenance"]
    render(result, policy, kept, stats, REPORTS_DIR,
           suppressed_count=len(suppressed), delta=delta, coverage=coverage,
           enrichment=enrichment, expired=expired, provenance=provenance)
    brief.render(REPORTS_DIR, kept, cfg, enabled, coverage, provenance,
                 CODE_DIR, excludes, image_mode, new_fps if delta else None)

    # Console summary.
    total = sum(policy.severity_counts.values())
    print("=" * 60)
    version = os.environ.get("ASS_VERSION", "")
    if version:
        print(f"appsec-compose {version}")
    dup_note = (f" ({stats.removed} duplicate(s) merged)"
                if cfg.dedup and stats.removed else "")
    print(f"appsec-compose: {total} unique finding(s) across "
          f"{len(result.reports_found)} report(s){dup_note}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        print(f"  {sev:>8}: {policy.severity_counts[sev]}")
    if unknown_count:
        print(f"  ({unknown_count} finding(s) of undetermined severity ranked as "
              f"{cfg.unknown_severity})")
    if suppressed:
        print(f"  (suppressed by ignore rules: {len(suppressed)})")
    for entry in expired:
        print(f"  ! ignore rule expired {entry.expires}: {entry.label} "
              f"— its findings count again")
    if enrichment.error:
        print(f"  ! CVE-PaaS enrichment unavailable: {enrichment.error}")
    elif enrichment.requested:
        note = (f", {enrichment.reprioritized} reprioritized"
                if enrichment.reprioritized else "")
        print(f"  exploitability: {enrichment.resolved}/{enrichment.requested} "
              f"CVE(s) resolved, {enrichment.exploitable} exploitable{note}")
    if result.reports_missing:
        print(f"  ! missing reports: {', '.join(result.reports_missing)}")
    if result.reports_errored:
        print(f"  ! unreadable reports: {'; '.join(result.reports_errored)}")
    for warning in coverage.warnings:
        print(f"  ! SCA coverage: {warning.message}")
        print(f"    -> {warning.advice}")
    if delta is not None:
        print(f"  baseline: {len(delta.new)} new, {len(delta.known)} known, "
              f"{delta.fixed} fixed")
        if delta.legacy:
            print("  ! baseline uses v1 fingerprints, which break when lines shift; "
                  "re-snapshot it with --update-baseline")
    if policy.exploitable_breaching:
        print(f"  ({policy.exploitable_breaching} breaching on exploitability "
              f"alone, below the severity threshold)")
    verdict = "FAIL" if policy.exit_code else "PASS"
    gate_scope = "new " if delta is not None else ""
    print(f"Policy fail_on={policy.label} -> {verdict} "
          f"({policy.breaching} {gate_scope}at/above threshold)")
    sboms = sorted(p.name for p in Path(REPORTS_DIR).glob("sbom.*.json"))
    sbom_note = (" | " + " | ".join(sboms)) if sboms else ""
    print(f"Reports: {REPORTS_DIR}/summary.md | summary.html | findings.json"
          f" | review-brief.md"
          f"{sbom_note} | native/")
    print("=" * 60)
    return EXIT_POLICY if policy.exit_code else EXIT_PASS


def run() -> int:
    """Entry point. An uncaught exception would exit 1 — a policy failure."""
    try:
        return main()
    except Exception:
        traceback.print_exc()
        print("ERROR: the collector crashed; no verdict was reached", file=sys.stderr)
        return EXIT_SCAN


if __name__ == "__main__":
    sys.exit(run())
