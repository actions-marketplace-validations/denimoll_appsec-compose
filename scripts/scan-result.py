#!/usr/bin/env python3
"""Print the result of a `run.sh --json` scan: exactly one JSON object.

    scan-result.py <exit_code> <reports_dir> <fresh>

This is the interface agents and the MCP server consume (documented in
README.md, "Machine-readable result"); fields are only ever added. `fresh` is 1
once run.sh has cleared the previous run's reports: before that point (an early
usage error) a findings.json in reports_dir belongs to an older run and must not
be reported as this one's. Stdlib only — it runs on the host.
"""
from __future__ import annotations

import json
import os
import sys

VERDICTS = {0: "pass", 1: "fail", 2: "usage_error", 3: "scan_error"}


def result(exit_code: int, reports_dir: str, fresh: bool) -> dict:
    reports_dir = os.path.abspath(reports_dir) if reports_dir else None

    def report(name: str) -> str | None:
        if not (fresh and reports_dir):
            return None
        path = os.path.join(reports_dir, name)
        return path if os.path.isfile(path) and os.path.getsize(path) else None

    findings_json = report("findings.json")
    data: dict = {}
    if findings_json:
        try:
            with open(findings_json, encoding="utf-8") as fh:
                loaded = json.load(fh)
            data = loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            data = {}
    policy = data.get("policy") if isinstance(data.get("policy"), dict) else {}
    baseline = data.get("baseline") if isinstance(data.get("baseline"), dict) else None

    return {
        "exit_code": exit_code,
        # Anything outside the contract is a run that broke on the way.
        "verdict": VERDICTS.get(exit_code, "scan_error"),
        "reports_dir": reports_dir,
        "findings_json": findings_json,
        "review_brief": report("review-brief.md"),
        "severity_counts": data.get("severity_counts"),
        "breaching": policy.get("breaching"),
        # Only a baseline that was in force says anything about "new".
        "baseline": baseline if baseline and baseline.get("enabled") else None,
    }


def main(argv: list[str]) -> int:
    code = int(argv[1]) if len(argv) > 1 and argv[1].lstrip("-").isdigit() else 3
    reports_dir = argv[2] if len(argv) > 2 else ""
    fresh = len(argv) > 3 and argv[3] == "1"
    print(json.dumps(result(code, reports_dir, fresh)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
