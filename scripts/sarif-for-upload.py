#!/usr/bin/env python3
"""Copy a SARIF file without the results suppressed in the code.

    sarif-for-upload.py <in.sarif> <out.sarif>

GitHub code scanning ignores SARIF's `suppressions`: a result the engine
reports as suppressed in source (`# nosemgrep`, a Checkov skip comment) opens
an alert all the same, and it never closes, since the engine keeps reporting
it. The collector already treats those as audited decisions (`suppressed` in
findings.json); this keeps code scanning in step. native/*.sarif stays whole —
ASPM tools that read `suppressions` get them. A suppression under review or
rejected (SARIF §3.35.3) still counts as a finding. Stdlib only — it runs on
the CI host.
"""
from __future__ import annotations

import json
import sys

_HONOURED = {"accepted", None}


def suppressed(result: dict) -> bool:
    return any(isinstance(s, dict) and s.get("status") in _HONOURED
               for s in result.get("suppressions") or [])


def strip(doc: dict) -> tuple[dict, int]:
    dropped = 0
    for run in doc.get("runs") or []:
        results = run.get("results") or []
        kept = [r for r in results if not suppressed(r)]
        dropped += len(results) - len(kept)
        if "results" in run:
            run["results"] = kept
    return doc, dropped


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: sarif-for-upload.py <in.sarif> <out.sarif>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        doc, dropped = strip(json.load(fh))
    with open(argv[2], "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    if dropped:
        print(f"{argv[1]}: {dropped} result(s) suppressed in the code left out of the upload")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
