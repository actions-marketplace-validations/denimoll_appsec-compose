#!/usr/bin/env python3
"""Headline benchmark numbers, before and after: what an engine upgrade did.

    compare.py <old results.json> <new results.json>    # Markdown table on stdout

Used by the engine-update workflow to put the effect of a version bump into
the pull request itself: an upgrade that quietly lowers recall shows up as a
red number before anyone merges it. Only the `default` profile — the shipped
configuration — and only suites present in both files are compared.
"""
from __future__ import annotations

import json
import sys

# suite -> [(label, path into score, higher is better)]
HEADLINES = {
    "sast": [("Java score", ("average", "score"), True), ("Java TPR", ("average", "tpr"), True),
             ("Java FPR", ("average", "fpr"), False)],
    "sast-python": [("Python score", ("average", "score"), True),
                    ("Python FPR", ("average", "fpr"), False)],
    "sast-js": [("JS/TS detected", ("totals", "tp"), True)],
    "secrets": [("Secrets recall", ("merged", "recall"), True),
                ("Secrets precision", ("merged", "precision"), True)],
    "sca": [("SCA recall", ("recall",), True)],
}


def _get(doc: dict, suite: str, path: tuple):
    node = (((doc.get("suites") or {}).get(suite) or {}).get("runs") or {}).get("default") or {}
    node = node.get("score") or {}
    for key in path:
        node = node.get(key) if isinstance(node, dict) else None
    return node if isinstance(node, (int, float)) else None


def compare(old: dict, new: dict) -> list[dict]:
    rows = []
    for suite, metrics in HEADLINES.items():
        for label, path, higher_better in metrics:
            a, b = _get(old, suite, path), _get(new, suite, path)
            if a is None or b is None:
                continue
            delta = b - a
            worse = (delta < 0) if higher_better else (delta > 0)
            rows.append({"metric": label, "old": a, "new": b, "delta": delta,
                         "worse": worse and abs(delta) > 1e-9})
    return rows


def markdown(rows: list[dict]) -> str:
    if not rows:
        return "_No benchmark numbers to compare._\n"
    fmt = lambda v: f"{v:.1%}" if isinstance(v, float) and abs(v) <= 1 else f"{v}"
    lines = ["| Metric | Before | After | |", "|---|---|---|---|"]
    for r in rows:
        mark = "worse" if r["worse"] else ("better" if abs(r["delta"]) > 1e-9 else "")
        lines.append(f"| {r['metric']} | {fmt(r['old'])} | {fmt(r['new'])} | {mark} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: compare.py <old results.json> <new results.json>", file=sys.stderr)
        return 2
    with open(argv[1]) as a, open(argv[2]) as b:
        print(markdown(compare(json.load(a), json.load(b))), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
