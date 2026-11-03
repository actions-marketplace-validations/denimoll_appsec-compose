#!/usr/bin/env python3
"""How long each engine ran, read from Docker once the scanners finished.

    engine-timings.py <container-id>...     # prints {"engine": seconds, ...}

run.sh calls it between `compose up` and `compose down`, while the one-shot
scanner containers still exist: Docker records when each started and
finished, so nothing has to time itself and an engine's own output is not
touched. The scanners run in parallel, so the scan takes as long as the
slowest of them — this is how a user, or the benchmark, finds out which.

Best effort by design: no ids, an unreachable daemon or an unparseable
timestamp give {} or skip the engine, never a failed scan.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime

# Docker prints nanoseconds ("2026-11-03T07:05:29.123456789Z"); fromisoformat
# takes at most microseconds.
_STAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$")


def _parse(stamp: str) -> datetime | None:
    m = _STAMP.match(stamp or "")
    if not m:
        return None
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    zone = "+00:00" if m.group(3) == "Z" else m.group(3)
    return datetime.fromisoformat(f"{m.group(1)}.{frac}{zone}")


def timings(inspected: list[dict]) -> dict[str, float]:
    out: dict[str, float] = {}
    for c in inspected:
        service = ((c.get("Config") or {}).get("Labels") or {}).get("com.docker.compose.service")
        state = c.get("State") or {}
        start, end = _parse(state.get("StartedAt", "")), _parse(state.get("FinishedAt", ""))
        if service and start and end and end >= start:
            out[service] = round((end - start).total_seconds(), 1)
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def main(argv: list[str]) -> int:
    ids = [a for a in argv[1:] if a]
    data: list[dict] = []
    if ids:
        try:
            proc = subprocess.run(["docker", "inspect", *ids], capture_output=True,
                                  text=True, timeout=30)
            data = json.loads(proc.stdout or "[]")
        except (OSError, subprocess.SubprocessError, ValueError):
            data = []
    print(json.dumps(timings(data if isinstance(data, list) else []), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
