#!/usr/bin/env python3
"""Propose engine upgrades: the latest stable release of each scanner, aged.

    update-engines.py            # report what would change (exit 0)
    update-engines.py --apply    # rewrite the versions; prints a JSON summary

An engine pinned to last year's release still exits 0 and still writes a
valid report — on an old database and old rules. Engine versions are written
in three places that must agree (scan-config.yml, the defaults in
scripts/render-env.py and in docker-compose.yml); this moves all three, and
tests/test_engine_versions.py fails if they ever disagree.

The candidate is the newest stable release (not draft, not prerelease) that is
at least COOLDOWN_DAYS old — a hijacked release is usually caught within days —
and whose image tag exists in the registry. Newest *aged*, not latest: Semgrep
and Trivy release more often than weekly, so their latest is nearly always too
young, and waiting for it to age would mean never upgrading them at all. A major bump is flagged: that is
where command lines change under us (gitleaks `detect` -> `dir`). Re-pinning
digests, the tests, the smoke test and the benchmark run afterwards, in the
workflow that opens the pull request.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COOLDOWN_DAYS = 7

# engine -> (GitHub repo with its releases, image tag from the release tag)
ENGINES = {
    "semgrep": ("semgrep/semgrep", lambda t: t.lstrip("v")),
    "trivy": ("aquasecurity/trivy", lambda t: t.lstrip("v")),
    "gitleaks": ("gitleaks/gitleaks", lambda t: "v" + t.lstrip("v")),
    "checkov": ("bridgecrewio/checkov", lambda t: t.lstrip("v")),
    "grype": ("anchore/grype", lambda t: "v" + t.lstrip("v")),
    "trufflehog": ("trufflesecurity/trufflehog", lambda t: t.lstrip("v")),
    "syft": ("anchore/syft", lambda t: "v" + t.lstrip("v")),
    "hadolint": ("hadolint/hadolint", lambda t: "v" + t.lstrip("v") + "-alpine"),
    "osv": ("google/osv-scanner", lambda t: "v" + t.lstrip("v")),
    "zizmor": ("zizmorcore/zizmor", lambda t: t.lstrip("v")),
}

_NUM = re.compile(r"(\d+)")


def _major(version: str) -> int | None:
    m = _NUM.search(version)
    return int(m.group(1)) if m else None


def _key(version: str) -> tuple:
    return tuple(int(n) for n in _NUM.findall(version.split("-")[0]))


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "appsec-compose-updater"})
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosemgrep: dynamic-urllib-use-detected
        return json.loads(resp.read().decode())


def releases(repo: str) -> list[dict]:
    """Recent releases, newest first (GitHub returns at most 100 per page)."""
    return _get(f"https://api.github.com/repos/{repo}/releases?per_page=50")


def _published(rel: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(str(rel.get("published_at", "")).replace("Z", "+00:00"))
    except ValueError:
        return None


def image_exists(ref: str) -> bool:
    """Whether the registry serves this tag (a release can precede its image)."""
    try:
        proc = subprocess.run(["docker", "manifest", "inspect", ref],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def current_versions() -> dict[str, tuple[str, str]]:
    """engine -> (image repo, version) as render-env defines them."""
    text = (ROOT / "scripts" / "render-env.py").read_text()
    return {name: (repo, ver) for name, repo, ver in
            re.findall(r'"(\w+)": \("([^"]+)", "([^"]+)", "[A-Z]+"\)', text)}


def plan(now: datetime | None = None, check_image=image_exists, release=releases) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    current = current_versions()
    out = []
    for name, (gh_repo, to_tag) in ENGINES.items():
        image_repo, have = current[name]
        entry = {"engine": name, "from": have, "to": None, "note": ""}
        try:
            listed = release(gh_repo)
        except Exception as exc:          # one engine's API hiccup must not block the rest
            entry["note"] = f"release lookup failed: {exc}"
            out.append(entry)
            continue
        stable = [r for r in listed if not r.get("draft") and not r.get("prerelease")
                  and _published(r) and _NUM.search(str(r.get("tag_name", "")))]
        aged = [r for r in stable if (now - _published(r)).days >= COOLDOWN_DAYS]
        newer = [r for r in aged if _key(to_tag(r["tag_name"])) > _key(have)]
        if not newer:
            young = [r for r in stable if _key(to_tag(r["tag_name"])) > _key(have)]
            entry["note"] = (f"{len(young)} newer release(s), none {COOLDOWN_DAYS} days old yet"
                             if young else "up to date")
            out.append(entry)
            continue
        rel = max(newer, key=lambda r: _key(to_tag(r["tag_name"])))
        want = to_tag(rel["tag_name"])
        if not check_image(f"{image_repo}:{want}"):
            entry["note"] = f"{want} released, but {image_repo}:{want} is not in the registry yet"
        else:
            entry["to"] = want
            entry["major"] = _major(want) != _major(have)
            entry["release_url"] = rel.get("html_url", "")
        out.append(entry)
    return out


def _in_config(text: str, change: dict) -> str:
    # The engine's own block: its `version:` line, not the next engine's.
    return re.sub(rf'(\n  {change["engine"]}:[^\n]*\n(?:    [^\n]*\n)*?    version: )'
                  rf'"{re.escape(change["from"])}"', rf'\g<1>"{change["to"]}"', text, count=1)


def _in_renderer(text: str, change: dict) -> str:
    return re.sub(rf'("{change["engine"]}": \("[^"]+", )"{re.escape(change["from"])}"',
                  rf'\g<1>"{change["to"]}"', text, count=1)


def _in_compose(text: str, change: dict) -> str:
    repo = current_versions()[change["engine"]][0]
    return text.replace(f"{repo}:{change['from']}}}", f"{repo}:{change['to']}}}", 1)


EDITS = {"scan-config.yml": _in_config, "scripts/render-env.py": _in_renderer,
         "docker-compose.yml": _in_compose}


def apply(changes: list[dict]) -> None:
    """All three places, or none: a half-applied bump is the drift this prevents."""
    updated = {}
    for rel, edit in EDITS.items():
        text = (ROOT / rel).read_text()
        for change in changes:
            new = edit(text, change)
            if new == text:
                raise SystemExit(f"ERROR: could not move {change['engine']} "
                                 f"{change['from']} -> {change['to']} in {rel}")
            text = new
        updated[rel] = text
    for rel, text in updated.items():
        (ROOT / rel).write_text(text)


def main(argv: list[str]) -> int:
    changes = plan()
    todo = [c for c in changes if c["to"]]
    if "--apply" in argv and todo:
        apply(todo)
    if "--json" in argv or "--apply" in argv:
        print(json.dumps({"changes": todo, "all": changes}, indent=2))
    else:
        for c in changes:
            arrow = f"{c['from']} -> {c['to']}" + (" (MAJOR)" if c.get("major") else "") \
                if c["to"] else f"{c['from']}  {c['note']}"
            print(f"{c['engine']:11} {arrow}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
