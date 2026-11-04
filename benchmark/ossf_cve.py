"""JavaScript/TypeScript SAST corpus from the OpenSSF CVE Benchmark.

The OpenSSF CVE Benchmark (MIT) is metadata for 200+ real JS/TS CVEs: the
repository, the last vulnerable commit with the vulnerable line(s) labelled,
and the commit that fixed it. Scanning both versions measures what OWASP
Benchmark measures with hand-written look-alikes — does the tool find the
flaw, and does it go quiet once the flaw is fixed — on real code whose "safe
look-alike" is the maintainers' actual patch.

Only the files that hold a labelled weakness are fetched, at both commits,
from raw.githubusercontent.com (immutable: addressed by commit SHA), into

    <CVE>/pre/<path>    the vulnerable version
    <CVE>/post/<path>   the same path after the fix

The upstream tooling clones each whole repository instead. Semgrep CE's taint
analysis does not cross file boundaries, so for it the surrounding files change
nothing about what is found in these; what changes is that "recognized" (an
on-target rule fires less often after the fix) is counted over these files,
not the whole repository — see RESULTS.md.

The code belongs to each project under its own licence; it is downloaded into
the benchmark cache and scanned locally, never redistributed.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

import scoring


def _owner_repo(url: str) -> str:
    return url.removeprefix("https://github.com/").removesuffix(".git").rstrip("/")


def _safe_rel(path: str) -> str:
    # A few records write the repository root as "/" ("/index.js").
    p = PurePosixPath(path.lstrip("/"))
    if ".." in p.parts or not p.parts:
        raise ValueError(f"refusing weakness path {path!r}")
    return p.as_posix()


def load_cves(cves_dir: Path) -> list[dict]:
    """Every CVE record of the pinned metadata, as scoring cases (no code yet)."""
    cases = []
    for p in sorted(cves_dir.glob("*.json")):
        rec = json.loads(p.read_text())
        weaknesses = [{"file": _safe_rel(w["location"]["file"]), "line": int(w["location"]["line"])}
                      for w in rec["prePatch"]["weaknesses"]]
        cve = rec["CVE"]
        cases.append({
            "cve": cve, "repository": _owner_repo(rec["repository"]),
            "pre_commit": rec["prePatch"]["commit"], "post_commit": rec["postPatch"]["commit"],
            "cwes": list(rec.get("CWEs", [])), "category": scoring.cve_category(rec.get("CWEs", [])),
            "pre": f"{cve}/pre", "post": f"{cve}/post",
            "files": sorted({w["file"] for w in weaknesses}), "weaknesses": weaknesses,
        })
    return cases


def _fetch_one(fetch, cache: Path, repo: str, commit: str, rel: str) -> bytes | None:
    """The file at repo@commit, from the download cache or GitHub; None if absent."""
    dest = cache / repo.replace("/", "__") / commit / rel
    missing = dest.with_name(dest.name + ".404")
    if dest.is_file():
        return dest.read_bytes()
    if missing.exists():
        return None
    try:
        body = fetch(f"https://raw.githubusercontent.com/{repo}/{commit}/{rel}")
    except Exception as exc:  # noqa: BLE001 — urllib's HTTPError and curl's RuntimeError
        # Only a 404 is a fact about the corpus worth caching; anything else
        # (rate limit, network) must fail the run rather than shrink the truth.
        if getattr(exc, "code", None) != 404 and "error: 404" not in str(exc):
            raise
        missing.parent.mkdir(parents=True, exist_ok=True)
        missing.write_text("")
        return None
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(body)
    return body


def build(cves_dir: Path, download_cache: Path, fetch) -> tuple[dict[str, bytes], list[dict], list[dict]]:
    """Return (corpus files, scorable cases, excluded cases with the reason).

    A CVE is excluded when a labelled file cannot be fetched at the vulnerable
    commit (repository deleted or rewritten) or no longer exists at the fix
    commit (renamed or moved: the fixed code is elsewhere, so "recognized"
    could not be judged fairly on this path).
    """
    cases = load_cves(cves_dir)
    jobs = [(c, side, rel) for c in cases for side in ("pre", "post") for rel in c["files"]]

    def run(job):
        c, side, rel = job
        return job, _fetch_one(fetch, download_cache, c["repository"], c[f"{side}_commit"], rel)

    with ThreadPoolExecutor(max_workers=8) as pool:
        got = {(j[0]["cve"], j[1], j[2]): body for j, body in pool.map(run, jobs)}

    files: dict[str, bytes] = {}
    kept, excluded = [], []
    for c in cases:
        absent = [f"{side}:{rel}" for side in ("pre", "post") for rel in c["files"]
                  if got[(c["cve"], side, rel)] is None]
        if absent:
            excluded.append({"cve": c["cve"], "repository": c["repository"],
                             "reason": "not fetchable: " + ", ".join(absent)})
            continue
        for side in ("pre", "post"):
            for rel in c["files"]:
                files[f"{c[side]}/{rel}"] = got[(c["cve"], side, rel)]
        # The fix did not touch the labelled file (it validates the input in
        # another module, bumps a dependency, ...). Upstream counts these too;
        # no file-local analysis can tell the two versions apart.
        c["fix_elsewhere"] = all(got[(c["cve"], "pre", r)] == got[(c["cve"], "post", r)]
                                 for r in c["files"])
        kept.append(c)
    return files, kept, excluded
