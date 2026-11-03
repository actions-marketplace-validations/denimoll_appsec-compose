"""The SCA corpus: pinned vulnerable packages, their manifests, and OSV truth.

Each package below is pinned to one exact version that is known to be
vulnerable. The harness writes them out as the lock files and manifests real
projects carry (requirements.txt, package-lock.json, go.mod, gradle.lockfile,
Gemfile.lock) — generated at benchmark time rather than committed, because this
repository scans itself and would otherwise fail its own gate on them.

Ground truth is the set of advisories OSV (https://osv.dev) lists for each
package@version, snapshotted into sca_truth.json with the date it was taken.
`python3 benchmark/bench.py --refresh-sca-truth` re-queries it. The truth is
only as complete as OSV on that day, and the engines read their own databases
(Trivy DB, Grype DB) built on other days — so the recall here is a statement
about a pair of dates, which RESULTS.md records.
"""
from __future__ import annotations

import json

import net

# (OSV ecosystem, package name, exact version). Chosen as widely used packages
# with well-known advisories, a handful per ecosystem.
PACKAGES = [
    ("PyPI", "django", "3.2.0"),
    ("PyPI", "requests", "2.25.1"),
    ("PyPI", "pyyaml", "5.3.1"),
    ("PyPI", "jinja2", "2.11.2"),
    ("PyPI", "urllib3", "1.26.4"),
    ("PyPI", "pillow", "8.1.0"),
    ("PyPI", "flask", "1.1.2"),
    ("npm", "lodash", "4.17.15"),
    ("npm", "minimist", "1.2.5"),
    ("npm", "axios", "0.21.0"),
    ("npm", "node-fetch", "2.6.0"),
    ("npm", "jsonwebtoken", "8.5.1"),
    ("npm", "express", "4.17.1"),
    ("Go", "github.com/gin-gonic/gin", "v1.6.0"),
    ("Go", "golang.org/x/text", "v0.3.5"),
    ("Go", "gopkg.in/yaml.v2", "v2.2.2"),
    ("Go", "github.com/gorilla/websocket", "v1.4.0"),
    ("Go", "github.com/dgrijalva/jwt-go", "v3.2.0+incompatible"),
    ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
    ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8"),
    ("Maven", "commons-collections:commons-collections", "3.2.1"),
    ("Maven", "org.yaml:snakeyaml", "1.30"),
    ("Maven", "org.springframework:spring-web", "5.3.17"),
    ("RubyGems", "nokogiri", "1.10.4"),
    ("RubyGems", "rack", "2.0.7"),
    ("RubyGems", "loofah", "2.2.2"),
]

MANIFEST = {"PyPI": "python/requirements.txt", "npm": "node/package-lock.json",
            "Go": "go/go.mod", "Maven": "jvm/gradle.lockfile",
            "RubyGems": "ruby/Gemfile.lock"}


def _by(eco: str) -> list[tuple[str, str]]:
    return [(n, v) for e, n, v in PACKAGES if e == eco]


def manifests() -> dict[str, str]:
    """Return {relative path: content} for every ecosystem's manifest."""
    out: dict[str, str] = {}

    out[MANIFEST["PyPI"]] = "".join(f"{n}=={v}\n" for n, v in _by("PyPI"))

    npm = _by("npm")
    lock = {"name": "bench-sca", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
            "packages": {"": {"name": "bench-sca", "version": "1.0.0",
                              "dependencies": {n: v for n, v in npm}}}}
    for n, v in npm:
        lock["packages"][f"node_modules/{n}"] = {
            "version": v, "resolved": f"https://registry.npmjs.org/{n}/-/{n}-{v}.tgz"}
    out[MANIFEST["npm"]] = json.dumps(lock, indent=2) + "\n"
    out["node/package.json"] = json.dumps(
        {"name": "bench-sca", "version": "1.0.0",
         "dependencies": {n: v for n, v in npm}}, indent=2) + "\n"

    out[MANIFEST["Go"]] = ("module example.com/bench-sca\n\ngo 1.16\n\nrequire (\n"
                           + "".join(f"\t{n} {v}\n" for n, v in _by("Go")) + ")\n")

    out[MANIFEST["Maven"]] = (
        "# This is a Gradle generated file for dependency locking.\n"
        "# Manual edits can break the build and are not advised.\n"
        "# This file is expected to be part of source control.\n"
        + "".join(f"{n}:{v}=compileClasspath,runtimeClasspath\n" for n, v in _by("Maven"))
        + "empty=annotationProcessor\n")

    gems = _by("RubyGems")
    out[MANIFEST["RubyGems"]] = (
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        + "".join(f"    {n} ({v})\n" for n, v in gems)
        + "\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n"
        + "".join(f"  {n} (= {v})\n" for n, v in gems)
        + "\nBUNDLED WITH\n   2.1.4\n")
    out["ruby/Gemfile"] = ("source 'https://rubygems.org'\n"
                           + "".join(f"gem '{n}', '{v}'\n" for n, v in gems))
    return out


# --------------------------------------------------------------------------
# Ground truth from OSV
# --------------------------------------------------------------------------

OSV_API = "https://api.osv.dev/v1"


def fetch_truth() -> list[dict]:
    """Query OSV for every pinned package; return the truth entries.

    Withdrawn advisories are dropped. Each kept advisory carries its aliases,
    so a scanner reporting the CVE and OSV listing the GHSA still match.
    """
    queries = [{"package": {"ecosystem": e, "name": n}, "version": v}
               for e, n, v in PACKAGES]
    results = net.post_json(f"{OSV_API}/querybatch", {"queries": queries})["results"]
    details: dict[str, dict] = {}
    truth = []
    for (eco, name, version), res in zip(PACKAGES, results):
        if res.get("next_page_token"):
            raise RuntimeError(f"OSV paginated {name}@{version}; extend fetch_truth")
        advisories = []
        for v in res.get("vulns") or []:
            vid = v["id"]
            if vid not in details:
                details[vid] = net.get_json(f"{OSV_API}/vulns/{vid}")
            d = details[vid]
            if d.get("withdrawn"):
                continue
            advisories.append({"id": vid, "aliases": sorted(set(d.get("aliases") or [])),
                               "published": d.get("published", "")})
        truth.append({"ecosystem": eco, "name": name, "version": version,
                      "manifest": MANIFEST[eco],
                      "advisories": sorted(advisories, key=lambda a: a["id"])})
    return truth
