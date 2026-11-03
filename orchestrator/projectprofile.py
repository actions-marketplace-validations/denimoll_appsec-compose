#!/usr/bin/env python3
"""Project profile: what a repository is made of, and the config that fits it.

    projectprofile.py <path> [--json] [--write]

One walk of the tree, standard library only, so the host (the `profile`
command, render-env's Checkov framework choice) and the collector (the review
brief) read a repository the same way. It reports the languages, the
frameworks its manifests declare, the IaC and CI files, and the dependency
manifests with their lock files — and from those, a short list of
recommendations, each with its reason. They are deliberately few: the
benchmark (benchmark/RESULTS.md) showed that adding Semgrep packs by
framework moves the score by at most a point or two, often with as many new
false positives as findings, so a profile only proposes what was measured to
help, or what a missing lock file or workflow makes plainly right.

`--write` puts the recommendations into `<path>/.appsec-compose.yml` — a
project config laid over the defaults — and never overwrites one.
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ---- languages, by extension ------------------------------------------------

LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go",
    ".java": "Java", ".kt": "Kotlin", ".scala": "Scala", ".rb": "Ruby", ".php": "PHP",
    ".cs": "C#", ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".rs": "Rust", ".swift": "Swift", ".m": "Objective-C", ".sh": "Shell",
    ".tf": "Terraform", ".sql": "SQL", ".ex": "Elixir", ".exs": "Elixir",
    ".dart": "Dart", ".lua": "Lua", ".pl": "Perl", ".vue": "Vue",
}

# ---- frameworks, from what the manifests declare ----------------------------

# manifest name pattern -> [(dependency pattern, framework)]
_FRAMEWORKS = [
    (re.compile(r"(^|/)(requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py|setup\.cfg)$"), [
        (re.compile(r"""(?im)(^|[\s"'\[,])django\b"""), "django"),
        (re.compile(r"""(?im)(^|[\s"'\[,])flask\b"""), "flask"),
        (re.compile(r"""(?im)(^|[\s"'\[,])fastapi\b"""), "fastapi"),
        (re.compile(r"""(?im)(^|[\s"'\[,])aiohttp\b"""), "aiohttp"),
        (re.compile(r"""(?im)(^|[\s"'\[,])tornado\b"""), "tornado"),
    ]),
    (re.compile(r"(^|/)package\.json$"), [
        (re.compile(r'"express"\s*:'), "express"),
        (re.compile(r'"koa"\s*:'), "koa"),
        (re.compile(r'"fastify"\s*:'), "fastify"),
        (re.compile(r'"@nestjs/core"\s*:'), "nestjs"),
        (re.compile(r'"next"\s*:'), "next"),
        (re.compile(r'"react"\s*:'), "react"),
        (re.compile(r'"vue"\s*:'), "vue"),
        (re.compile(r'"@angular/core"\s*:'), "angular"),
        (re.compile(r'"electron"\s*:'), "electron"),
    ]),
    (re.compile(r"(^|/)(pom\.xml|build\.gradle(\.kts)?)$"), [
        (re.compile(r"spring-boot|org\.springframework"), "spring"),
        (re.compile(r"io\.quarkus"), "quarkus"),
        (re.compile(r"(javax|jakarta)\.servlet"), "servlet"),
    ]),
    (re.compile(r"(^|/)Gemfile$"), [
        (re.compile(r"""gem\s+["']rails["']"""), "rails"),
        (re.compile(r"""gem\s+["']sinatra["']"""), "sinatra"),
    ]),
    (re.compile(r"(^|/)composer\.json$"), [
        (re.compile(r'"laravel/framework"'), "laravel"),
        (re.compile(r'"symfony/[a-z-]+"'), "symfony"),
    ]),
    (re.compile(r"(^|/)go\.mod$"), [
        (re.compile(r"github\.com/gin-gonic/gin"), "gin"),
        (re.compile(r"github\.com/labstack/echo"), "echo"),
        (re.compile(r"github\.com/gofiber/fiber"), "fiber"),
    ]),
    (re.compile(r"\.csproj$"), [
        (re.compile(r"Microsoft\.AspNetCore|Sdk=\"Microsoft\.NET\.Sdk\.Web\""), "aspnetcore"),
    ]),
]

# ---- dependency manifests and their lock files --------------------------------

_MANIFESTS = {
    "requirements.txt": "python", "pyproject.toml": "python", "Pipfile": "python",
    "setup.py": "python", "package.json": "node", "go.mod": "go", "pom.xml": "java",
    "build.gradle": "java", "build.gradle.kts": "java", "Gemfile": "ruby",
    "composer.json": "php", "Cargo.toml": "rust",
}
_LOCKS = {
    "python": {"poetry.lock", "Pipfile.lock", "uv.lock", "requirements.lock", "pdm.lock"},
    "node": {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"},
    "go": {"go.sum"}, "ruby": {"Gemfile.lock"}, "php": {"composer.lock"},
    "rust": {"Cargo.lock"},
}
# Ecosystems whose manifest alone pins what Trivy needs (Maven resolves the
# tree from pom.xml online), so no lock file is expected.
_NO_LOCK_NEEDED = {"java"}
_REQ_LINE = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9._\[\],-]*\s*(?P<op>===|==|>=|<=|~=|!=|>|<|@)?")

# ---- IaC and CI: which Checkov frameworks have files to check -------------------
#
# Checkov walks the whole tree once per framework, whether or not anything of
# that kind exists (on django helm alone took 49 s, the useful github_actions
# 11 s), so render-env runs only these. Detection errs towards including a
# framework: an extra one costs seconds, a missed one silently drops coverage.
_IAC_BY_NAME = [
    (re.compile(r"\.tf$"), "terraform"),
    (re.compile(r"\.tf\.json$"), "terraform_json"),
    (re.compile(r"(^|/)(Dockerfile|Containerfile)([.-][^/]*)?$|\.(dockerfile|containerfile)$", re.I), "dockerfile"),
    (re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$|(^|/)action\.ya?ml$"), "github_actions"),
    (re.compile(r"(^|/)(\.gitlab-ci|[^/]+\.gitlab-ci)\.ya?ml$"), "gitlab_ci"),
    (re.compile(r"(^|/)bitbucket-pipelines\.ya?ml$"), "bitbucket_pipelines"),
    (re.compile(r"(^|/)([^/]*azure-pipelines[^/]*)\.ya?ml$"), "azure_pipelines"),
    (re.compile(r"(^|/)\.circleci/config\.ya?ml$"), "circleci_pipelines"),
    (re.compile(r"(^|/)Chart\.ya?ml$"), "helm"),
    (re.compile(r"(^|/)(kustomization\.ya?ml|Kustomization)$"), "kustomize"),
    (re.compile(r"(^|/)serverless\.(ya?ml|json)$"), "serverless"),
    (re.compile(r"\.bicep$"), "bicep"),
]
_IAC_BY_CONTENT = [
    (re.compile(r"apiVersion\W"), re.compile(r"\bkind\W"), "kubernetes"),
    (re.compile(r"AWSTemplateFormatVersion|AWS::[A-Za-z0-9]+::"), None, "cloudformation"),
    (re.compile(r"schema\.management\.azure\.com"), None, "arm"),
    (re.compile(r"""(?m)(^|[{,])\s*["']?(openapi|swagger)["']?\s*:"""), None, "openapi"),
    (re.compile(r"(?m)^\s*-?\s*hosts\s*:"), re.compile(r"(?m)^\s*-?\s*(tasks|roles|import_playbook)\s*:"), "ansible"),
    (re.compile(r"argoproj\.io"), None, "argo_workflows"),
    (re.compile(r'"(planned_values|resource_changes)"\s*:'), None, "terraform_plan"),
]
_CDK = re.compile(r"aws-cdk-lib|aws_cdk")
_CDK_FILES = re.compile(r"(^|/)(cdk\.json|requirements[^/]*\.txt|package\.json|pyproject\.toml|setup\.py)$")
CI_FRAMEWORKS = {"github_actions", "gitlab_ci", "bitbucket_pipelines", "azure_pipelines",
                 "circleci_pipelines", "argo_workflows"}

# Generated or vendored trees the default `exclude:` does not cover; found
# ones are suggested, never applied silently.
_EXTRA_GENERATED = [".next", ".nuxt", "storybook-static", "bower_components", "coverage",
                    "third_party"]

# The `exclude:` defaults every engine already skips (scan-config.yml).
DEFAULT_EXCLUDES = [".git", "node_modules", "vendor", "dist", "build", "target",
                    ".venv", "venv", "__pycache__", ".gradle", ".tox", ".mypy_cache"]

_SNIFF_BYTES = 256 * 1024
MAX_FILES = 50_000


def _excluded(patterns: list[str]):
    rx = [re.compile("(^|/)" + "".join(".*" if c == "*" else re.escape(c)
                                       for c in p.rstrip("/").replace("**", "*")) + "(/|$)")
          for p in patterns if p]
    return lambda rel: any(r.search(rel) for r in rx)


@dataclass
class Profile:
    path: str
    files: int = 0
    truncated: bool = False                    # stopped at MAX_FILES
    languages: list[tuple[str, int]] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    iac: list[str] = field(default_factory=list)          # Checkov framework names
    manifests: dict[str, list[str]] = field(default_factory=dict)   # ecosystem -> files
    locks: dict[str, list[str]] = field(default_factory=dict)       # ecosystem -> lock files
    unpinned: list[str] = field(default_factory=list)     # requirements.txt with ranges
    dependabot: bool = False
    generated_dirs: list[str] = field(default_factory=list)

    @property
    def ci(self) -> list[str]:
        return [f for f in self.iac if f in CI_FRAMEWORKS]


def _unpinned(path: Path) -> bool:
    pinned = ranged = 0
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return False
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        if m.group("op") in ("==", "===", "@"):
            pinned += 1
        else:
            ranged += 1
    return ranged > 0 and ranged >= pinned


def scan(root: str, excludes: list[str] | None = None) -> Profile:
    """Walk `root` once. Excluded paths are not read, as for every engine."""
    base = Path(root)
    prof = Profile(path=str(base))
    if not base.is_dir():
        return prof
    skip = _excluded(list(excludes or []))
    langs: Counter = Counter()
    iac, frameworks, generated = set(), set(), set()
    for dirpath, dirs, files in os.walk(base):
        rel_dir = os.path.relpath(dirpath, base)
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        generated.update(rel_dir + d for d in dirs if d in _EXTRA_GENERATED)
        dirs[:] = [d for d in dirs if d != ".git" and not skip(rel_dir + d)]
        for name in files:
            prof.files += 1
            if prof.files > MAX_FILES:
                prof.truncated = True
                break
            rel = rel_dir + name
            if skip(rel):
                continue
            lang = LANGUAGES.get(Path(name).suffix.lower())
            if lang:
                langs[lang] += 1
            iac.update(fw for rx, fw in _IAC_BY_NAME if rx.search(rel))
            if re.search(r"(^|/)\.github/dependabot\.ya?ml$", rel):
                prof.dependabot = True
            eco = _MANIFESTS.get(name) or ("dotnet" if name.endswith(".csproj") else None)
            if eco:
                prof.manifests.setdefault(eco, []).append(rel)
                if name == "requirements.txt" and _unpinned(Path(dirpath, name)):
                    prof.unpinned.append(rel)
            for e, locks in _LOCKS.items():
                if name in locks:
                    prof.locks.setdefault(e, []).append(rel)
            sniff_manifest = any(rx.search(rel) for rx, _ in _FRAMEWORKS)
            sniff_iac = name.lower().endswith((".yml", ".yaml", ".json", ".template"))
            if not (sniff_manifest or sniff_iac or _CDK_FILES.search(rel)):
                continue
            try:
                with open(os.path.join(dirpath, name), "rb") as fh:
                    text = fh.read(_SNIFF_BYTES).decode("utf-8", "replace")
            except OSError:
                continue
            for rx, deps in _FRAMEWORKS:
                if rx.search(rel):
                    frameworks.update(fw for drx, fw in deps if drx.search(text))
            if sniff_iac:
                for rx, also, fw in _IAC_BY_CONTENT:
                    if fw not in iac and rx.search(text) and (also is None or also.search(text)):
                        iac.add(fw)
            if _CDK.search(text):
                iac.add("cdk")
        if prof.truncated:
            break
    prof.languages = langs.most_common()
    prof.frameworks = sorted(frameworks)
    prof.iac = sorted(iac)
    prof.generated_dirs = sorted(generated)
    for files in (*prof.manifests.values(), *prof.locks.values()):
        files.sort()
    return prof


def iac_frameworks(root: str, excludes: list[str]) -> list[str] | None:
    """The Checkov frameworks `root` has files for; None = check them all
    (nothing to inspect, or a tree too large to inspect quickly)."""
    if not root or not Path(root).is_dir():
        return None
    prof = scan(root, excludes)
    return None if prof.truncated else prof.iac


# ---- recommendations ------------------------------------------------------------

@dataclass
class Recommendation:
    path: list[str]          # config keys, e.g. ["scanners", "osv", "enabled"]
    value: object
    reason: str


def significant(prof: Profile, language: str) -> bool:
    """A language the project is written in, not three helper scripts in it."""
    counts = dict(prof.languages)
    n, total = counts.get(language, 0), sum(counts.values()) or 1
    return n >= 50 or (n >= 10 and n / total >= 0.10)


def recommend(prof: Profile) -> list[Recommendation]:
    recs: list[Recommendation] = []
    if significant(prof, "Python"):
        recs.append(Recommendation(
            ["scanners", "semgrep", "rules"], ["default", "auto"],
            "Python: `auto` adds p/python to p/default — the one pack the benchmark "
            "found worth adding (weak-hash detection 37 -> 54 of 71, no new false "
            "positives); framework packs added nothing measurable."))
    def unlocked(eco: str) -> bool:
        if eco in _NO_LOCK_NEEDED or eco == "dotnet" or prof.locks.get(eco):
            return False
        # A requirements.txt of exact pins is its own lock; anything else
        # Python (pyproject.toml, Pipfile, setup.py) needs one.
        return not (eco == "python" and all(Path(m).name == "requirements.txt"
                                             for m in prof.manifests[eco]))
    unlocked = sorted(e for e in prof.manifests if unlocked(e))
    if unlocked or prof.unpinned:
        what = ", ".join(sorted(set(unlocked) | ({"python"} if prof.unpinned else set())))
        recs.append(Recommendation(
            ["scanners", "osv", "enabled"], True,
            f"{what}: dependencies without a lock file or with version ranges — Trivy "
            "resolves only exact versions, so they would go unscanned. OSV-Scanner "
            "resolves ranges; it sends dependency names and versions to api.osv.dev "
            "(see PRIVACY.md). Committing a lock file is the better fix."))
    if "github_actions" not in prof.iac and not prof.dependabot:
        recs.append(Recommendation(
            ["scanners", "zizmor", "enabled"], False,
            "no GitHub Actions workflows, actions or dependabot config: nothing for "
            "zizmor to audit."))
    if prof.generated_dirs:
        recs.append(Recommendation(
            ["exclude"], None,
            "generated or vendored directories present ("
            + ", ".join(prof.generated_dirs)
            + "): consider adding them to `exclude:` — it replaces the default list, "
            "so repeat the defaults. Review first: `coverage` or `third_party` can be "
            "real code."))
    return recs


def overlay(recs: list[Recommendation]) -> str:
    """The recommendations as a project config, each with its reason."""
    lines = ["# appsec-compose project config, from `appsec-compose profile`.",
             "# Laid over the shipped scan-config.yml: only what differs is here.", ""]
    scanners = [r for r in recs if r.path[0] == "scanners"]
    if scanners:
        lines.append("scanners:")
        for r in scanners:
            lines += [f"  # {line}" for line in _wrap(r.reason, 74)]
            lines.append(f"  {r.path[1]}: {{ {r.path[2]}: {json.dumps(r.value)} }}")
    for r in recs:
        if r.path[0] == "exclude":
            lines += ["", *(f"# {line}" for line in _wrap(r.reason, 76))]
    return "\n".join(lines) + "\n"


def _wrap(text: str, width: int) -> list[str]:
    out, line = [], ""
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    return out + ([line] if line else [])


# ---- command line ---------------------------------------------------------------

def _text(prof: Profile, recs: list[Recommendation]) -> str:
    out = [f"Project: {prof.path} ({prof.files:,} files"
           + (", stopped counting" if prof.truncated else "") + ")"]
    if prof.languages:
        out.append("Languages: " + ", ".join(f"{l} ({n})" for l, n in prof.languages[:8]))
    out.append("Frameworks: " + (", ".join(prof.frameworks) or "none detected"))
    out.append("IaC / CI: " + (", ".join(prof.iac) or "none"))
    for eco, files in sorted(prof.manifests.items()):
        lock = ", ".join(prof.locks.get(eco, [])) or (
            "exact pins (requirements.txt)" if eco == "python" and not prof.unpinned
            and all(Path(m).name == "requirements.txt" for m in files) else "no lock file")
        out.append(f"Dependencies ({eco}): {', '.join(files[:4])}"
                   + (f" +{len(files) - 4}" if len(files) > 4 else "") + f" — {lock}")
    out.append("")
    if recs:
        out.append("Recommended for .appsec-compose.yml:")
        for r in recs:
            key = ".".join(r.path)
            val = "" if r.value is None else f" = {json.dumps(r.value)}"
            out += [f"  - {key}{val}", *(f"      {l}" for l in _wrap(r.reason, 72))]
    else:
        out.append("The shipped defaults fit this project; no config needed.")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = {a for a in argv[1:] if a.startswith("--")}
    unknown = flags - {"--json", "--write"}
    if unknown or len(args) > 1:
        print("usage: profile [<path>] [--json] [--write]", file=sys.stderr)
        return 2
    target = Path(args[0] if args else ".").resolve()
    if not target.is_dir():
        print(f"ERROR: {target} is not a directory", file=sys.stderr)
        return 2
    prof = scan(str(target), DEFAULT_EXCLUDES)
    recs = recommend(prof)
    written = None
    if "--write" in flags and recs:
        dest = target / ".appsec-compose.yml"
        if dest.exists():
            print(f"{dest} exists; not overwritten — merge the recommendations by hand.",
                  file=sys.stderr)
        else:
            dest.write_text(overlay(recs))
            written = str(dest)
    if "--json" in flags:
        doc = {"profile": {**asdict(prof), "ci": prof.ci},
               "recommendations": [asdict(r) for r in recs], "written": written}
        print(json.dumps(doc, separators=(",", ":")))
    else:
        print(_text(prof, recs))
        if written:
            print(f"\nWrote {written}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
