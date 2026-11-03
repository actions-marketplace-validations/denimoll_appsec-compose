#!/usr/bin/env python3
"""Diff mode (./run.sh <path> --diff <base-ref>): what did the change touch?

A developer or an AI agent iterating on a branch wants the verdict on *their
change*, in seconds, not a full scan of the codebase on every edit. This works
out the changed set on the host, with git, and narrows every engine to it:

  changed set  = files that differ between merge-base(<base-ref>, HEAD) and the
                 working tree, including uncommitted and untracked (but not
                 ignored) files — an agent's edits are usually uncommitted.
                 Deleted files are gone and are not scanned; `exclude:` applies.

  SAST         Semgrep scans a copy of the changed files only (`tree/`).
  Secrets      Gitleaks / TruffleHog scan the same copy, and Gitleaks also
               walks the commits merge-base..HEAD, so a secret committed on the
               branch and removed again is still caught.
  IaC          Checkov / Trivy config / Hadolint scan a copy of the changed IaC
               files (`iac/`), plus the Terraform files beside a changed one —
               a module is evaluated as a whole, and a resource scanned without
               its variables is mis-evaluated.
  SCA          Dependency scanning only runs when a manifest or lock file is in
               the changed set (then over the whole repo — a lock file is only
               meaningful with its siblings — and the collector keeps what is in
               scope). Otherwise the engines are not started at all.

The copies live in the run's private directory and are bind-mounted at /code in
place of the repo, so the engines' command lines and report paths are exactly
those of a full scan — the collector needs no path translation.

Writes <out-dir>/{tree/, iac/, scope.json} and prints shell assignments for
run.sh to eval. Exit 2 is a usage problem (not a git repo, unknown ref); any
other failure is a crash and run.sh reports it as an incomplete scan.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

EXIT_USAGE = 2

ROOT = Path(__file__).resolve().parent.parent


def _render_env():
    """render-env.py owns the exclude-pattern semantics; load it by path."""
    spec = importlib.util.spec_from_file_location("ass_render_env",
                                                  ROOT / "scripts" / "render-env.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- what a file is ---------------------------------------------------------

# Dependency manifests and lock files: a change to any of them is a change to
# the dependency set, so SCA runs. A superset of what coverage.py looks for
# (tests/test_diff_scope.py keeps it that way).
_SCA_NAMES = {
    "requirements.txt", "requirements.lock", "pyproject.toml", "setup.py",
    "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock",
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "bun.lock",
    "go.mod", "go.sum",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "Gemfile", "Gemfile.lock", "gems.rb", "gems.locked",
    "composer.json", "composer.lock",
    "Cargo.toml", "Cargo.lock",
    "packages.config", "packages.lock.json", "Directory.Packages.props",
    "mix.lock", "pubspec.lock", "Podfile.lock", "Package.resolved",
    "conan.lock", "conanfile.txt", "vcpkg.json", "renv.lock",
}
_SCA_SUFFIXES = (".csproj", ".vbproj", ".fsproj", ".deps.json", ".gemspec",
                 ".nuspec", ".jar", ".war", ".ear")
_REQUIREMENTS = re.compile(r"^requirements.*\.(txt|in)$")

# IaC by name. YAML and JSON are deliberately broad: a Kubernetes manifest, a
# CloudFormation template or a workflow cannot be told from any other YAML by
# its name, and scanning a few extra files costs far less than missing one.
_IAC_SUFFIXES = (".tf", ".tfvars", ".tf.json", ".hcl", ".bicep", ".yaml", ".yml",
                 ".json", ".template")
# Evaluated per directory (module), so a changed one brings its siblings along.
_TERRAFORM_SUFFIXES = (".tf", ".tfvars", ".tf.json")


def is_sca_manifest(path: str) -> bool:
    name = os.path.basename(path)
    return (name in _SCA_NAMES or name.endswith(_SCA_SUFFIXES)
            or bool(_REQUIREMENTS.match(name)))


def is_dockerfile(path: str) -> bool:
    name = os.path.basename(path).lower()
    return (name in ("dockerfile", "containerfile")
            or name.startswith(("dockerfile.", "containerfile."))
            or name.endswith((".dockerfile", ".containerfile")))


def is_iac(path: str) -> bool:
    if is_sca_manifest(path):          # package.json is JSON, not a template
        return False
    return is_dockerfile(path) or path.lower().endswith(_IAC_SUFFIXES)


# --- engines ----------------------------------------------------------------

# How each engine is narrowed, by the part of the change it looks at. An
# engine not listed here is not narrowed: it runs over the whole target as in
# a full scan, and the collector still drops its findings outside the scope.
ENGINE_PARTS = {
    "semgrep": ("sast",),
    "gitleaks": ("secrets",),
    "trufflehog": ("secrets",),
    "trivy": ("sca", "iac"),
    "grype": ("sca",),
    "osv": ("sca",),
    "syft": ("sca",),             # SBOM only — meaningless without SCA
    "checkov": ("iac",),
    "hadolint": ("iac",),
}
# The reports each part of an engine writes (mirrors normalize.SCANNER_FILES;
# tests/test_diff_scope.py keeps the two in step).
ENGINE_REPORTS = {
    "semgrep": {"sast": ["semgrep.sarif"]},
    "gitleaks": {"secrets": ["gitleaks.sarif"]},
    "trufflehog": {"secrets": ["trufflehog.sarif"]},
    "trivy": {"sca": ["trivy-fs.sarif"], "iac": ["trivy-config.sarif"]},
    "grype": {"sca": ["grype.json"]},
    "osv": {"sca": ["osv.sarif"]},
    "syft": {"sca": []},
    "checkov": {"iac": ["checkov.sarif"]},
    "hadolint": {"iac": ["hadolint.sarif"]},
}
SKIP_REASONS = {
    "sast": "no file changed",
    "secrets": "no file changed and no commits on the branch",
    "sca": "no dependency manifest or lock file changed",
    "iac": "no IaC file changed",
}


class UsageError(Exception):
    """The invocation cannot work: exit 2, with a message saying why."""


@dataclass
class Scope:
    base: str
    merge_base: str
    head: str
    files: list[str]                       # changed, present, in scope
    new_files: list[str]                   # added or untracked: every line is new
    changed_lines: dict[str, list[list[int]]]   # modified file -> [[start, end]]
    sca_dirs: list[str]                    # dirs holding a changed manifest/lock
    iac_files: list[str]                   # changed IaC files
    iac_context: list[str]                 # unchanged files scanned beside them
    commits: int                           # commits merge-base..HEAD
    history_scanned: bool                  # Gitleaks walks those commits
    history_note: str = ""                 # why it does not, when it does not
    excluded: int = 0                      # changed files dropped by `exclude:`
    deleted: int = 0                       # changed files that no longer exist
    parts: dict[str, bool] = field(default_factory=dict)
    skipped_engines: dict[str, str] = field(default_factory=dict)
    skipped_reports: dict[str, str] = field(default_factory=dict)
    run_engines: list[str] = field(default_factory=list)


# --- git --------------------------------------------------------------------

def _git(cwd: str, *args: str) -> str:
    try:
        proc = subprocess.run(["git", "-c", "core.quotePath=false", *args],
                              cwd=cwd, capture_output=True, text=True,
                              encoding="utf-8", errors="surrogateescape")
    except FileNotFoundError:
        raise UsageError("--diff needs git on the host") from None
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, args, proc.stdout,
                                            proc.stderr)
    return proc.stdout


def _name_status(target: str, merge_base: str) -> tuple[list[str], set[str], int]:
    """Changed paths (relative to target) vs the working tree; added ones; deletions."""
    out = _git(target, "diff", "--name-status", "-z", "-M", "--relative",
               merge_base, "--")
    parts = out.split("\0")
    changed, added, deleted = [], set(), 0
    i = 0
    while i < len(parts) and parts[i]:
        status = parts[i]
        if status[0] in "RC":          # rename/copy: old path, then new path
            path = parts[i + 2]
            i += 3
        else:
            path = parts[i + 1]
            i += 2
        if status[0] == "D":
            deleted += 1
            continue
        changed.append(path)
        if status[0] == "A":
            added.add(path)
    return changed, added, deleted


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _changed_lines(target: str, merge_base: str) -> dict[str, list[list[int]]]:
    """Line ranges each modified file gained or changed, from a zero-context diff.

    Pure deletions mark nothing: there is no line left to point at.
    """
    out = _git(target, "diff", "-U0", "-M", "--no-color", "--no-ext-diff",
               "--relative", merge_base, "--")
    ranges: dict[str, list[list[int]]] = {}
    current = None
    for line in out.splitlines():
        if line.startswith("+++ "):
            name = line[4:].rstrip("\t")
            current = name[2:] if name.startswith("b/") else None
            if current is not None:
                ranges.setdefault(current, [])
        elif current is not None and line.startswith("@@"):
            m = _HUNK.match(line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or 1)
                if count:
                    ranges[current].append([start, start + count - 1])
    return ranges


def _resolve(target: str, base: str) -> tuple[str, str, str]:
    """(repo top level, merge-base sha, HEAD sha) — or a usage error saying why."""
    try:
        top = _git(target, "rev-parse", "--show-toplevel").strip()
    except subprocess.CalledProcessError:
        raise UsageError(f"--diff needs a git repository, and {target} is not "
                         f"inside one") from None
    try:
        head = _git(target, "rev-parse", "--verify", "--quiet", "HEAD^{commit}").strip()
    except subprocess.CalledProcessError:
        raise UsageError("--diff needs at least one commit (HEAD does not exist)") from None
    try:
        _git(target, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}")
    except subprocess.CalledProcessError:
        raise UsageError(f"--diff: unknown ref '{base}' in {top}. Use a branch, "
                         f"tag or commit that exists locally (fetch it first "
                         f"if it lives on a remote).") from None
    try:
        merge_base = _git(target, "merge-base", base, "HEAD").strip()
    except subprocess.CalledProcessError:
        raise UsageError(f"--diff: '{base}' and HEAD have no common ancestor. In "
                         f"a shallow clone, fetch more history "
                         f"(git fetch --unshallow) or the base branch.") from None
    return top, merge_base, head


def _history(target: str, top: str, merge_base: str, head: str) -> tuple[int, bool, str]:
    """How many commits the branch has, and whether Gitleaks can walk them.

    Gitleaks runs in a container that sees the target directory only. It needs
    the repository itself there: not a subdirectory of one, and not a linked
    worktree, whose .git is a pointer to a path outside the mount.
    """
    commits = int(_git(target, "rev-list", "--count", f"{merge_base}..{head}").strip() or 0)
    if not commits:
        return 0, False, ""
    if os.path.realpath(top) != os.path.realpath(target):
        return commits, False, ("the target is a subdirectory of the repository, "
                                "so its git history is not visible to the scanner")
    if not os.path.isdir(os.path.join(target, ".git")):
        return commits, False, ("the target is a linked worktree or submodule, whose "
                                ".git points outside the scanned directory")
    return commits, True, ""


# --- the scope --------------------------------------------------------------

def compute(target: str, base: str, excludes: list[str], enabled: list[str]) -> Scope:
    target = os.path.realpath(target)
    top, merge_base, head = _resolve(target, base)

    changed, added, deleted = _name_status(target, merge_base)
    untracked = [p for p in _git(target, "ls-files", "--others", "--exclude-standard",
                                 "-z").split("\0") if p]
    regexes = [re.compile(_render_env()._path_regex(e)) for e in excludes if e]

    files, new_files, excluded = [], [], 0
    for path in sorted(set(changed) | set(untracked)):
        full = os.path.join(target, path)
        # Gone (deleted in the working tree) or not a regular file (a submodule,
        # a symlink that could point anywhere): nothing to scan.
        if os.path.islink(full) or not os.path.isfile(full):
            if not os.path.lexists(full):
                deleted += 1
            continue
        if any(r.search(path) for r in regexes):
            excluded += 1
            continue
        files.append(path)
        if path in added or path in untracked:
            new_files.append(path)

    lines = _changed_lines(target, merge_base)
    in_scope = set(files)
    changed_lines = {p: r for p, r in lines.items()
                     if p in in_scope and p not in new_files}

    sca_dirs = sorted({os.path.dirname(p) for p in files if is_sca_manifest(p)})
    iac_files = [p for p in files if is_iac(p)]
    iac_context = _terraform_context(target, iac_files, regexes)

    commits, history_scanned, note = _history(target, top, merge_base, head)
    if "gitleaks" not in enabled:
        history_scanned = False

    parts = {"sast": bool(files), "secrets": bool(files) or history_scanned,
             "sca": bool(sca_dirs), "iac": bool(iac_files)}
    scope = Scope(base=base, merge_base=merge_base, head=head, files=files,
                  new_files=new_files, changed_lines=changed_lines,
                  sca_dirs=sca_dirs, iac_files=iac_files, iac_context=iac_context,
                  commits=commits, history_scanned=history_scanned,
                  history_note=note, excluded=excluded, deleted=deleted, parts=parts)
    _plan(scope, enabled)
    return scope


def _terraform_context(target: str, iac_files: list[str], regexes) -> list[str]:
    """Unchanged Terraform files in the same module as a changed one."""
    changed = set(iac_files)
    dirs = {os.path.dirname(p) for p in iac_files if p.endswith(_TERRAFORM_SUFFIXES)}
    context = []
    for d in sorted(dirs):
        try:
            names = sorted(os.listdir(os.path.join(target, d) if d else target))
        except OSError:
            continue
        for name in names:
            rel = os.path.join(d, name) if d else name
            full = os.path.join(target, rel)
            if (name.endswith(_TERRAFORM_SUFFIXES) and rel not in changed
                    and os.path.isfile(full) and not os.path.islink(full)
                    and not any(r.search(rel) for r in regexes)):
                context.append(rel)
    return context


def _plan(scope: Scope, enabled: list[str]) -> None:
    """Which engines start, and which reports the collector should not expect."""
    for engine in enabled:
        parts = ENGINE_PARTS.get(engine)
        if parts is None:                      # not narrowed: runs as usual
            scope.run_engines.append(engine)
            continue
        live = [p for p in parts if scope.parts[p]]
        for part in parts:
            if not scope.parts[part]:
                for report in ENGINE_REPORTS[engine][part]:
                    scope.skipped_reports[report] = SKIP_REASONS[part]
        if live:
            scope.run_engines.append(engine)
        else:
            scope.skipped_engines[engine] = "; ".join(SKIP_REASONS[p] for p in parts)


def _copy(target: str, paths: list[str], dest: Path) -> None:
    for rel in paths:
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(os.path.join(target, rel), out)


def materialize(target: str, scope: Scope, out_dir: Path) -> None:
    """The copies the engines see at /code, and scope.json for the collector."""
    target = os.path.realpath(target)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    tree, iac = out_dir / "tree", out_dir / "iac"
    tree.mkdir(parents=True)
    iac.mkdir()
    _copy(target, scope.files, tree)
    # The repo's own Semgrep ignore file still applies to the files it names.
    if (os.path.isfile(os.path.join(target, ".semgrepignore"))
            and ".semgrepignore" not in scope.files):
        _copy(target, [".semgrepignore"], tree)
    _copy(target, scope.iac_files + scope.iac_context, iac)
    (out_dir / "scope.json").write_text(json.dumps(asdict(scope), indent=2))


def summary(scope: Scope) -> str:
    """The console lines run.sh prints under Target/Scanners."""
    head = (f"Diff     : vs {scope.base} (merge-base {scope.merge_base[:12]}): "
            f"{len(scope.files)} changed file(s), {scope.commits} commit(s)")
    extras = []
    if scope.excluded:
        extras.append(f"{scope.excluded} excluded")
    if scope.deleted:
        extras.append(f"{scope.deleted} deleted, not scanned")
    if extras:
        head += f" ({', '.join(extras)})"
    lines = [head]
    if scope.commits and not scope.history_scanned and scope.history_note:
        lines.append(f"           branch commits not scanned for secrets: {scope.history_note}")
    if scope.skipped_engines:
        lines.append("Skipped  : " + "; ".join(
            f"{e} ({r})" for e, r in sorted(scope.skipped_engines.items())))
    partial = sorted(r for r in scope.skipped_reports
                     if not any(r in sum(ENGINE_REPORTS[e].values(), [])
                                for e in scope.skipped_engines))
    if partial:
        lines.append("           not run: " + "; ".join(
            f"{r} ({scope.skipped_reports[r]})" for r in partial))
    return "\n".join(lines)


def _env_value(env_file: Path, key: str) -> str:
    """One value from the rendered .env (single-quoted, no escapes)."""
    try:
        text = env_file.read_text()
    except OSError:
        return ""
    m = re.search(rf"^{re.escape(key)}='(.*)'$", text, re.M)
    return m.group(1) if m else ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--enabled", default="", help="space-separated engines")
    parser.add_argument("--env-file", type=Path, required=True,
                        help="the run's rendered .env (for ASS_EXCLUDES)")
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    excludes = _env_value(args.env_file, "ASS_EXCLUDES").split()
    enabled = args.enabled.split()
    try:
        scope = compute(args.target, args.base, excludes, enabled)
    except UsageError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    out_dir = args.out_dir.resolve()
    materialize(args.target, scope, out_dir)

    q = shlex.quote
    exports = {
        "ASS_DIFF": "1",
        "ASS_DIFF_DIR": str(out_dir),
        "ASS_DIFF_TREE": str(out_dir / "tree"),
        "ASS_DIFF_IAC_TREE": str(out_dir / "iac"),
        "ASS_DIFF_SCA": "1" if scope.parts["sca"] else "0",
        "ASS_DIFF_IAC": "1" if scope.parts["iac"] else "0",
        "ASS_DIFF_LOG_OPTS": (f"--log-opts={scope.merge_base}..{scope.head}"
                              if scope.history_scanned else ""),
        # /code is the copy of the changed files, which has no .git: the
        # working-tree mode is the only one that can read it. History is a
        # separate pass over the real repo (ASS_DIFF_LOG_OPTS).
        "GITLEAKS_CMD": "dir",
        "GITLEAKS_LOG_OPTS": "",
    }
    for key, value in exports.items():
        print(f"export {key}={q(value)}")
    print(f"DIFF_RUN_ENGINES={q(' '.join(scope.run_engines))}")
    print(f"DIFF_SUMMARY={q(summary(scope))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
