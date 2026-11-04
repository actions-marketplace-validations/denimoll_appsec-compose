"""Shared set-up for the manager tests: a sandboxed home, a stub docker and a stub git.

The docker stub is test_run_sh.py's idea, made per project: an outcome file named
after COMPOSE_PROJECT_NAME says what that project's scan does, so one batch can
hold a pass, a fail and a crash. It also keeps the effective config each project
was given. The git stub records its argv and fakes a clone; a real clone needs a
remote, and file:// is exactly what the code refuses.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LAUNCHER = ROOT / "bin" / "appsec-compose"

DOCKER = r"""#!/bin/sh
dump="$STUB_DUMP"
key="$COMPOSE_PROJECT_NAME"
STUB_RUN=0
[ -f "$dump/outcome-$key" ] && . "$dump/outcome-$key"
case " $* " in
  *" up "*)
    [ -n "$ASS_CONFIG_FILE" ] && cp "$ASS_CONFIG_FILE" "$dump/config-$key.yml"
    env > "$dump/environ-$key"
    exit "${STUB_UP:-0}" ;;
  *" run "*)
    if [ -z "$STUB_NO_FINDINGS" ]; then
      if [ -f "$dump/findings-$key.json" ]; then
        cp "$dump/findings-$key.json" "$ASS_REPORTS_DIR/findings.json"
      else
        printf '%s' '{"severity_counts": {"high": 2, "low": 1}, "policy": {"breaching": 2},
          "baseline": {"enabled": false}}' > "$ASS_REPORTS_DIR/findings.json"
      fi
      echo "<html><body>the summary</body></html>" > "$ASS_REPORTS_DIR/summary.html"
      echo "the brief" > "$ASS_REPORTS_DIR/review-brief.md"
      echo '{"raw": "NATIVE-SECRET-VALUE"}' > "$ASS_REPORTS_DIR/native/trufflehog.json"
    fi
    exit "$STUB_RUN" ;;
esac
exit 0
"""

GIT = r"""#!/bin/sh
for a in "$@"; do printf '%s\036' "$a"; done >> "$STUB_DUMP/git-calls"
echo >> "$STUB_DUMP/git-calls"
env | grep '^GIT_' > "$STUB_DUMP/git-env"
[ -n "$STUB_GIT_FAIL" ] && { echo "fatal: could not read from remote" >&2; exit 128; }
for a in "$@"; do last="$a"; done
case " $* " in
  *" clone "*) mkdir -p "$last/.git"; echo cloned > "$last/app.py" ;;
  *" get-url "*) cat "$STUB_DUMP/git-origin" ;;
esac
exit 0
"""


class Sandbox:
    def __init__(self, tmp_path: Path, monkeypatch):
        self.tmp = tmp_path
        self.dump = tmp_path / "dump"
        self.bin = tmp_path / "bin"
        self.home = tmp_path / "home"
        self.config = tmp_path / "config"
        self.state = tmp_path / "state"
        for folder in (self.dump, self.bin, self.home):
            folder.mkdir()
        for tool, text in (("docker", DOCKER), ("git", GIT)):
            (self.bin / tool).write_text(text)
            (self.bin / tool).chmod(0o755)
        for key in list(os.environ):
            if key.startswith(("ASS_", "STUB_", "APPSEC_COMPOSE_")):
                monkeypatch.delenv(key)
        monkeypatch.setenv("HOME", str(self.home))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(self.config))
        monkeypatch.setenv("XDG_STATE_HOME", str(self.state))
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        monkeypatch.setenv("PATH", f"{self.bin}:{os.environ['PATH']}")
        monkeypatch.setenv("STUB_DUMP", str(self.dump))

    def cli(self, *args, cwd=None):
        return subprocess.run([str(LAUNCHER), *map(str, args)], capture_output=True, text=True,
                              cwd=cwd or self.tmp)

    def repo(self, name="repo") -> Path:
        path = self.tmp / name
        path.mkdir(exist_ok=True)
        return path

    def add(self, name, target=None, *flags):
        proc = self.cli("project", "add", name, target or self.repo(f"src-{name}"), *flags)
        assert proc.returncode == 0, proc.stderr
        return proc

    def outcome(self, project, text):
        """What this project's scan does: shell assignments such as STUB_RUN=1."""
        (self.dump / f"outcome-appsec-project-{project}").write_text(text + "\n")

    def findings(self, project, data):
        (self.dump / f"findings-appsec-project-{project}.json").write_text(json.dumps(data))

    def effective_config(self, project):
        return self.dump / f"config-appsec-project-{project}.yml"

    def environ(self, project):
        path = self.dump / f"environ-appsec-project-{project}"
        return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)

    def git_calls(self):
        path = self.dump / "git-calls"
        if not path.exists():
            return []
        return [line.split("\036")[:-1] for line in path.read_text().split("\n") if line]

    def profile(self, name, text):
        folder = self.config / "appsec-compose" / "profiles"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{name}.yml").write_text(text)

    def project_state(self, name):
        return self.state / "appsec-compose" / "projects" / name

    def definition(self, name):
        return self.config / "appsec-compose" / "projects" / f"{name}.yml"
