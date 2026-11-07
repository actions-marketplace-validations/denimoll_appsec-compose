"""The MCP server (appsec_mcp): path validation, the scan contract, paging,
secret masking and the suppress edit.

The CLI is a stub that speaks the `appsec-compose scan --json` contract over a
fixture findings.json, so these run without Docker. Secret values are built at
runtime: a literal token in this file would be the first thing the project's own
secret scan reports.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import textwrap
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from appsec_mcp import core, triage, views  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "mcp" / "findings.json"
SECRET = "glpat-" + "Zq9" * 7                      # 27 chars: config.env:2, cols 14..41
SECRET2 = "sk_" + "live" + "_" + "4f9a" * 6        # 32 chars: src/app.py:9, cols 12..44

STUB = """\
#!{python}
import json, os, sys
from pathlib import Path
import yaml

args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps(args) + "\\n")
assert args[0] == "scan", args
reports = Path(args[args.index("--reports") + 1])
data = json.loads(Path(os.environ["STUB_FINDINGS"]).read_text())
ignored = {{}}
if "--repo-config" in args:
    cfg = yaml.safe_load(Path(args[args.index("--repo-config") + 1]).read_text()) or {{}}
    ignored = {{e["fingerprint"]: e["reason"] for e in cfg.get("ignore") or []
               if isinstance(e, dict) and "fingerprint" in e}}
kept = [f for f in data["findings"] if f["fingerprint"] not in ignored]
data["suppressed"] += [dict(f, reason=ignored[f["fingerprint"]])
                       for f in data["findings"] if f["fingerprint"] in ignored]
data["findings"] = kept
data["suppressed_count"] = len(data["suppressed"])
data["policy"]["breaching"] = sum(f["severity"] in ("high", "critical") for f in kept)
reports.mkdir(parents=True, exist_ok=True)
(reports / "findings.json").write_text(json.dumps(data))
(reports / "review-brief.md").write_text(Path(os.environ["STUB_BRIEF"]).read_text())
for i in range(3):
    print(f"semgrep-1 | scanning step {{i}}", file=sys.stderr)
code = 1 if data["policy"]["breaching"] else 0
print(json.dumps({{"exit_code": code, "verdict": "fail" if code else "pass",
                  "reports_dir": str(reports),
                  "findings_json": str(reports / "findings.json"),
                  "review_brief": str(reports / "review-brief.md"),
                  "severity_counts": data["severity_counts"],
                  "breaching": data["policy"]["breaching"],
                  "baseline": data["baseline"]}}))
sys.exit(code)
"""

BRIEF = """\
# Security review brief

appsec-compose 1.2.0 · 2026-11-02T12:00:00Z · target: filesystem

## Scope

- Engines: checkov, gitleaks, semgrep, trivy

## Blind spots

What this scan did not or could not check.

- **Cross-file data flow:** Semgrep CE follows taint within one file.
- **Logic the tools cannot model:** authentication and authorization.

## Findings (8, 5 gating)

#### `src/app.py:7` — python.lang.security.audit.subprocess-shell-true.subprocess-shell-true

- **MEDIUM** · sast · semgrep
- fingerprint: `c75f00c2ba12000000000000000000000000000e`

```
    5 | def run(cmd):
    6 |     # shell injection
>   7 |     return subprocess.call(cmd, shell=True)
    8 |
    9 | API_KEY = "{secret2}"
```

## Recording a verdict

```yaml
ignore:
  - fingerprint: <fingerprint>
```
"""


# ---- fixtures -------------------------------------------------------------------

@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "work" / "repo"
    (r / "src").mkdir(parents=True)
    (r / "config.env").write_text(f"# Fake credential for tests.\nGITLAB_TOKEN={SECRET}\n")
    (r / "src" / "app.py").write_text(
        '"""Sample."""\nimport subprocess\n\n\ndef run(cmd):\n    # shell injection\n'
        "    return subprocess.call(cmd, shell=True)\n\n"
        f'API_KEY = "{SECRET2}"\n')
    (r / "Dockerfile").write_text("FROM ubuntu:latest\n")
    (r / "requirements.txt").write_text("flask==1.0\nrequests==2.20.0\n")
    return r.resolve()


@pytest.fixture
def tool(tmp_path, monkeypatch):
    """A tool checkout whose CLI is the stub; state under tmp."""
    t = tmp_path / "tool"
    (t / "bin").mkdir(parents=True)
    shutil.copy(ROOT / "scan-config.yml", t / "scan-config.yml")
    (t / "VERSION").write_text("9.9.9\n")
    cli = t / "bin" / "appsec-compose"
    cli.write_text(STUB.format(python=sys.executable))
    cli.chmod(0o755)
    findings = tmp_path / "findings.json"
    findings.write_text(FIXTURE.read_text().replace("{{SECRET}}", SECRET))
    brief = tmp_path / "brief.md"
    brief.write_text(BRIEF.format(secret2=SECRET2))
    log = tmp_path / "argv.log"
    monkeypatch.setattr(core, "TOOL_DIR", t.resolve())
    monkeypatch.setenv("APPSEC_MCP_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("STUB_FINDINGS", str(findings))
    monkeypatch.setenv("STUB_BRIEF", str(brief))
    monkeypatch.setenv("STUB_LOG", str(log))
    monkeypatch.delenv("APPSEC_MCP_ALLOWED_ROOTS", raising=False)
    return t.resolve()


def run_scan(target, **kw):
    return asyncio.run(core.scan(target, **kw))


@pytest.fixture
def scanned(tool, repo):
    run_scan(repo)
    return repo


def argv_calls(tool) -> list[list[str]]:
    return [json.loads(l) for l in Path(tool / ".." / "argv.log").read_text().splitlines()]


def everything(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)


# ---- path validation ----------------------------------------------------------------

def test_fixture_matches_the_findings_contract():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "schemas" / "findings.schema.json").read_text())
    jsonschema.validate(json.loads(FIXTURE.read_text()), schema)


@pytest.mark.parametrize("bad", ["", "   ", "/", "/usr", "~", "\x00x"])
def test_target_rejects_roots_home_and_junk(bad):
    with pytest.raises(core.UserError):
        core.resolve_target(bad)


def test_target_rejects_home_ancestor_missing_and_files(tmp_path):
    with pytest.raises(core.UserError):
        core.resolve_target(str(Path.home().parent))
    with pytest.raises(core.UserError, match="does not exist"):
        core.resolve_target(str(tmp_path / "nope"))
    f = tmp_path / "file.txt"
    f.write_text("x")
    with pytest.raises(core.UserError, match="not a directory"):
        core.resolve_target(str(f))


def test_target_resolves_relative_and_symlinked_paths(repo, monkeypatch):
    monkeypatch.chdir(repo.parent)
    assert core.resolve_target("repo") == repo
    link = repo.parent / "link"
    link.symlink_to(repo)
    assert core.resolve_target(str(link)) == repo


def test_target_honours_allowed_roots(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_MCP_ALLOWED_ROOTS", str(tmp_path / "elsewhere"))
    with pytest.raises(core.UserError, match="ALLOWED_ROOTS"):
        core.resolve_target(str(repo))
    monkeypatch.setenv("APPSEC_MCP_ALLOWED_ROOTS", str(repo.parent))
    assert core.resolve_target(str(repo)) == repo


@pytest.mark.parametrize("ref", ["-rf", "--output=/x", "a..b", "main branch", "$(id)", "a;b", "`x`"])
def test_diff_base_rejects_anything_but_a_ref(ref):
    with pytest.raises(core.UserError):
        core.validate_diff_base(ref)


@pytest.mark.parametrize("ref", ["origin/main", "HEAD~1", "HEAD^", "v1.2.0", "a1b2c3d", "@{upstream}"])
def test_diff_base_accepts_refs(ref):
    assert core.validate_diff_base(ref) == ref


# ---- scan --------------------------------------------------------------------------------

def test_scan_returns_compact_verdict_and_remembers_it(tool, repo):
    lines = []

    async def on_line(line):
        lines.append(line)

    out = run_scan(repo, on_line=on_line)
    assert out["verdict"] == "fail" and out["exit_code"] == 1
    assert out["gating"] == 5 and out["findings"] == 8
    assert out["severity_counts"] == {"critical": 1, "high": 4, "medium": 2, "low": 1}
    assert out["blind_spots"][0].startswith("Cross-file data flow:")
    assert "**" not in "".join(out["blind_spots"])
    assert out["suppressed"] == 1
    assert len(lines) == 3                        # stderr streamed as progress

    reports = Path(out["reports"]["dir"])
    assert not reports.is_relative_to(repo)       # nothing written into the target
    assert sorted(p.name for p in repo.iterdir()) == [
        "Dockerfile", "config.env", "requirements.txt", "src"]
    assert core.load_last_scan(repo)["findings_json"] == str(reports / "findings.json")

    argv = argv_calls(tool)[-1]
    assert argv[:2] == ["scan", str(repo)] and "--json" in argv
    assert "--repo-config" not in argv and "--baseline" not in argv


def test_scan_passes_project_config_baseline_and_flags(tool, repo):
    (repo / core.PROJECT_CONFIG).write_text("scanners:\n  semgrep: {enabled: true}\n")
    (repo / core.PROJECT_BASELINE).write_text('{"fingerprints": []}')
    run_scan(repo, diff_base="origin/main", fail_on="critical")
    argv = argv_calls(tool)[-1]
    assert argv[argv.index("--repo-config") + 1] == str(repo / core.PROJECT_CONFIG)
    assert argv[argv.index("--baseline") + 1] == str(repo / core.PROJECT_BASELINE)
    assert argv[argv.index("--diff") + 1] == "origin/main"
    assert argv[argv.index("--fail-on") + 1] == "critical"


def write_run_sh(tool, extra_flags=""):
    os.remove(tool / "bin" / "appsec-compose")
    (tool / "run.sh").write_text(textwrap.dedent(f"""\
        #!/usr/bin/env bash
        # argument parser excerpt the server inspects:
        #   case "$1" in
        {extra_flags}
        echo "$@" > "$STUB_LOG"
        while [[ $# -gt 0 ]]; do
          case "$1" in
            --reports) R="$2"; shift 2 ;;
            *) shift ;;
          esac
        done
        mkdir -p "$R"
        cp "$STUB_FINDINGS" "$R/findings.json"
        cp "$STUB_BRIEF" "$R/review-brief.md"
        echo "Done." ; echo "compose noise" >&2
        exit 1
        """))


def test_scan_falls_back_to_run_sh_without_json(tool, repo):
    write_run_sh(tool)
    cli = core.detect_cli()
    assert cli.kind == "run.sh" and not cli.supports_json and not cli.supports_diff
    out = run_scan(repo)
    assert out["verdict"] == "fail" and out["gating"] == 5      # read from findings.json
    argv = Path(os.environ["STUB_LOG"]).read_text().split()
    assert "--json" not in argv and "--name" in argv
    assert argv[argv.index("--name") + 1].startswith("mcp-")
    with pytest.raises(core.UserError, match="diff mode"):
        run_scan(repo, diff_base="origin/main")


def test_run_sh_flag_support_is_read_from_its_parser(tool):
    write_run_sh(tool, extra_flags="    --json) JSON=1; shift ;;\n    --diff) D=$2; shift 2 ;;")
    cli = core.detect_cli()
    assert cli.supports_json and cli.supports_diff


@pytest.mark.parametrize("code,verdict", [(2, "usage_error"), (3, "scan_error"), (137, "scan_error")])
def test_failed_scan_never_reports_the_previous_result(tool, repo, code, verdict):
    assert run_scan(repo)["verdict"] == "fail"        # leaves a findings.json behind
    os.remove(tool / "bin" / "appsec-compose")
    (tool / "run.sh").write_text(f"#!/usr/bin/env bash\necho 'Error: docker is not running' >&2\nexit {code}\n")
    out = run_scan(repo)
    assert out["verdict"] == verdict and "findings" not in out and "gating" not in out
    assert "Error: docker is not running" in out["log_tail"]
    with pytest.raises(core.UserError, match="without findings"):
        views.load_report(repo)


def test_a_hung_scan_is_killed_at_the_timeout():
    import time
    started = time.monotonic()
    out = asyncio.run(core.run_cli(["bash", "-c", "echo starting >&2; sleep 30"],
                                   json_stdout=False, timeout=0.5))
    assert out.timed_out and out.exit_code == 3 and "starting" in out.log_tail
    assert time.monotonic() - started < 10


def test_tools_need_a_scan_first(tool, repo):
    with pytest.raises(core.UserError, match="scan"):
        views.load_report(repo)


# ---- findings / finding / brief ----------------------------------------------------

def test_findings_paginate_in_gate_order(scanned):
    report = views.load_report(scanned)
    first = views.list_findings(report, limit=3)
    assert first["total"] == 8 and first["returned"] == 3 and first["next_offset"] == 3
    assert [f["severity"] for f in first["findings"]] == ["critical", "high", "high"]
    assert all(f["gating"] for f in first["findings"])
    assert all(len(f["fingerprint"]) == 12 for f in first["findings"])
    rest = views.list_findings(report, limit=3, offset=6)
    assert rest["returned"] == 2 and rest["next_offset"] is None
    seen = {f["fingerprint"] for p in (0, 3, 6)
            for f in views.list_findings(report, limit=3, offset=p)["findings"]}
    assert len(seen) == 8


def test_findings_filters(scanned):
    report = views.load_report(scanned)
    gating = views.list_findings(report, gating_only=True)
    assert gating["total"] == 5
    assert {f["category"] for f in views.list_findings(report, category="iac")["findings"]} == {"iac"}
    assert views.list_findings(report, severity_min="high")["total"] == 5
    assert views.list_findings(report, file="src")["total"] == 2
    assert views.list_findings(report, file="*.txt")["total"] == 2
    assert views.list_findings(report, file="config.env")["total"] == 2   # /code/ prefix normalised
    flask = views.list_findings(report, category="sca", severity_min="high")["findings"]
    assert any(f.get("package") == "flask@1.0" and f["fixed_in"] == "2.3.2, 2.2.5" for f in flask)
    new = views.list_findings(report, new_only=True)
    assert new["total"] == 8 and "notes" in new                # baseline off: no-op, said so
    with_supp = views.list_findings(report, include_suppressed=True)
    assert with_supp["total"] == 9
    assert with_supp["findings"][-1]["suppressed"].startswith("not reachable")
    with pytest.raises(core.UserError):
        views.list_findings(report, category="web")


def test_findings_messages_are_one_line_and_short(scanned):
    items = views.list_findings(views.load_report(scanned), limit=200)["findings"]
    for f in items:
        assert "\n" not in f["message"] and len(f["message"]) <= 160
    ds = next(f for f in items if f["rule"] == "DS-0002")
    assert ds["message"].startswith("Specify at least 1 USER")      # Trivy headers dropped


def test_finding_resolves_prefixes(scanned):
    report = views.load_report(scanned)
    assert views.detail(report, "b1e2adb8e3c2")["rule"] == "CVE-2023-30861"
    with pytest.raises(core.UserError, match="ambiguous"):
        views.detail(report, "aaaaaaaaaa")
    with pytest.raises(core.UserError, match="no finding"):
        views.detail(report, "0123456789ab")
    with pytest.raises(core.UserError, match="hex"):
        views.detail(report, "../../etc/passwd")
    supp = views.detail(report, "50055005")
    assert supp["status"] == "suppressed" and "gating" not in supp


def test_finding_shows_code_context(scanned):
    d = views.detail(views.load_report(scanned), "c75f00c2ba12", context_lines=2)
    assert d["code"][2].startswith(">    7 |") and "shell=True" in d["code"][2]
    assert d["cwe"] == ["CWE-78"] and d["gating"] is False


def test_no_secret_value_in_any_output(scanned):
    """The secret is in the code, in an engine message that echoes it, and in
    the context window of a neighbouring SAST finding. None of it may leave."""
    report = views.load_report(scanned)
    outputs = [views.list_findings(report, limit=200, include_suppressed=True),
               views.brief(report), views.brief(report, "findings")]
    for f in report.findings + report.suppressed:
        outputs.append(views.detail(report, f["fingerprint"], context_lines=30))
    text = everything(outputs)
    for secret in (SECRET, SECRET2):
        assert secret not in text
        assert secret[6:20] not in text                    # nor a recognisable part
    assert "Zq9Zq9" not in text and "4f9a4f9a" not in text

    trivy = views.detail(report, "aaaaaaaaaa11")
    assert trivy["code"][-1].startswith(">    2 |") and "*" in trivy["code"][-1]
    assert "secret_note" in trivy
    sast = views.detail(report, "c75f00c2ba12", context_lines=5)
    line9 = next(r for r in sast["code"] if r.lstrip(" >").startswith("9 |"))
    assert "*" in line9 and "API_KEY" in line9               # masked, still readable
    # The brief's own snippet showed line 9 raw; the brief tool re-masks it.
    row9 = next(l for l in views.brief(report, "findings").splitlines()
                if l.lstrip().startswith("9 |"))
    assert "*" in row9 and "API_KEY" in row9


def test_brief_sections_and_truncation(scanned):
    report = views.load_report(scanned)
    spots = views.brief(report, "blind")
    assert spots.startswith("## Blind spots") and "## Findings" not in spots
    with pytest.raises(core.UserError, match="sections"):
        views.brief(report, "nonexistent")
    long_brief = Path(report.last["review_brief"])
    long_brief.write_text(long_brief.read_text() + "\n" + "filler line\n" * 300)
    short = views.brief(report, max_chars=1000)
    assert "[truncated:" in short


# ---- suppress ---------------------------------------------------------------------------

def enabled_scanners(raw: dict) -> set[str]:
    return {n for n, c in (raw.get("scanners") or {}).items() if (c or {}).get("enabled", True)}


def test_suppress_creates_a_minimal_overlay_config(scanned, tool):
    report = views.load_report(scanned)
    out = triage.suppress(report, "c75f00c2ba12", "cmd is a constant from the CLI table, never user input")
    cfg = scanned / core.PROJECT_CONFIG
    assert out["status"] == "added" and out["created"] is True
    raw = yaml.safe_load(cfg.read_text())
    # Only the verdict: the rest comes from the tool's defaults on every run.
    assert list(raw) == ["ignore"]
    assert raw["ignore"] == [{"fingerprint": "c75f00c2ba12000000000000000000000000000e",
                              "reason": "cmd is a constant from the CLI table, never user input",
                              "expires": date.today() + timedelta(days=90)}]
    from appsec_mcp._orchestrator import normalize, schema
    assert schema.validate(raw, known_scanners=set(normalize.SCANNER_FILES)) == []
    # Laid over the defaults, it must not quietly switch scanners off.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "effective_config", Path(__file__).resolve().parent.parent / "scripts" / "effective-config.py")
    ec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ec)
    defaults = yaml.safe_load((tool / "scan-config.yml").read_text())
    assert enabled_scanners(ec.merge(defaults, raw)) == enabled_scanners(defaults) != set()


def test_suppress_preserves_existing_text_and_is_idempotent(scanned):
    original = textwrap.dedent("""\
        # Project policy — reviewed by the security team.
        scanners:
          semgrep: {enabled: true}   # SAST only for now
          gitleaks: {enabled: true}

        fail_on: medium   # stricter than the default

        ignore:
          # legacy acceptance
          - rule: CVE-2018-1000656
            reason: "mitigated at the proxy"
            expires: 2099-01-01

        # ---- trailing section comment stays below the list
        offline: false
        """)
    cfg = scanned / core.PROJECT_CONFIG
    cfg.write_text(original)
    report = views.load_report(scanned)
    out = triage.suppress(report, "da84b24e3939", "image runs as root by design in the CI sandbox only",
                          expires=(date.today() + timedelta(days=30)).isoformat())
    assert out["status"] == "added" and out["created"] is False
    text = cfg.read_text()
    # Every original line is still there, in order; only lines were added.
    it = iter(text.splitlines())
    assert all(any(line == got for got in it) for line in original.splitlines())
    raw = yaml.safe_load(text)
    assert raw["fail_on"] == "medium" and len(raw["ignore"]) == 2
    assert raw["ignore"][1]["fingerprint"] == "da84b24e3939000000000000000000000000000d"
    assert text.index("da84b24e") < text.index("# ---- trailing section")

    again = triage.suppress(report, "da84b24e3939", "image runs as root by design in the CI sandbox only")
    assert again["status"] == "already_present"
    assert cfg.read_text() == text


@pytest.mark.parametrize("ignore_line", ["ignore: []  # nothing accepted yet", "ignore:", None])
def test_suppress_handles_empty_or_missing_ignore(scanned, ignore_line):
    body = "scanners:\n  semgrep: {enabled: true}\n" + (ignore_line + "\n" if ignore_line else "")
    cfg = scanned / core.PROJECT_CONFIG
    cfg.write_text(body)
    triage.suppress(views.load_report(scanned), "c75f00c2ba12", "constant command, not user controlled")
    raw = yaml.safe_load(cfg.read_text())
    assert raw["scanners"] == {"semgrep": {"enabled": True}}
    assert [e["fingerprint"][:12] for e in raw["ignore"]] == ["c75f00c2ba12"]
    if ignore_line and "#" in ignore_line:
        assert "# nothing accepted yet" in cfg.read_text()


def test_suppress_refuses_flow_style_and_invalid_configs(scanned):
    cfg = scanned / core.PROJECT_CONFIG
    report = views.load_report(scanned)
    cfg.write_text("ignore: [{rule: CVE-1}]\n")
    with pytest.raises(core.UserError, match="by hand"):
        triage.suppress(report, "c75f00c2ba12", "constant command, not user controlled")
    cfg.write_text("fail_on_severity: high\nignore: []\n")
    with pytest.raises(core.UserError, match="fail_on_severity"):
        triage.suppress(report, "c75f00c2ba12", "constant command, not user controlled")
    assert cfg.read_text() == "fail_on_severity: high\nignore: []\n"


def test_suppress_never_writes_through_a_symlink(scanned, tmp_path):
    victim = tmp_path / "victim.yml"
    victim.write_text("precious: true\n")
    (scanned / core.PROJECT_CONFIG).symlink_to(victim)
    with pytest.raises(core.UserError, match="symlink"):
        triage.suppress(views.load_report(scanned), "c75f00c2ba12", "constant command, not user controlled")
    assert victim.read_text() == "precious: true\n"


def test_suppress_validates_its_inputs(scanned):
    report = views.load_report(scanned)
    for reason in ("", "   ", "fp"):
        with pytest.raises(core.UserError, match="reason"):
            triage.suppress(report, "c75f00c2ba12", reason)
    for expires in ((date.today() - timedelta(days=1)).isoformat(), date.today().isoformat()):
        with pytest.raises(core.UserError, match="future"):
            triage.suppress(report, "c75f00c2ba12", "constant command, not user input", expires)
    with pytest.raises(core.UserError, match="365"):
        triage.suppress(report, "c75f00c2ba12", "constant command, not user input",
                        (date.today() + timedelta(days=400)).isoformat())
    with pytest.raises(core.UserError, match="YYYY-MM-DD"):
        triage.suppress(report, "c75f00c2ba12", "constant command, not user input", "next year")
    with pytest.raises(core.UserError, match="no finding"):
        triage.suppress(report, "0123456789ab", "constant command, not user input")
    assert not (scanned / core.PROJECT_CONFIG).exists()
    supp = triage.suppress(report, "50055005", "already covered by an existing rule")
    assert supp["status"] == "already_suppressed"


def test_reason_cannot_break_out_of_its_yaml_string(scanned):
    nasty = 'ok" \nfail_on: none\n# "\\   trailing'
    triage.suppress(views.load_report(scanned), "c75f00c2ba12", nasty)
    raw = yaml.safe_load((scanned / core.PROJECT_CONFIG).read_text())
    assert list(raw) == ["ignore"]                     # no key smuggled in
    assert raw["ignore"][-1]["reason"] == " ".join(nasty.split())


def test_scan_suppress_rescan_loop(tool, repo):
    run_scan(repo)
    triage.suppress(views.load_report(repo), "da84b24e3939", "sandbox image, never deployed")
    out = run_scan(repo)
    assert out["gating"] == 4 and out["suppressed"] == 2
    d = views.detail(views.load_report(repo), "da84b24e3939")
    assert d["status"] == "suppressed" and d["suppressed_reason"] == "sandbox image, never deployed"
    assert "--repo-config" in argv_calls(tool)[-1]


# ---- the MCP surface -------------------------------------------------------------------

def test_tools_and_prompt_are_registered():
    pytest.importorskip("mcp")
    from appsec_mcp.server import mcp

    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    assert set(tools) == {"scan", "profile", "findings", "components", "finding", "brief", "suppress"}
    for t in tools.values():
        assert t.description and len(t.description) > 80
        assert "ctx" not in t.input_schema["properties"]
    assert tools["findings"].annotations.read_only_hint is True
    assert tools["suppress"].annotations.read_only_hint is False
    assert set(tools["suppress"].input_schema["required"]) == {"path", "fingerprint", "reason"}
    sev = tools["findings"].input_schema["properties"]["severity_min"]
    assert "critical" in json.dumps(sev)
    prompts = asyncio.run(mcp.list_prompts())
    assert [p.name for p in prompts] == ["security_review"]


def test_tools_over_an_in_process_client(tool, repo):
    pytest.importorskip("mcp")
    from mcp import Client
    from appsec_mcp.server import mcp

    async def drive():
        async with Client(mcp) as client:
            bad = await client.call_tool("scan", {"path": "/"})
            assert bad.is_error and "refusing" in bad.content[0].text
            res = await client.call_tool("scan", {"path": str(repo)})
            assert not res.is_error, res.content
            summary = json.loads(res.content[0].text)
            listed = json.loads((await client.call_tool(
                "findings", {"path": str(repo), "gating_only": True, "limit": 2})).content[0].text)
            fp = listed["findings"][0]["fingerprint"]
            detail = (await client.call_tool("finding", {"path": str(repo), "fingerprint": fp})).content[0].text
            sup = await client.call_tool("suppress", {"path": str(repo), "fingerprint": fp, "reason": ""})
            prompt = await client.get_prompt("security_review", {"path": str(repo)})
            return summary, listed, detail, sup, prompt

    summary, listed, detail, sup, prompt = asyncio.run(drive())
    assert summary["verdict"] == "fail" and summary["gating"] == 5
    assert listed["returned"] == 2 and listed["next_offset"] == 2
    assert SECRET not in detail and "secret_note" in detail
    assert sup.is_error and "reason" in sup.content[0].text
    assert "scan(" in prompt.messages[0].content.text


def test_components_group_dependencies_and_say_what_to_upgrade_to(scanned):
    report = views.load_report(scanned)
    with pytest.raises(core.UserError, match="predates the component view"):
        views.list_components(report)
    flask = [f for f in report.findings if f.get("package") == "flask@1.0"]
    report.doc["components"] = [{
        "package": "flask@1.0", "name": "flask", "version": "1.0", "files": ["requirements.txt"],
        "severity": "high", "counts": {"high": len(flask)}, "vulnerabilities": len(flask),
        "upgrade_to": "2.2.5", "fixed_in": ["2.2.5"], "unfixed": 0,
        "malicious": False, "exploitable": False,
        "findings": [f["fingerprint"] for f in flask]}]
    out = views.list_components(report)
    comp, = out["components"]
    assert comp["package"] == "flask@1.0" and comp["upgrade_to"] == "2.2.5"
    assert [f["fingerprint"] for f in comp["findings"]] == [f["fingerprint"][:12] for f in flask]
    assert out["total"] == 1 and out["next_offset"] is None


def test_profile_tool_describes_the_repo_without_scanning(repo):
    pytest.importorskip("mcp")
    from appsec_mcp import server
    out = json.loads(server.profile(str(repo)))
    assert "languages" in out["profile"] and isinstance(out["recommendations"], list)


def test_no_repo_config_passes_neither_the_config_nor_the_baseline(tool, repo):
    (repo / core.PROJECT_CONFIG).write_text("ignore: []\n")
    (repo / core.PROJECT_BASELINE).write_text('{"fingerprints": []}')
    argv = core.build_argv(core.detect_cli(), repo, repo / "r", no_repo_config=True)
    assert "--no-repo-config" in argv
    assert "--repo-config" not in argv and "--baseline" not in argv


def test_the_servers_gate_honours_min_confidence(tmp_path):
    doc = {"policy": {"fail_on": "high", "min_confidence": "medium"}}
    report = views.Report(tmp_path, {}, doc, [], [])
    low = {"category": "sast", "severity": "high", "confidence": "low"}
    assert not report.gates(low)
    assert report.gates({**low, "confidence": ""}) and report.gates({**low, "confidence": "medium"})
    argv = core.build_argv(core.Cli(["appsec-compose", "scan"], "cli", True, True),
                           tmp_path, tmp_path / "r", min_confidence="medium")
    assert argv[argv.index("--min-confidence") + 1] == "medium"
