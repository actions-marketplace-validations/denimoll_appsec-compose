"""`appsec-compose serve`: the flows, and above all the attacks.

A real server on an ephemeral loopback port, spoken to with http.client so that
Host and Origin can lie, which a browser would not let a test do. Scans go through
the real launcher with docker stubbed where the test needs a report.
"""
import base64
import hashlib
import http.client
import json
import re
import signal
import subprocess
import threading
import time
from urllib.parse import urlencode

import pytest

from manager_helpers import LAUNCHER, ROOT, Sandbox

from manager import jobs, reports, store, web
from manager.paths import UsageError


@pytest.fixture
def box(tmp_path, monkeypatch):
    return Sandbox(tmp_path, monkeypatch)


class Client:
    def __init__(self, server):
        self.server = server
        self.port = server.server_address[1]
        self.host = f"127.0.0.1:{self.port}"

    def request(self, method, path, body=None, headers=None, host="default"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        if host == "default":
            host = self.host
        for value in ([host] if isinstance(host, str) else host or []):
            conn.putheader("Host", value)
        data = body.encode() if isinstance(body, str) else body
        for key, value in (headers or {}).items():
            conn.putheader(key, value)
        if data is not None:
            conn.putheader("Content-Length", str(len(data)))
        conn.endheaders()
        if data:
            conn.send(data)
        response = conn.getresponse()
        text = response.read().decode("utf-8", "replace")
        conn.close()
        response.text = text
        return response

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, fields=None, csrf="good", **kw):
        fields = dict(fields or {})
        if csrf == "good":
            fields["csrf"] = self.server.csrf
        elif csrf is not None:
            fields["csrf"] = csrf
        headers = {"Content-Type": "application/x-www-form-urlencoded", **kw.pop("headers", {})}
        return self.request("POST", path, urlencode(fields), headers=headers, **kw)


@pytest.fixture
def scans():
    return jobs.Scans(scan=lambda *a, **k: None)


@pytest.fixture
def client(box, scans):
    server = web.Server("127.0.0.1", 0, [], scans)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield Client(server)
    server.shutdown()
    server.server_close()


def wait_idle(scans, name, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if scans.state(name) == "idle":
            return
        time.sleep(0.05)
    raise AssertionError(f"{name} still {scans.state(name)}")


# ---- Host: DNS rebinding ------------------------------------------------------

@pytest.mark.parametrize("host", ["evil.example", "evil.example:8787", "127.0.0.1", "127.0.0.1:1",
                                  "localhost", "localhost:1", "127.0.0.1.evil.example", "", "[::1]"])
def test_a_foreign_host_is_refused(client, host):
    assert client.get("/", host=host).status == 403
    assert client.post("/projects", {"name": "x", "target": "/tmp"}, host=host).status == 403
    assert not store.list_projects()[0]


def test_host_is_case_insensitive_and_localhost_allowed(client):
    assert client.get("/", host=f"LOCALHOST:{client.port}").status == 200
    assert client.get("/", host=f"127.0.0.1:{client.port}").status == 200


def test_a_missing_or_doubled_host_is_refused(client):
    assert client.get("/", host=None).status == 403
    assert client.get("/", host=[client.host, "evil.example"]).status == 403


def test_host_applies_to_reports_too(box, client):
    box.add("p")
    reports_dir = box.project_state("p") / "reports"
    reports_dir.mkdir(parents=True)
    (reports_dir / "summary.md").write_text("private")
    assert client.get("/projects/p/reports/summary.md").status == 200
    response = client.get("/projects/p/reports/summary.md", host="evil.example")
    assert response.status == 403 and "private" not in response.text


# ---- CSRF, Origin ------------------------------------------------------------

@pytest.mark.parametrize("csrf", [None, "", "wrong"])
def test_every_post_needs_the_token(box, client, csrf):
    box.add("p")
    box.profile("q", "strict: true\n")
    before = box.definition("p").read_text()
    for path, fields in (("/projects", {"name": "new-one", "target": str(box.tmp)}),
                         ("/projects/p", {"target": str(box.tmp)}),
                         ("/projects/p/scan", {}),
                         ("/projects/p/delete", {"confirm": "1"}),
                         ("/profiles", {"name": "z", "yaml": ""}),
                         ("/profiles/q", {"yaml": "strict: false\n"}),
                         ("/profiles/q/delete", {})):
        assert client.post(path, fields, csrf=csrf).status == 403, path
    assert box.definition("p").read_text() == before
    assert [p.name for p in store.list_projects()[0]] == ["p"]
    assert store.read_profile("q") == "strict: true\n"
    assert client.server.scans.state("p") == "idle"


def test_a_token_in_the_query_string_does_not_count(box, client):
    box.add("p")
    assert client.post(f"/projects/p/scan?csrf={client.server.csrf}", {}, csrf=None).status == 403


def test_the_token_is_per_process(box, scans):
    a, b = web.Server("127.0.0.1", 0, [], scans), web.Server("127.0.0.1", 0, [], scans)
    try:
        assert a.csrf != b.csrf and len(a.csrf) >= 32
    finally:
        a.server_close()
        b.server_close()


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://127.0.0.1:1",
                                    "https://127.0.0.1", "http://evil.example"])
def test_a_foreign_origin_is_refused_even_with_the_token(box, client, origin):
    box.add("p")
    response = client.post("/projects/p/delete", {"confirm": "1"}, headers={"Origin": origin})
    assert response.status == 403 and box.definition("p").exists()


def test_the_same_origin_passes(box, client):
    box.add("p")
    response = client.post("/projects/p/delete", {"confirm": "1"},
                           headers={"Origin": f"http://{client.host}"})
    assert response.status == 303 and not box.definition("p").exists()


def test_cross_site_fetch_metadata_is_refused(box, client):
    box.add("p")
    assert client.post("/projects/p/scan", {}, headers={"Sec-Fetch-Site": "cross-site"}).status == 403


def test_only_a_form_body_is_accepted(box, client):
    box.add("p")
    body = urlencode({"csrf": client.server.csrf})
    # text/plain is what a cross-site form can send without a preflight.
    assert client.request("POST", "/projects/p/scan", body,
                          headers={"Content-Type": "text/plain"}).status == 415
    assert client.request("POST", "/projects/p/scan", body).status == 415


def test_a_huge_or_malformed_body_is_refused(box, client):
    box.add("p")
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    assert client.request("POST", "/projects/p/scan", b"x" * 10,
                          headers={**form, "Content-Length": str(web.MAX_BODY + 1)}).status == 413
    assert client.request("POST", "/projects/p/scan", b"\xff\xfe", headers=form).status == 400
    assert client.request("POST", "/projects/p/scan", "&".join(["a=1"] * 100), headers=form).status == 400


# ---- GET never changes anything ----------------------------------------------

@pytest.mark.parametrize("path", ["/projects/p/scan", "/projects/p/delete", "/profiles/q/delete",
                                  "/projects/p/schedule"])
def test_get_on_an_action_does_nothing(box, client, path):
    box.add("p")
    box.profile("q", "strict: true\n")
    token = client.server.csrf
    assert client.get(path).status == 404
    assert client.get(f"{path}?csrf={token}&confirm=1").status == 404
    assert box.definition("p").exists() and store.read_profile("q")
    assert client.server.scans.state("p") == "idle"


def test_reading_every_page_changes_no_file(box, client):
    box.add("p")
    box.profile("q", "strict: true\n")
    before = sorted(str(p) for p in box.config.rglob("*")), sorted(str(p) for p in box.state.rglob("*"))
    for path in ("/", "/projects/new", "/projects/p", "/projects/p/status.json", "/profiles", "/profiles/q",
                 "/app.css"):
        assert client.get(path).status == 200, path
    assert (sorted(str(p) for p in box.config.rglob("*")), sorted(str(p) for p in box.state.rglob("*"))) == before


def test_other_methods_are_not_implemented(client):
    for method in ("PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
        assert client.request(method, "/").status == 501


# ---- report serving ----------------------------------------------------------

@pytest.fixture
def report_tree(box):
    box.add("p")
    box.add("other")
    folder = box.project_state("p") / "reports"
    (folder / "native").mkdir(parents=True)
    (folder / "summary.html").write_text("<html>the summary</html>")
    (folder / "summary.md").write_text("# md")
    (folder / "review-brief.md").write_text("brief")
    (folder / "findings.json").write_text('{"severity_counts": {}}')
    (folder / "sbom.trivy.cdx.json").write_text("{}")
    (folder / "native" / "trufflehog.json").write_text('{"raw": "NATIVE-SECRET"}')
    (folder / "native" / "semgrep.sarif").write_text("{}")
    (box.tmp / "outside.txt").write_text("OUTSIDE-FILE")
    other = box.project_state("other") / "reports"
    other.mkdir(parents=True)
    (other / "summary.md").write_text("OTHER-PROJECT")
    return folder


@pytest.mark.parametrize("name", ["summary.html", "summary.md", "review-brief.md", "findings.json",
                                  "sbom.trivy.cdx.json"])
def test_reports_are_served(client, report_tree, name):
    response = client.get(f"/projects/p/reports/{name}")
    assert response.status == 200 and response.text == (report_tree / name).read_text()


@pytest.mark.parametrize("path", [
    "/projects/p/reports/native/trufflehog.json",
    "/projects/p/reports/native%2Ftrufflehog.json",
    "/projects/p/reports/native/semgrep.sarif",
    "/projects/p/reports/trufflehog.json",
    "/projects/p/reports/../../../../../../etc/passwd",
    "/projects/p/reports/..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/projects/p/reports/%2e%2e/%2e%2e/runs.json",
    "/projects/p/reports/%2e%2e%2f%2e%2e%2fother%2freports%2fsummary.md",
    "/projects/p/reports/..",
    "/projects/p/reports/",
    "/projects/p/reports",
    "/projects/p/reports/summary.md%00.html",
    "/projects/p/reports/.lock",
    "/projects/p/reports/scan.log",
    "/projects/../../../../etc/reports/summary.md",
    "/projects/%2e%2e/reports/summary.md",
    "/projects/..%2fother/reports/summary.md",
    "/projects/P/reports/summary.md",
    "/projects/absent/reports/summary.md",
])
def test_traversal_finds_nothing(client, report_tree, path):
    response = client.get(path)
    assert response.status == 404, path
    for leak in ("NATIVE-SECRET", "OUTSIDE-FILE", "OTHER-PROJECT", "root:"):
        assert leak not in response.text


def test_a_symlink_out_of_the_reports_dir_is_not_followed(client, report_tree, box):
    (report_tree / "summary.md").unlink()
    (report_tree / "summary.md").symlink_to(box.tmp / "outside.txt")
    response = client.get("/projects/p/reports/summary.md")
    assert response.status == 404 and "OUTSIDE-FILE" not in response.text


def test_a_symlink_to_a_native_report_is_not_followed(client, report_tree):
    (report_tree / "review-brief.md").unlink()
    (report_tree / "review-brief.md").symlink_to(report_tree / "native" / "trufflehog.json")
    response = client.get("/projects/p/reports/review-brief.md")
    assert response.status == 404 and "NATIVE-SECRET" not in response.text


def test_a_symlinked_reports_dir_is_not_followed(client, report_tree, box):
    elsewhere = box.tmp / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "summary.md").write_text("OUTSIDE-FILE")
    state = box.project_state("other")
    import shutil
    shutil.rmtree(state / "reports")
    (state / "reports").symlink_to(elsewhere)
    response = client.get("/projects/other/reports/summary.md")
    assert response.status == 404 and "OUTSIDE-FILE" not in response.text


def test_a_directory_named_like_a_report_is_not_served(client, report_tree):
    (report_tree / "summary.md").unlink()
    (report_tree / "summary.md").mkdir()
    assert client.get("/projects/p/reports/summary.md").status == 404


def test_markdown_is_never_interpreted_and_json_never_sniffed(client, report_tree):
    (report_tree / "summary.md").write_text("<script>alert(1)</script>")
    response = client.get("/projects/p/reports/summary.md")
    assert response.getheader("Content-Type").startswith("text/plain")
    assert response.getheader("X-Content-Type-Options") == "nosniff"
    assert "sandbox" in response.getheader("Content-Security-Policy")
    assert client.get("/projects/p/reports/findings.json").getheader("Content-Type") == "application/json"


def test_the_summary_csp_allows_only_its_own_script(client, report_tree):
    csp = client.get("/projects/p/reports/summary.html").getheader("Content-Security-Policy")
    assert "sandbox allow-scripts" in csp and "default-src 'none'" in csp
    assert "unsafe-inline" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    source = (ROOT / "orchestrator" / "summary.py").read_text()
    script = re.search(r"<script>(.*?)</script>", source, re.S).group(1)
    expected = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    assert f"'sha256-{expected}'" in csp


def test_the_summary_template_renders_the_script_byte_for_byte():
    # The hash above is taken from the template; it must equal what a browser hashes.
    import jinja2
    import summary
    script = re.search(r"<script>(.*?)</script>", summary._HTML_TEMPLATE, re.S).group(1)
    env = jinja2.Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)   # as render() does
    block = f"<script>{script}</script>"
    assert env.from_string(block).render() == block


def test_listed_reports_names_only_servable_ones(report_tree):
    names = reports.listed_reports("p")
    assert names[:4] == ["summary.html", "summary.md", "review-brief.md", "findings.json"]
    assert "sbom.trivy.cdx.json" in names and not [n for n in names if "truffle" in n or "native" in n]


# ---- headers and escaping ----------------------------------------------------

def test_pages_carry_a_strict_csp_and_no_script(box, client):
    box.add("p")
    for path in ("/", "/projects/new", "/projects/p", "/profiles"):
        response = client.get(path)
        csp = response.getheader("Content-Security-Policy")
        assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp and "script-src" not in csp
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert response.getheader("X-Frame-Options") == "DENY"
        assert "<script" not in response.text


def test_error_responses_carry_the_headers_too(client):
    for response in (client.get("/nothing"), client.get("/", host="evil.example"),
                     client.request("PUT", "/")):
        assert "default-src 'none'" in response.getheader("Content-Security-Policy")
        assert response.getheader("X-Content-Type-Options") == "nosniff"


EVIL = '<script>alert(1)</script>"\'><img src=x onerror=alert(2)>'


def assert_clean(text):
    assert "<script>alert" not in text and "<img src=x" not in text
    assert "&lt;script&gt;alert(1)" in text


def test_a_malicious_finding_is_escaped_everywhere(box, client):
    box.add("p")
    box.findings("p", {"severity_counts": {"high": 1}, "policy": {"breaching": 1},
                       "components": [{"package": EVIL, "severity": "high", "vulnerabilities": 1,
                                       "upgrade_to": EVIL}]})
    assert subprocess.run([str(LAUNCHER), "project", "scan", "p"], capture_output=True).returncode == 0
    assert_clean(client.get("/").text)
    status = json.loads(client.get("/projects/p/status.json").text)
    assert EVIL[:20] in status["latest"]["top_component"]     # raw only as JSON


def test_a_malicious_verdict_in_the_history_is_escaped(box, client):
    box.add("p")
    state = box.project_state("p")
    state.mkdir(parents=True)
    (state / "runs.json").write_text(json.dumps([
        {"verdict": EVIL, "severity_counts": None, "error": EVIL, "top_component": EVIL,
         "finished": EVIL, "trigger": EVIL, "duration_s": EVIL}]))
    assert_clean(client.get("/").text)
    assert_clean(client.get("/projects/p").text)


def test_a_malicious_project_file_name_is_escaped(box, client):
    box.add("p")
    box.definition("p").with_name("<script>alert(1)<").with_suffix(".yml")\
        .write_text("target: /x\n")
    response = client.get("/")
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;alert(1)" in response.text


def test_malicious_metadata_and_target_are_escaped(box, client):
    target = box.tmp / EVIL.replace("/", "_")
    target.mkdir()
    response = client.post("/projects", {"name": "p", "target": str(target),
                                         "meta": f"owner={EVIL}"})
    assert response.status == 303
    text = client.get("/projects/p").text
    assert "<script>alert" not in text and "<img src=x" not in text
    assert "&lt;img src=x" in text


def test_malicious_input_echoed_in_a_form_error_is_escaped(client):
    response = client.post("/projects", {"name": EVIL, "target": EVIL, "meta": EVIL, "schedule": EVIL})
    assert response.status == 400
    assert "<script>alert" not in response.text and "<img src=x" not in response.text


def test_a_malicious_profile_cannot_break_out_of_the_text_box(box, client):
    box.profile("q", f"# </textarea>{EVIL}\nstrict: true\n")
    text = client.get("/profiles/q").text
    assert "</textarea><script" not in text and "<img src=x" not in text
    assert "&lt;/textarea&gt;" in text


def test_a_bad_profile_error_is_escaped(box, client):
    box.profile("q", "strict: true\n")
    response = client.post("/profiles/q", {"yaml": f"{EVIL}: [\n"})
    assert response.status == 400
    assert "<script>alert" not in response.text and "<img src=x" not in response.text


def test_redirects_stay_local_and_on_validated_names(client, box):
    response = client.post("/projects", {"name": "//evil.example", "target": str(box.tmp)})
    assert response.status == 400 and response.getheader("Location") is None


# ---- binding -----------------------------------------------------------------

def test_loopback_binds_need_no_flag():
    assert web.check_bind("127.0.0.1", [], False) == "127.0.0.1"
    assert web.check_bind("localhost", [], False) == "127.0.0.1"
    assert web.check_bind("::1", [], False) == "::1"


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.5"])
def test_a_non_loopback_bind_needs_the_flag(host):
    with pytest.raises(UsageError, match="--allow-remote"):
        web.check_bind(host, [], False)


def test_a_wildcard_bind_needs_named_hosts():
    with pytest.raises(UsageError, match="--public-host"):
        web.check_bind("0.0.0.0", [], True)
    assert web.check_bind("0.0.0.0", ["scan.lan"], True) == "0.0.0.0"
    assert web.check_bind("192.168.1.5", [], True) == "192.168.1.5"


def test_a_hostname_is_not_bound():
    with pytest.raises(UsageError):
        web.check_bind("evil.example", [], True)


def test_allowed_hosts():
    assert web.allowed_hosts("127.0.0.1", 8787, []) == {"127.0.0.1:8787", "localhost:8787"}
    assert web.allowed_hosts("::1", 8787, []) == {"[::1]:8787", "localhost:8787"}
    assert web.allowed_hosts("0.0.0.0", 9, ["Scan.Lan"]) == {"scan.lan:9"}
    assert web.allowed_hosts("192.168.1.5", 9, []) == {"192.168.1.5:9"}


def _serve(box, *args):
    return subprocess.Popen([str(LAUNCHER), "serve", "--port", "0", *args],
                            stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True, cwd=box.tmp)


def test_serve_defaults_to_loopback_with_no_warning(box):
    proc = _serve(box)
    try:
        lines = [proc.stderr.readline()]
        assert "Serving on http://127.0.0.1:" in lines[0]
        assert "WARNING" not in lines[0]
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(10)
    assert proc.returncode == 0


def test_serve_warns_on_a_remote_bind(box):
    proc = _serve(box, "--host", "0.0.0.0", "--allow-remote", "--public-host", "scan.lan")
    try:
        first = proc.stderr.readline()
        assert first.startswith("WARNING") and "NO login" in first
        assert "Serving on" in proc.stderr.readline()
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(10)


def test_serve_refuses_a_remote_bind_without_the_flag(box):
    proc = _serve(box, "--host", "0.0.0.0")
    assert proc.wait(10) == 2 and "--allow-remote" in proc.stderr.read()


# ---- the flows ---------------------------------------------------------------

def test_create_edit_and_delete_a_project(box, client):
    target = box.repo()
    box.profile("q", "strict: true\n")
    response = client.post("/projects", {"name": "api", "target": str(target), "profile": "q",
                                         "meta": "owner=me\n\ntier=1\n", "schedule": "0  3 * * *"})
    assert response.status == 303 and response.getheader("Location") == "/projects/api"
    project = store.load_project("api")
    assert (project.profile, project.meta, project.schedule) == ("q", {"owner": "me", "tier": "1"}, "0 3 * * *")
    assert "api" in client.get("/").text and "owner=me" in client.get("/projects/api").text

    assert client.post("/projects/api", {"target": "https://git.example/a/b.git", "profile": "",
                                         "meta": "", "schedule": ""}).status == 303
    project = store.load_project("api")
    assert project.is_git and project.profile is None and project.schedule is None

    assert client.post("/projects/api/delete", {}).status == 400   # no confirmation box
    assert store.load_project("api")
    assert client.post("/projects/api/delete", {"confirm": "1"}).status == 303
    assert client.get("/projects/api").status == 404


@pytest.mark.parametrize("fields,message", [
    ({"name": "../x", "target": "/tmp"}, "invalid project name"),
    ({"name": "x", "target": "ext::sh -c id"}, "not allowed"),
    ({"name": "x", "target": "file:///etc"}, "not allowed"),
    ({"name": "x", "target": "/does/not/exist"}, "not a directory"),
    ({"name": "x", "target": "/tmp", "schedule": "nope"}, "cron"),
    ({"name": "x", "target": "/tmp", "profile": "absent"}, "no profile"),
    ({"name": "x", "target": "/tmp", "meta": "novalue"}, "key=value"),
])
def test_a_bad_form_is_explained_and_changes_nothing(client, fields, message):
    response = client.post("/projects", fields)
    assert response.status == 400 and message in response.text
    assert not store.list_projects()[0]


def test_set_a_schedule_from_the_ui(box, client):
    box.add("p")
    assert client.post("/projects/p", {"target": str(box.tmp), "schedule": "*/5 * * * *"}).status == 303
    assert store.load_project("p").schedule == "*/5 * * * *"
    assert "*/5 * * * *" in client.get("/").text


def test_profiles_crud(box, client):
    assert client.post("/profiles", {"name": "q", "yaml": "strict: true\r\n"}).status == 303
    assert store.read_profile("q") == "strict: true\n"
    assert "strict: true" in client.get("/profiles/q").text and "/profiles/q" in client.get("/profiles").text
    assert client.post("/profiles/q", {"yaml": "strickt: true\n"}).status == 400
    assert store.read_profile("q") == "strict: true\n"
    assert client.post("/profiles/q", {"yaml": "strict: false\n"}).status == 303
    assert client.post("/profiles", {"name": "../x", "yaml": ""}).status == 400
    assert client.post("/profiles", {"name": "q", "yaml": ""}).status == 400
    box.add("p", box.repo(), "--profile", "q")
    assert client.post("/profiles/q/delete", {}).status == 400     # in use
    box.cli("project", "rm", "p")
    assert client.post("/profiles/q/delete", {}).status == 303
    assert client.get("/profiles/q").status == 404


def test_a_scan_is_refused_while_one_runs(box, client):
    box.add("p")
    release, entered = threading.Event(), threading.Event()

    def slow(name, trigger="manual", on_start=None):
        entered.set()
        release.wait(10)
    client.server.scans = jobs.Scans(scan=slow)
    assert client.post("/projects/p/scan", {}).status == 303
    assert entered.wait(5)
    assert client.post("/projects/p/scan", {}).status == 409
    assert json.loads(client.get("/projects/p/status.json").text)["state"] == "running"
    page = client.get("/projects/p").text
    assert 'http-equiv="refresh"' in page
    assert client.post("/projects/p/delete", {"confirm": "1"}).status == 409
    assert box.definition("p").exists()
    release.set()
    wait_idle(client.server.scans, "p")


def test_scan_end_to_end_through_the_ui(box, client):
    box.add("p")
    box.outcome("p", "STUB_RUN=1")
    client.server.scans = jobs.Scans()
    assert client.post("/projects/p/scan", {}).status == 303
    wait_idle(client.server.scans, "p")
    status = json.loads(client.get("/projects/p/status.json").text)
    assert status["state"] == "idle" and status["latest"]["verdict"] == "fail"
    assert status["latest"]["severity_counts"]["high"] == 2
    page = client.get("/projects/p").text
    assert "/projects/p/reports/summary.html" in page and "review-brief.md" in page
    assert "trufflehog" not in page and "NATIVE-SECRET" not in page
    assert "the summary" in client.get("/projects/p/reports/summary.html").text
    dashboard = client.get("/").text
    assert "/projects/p/reports/summary.html" in dashboard and "2 high, 1 low" in dashboard
    assert (box.project_state("p") / "reports" / "native" / "trufflehog.json").exists()
    assert client.get("/projects/p/reports/native/trufflehog.json").status == 404


def test_a_broken_definition_shows_up_rather_than_breaking_the_page(box, client):
    box.add("p")
    box.definition("p").with_name("bad.yml").write_text("target: ext::sh\n")
    text = client.get("/").text
    assert "bad" in text and "not allowed" in text and "/projects/p" in text
    assert client.get("/projects/bad").status == 404


def test_an_unexpected_failure_is_a_bare_500(box, client, monkeypatch):
    def explode(*a, **k):
        raise RuntimeError("SECRET-DETAIL")
    monkeypatch.setattr(store, "list_projects", explode)
    response = client.get("/")
    assert response.status == 500 and "SECRET-DETAIL" not in response.text


def test_the_scan_log_is_never_rendered(box, client):
    box.add("p")
    state = box.project_state("p")
    state.mkdir(parents=True)
    (state / "scan.log").write_text("ENGINE-OUTPUT")
    for path in ("/", "/projects/p", "/projects/p/status.json"):
        assert "ENGINE-OUTPUT" not in client.get(path).text


def test_browsers_get_a_real_origin_on_the_uis_own_forms(box, client):
    """With Referrer-Policy: no-referrer a browser sends "Origin: null" on a
    same-origin form post, and the Origin check refuses the UI's own forms."""
    assert client.get("/").headers["Referrer-Policy"] == "same-origin"


def test_the_add_form_explains_its_fields(box, client):
    page = client.get("/projects/new").text
    assert 'class="hint"' in page and "owner=team-payments" in page


def test_the_stylesheet_is_local_and_nothing_loads_from_elsewhere(box, client):
    css = client.get("/pico.css")
    assert css.status == 200 and "Pico CSS" in css.text and css.getheader("Content-Type").startswith("text/css")
    page = client.get("/")
    assert 'href="/pico.css"' in page.text and "http://" not in page.text.split("</head>")[0]
    csp = page.getheader("Content-Security-Policy")
    assert "img-src data:" in csp and "script-src" not in csp and "default-src 'none'" in csp


def _seed_report(box, name, findings, brief=""):
    from manager import runs
    from manager.paths import reports_dir
    box.add(name)
    base = reports_dir(name)
    base.mkdir(parents=True, exist_ok=True)
    (base / "findings.json").write_text(json.dumps(findings))
    (base / "review-brief.md").write_text(brief)
    return base, runs


def test_a_result_with_holes_says_so_on_the_ui(box, client):
    """266 findings and no word that no dependency was checked reads as complete."""
    evil = '<script>alert(1)</script>/requirements.txt'
    findings = {"severity_counts": {"high": 1}, "policy": {"breaching": 1},
                "coverage": {"warnings": [{"kind": "k", "message": f"{evil} specifies ranges.",
                                           "advice": "Pin the versions."}]},
                "reports_errored": ["semgrep.sarif: incomplete — engine was killed"],
                "provenance": {"repo_config": {"file": ".appsec-compose.yml", "applied": ["fail_on"]}}}
    brief = "## Blind spots\n\n- **Reachability:** not checked.\n\n## Findings (0)\n- not a spot\n"
    _, runs = _seed_report(box, "holes", findings, brief)
    # A run recorded before the field existed still shows them, from the report.
    runs.record("holes", {"finished": "t", "verdict": "fail", "has_reports": True})
    page = client.get("/projects/holes").text
    assert "Check before trusting this result" in page and "Pin the versions." in page
    assert "engine was killed" in page and "set: fail_on" in page
    assert "Reachability: not checked." in page and "not a spot" not in page
    assert "<script>alert(1)" not in page and "&lt;script&gt;" in page
    board = client.get("/").text
    assert "3 to check" in board and "<script>alert(1)" not in board


def test_a_clean_result_shows_no_warning(box, client):
    _, runs = _seed_report(box, "clean", {"severity_counts": {}, "coverage": {"warnings": []}})
    runs.record("clean", {"finished": "t", "verdict": "pass", "has_reports": True, "attention": []})
    assert "Check before trusting" not in client.get("/projects/clean").text
    assert "to check" not in client.get("/").text
