"""`appsec-compose serve`: a local UI on http.server, with no dependency beyond the stdlib.

It reads local files and starts scans, on a port any web page in the user's
browser can reach, so every check here answers a specific attack:

- Host allowlist: DNS rebinding (evil.example re-pointed at 127.0.0.1 is same-origin
  to the attacker's page, but its requests still say `Host: evil.example`).
- CSRF token on each POST, Origin and Sec-Fetch-Site: a cross-site form post. The
  token is per process, and rebinding is what would otherwise let a page read it.
- Nothing changes on GET: an <img> or a link cannot do anything.
- CSP, nosniff, no framing: findings are attacker-controlled through scanned repos,
  so output is escaped (htmlsafe) and a slip in that still runs no script.
- Reports go through manager/reports.py: an allowlist, no symlinks, no native/.

This is not an authenticated service. A non-loopback bind needs --allow-remote and
then serves anyone who can reach the port, which the warning says in so many words.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import secrets
import shutil
import signal
import socket
import socketserver
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote

from . import runs, store, views
from .htmlsafe import CSS
from .jobs import Scans, Scheduler
from .paths import UsageError, check_name
from .reports import content_type, csp_for, open_report

UI_CSP = ("default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'self'; "
          "frame-ancestors 'none'")
MAX_BODY = 1024 * 1024
_FORM = "application/x-www-form-urlencoded"


def check_bind(host: str, public_hosts: list[str], allow_remote: bool) -> str:
    """The literal address to bind; refuses anything non-loopback that was not asked for."""
    literal = "127.0.0.1" if host == "localhost" else host
    try:
        address = ipaddress.ip_address(literal)
    except ValueError as exc:
        raise UsageError(f"--host must be an IP address or localhost, not {host!r}") from exc
    if address.is_loopback:
        return literal
    if not allow_remote:
        raise UsageError(f"--host {host} is not loopback: pass --allow-remote if you mean it")
    if address.is_unspecified and not public_hosts:
        raise UsageError(f"--host {host} needs --public-host NAME: the names clients will use, "
                         "for the Host header check")
    return literal


def allowed_hosts(literal: str, port: int, public_hosts: list[str]) -> frozenset:
    address = ipaddress.ip_address(literal)
    shown = f"[{literal}]" if address.version == 6 else literal
    names = [] if address.is_unspecified else [shown]
    if address.is_loopback:
        names.append("localhost")
    names += public_hosts
    with_port = {f"{n.lower()}:{port}" for n in names}
    return frozenset(with_port | ({n.lower() for n in names} if port == 80 else set()))


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, literal: str, port: int, public_hosts: list[str], scans: Scans):
        self.address_family = socket.AF_INET6 if ":" in literal else socket.AF_INET
        super().__init__((literal, port), Handler)
        self.allowed = allowed_hosts(literal, self.server_address[1], public_hosts)
        self.csrf = secrets.token_urlsafe(32)
        self.scans = scans

    def server_bind(self) -> None:
        # HTTPServer's own also does a reverse DNS lookup, which can stall for seconds.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Handler(BaseHTTPRequestHandler):
    server_version = "appsec-compose"
    sys_version = ""
    timeout = 30   # a client that stalls mid-request gives its thread back
    error_content_type = "text/plain; charset=utf-8"
    error_message_format = "%(code)d %(message)s\n"
    _csp = UI_CSP

    # ---- every response -------------------------------------------------------

    def end_headers(self) -> None:
        self.send_header("Content-Security-Policy", self._csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        # Not no-referrer: browsers then send "Origin: null" on this UI's own form
        # posts, which the Origin check rightly refuses. same-origin still sends
        # nothing to other sites.
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:
        line = fmt % args
        sys.stderr.write(f"{self.address_string()} {''.join(c if c.isprintable() else '?' for c in line)}\n")

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _plain(self, code: int, text: str) -> None:
        self._send(code, f"{code} {text}\n".encode(), "text/plain; charset=utf-8")

    def _redirect(self, location: str) -> None:
        """Only ever built from validated names."""
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ---- the checks -----------------------------------------------------------

    def _host(self) -> str | None:
        hosts = self.headers.get_all("Host") or []
        if len(hosts) == 1 and hosts[0].strip().lower() in self.server.allowed:
            return hosts[0].strip().lower()
        return None

    def _same_origin(self, host: str) -> bool:
        origins = self.headers.get_all("Origin") or []
        if len(origins) > 1 or (origins and origins[0].strip().lower() != f"http://{host}"):
            return False
        return self.headers.get("Sec-Fetch-Site", "same-origin") in ("same-origin", "none")

    def _form(self) -> dict | None:
        """The urlencoded body as {key: first value}; None after answering a bad one."""
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != _FORM:
            self._plain(415, "Unsupported Media Type")
            return None
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._plain(411, "Length Required")
            return None
        if not 0 <= length <= MAX_BODY:
            self._plain(413, "Payload Too Large")
            return None
        try:
            parsed = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True,
                              max_num_fields=50)
        except ValueError:   # also UnicodeDecodeError
            self._plain(400, "Bad Request")
            return None
        return {key: values[0] for key, values in parsed.items()}

    def _segments(self) -> list[str]:
        path = self.path.split("#", 1)[0].split("?", 1)[0]
        return [unquote(part) for part in path.split("/")[1:]]

    # ---- dispatch -------------------------------------------------------------

    def do_GET(self) -> None:
        if self._host() is None:
            return self._plain(403, "Forbidden: unexpected Host header")
        try:
            self._get(self._segments())
        except UsageError:
            self._plain(404, "Not Found")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            self._failed(exc)

    def do_POST(self) -> None:
        host = self._host()
        if host is None:
            return self._plain(403, "Forbidden: unexpected Host header")
        if not self._same_origin(host):
            return self._plain(403, "Forbidden: cross-origin request")
        form = self._form()
        if form is None:
            return None
        if not hmac.compare_digest(form.get("csrf", "").encode(), self.server.csrf.encode()):
            return self._plain(403, "Forbidden: missing or wrong CSRF token")
        try:
            self._post(self._segments(), form)
        except UsageError as exc:   # a form re-renders its own errors; this is the rest
            self._send(400, views.message("Not done", str(exc)))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            self._failed(exc)
        return None

    def _failed(self, exc: Exception) -> None:
        """The detail goes to the server's stderr, never to the client."""
        print(f"{self.command} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        self._plain(500, "Internal Server Error")

    # ---- GET: reads only ------------------------------------------------------

    def _get(self, seg: list[str]) -> None:
        scans, token = self.server.scans, self.server.csrf
        if seg == [""]:
            return self._send(200, views.dashboard(scans, token))
        if seg == ["app.css"]:
            return self._send(200, CSS.encode(), "text/css; charset=utf-8")
        if seg == ["projects", "new"]:
            return self._send(200, views.new_project(token))
        if seg == ["profiles"]:
            return self._send(200, views.profiles_page(token))
        if len(seg) == 2 and seg[0] == "profiles":
            return self._send(200, views.profile_page(seg[1], store.read_profile(seg[1]), token))
        if len(seg) >= 2 and seg[0] == "projects":
            project = store.load_project(seg[1])
            if len(seg) == 2:
                return self._send(200, views.project_page(project, scans, token))
            if seg[2:] == ["status.json"]:
                return self._status(project.name)
            if len(seg) == 4 and seg[2] == "reports":
                return self._report(project.name, seg[3])
        return self._plain(404, "Not Found")

    def _status(self, name: str) -> None:
        history = runs.read_runs(name)
        body = json.dumps({"project": name, "state": self.server.scans.state(name),
                           "latest": history[-1] if history else None,
                           "trend": runs.trend(history)})
        self._send(200, body.encode(), "application/json")

    def _report(self, name: str, filename: str) -> None:
        opened = open_report(name, filename)
        if opened is None:
            return self._plain(404, "Not Found")
        fd, size = opened
        with os.fdopen(fd, "rb") as fh:
            self._csp = csp_for(filename)
            self.send_response(200)
            self.send_header("Content-Type", content_type(filename))
            self.send_header("Content-Length", str(size))
            self.end_headers()
            shutil.copyfileobj(fh, self.wfile)
        return None

    # ---- POST: every change, behind the checks above --------------------------

    def _post(self, seg: list[str], form: dict) -> None:
        if seg == ["projects"]:
            return self._create_project(form)
        if seg == ["profiles"]:
            return self._create_profile(form)
        if len(seg) >= 2 and seg[0] == "projects":
            return self._post_project(check_name(seg[1]), seg[2:], form)
        if len(seg) >= 2 and seg[0] == "profiles":
            return self._post_profile(check_name(seg[1], "profile"), seg[2:], form)
        return self._plain(404, "Not Found")

    def _create_project(self, form: dict) -> None:
        name = form.get("name", "")
        try:
            store.add_project(name, form.get("target", ""), form.get("profile") or None,
                              store.parse_meta(_meta_lines(form)), form.get("schedule", "").strip() or None)
        except UsageError as exc:
            return self._send(400, views.new_project(self.server.csrf, form, str(exc)))
        return self._redirect(f"/projects/{check_name(name)}")

    def _post_project(self, name: str, rest: list[str], form: dict) -> None:
        scans, token = self.server.scans, self.server.csrf
        project = store.load_project(name)
        if rest == ["scan"]:
            if not scans.start(name):
                return self._send(409, views.project_page(
                    project, scans, token, "A scan of this project is already queued or running."))
            return self._redirect(f"/projects/{name}")
        if rest == ["delete"]:
            if form.get("confirm") != "1":
                return self._send(400, views.project_page(project, scans, token, "Tick the box to confirm."))
            if scans.state(name) != "idle":
                return self._send(409, views.project_page(project, scans, token, "A scan is running."))
            try:
                store.delete_project(name)
            except UsageError as exc:
                return self._send(409, views.project_page(project, scans, token, str(exc)))
            return self._redirect("/")
        if rest == []:
            try:
                store.update_project(name, form.get("target", ""), form.get("profile") or None,
                                     store.parse_meta(_meta_lines(form)),
                                     form.get("schedule", "").strip() or None)
            except UsageError as exc:
                return self._send(400, views.project_page(project, scans, token, str(exc)))
            return self._redirect(f"/projects/{name}")
        return self._plain(404, "Not Found")

    def _create_profile(self, form: dict) -> None:
        name = form.get("name", "")
        try:
            store.save_profile(name, form.get("yaml", ""), create=True)
        except UsageError as exc:
            return self._send(400, views.message("Profile not created", str(exc)))
        return self._redirect(f"/profiles/{check_name(name, 'profile')}")

    def _post_profile(self, name: str, rest: list[str], form: dict) -> None:
        token = self.server.csrf
        if rest == ["delete"]:
            store.delete_profile(name)
            return self._redirect("/profiles")
        if rest == []:
            try:
                store.save_profile(name, form.get("yaml", ""))
            except UsageError as exc:
                return self._send(400, views.profile_page(name, form.get("yaml", ""), token, str(exc)))
            return self._redirect(f"/profiles/{name}")
        return self._plain(404, "Not Found")


def _meta_lines(form: dict) -> list[str]:
    return [line for line in form.get("meta", "").splitlines() if line.strip()]


def serve(host: str, port: int, public_hosts: list[str], allow_remote: bool, jobs: int) -> int:
    if not 0 <= port <= 65535:
        raise UsageError(f"--port {port} is out of range")
    literal = check_bind(host, public_hosts, allow_remote)
    scans = Scans(jobs)
    try:
        server = Server(literal, port, public_hosts, scans)
    except OSError as exc:
        raise UsageError(f"cannot listen on {host}:{port}: {exc.strerror or exc}") from exc
    actual = server.server_address[1]
    if not ipaddress.ip_address(literal).is_loopback:
        print(f"WARNING: listening on {literal}:{actual}, beyond this machine. There is NO login: "
              "anyone who can reach this port can read reports, add projects and start scans.",
              file=sys.stderr)
    shown = f"[{literal}]" if ":" in literal else literal

    def _terminate(*_):
        raise KeyboardInterrupt
    scheduler = Scheduler(scans)
    # Before the banner, and the banner inside the try: a caller may stop the
    # server the moment it says it is up, and that must still be a clean exit.
    signal.signal(signal.SIGTERM, _terminate)
    try:
        print(f"Serving on http://{shown}:{actual}/ (Ctrl-C to stop)", file=sys.stderr, flush=True)
        scheduler.start()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        scheduler.halted.set()
        scans.stop()
        server.server_close()
    return 0
