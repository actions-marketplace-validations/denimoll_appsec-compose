"""HTTP for the benchmark harness: stdlib first, curl as the fallback.

The python.org macOS installer ships without a CA bundle until "Install
Certificates.command" is run, so urllib fails TLS verification on a stock
install. curl uses the system trust store, so it is the fallback rather than
turning verification off.
"""
from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import urllib.error
import urllib.request


def _curl(url: str, data: bytes | None, out: str | None) -> bytes:
    if not shutil.which("curl"):
        raise RuntimeError(f"cannot fetch {url}: TLS verification failed and curl is not installed")
    cmd = ["curl", "-fsSL", "--retry", "3"]
    if data is not None:
        cmd += ["-H", "Content-Type: application/json", "--data-binary", "@-"]
    if out:
        cmd += ["-o", out]
    proc = subprocess.run(cmd + [url], input=data, capture_output=True)
    if proc.returncode:
        raise RuntimeError(f"curl {url} failed: {proc.stderr.decode().strip()}")
    return proc.stdout


_USE_CURL = False   # set once urllib has failed TLS verification


def fetch(url: str, data: bytes | None = None, out: str | None = None,
          timeout: int = 120) -> bytes:
    """GET (or POST JSON when `data` is given); write to `out` if named."""
    global _USE_CURL
    if _USE_CURL:
        return _curl(url, data, out)
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.URLError as exc:
        if not isinstance(exc.reason, ssl.SSLError):
            raise
        _USE_CURL = True
        return _curl(url, data, out)
    if out:
        with open(out, "wb") as fh:
            fh.write(body)
    return body


def get_json(url: str) -> dict:
    return json.loads(fetch(url))


def post_json(url: str, payload: dict) -> dict:
    return json.loads(fetch(url, data=json.dumps(payload).encode()))
