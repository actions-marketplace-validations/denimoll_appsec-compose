"""Enrich SCA findings with exploitability data from CVE-PaaS.

A CVSS score says how bad a vulnerability would be; it does not say whether
anyone is exploiting it. A gate built on CVSS alone fires on dozens of
theoretical "high" findings, which is how teams learn to ignore the report.

CVE-PaaS (https://github.com/denimoll/CVE-PaaS) answers the other question —
is it in CISA KEV, is there a public PoC or Nuclei template, what is the EPSS
score — and returns a priority on the same scale we already use.

Only stdlib HTTP: the collector image stays at two dependencies.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from normalize import Finding

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# CVE-PaaS returns exactly our severity names, plus "Undefined" for a CVE whose
# CVSS/EPSS could not be resolved — that maps onto our `unknown_severity`.
_PRIORITY_TO_SEVERITY = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info",
}

_BATCH = 50          # /v1/cve accepts 1-50 ids per call


@dataclass
class Verdict:
    priority: str
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    poc: bool = False
    nuclei: bool = False
    links: dict = field(default_factory=dict)

    @property
    def exploitable(self) -> bool:
        """Something concrete exists to exploit this, right now.

        `Critical` is part of the CVE-PaaS contract — it is returned exactly
        when a CVE is in KEV or has a public PoC or a Nuclei template — so we
        honour the verdict as well as the individual flags. That keeps the gate
        correct even if the detail fields are renamed upstream.
        """
        return bool(self.kev or self.poc or self.nuclei
                    or self.priority.lower() == "critical")


@dataclass
class EnrichResult:
    verdicts: dict[str, Verdict]      # CVE id (upper) -> verdict
    requested: int = 0
    resolved: int = 0
    reprioritized: int = 0
    exploitable: int = 0
    error: str = ""                   # set when the service could not be used


def cve_ids(finding: Finding) -> list[str]:
    """Every CVE id this finding is known by (its own id and its aliases)."""
    found = []
    for token in [finding.rule_id, *finding.aliases]:
        found.extend(m.group(0).upper() for m in CVE_RE.finditer(token or ""))
    return list(dict.fromkeys(found))


def _post(url: str, payload: dict, api_key: str, timeout: float) -> dict:
    # urlopen also opens file:// and ftp://; this only ever talks to a web API.
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"CVE-PaaS url must be http(s), got {url!r}")
    data = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    if api_key:
        request.add_header("X-API-Key", api_key)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosemgrep: dynamic-urllib-use-detected
        return json.loads(response.read().decode())


def _verdict_from(payload: dict) -> Verdict | None:
    """Build a Verdict from one CVE-PaaS entry, skipping its error records."""
    if not isinstance(payload, dict) or "Priority" not in payload:
        return None                     # {"error": ...} — transient fetch failure
    details = payload.get("Details") or {}
    raw_links = details.get("Links") or {}

    # CVE-PaaS >= 1.4.0 reports KEV membership explicitly (is_kev is CISA,
    # is_vkev is VulnCheck, is_exploited is their union). Older releases left
    # is_exploited null and carried the catalogue entries under Links.KEV
    # instead, so accept any of those signals.
    kev = bool(details.get("is_kev") or details.get("is_vkev")
               or details.get("is_exploited") or raw_links.get("KEV"))

    # Links values are URL strings from 1.4.0 on; older releases put a list of
    # KEV records in there, which is not a link.
    links = {k: v for k, v in raw_links.items() if isinstance(v, str) and v}

    return Verdict(
        priority=str(payload["Priority"]),
        cvss=details.get("CVSS"),
        epss=details.get("EPSS"),
        kev=kev,
        poc=bool(details.get("is_poc")),
        nuclei=bool(details.get("is_template")),
        links=links,
    )


def fetch(ids: list[str], base_url: str, api_key: str = "",
          timeout: float = 30.0) -> tuple[dict[str, Verdict], str]:
    """Look every CVE up, in batches. Returns (verdicts, error message)."""
    verdicts: dict[str, Verdict] = {}
    endpoint = base_url.rstrip("/") + "/v1/cve"
    for start in range(0, len(ids), _BATCH):
        batch = ids[start:start + _BATCH]
        try:
            body = _post(endpoint, {"cve_ids": batch}, api_key, timeout)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            # Partial results are still worth keeping; report why we stopped.
            return verdicts, f"{type(exc).__name__}: {exc}"
        for cve, payload in (body or {}).items():
            verdict = _verdict_from(payload)
            if verdict:
                verdicts[cve.upper()] = verdict
    return verdicts, ""


def apply(findings: list[Finding], base_url: str, api_key: str = "",
          timeout: float = 30.0, reprioritize: bool = False) -> EnrichResult:
    """Attach exploitability data to every finding carrying a CVE id."""
    wanted: list[str] = []
    for finding in findings:
        for cve in cve_ids(finding):
            if cve not in wanted:
                wanted.append(cve)

    if not wanted:
        return EnrichResult(verdicts={})

    verdicts, error = fetch(wanted, base_url, api_key, timeout)
    result = EnrichResult(verdicts=verdicts, requested=len(wanted),
                          resolved=len(verdicts), error=error)

    for finding in findings:
        matches = [verdicts[c] for c in cve_ids(finding) if c in verdicts]
        if not matches:
            continue
        # A finding may carry several CVEs; the most urgent one wins.
        verdict = max(matches, key=lambda v: (v.exploitable, v.epss or 0.0))
        finding.priority = verdict.priority
        finding.epss = verdict.epss
        finding.kev = verdict.kev
        finding.poc = verdict.poc
        finding.nuclei = verdict.nuclei
        finding.exploitable = verdict.exploitable
        if verdict.links and not finding.url:
            finding.url = next(iter(verdict.links.values()), "")
        if verdict.exploitable:
            result.exploitable += 1
        # A malicious package is not a vulnerability waiting for an exploit:
        # it is the exploit. No EPSS or KEV verdict may talk it down.
        if reprioritize and not finding.malicious:
            mapped = _PRIORITY_TO_SEVERITY.get(verdict.priority.lower())
            if mapped and mapped != finding.severity:
                finding.scanner_severity = finding.severity
                finding.severity = mapped
                result.reprioritized += 1
    return result


def config_from(raw: dict) -> dict:
    """Read and validate the `enrich.cve_paas` block."""
    block = ((raw.get("enrich") or {}).get("cve_paas") or {})
    mode = str(block.get("mode", "annotate")).lower()
    if mode not in ("annotate", "reprioritize"):
        raise ValueError(f"Invalid enrich.cve_paas.mode={mode!r}; "
                         f"expected 'annotate' or 'reprioritize'")
    key_var = str(block.get("api_key_env", "CVE_PAAS_API_KEY"))
    return {
        "enabled": bool(block.get("enabled", False)),
        "url": str(block.get("url", "http://host.docker.internal:8000")),
        "mode": mode,
        "timeout": float(block.get("timeout", 30)),
        "fail_on_exploitable": bool(block.get("fail_on_exploitable", False)),
        # The key never lives in the config file, only in the environment.
        "api_key": os.environ.get(key_var, ""),
    }
