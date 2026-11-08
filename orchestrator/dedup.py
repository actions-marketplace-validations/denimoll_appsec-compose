"""Merge duplicate findings reported by multiple tools.

Operates only on our internal model (the raw native per-tool reports are left
untouched for ASPM import). Dedup key depends on category:

- secrets : same location (file, line) is the same secret, regardless of tool.
- sca     : same package@version + file, clustered by overlapping vuln IDs so
            that e.g. Trivy's CVE-2018-1000656 and Grype's GHSA-562c-5r94-xh97
            (whose relatedVulnerabilities lists that CVE) collapse into one.
- iac     : engines use different ids for the same policy, so findings whose
            rule maps to a known equivalence class merge per file; the rest
            fall back to the same rule at the same (file, line).
- sast    : same rule at the same (file, line).
- workflow: the same flaw in a CI workflow from different engines merges where
            their regions overlap, across categories, into one iac finding.

A merged finding records every tool that reported it (provenance) plus the
union of equivalent IDs (aliases). Its severity is the highest among the tools
that actually assigned one — a score-derived severity never outranks a verdict,
for the same reason it does not inside a single report (see _tool_severity).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from normalize import CONFIDENCE_RANK, Finding, _SEVERITY_RANK, _max_severity

# Cross-tool IaC rule equivalence. Trivy, Checkov and Hadolint each use their
# own id for the same Dockerfile policy, so keying on the rule id alone leaves
# obvious duplicates in the report. Ids below were confirmed against the
# engines' own output; anything unmapped keeps its (rule, file, line) identity.
# KICS names its queries by UUID; the comment beside each gives its title.
_IAC_EQUIVALENCE = {
    "docker.latest-tag":        ["DS-0001", "CKV_DOCKER_7", "DL3007", "DL3006",
                                 "F45EA400-6BBE-4501-9FC7-1C3D75C32067"],   # Image Version Using 'latest'
    "docker.root-user":         ["DS-0002", "CKV_DOCKER_3", "CKV_DOCKER_8", "DL3002",
                                 "FD54F200-402C-4333-A5A4-36EF6709AF2F"],   # Missing User Instruction
    "docker.ssh-port":          ["DS-0004", "CKV_DOCKER_1",
                                 "5907595B-5B6D-4142-B173-DBB0E73FBFF8"],   # Exposing Port 22 (SSH)
    "docker.add-instead-copy":  ["DS-0005", "CKV_DOCKER_4", "DL3020"],
    "docker.relative-workdir":  ["DS-0009", "CKV_DOCKER_10", "DL3000"],
    "docker.no-healthcheck":    ["DS-0026", "CKV_DOCKER_2",
                                 "B03A748A-542D-44F4-BB86-9199AB4FD2D5"],   # Healthcheck Instruction Missing
    "docker.apt-recommends":    ["DS-0029", "DL3015",
                                 "7384DFB2-FCD1-4FBF-91CD-6C44C318C33C"],   # APT-GET Not Avoiding Additional Packages
    "docker.apt-pin":           ["DL3008",
                                 "965A08D7-EF86-4F14-8792-4A3B2098937E"],   # Apt Get Install Pin Version Not Defined
    "docker.apt-lists":         ["DL3009",
                                 "DF746B39-6564-4FED-BF85-E9C44382303C"],   # Apt Get Install Lists Were Not Deleted
    "docker.apt-used":          ["CKV_DOCKER_9", "DL3027",
                                 "B84A0B47-2E99-4C9F-8933-98BCABE2B94D"],   # Run Using apt
}

# Terraform and Kubernetes: one file holds many resources, so these merge per
# resource (iacunits), never per file. Each class was confirmed by running the
# engines over TerraGoat and Kubernetes Goat: the rules fire on the same
# resources, and their titles say the same thing. Look-alikes that differ in
# strictness stay apart (CKV_AWS_145 accepts any KMS key, AWS-0132 only a
# customer-managed one).
_IAC_RESOURCE_EQUIVALENCE = {
    # Kubernetes workloads
    "k8s.privileged":           ["CKV_K8S_16", "KSV-0017",
                                 "DD29336B-FE57-445B-A26E-E6AA867AE609"],   # Container Is Privileged
    "k8s.privilege-escalation": ["CKV_K8S_20", "KSV-0001"],
    "k8s.host-pid":             ["CKV_K8S_17", "KSV-0010",
                                 "302736F4-B16C-41B8-BEFE-C0BAFFA0BD9D"],   # Shared Host PID Namespace
    "k8s.host-ipc":             ["CKV_K8S_18", "KSV-0008",
                                 "CD290EFD-6C82-4E9D-A698-BE12AE31D536"],   # Shared Host IPC Namespace
    "k8s.host-network":         ["CKV_K8S_19", "KSV-0009"],
    "k8s.docker-socket":        ["CKV_K8S_27", "KSV-0006",
                                 "A6F34658-FDFB-4154-9536-56D516F65828"],   # Docker Daemon Socket is Exposed
    "k8s.run-as-root":          ["CKV_K8S_23", "KSV-0012",
                                 "CF34805E-3872-4C08-BF92-6FF7BB0CFADB"],   # Container Running As Root
    "k8s.high-uid":             ["CKV_K8S_40", "KSV-0020",
                                 "02323C00-CDC3-4FDC-A310-4F2B3E7A1660"],   # Container Running With Low UID
    "k8s.readonly-rootfs":      ["CKV_K8S_22", "KSV-0014",
                                 "A9C2F49D-0671-4FC9-9ECE-F4E261E128D0"],   # Root Container Not Mounted Read-only
    "k8s.drop-capabilities":    ["KSV-0003",
                                 "268CA686-7FB7-4AE9-B129-955A2A89064E"],   # No Drop Capabilities for Containers
    "k8s.seccomp":              ["CKV_K8S_31", "KSV-0030",
                                 "F377B83E-BD07-4F48-A591-60C82B14A78B"],   # Seccomp Profile Is Not Configured
    "k8s.cpu-requests":         ["CKV_K8S_10", "KSV-0015",
                                 "CA469DD4-C736-448F-8AC1-30A642705E0A"],   # CPU Requests Not Set
    "k8s.cpu-limits":           ["CKV_K8S_11", "KSV-0011",
                                 "4AC0E2B7-D2D2-4AF7-8799-E8DE6721CCDA"],   # CPU Limits Not Set
    "k8s.memory-requests":      ["CKV_K8S_12", "KSV-0016",
                                 "229588EF-8FDE-40C8-8756-F4F2B5825DED"],   # Memory Requests Not Defined
    "k8s.memory-limits":        ["CKV_K8S_13", "KSV-0018",
                                 "B14D1BC4-A208-45DB-92F0-E21F8E2588E9"],   # Memory Limits Not Defined
    "k8s.image-tag":            ["CKV_K8S_14", "KSV-0013",
                                 "583053B7-E632-46F0-B989-F81FF8045385"],   # Invalid Image Tag
    "k8s.image-digest":         ["CKV_K8S_43",
                                 "7C81D34C-8E5A-402B-9798-9F442630E678"],   # Image Without Digest
    "k8s.default-namespace":    ["CKV_K8S_21", "KSV-0110",
                                 "611AB018-C4AA-4BA2-B0F6-A448337509A6"],   # Using Unrecommended Namespace
    "k8s.sa-token-automount":   ["CKV_K8S_38",
                                 "48471392-D4D0-47C0-B135-CDEC95EB3EEF"],   # Service Account Token Automount Not Disabled
    "k8s.liveness-probe":       ["CKV_K8S_8",
                                 "ADE74944-A674-4E00-859E-C6EAB5BDE441"],   # Liveness Probe Is Not Defined
    "k8s.readiness-probe":      ["CKV_K8S_9",
                                 "A659F3B5-9BF0-438A-BD9A-7D3A6427F1E3"],   # Readiness Probe Is Not Configured
    # Terraform — AWS
    "aws.s3-versioning":        ["CKV_AWS_21", "AWS-0090",
                                 "568A4D22-3517-44A6-A7AD-6A7EED88722C"],   # S3 Bucket Without Versioning
    "aws.s3-access-logging":    ["CKV_AWS_18", "AWS-0089",
                                 "F861041C-8C9F-4156-ACFC-5E6E524F5884"],   # S3 Bucket Logging Disabled
    "aws.s3-public-access-block": ["CKV2_AWS_6", "AWS-0094"],
    "aws.rds-cluster-encryption": ["CKV_AWS_96", "AWS-0079",
                                 "1A690D1D-0AE7-49FA-B2DB-B75AE0DD1D3E",    # Aurora With Disabled at Rest Encryption
                                 "3199C26C-7871-4CB3-99C2-10A59244CE7F"],   # RDS Storage Not Encrypted
    "aws.rds-deletion-protection": ["CKV_AWS_139", "AWS-0343"],
    "aws.rds-copy-tags":        ["CKV_AWS_313",
                                 "6D3DEAD4-C6B2-4DB7-81BD-3A83EAE8F255"],   # Tags Not Copied to RDS Cluster Snapshot
    "aws.subnet-public-ip":     ["CKV_AWS_130", "AWS-0164",
                                 "52F04A44-6BFA-4C41-B1D3-4AE99A2DE05C"],   # VPC Subnet Assigns Public IP
    "aws.sg-rule-description":  ["CKV_AWS_23", "AWS-0124",
                                 "68EB4BF3-F9BF-463D-B5CF-E029BB446D2E"],   # Security Group Rule Without Description
    "aws.ec2-imdsv1":           ["CKV_AWS_79", "AWS-0028",
                                 "C306AC53-EE5B-41D3-86A9-0FD2722B4E67"],   # Instance Uses Metadata Service IMDSv1
    "aws.ec2-monitoring":       ["CKV_AWS_126",
                                 "23B70E32-032E-4FA6-BA5C-82F56B9980E6"],   # EC2 Instance Monitoring Disabled
    "aws.ec2-ebs-optimized":    ["CKV_AWS_135",
                                 "60224630-175A-472A-9E23-133827040766"],   # EC2 Not EBS Optimized
    "aws.iam-data-exfiltration": ["CKV_AWS_288",
                                 "BA2ED23B-52D3-45CA-BE25-F6C358D45ABD"],   # IAM policy allows for data exfiltration
    # Terraform — Azure
    "azure.appservice-auth":    ["CKV_AZURE_13", "AZU-0003",
                                 "C7FC1481-2899-4490-BBD8-544A3A61A2F3"],   # App Service Authentication Disabled
    "azure.appservice-identity": ["CKV_AZURE_71", "AZU-0002",
                                 "B61CCE4B-0CC4-472B-8096-15617A6D769B"],   # App Service Managed Identity Disabled
    "azure.appservice-client-cert": ["CKV_AZURE_17", "AZU-0001",
                                 "A81573F9-3691-4D83-88A0-7D4AF63E17A3"],   # App Service Client Certificate Disabled
    "azure.appservice-http2":   ["CKV_AZURE_18", "AZU-0005",
                                 "525B53BE-62ED-4244-B4DF-41AECFCB4071"],   # App Service HTTP2 Disabled
    "azure.sql-public-access":  ["CKV_AZURE_113", "AZU-0022",
                                 "ADE36CF4-329F-4830-A83D-9DB72C800507"],   # MSSQL Server Public Network Access Enabled
    "azure.sql-auditing":       ["CKV_AZURE_23",
                                 "609839AE-BD81-4375-9910-5BCE72AE7B92"],   # MSSQL Server Auditing Disabled
    "azure.sql-alerts":         ["AZU-0028",
                                 "25CD1853-7E80-4106-9AC3-03F8636C25BE"],   # MSSQL Server Database With Alerts Disabled
    # Terraform — Alibaba Cloud
    "alicloud.oss-versioning":  ["CKV_ALI_10",
                                 "70919C0B-2548-4E6B-8D7A-3D84AB6DABBA"],   # OSS Bucket Versioning Disabled
    "alicloud.oss-logging":     ["CKV_ALI_12",
                                 "05DB341E-DE7D-4972-A106-3E2BD5EE53E1"],   # OSS Bucket Logging Disabled
    "alicloud.oss-transfer-acceleration": ["CKV_ALI_11",
                                 "8F98334A-99AA-4D85-B72A-1399CA010413"],   # OSS Bucket Transfer Acceleration Disabled
    "alicloud.oss-cmk":         ["CKV_ALI_6",
                                 "F20E97F9-4919-43F1-9BE9-F203CD339CDD"],   # OSS Bucket Encryption Using CMK Disabled
}

_IAC_CLASS = {rule: cls for cls, rules in _IAC_EQUIVALENCE.items() for rule in rules}
_IAC_RESOURCE_CLASS = {rule: cls for cls, rules in _IAC_RESOURCE_EQUIVALENCE.items()
                       for rule in rules}


# The same flaw in a CI workflow, as each engine names it. Unlike the Dockerfile
# policies above these occur many times per file, so they merge only where the
# engines' regions overlap: Semgrep flags a whole `run:` step, zizmor the
# expression inside it, and two steps stay two findings. CKV2_GHA_1 (file) and
# zizmor's excessive-permissions (job) are not here: different places to fix.
# Semgrep ids carry a prefix, so names match on the id's last segment too.
_WORKFLOW_EQUIVALENCE = {
    "workflow.template-injection": ["zizmor/template-injection", "run-shell-injection", "CKV_GHA_2",
                                    "20f14e1a-a899-4e79-9f09-b6a84cd4649b"],   # KICS: Run Block Injection
    "workflow.unpinned-action": ["zizmor/unpinned-uses", "github-actions-mutable-action-tag",
                                 "555ab8f9-2001-455e-a077-f2d0f41e2fb9"],      # KICS: Unpinned Actions Full Length Commit SHA
}
_WORKFLOW_CLASS = {rule.lower(): cls for cls, rules in _WORKFLOW_EQUIVALENCE.items()
                   for rule in rules}


def workflow_class(rule_id: str) -> str | None:
    rule = (rule_id or "").lower()
    return _WORKFLOW_CLASS.get(rule) or _WORKFLOW_CLASS.get(rule.rsplit(".", 1)[-1])


def iac_class(rule_id: str) -> str | None:
    """Per-file equivalence class (Dockerfile policies), or None."""
    return _IAC_CLASS.get((rule_id or "").upper())


def iac_resource_class(rule_id: str) -> str | None:
    """Per-resource equivalence class (Terraform, Kubernetes), or None."""
    return _IAC_RESOURCE_CLASS.get((rule_id or "").upper())


@dataclass
class DedupStats:
    raw: int
    unique: int

    @property
    def removed(self) -> int:
        return self.raw - self.unique


def _norm_file(path: str) -> str:
    # Align paths across tools: some report relative ("app.py"), others report
    # the container mount ("/code/app.py"). /code is our fixed mount root.
    # Strip "./" and "/" as prefixes only: lstrip("./") would also eat the dot
    # of ".github/" and point at a file that does not exist.
    p = path or ""
    while p.startswith(("./", "/")):
        p = p[2:] if p.startswith("./") else p[1:]
    if p.startswith("code/"):
        p = p[len("code/"):]
    return p


def _id_tokens(f: Finding) -> set[str]:
    return {f.rule_id.upper()} | {a.upper() for a in f.aliases}


def _merge_group(group: list[Finding]) -> Finding:
    # Engines that stated a severity themselves decide it. OSV-Scanner reports
    # no verdict, so its CVSS-derived level would otherwise override Trivy and
    # Grype whenever an advisory's raw score disagrees with its own rating —
    # re-inflating exactly what reading the verdict was meant to fix.
    verdicts = [f for f in group if f.severity_stated]
    ranked = verdicts or group

    rep = max(ranked, key=lambda f: _SEVERITY_RANK[f.severity])
    tools = sorted({t for f in group for t in f.tools})
    ids = sorted({t for f in group for t in _id_tokens(f)})

    severity = "info"
    for f in ranked:
        severity = _max_severity(severity, f.severity)

    # Prefer a CVE id as the canonical rule_id for readability/ASPM matching.
    rule_id = next((i for i in ids if i.startswith("CVE-")), rep.rule_id)
    aliases = [i for i in ids if i != rule_id.upper()]

    description = next((f.description for f in group if f.description), "")
    url = next((f.url for f in group if f.url), "")
    fixed_version = next((f.fixed_version for f in group if f.fixed_version), "")
    cwe = sorted({c for f in group for c in f.cwe}, key=lambda c: int(c[4:]))
    # Columns locate a secret's span on the line; TruffleHog reports none, so
    # borrow them from an engine that flagged the same line.
    span = next((f for f in [rep, *group]
                 if f.column is not None and f.line == rep.line), rep)

    # One engine recognising the advisory as malware is enough: OSV knows the
    # MAL- alias that Trivy, reporting the same CVE, does not.
    malicious = any(f.malicious for f in group)
    if malicious:
        severity = "critical"
    marked = next((f for f in group if f.malicious), rep)
    # Engines that agree are a confidence of their own: the merged finding is
    # as sure as its surest engine, and one that states none is not "low".
    stated = [f.confidence for f in group]
    confidence = ("" if "" in stated
                  else max(stated, key=lambda c: CONFIDENCE_RANK.get(c, 0)))

    return Finding(
        tool=rep.tool, category=rep.category, rule_id=rule_id, severity=severity,
        malicious=malicious, scanner_severity=marked.scanner_severity,
        message=marked.message if malicious else rep.message,
        file=rep.file, line=rep.line, package=rep.package,
        aliases=aliases, tools=tools, description=description, url=url,
        severity_stated=bool(verdicts), end_line=span.end_line,
        column=span.column, end_column=span.end_column, cwe=cwe,
        fixed_version=fixed_version, confidence=confidence,
    )


def _cluster_sca(findings: list[Finding]) -> list[list[Finding]]:
    """Union-find within each (package, file) bucket, joined by shared vuln IDs."""
    buckets: dict[tuple, list[Finding]] = {}
    for f in findings:
        key = (f.package or f.rule_id, _norm_file(os.path.basename(f.file)))
        buckets.setdefault(key, []).append(f)

    groups: list[list[Finding]] = []
    for bucket in buckets.values():
        parent = list(range(len(bucket)))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            parent[find(a)] = find(b)

        token_owner: dict[str, int] = {}
        for i, f in enumerate(bucket):
            for tok in _id_tokens(f):
                if tok in token_owner:
                    union(i, token_owner[tok])
                else:
                    token_owner[tok] = i

        clusters: dict[int, list[Finding]] = {}
        for i, f in enumerate(bucket):
            clusters.setdefault(find(i), []).append(f)
        groups.extend(clusters.values())
    return groups


def _cluster_workflow(findings: list[Finding]) -> tuple[list[list[Finding]], list[Finding]]:
    """Workflow findings reported by more than one engine, grouped by overlap.

    Returns those groups and everything else. A cluster one engine reported
    alone is not a duplicate: its findings go on unchanged, keeping their
    category and fingerprint.
    """
    buckets: dict[tuple, list[Finding]] = {}
    rest: list[Finding] = []
    for f in findings:
        cls = workflow_class(f.rule_id)
        if cls and f.line:
            buckets.setdefault((cls, _norm_file(f.file)), []).append(f)
        else:
            rest.append(f)
    groups: list[list[Finding]] = []
    for bucket in buckets.values():
        bucket.sort(key=lambda f: f.line)
        clusters: list[list[Finding]] = []
        end = 0
        for f in bucket:
            if clusters and f.line <= end:
                clusters[-1].append(f)
            else:
                clusters.append([f])
                end = 0
            end = max(end, f.end_line or f.line, f.line)
        for cluster in clusters:
            if len({f.tool for f in cluster}) > 1:
                groups.append(cluster)
            else:
                rest.extend(cluster)
    return groups, rest


def merge(findings: list[Finding], enabled: bool = True,
          units=None) -> tuple[list[Finding], DedupStats]:
    """`units` (iacunits.Units) places Terraform/K8s findings in their
    resource; without it they merge only on an identical rule and line."""
    raw = len(findings)
    if not enabled:
        return list(findings), DedupStats(raw=raw, unique=raw)

    # Across categories: Semgrep files these under sast, the others under iac.
    workflow_groups, findings = _cluster_workflow(findings)

    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    groups: list[list[Finding]] = []
    for category, items in by_cat.items():
        if category == "sca":
            groups.extend(_cluster_sca(items))
        else:
            keyed: dict[tuple, list[Finding]] = {}
            for f in items:
                if category == "secrets":
                    sig = (_norm_file(f.file), f.line)
                elif category == "iac" and iac_class(f.rule_id):
                    # Engines flag the same policy on different lines of a file
                    # (the FROM line vs. line 1), so equivalence merges per file.
                    sig = (iac_class(f.rule_id), _norm_file(f.file), None)
                elif (category == "iac" and iac_resource_class(f.rule_id) and units
                      and (unit := units.label(_norm_file(f.file), f.line))):
                    # ...and per resource where a file holds many.
                    sig = (iac_resource_class(f.rule_id), _norm_file(f.file), unit)
                else:
                    sig = (f.rule_id, _norm_file(f.file), f.line)
                keyed.setdefault(sig, []).append(f)
            groups.extend(keyed.values())

    merged = [_merge_group(g) for g in groups]
    for group in workflow_groups:
        finding = _merge_group(group)
        finding.category = "iac"     # one gate threshold, whichever engine leads
        merged.append(finding)
    merged.sort(key=lambda f: (-_SEVERITY_RANK[f.severity], f.category, f.tools))
    return merged, DedupStats(raw=raw, unique=len(merged))
