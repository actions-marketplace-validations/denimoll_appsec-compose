from dedup import _norm_file, iac_class, merge
from normalize import Finding


def sca(tool, rule, package, file="requirements.txt", severity="high", aliases=()):
    return Finding(tool=tool, category="sca", rule_id=rule, severity=severity,
                   message=rule, file=file, line=None, package=package,
                   aliases=list(aliases))


def iac(tool, rule, file="Dockerfile", line=1, severity="medium"):
    return Finding(tool=tool, category="iac", rule_id=rule, severity=severity,
                   message=rule, file=file, line=line)


def test_norm_file_aligns_mount_prefixed_and_relative_paths():
    assert _norm_file("/code/app.py") == _norm_file("app.py") == "app.py"
    assert _norm_file("./app.py") == "app.py"


def test_sca_merges_cve_and_ghsa_via_aliases():
    findings = [
        sca("trivy", "CVE-2018-1000656", "flask@1.0"),
        sca("grype", "GHSA-562c-5r94-xh97", "flask@1.0",
            aliases=["CVE-2018-1000656"]),
    ]
    merged, stats = merge(findings)
    assert stats.raw == 2 and stats.unique == 1
    assert merged[0].rule_id == "CVE-2018-1000656"        # CVE is canonical
    assert merged[0].tools == ["grype", "trivy"]
    assert "GHSA-562C-5R94-XH97" in merged[0].aliases


def test_sca_keeps_distinct_cves_in_the_same_package():
    merged, stats = merge([sca("trivy", "CVE-1", "flask@1.0"),
                           sca("trivy", "CVE-2", "flask@1.0")])
    assert stats.unique == 2


def test_merged_finding_keeps_the_highest_severity():
    merged, _ = merge([sca("trivy", "CVE-1", "flask@1.0", severity="medium"),
                       sca("grype", "CVE-1", "flask@1.0", severity="critical")])
    assert merged[0].severity == "critical"


def test_iac_equivalence_merges_the_same_policy_across_engines():
    # Same Dockerfile policy, three engines, three ids, three different lines.
    findings = [iac("trivy", "DS-0002", line=1),
                iac("checkov", "CKV_DOCKER_3", line=None),
                iac("hadolint", "DL3002", line=7)]
    merged, stats = merge(findings)
    assert stats.unique == 1
    assert merged[0].tools == ["checkov", "hadolint", "trivy"]


def test_iac_equivalence_does_not_merge_different_policies():
    merged, stats = merge([iac("trivy", "DS-0002"), iac("trivy", "DS-0026")])
    assert stats.unique == 2


def test_iac_equivalence_is_per_file():
    merged, stats = merge([iac("trivy", "DS-0002", file="a/Dockerfile"),
                           iac("checkov", "CKV_DOCKER_3", file="b/Dockerfile")])
    assert stats.unique == 2


def test_unmapped_iac_rules_keep_rule_file_line_identity():
    assert iac_class("CKV_AWS_999") is None
    merged, stats = merge([iac("checkov", "CKV_AWS_999", line=1),
                           iac("checkov", "CKV_AWS_999", line=2)])
    assert stats.unique == 2


def test_secrets_merge_on_location_regardless_of_rule():
    a = Finding("gitleaks", "secrets", "aws-key", "high", "m", "/code/x.env", 4)
    b = Finding("trufflehog", "secrets", "trufflehog.AWS", "critical", "m", "x.env", 4)
    merged, stats = merge([a, b])
    assert stats.unique == 1 and merged[0].severity == "critical"


def test_dedup_disabled_is_a_passthrough():
    findings = [sca("trivy", "CVE-1", "flask@1.0"), sca("grype", "CVE-1", "flask@1.0")]
    merged, stats = merge(findings, enabled=False)
    assert len(merged) == 2 and stats.removed == 0


def test_a_lone_finding_does_not_alias_its_own_id():
    lone = Finding("semgrep", "sast", "python.lang.security.audit.x", "medium",
                   "m", "a.py", 1)
    merged, _ = merge([lone])
    assert merged[0].aliases == []


# --- a verdict outranks a score, across tools as well as within one ----------

def stated(tool, rule, severity, package="aiohttp@3.13.3", aliases=()):
    f = sca(tool, rule, package, severity=severity, aliases=aliases)
    f.severity_stated = True
    return f


def derived(tool, rule, severity, package="aiohttp@3.13.3", aliases=()):
    return sca(tool, rule, package, severity=severity, aliases=aliases)


def test_a_score_derived_severity_never_outranks_a_verdict():
    """CVE-2026-34520: Trivy and Grype both rate it LOW; OSV only has the 9.1
    CVSS the advisory carries, and used to win the merge."""
    merged, stats = merge([
        stated("trivy", "CVE-2026-34520", "low"),
        stated("grype", "GHSA-63hf-3vf5-4wqf", "low", aliases=["CVE-2026-34520"]),
        derived("osv", "CVE-2026-34520", "critical"),
    ])
    assert stats.unique == 1
    assert merged[0].severity == "low"
    assert merged[0].tools == ["grype", "osv", "trivy"]


def test_the_highest_verdict_still_wins_among_tools_that_have_one():
    merged, _ = merge([stated("trivy", "CVE-1", "low"),
                       stated("grype", "CVE-1", "high")])
    assert merged[0].severity == "high"


def test_scores_still_rank_a_group_where_nobody_stated_a_verdict():
    """OSV alone must keep its only gradation."""
    merged, _ = merge([derived("osv", "CVE-1", "critical"),
                       derived("osv", "CVE-1", "medium")])
    assert merged[0].severity == "critical"


def test_the_merged_finding_reports_whether_a_verdict_backed_it():
    verdict, _ = merge([stated("trivy", "CVE-1", "low"),
                        derived("osv", "CVE-1", "critical")])
    assert verdict[0].severity_stated is True
    score, _ = merge([derived("osv", "CVE-2", "critical")])
    assert score[0].severity_stated is False


def test_the_representative_comes_from_the_tools_that_decided():
    merged, _ = merge([
        stated("trivy", "CVE-1", "low"),
        derived("osv", "CVE-1", "critical"),
    ])
    # message/location follow the verdict, not the loudest score
    assert merged[0].severity == "low"


def test_merge_keeps_fix_cwe_and_borrows_the_secret_span():
    gitleaks = Finding("gitleaks", "secrets", "aws", "high", "m", "a.py", 3,
                       column=5, end_column=25)
    truffle = Finding("trufflehog", "secrets", "th.aws", "critical", "m", "a.py", 3)
    merged, _ = merge([gitleaks, truffle])
    assert (merged[0].tool, merged[0].column, merged[0].end_column) == ("trufflehog", 5, 25)

    a = sca("trivy", "CVE-1", "flask@1.0")
    a.fixed_version, a.cwe = "1.1", ["CWE-79"]
    b = sca("grype", "CVE-1", "flask@1.0")
    b.cwe = ["CWE-20"]
    merged, _ = merge([b, a])
    assert merged[0].fixed_version == "1.1" and merged[0].cwe == ["CWE-20", "CWE-79"]


def test_norm_file_keeps_the_dot_of_a_hidden_directory():
    assert _norm_file("/code/.github/workflows/ci.yml") == ".github/workflows/ci.yml"
    assert _norm_file("./.env") == ".env"


def test_grype_maven_packages_merge_with_trivy_by_group_and_artifact(tmp_path):
    import json
    from normalize import load_findings
    (tmp_path / "grype.json").write_text(json.dumps({"matches": [{
        "vulnerability": {"id": "GHSA-57j2-w4cx-62h2", "severity": "High"},
        "relatedVulnerabilities": [{"id": "CVE-2020-36518"}],
        "artifact": {"name": "jackson-databind", "version": "2.9.8",
                     "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8",
                     "locations": [{"path": "/pom.xml"}]}}]}))
    grype, = load_findings(str(tmp_path), expected={"grype.json"}).findings
    assert grype.package == "com.fasterxml.jackson.core:jackson-databind@2.9.8"
    trivy = sca("trivy", "CVE-2020-36518", "com.fasterxml.jackson.core:jackson-databind@2.9.8",
                file="pom.xml")
    merged, _ = merge([grype, trivy])
    assert len(merged) == 1 and merged[0].tools == ["grype", "trivy"]


def test_upgrade_to_is_the_lowest_version_fixing_every_vulnerability():
    from components import group, upgrade_target
    assert upgrade_target("2.9.8", [["2.9.9.2", "2.8.11.4"]]) == "2.9.9.2"
    assert upgrade_target("v8.1.2", [["6.4.0", "8.1.6", "8.1.0"]]) == "8.1.6"
    # A per-branch fix list: 2.20 is not fixed for the first one, so the
    # answer is not 2.20.1 but the first version both cover.
    assert upgrade_target("2.9.8", [["2.18.11", "2.21.7"], ["2.20.1"]]) == "2.21.7"
    assert upgrade_target("1.0", [["2.0.0-rc1"]]) is None    # not comparable: no guess
    assert upgrade_target("2.9.8", [["2.8.1"]]) is None      # nothing above installed
    a = sca("trivy", "CVE-1", "jackson-databind@2.9.8")
    a.fixed_version = "2.9.9.2, 2.8.11.4"
    b = sca("trivy", "CVE-2", "jackson-databind@2.9.8")
    b.fixed_version = "2.12.6.1, 2.13.2.1"
    comp, = group([a, b])
    assert comp.upgrade_to == "2.12.6.1"
    c = sca("trivy", "CVE-3", "jackson-databind@2.9.8")      # no fix known
    assert group([a, b, c])[0].upgrade_to is None


def test_trivy_without_a_fix_does_not_take_the_next_line(tmp_path):
    import json
    from normalize import load_findings
    (tmp_path / "trivy-fs.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "t", "rules": []}},
        "results": [{"ruleId": "GHSA-x", "level": "error",
                     "message": {"text": "Package: flatmap-stream\nInstalled Version: 0.1.1\n"
                                         "Fixed Version: \nLink: [GHSA-x](https://x)"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"}}}]}]}]}))
    f, = load_findings(str(tmp_path), expected={"trivy-fs.sarif"}).findings
    assert f.fixed_version == "" and f.package == "flatmap-stream@0.1.1"
