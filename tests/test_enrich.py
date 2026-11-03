import pytest

import enrich
from enrich import EnrichResult, Verdict, _verdict_from, apply, cve_ids, config_from
from normalize import Finding

# Shapes taken from live CVE-PaaS instances, not invented.
#
# 1.4.0+ reports KEV membership explicitly and every Links value is a URL.
LOG4SHELL = {
    "Priority": "Critical",
    "Details": {
        "CVSS": 10, "EPSS": 0.99999,
        "is_template": True, "is_poc": True,
        "is_kev": True, "is_vkev": True, "is_exploited": True,
        "kev": [{"added_date": "2021-12-10T00:00:00Z", "source": "cisa"}],
        "nuclei_template_count": 75,
        "Links": {
            "POC": "http://packetstormsecurity.com/files/165261/",
            "Nuclei templates": "https://github.com/search?q=CVE-2021-44228",
            "KEV": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        },
    },
}

# Before 1.4.0 is_exploited was always null and Links.KEV held catalogue
# records rather than a URL. Kept so an older service still gates correctly.
LOG4SHELL_LEGACY = {
    "Priority": "Critical",
    "Details": {
        "CVSS": 10, "EPSS": 0.99999,
        "is_template": True, "is_exploited": None, "is_poc": True,
        "Links": {
            "POC": "http://packetstormsecurity.com/files/165261/",
            "Nuclei templates": None,
            "KEV": [{"added_date": "2021-12-10T00:00:00Z", "source": "cisa"}],
        },
    },
}
HIGH_CVSS_LOW_EPSS = {
    "Priority": "Medium",
    "Details": {"CVSS": 9.1, "EPSS": 0.00581, "is_template": False,
                "is_exploited": None, "is_poc": False, "Links": None},
}


def sca(rule_id, severity="high", aliases=()):
    return Finding("trivy", "sca", rule_id, severity, "m", "requirements.txt",
                   None, package="x@1", aliases=list(aliases))


def test_kev_is_read_from_the_explicit_flags():
    v = _verdict_from(LOG4SHELL)
    assert v.kev and v.poc and v.nuclei and v.exploitable
    assert v.epss == 0.99999
    assert sorted(v.links) == ["KEV", "Nuclei templates", "POC"]


def test_kev_is_still_detected_on_a_pre_1_4_0_service():
    """is_exploited was null back then; the catalogue records were the only signal."""
    v = _verdict_from(LOG4SHELL_LEGACY)
    assert v.kev and v.exploitable


def test_kev_records_are_not_mistaken_for_a_link():
    """A pre-1.4.0 Links.KEV is a list of entries, so it must not become a URL."""
    v = _verdict_from(LOG4SHELL_LEGACY)
    assert list(v.links) == ["POC"]
    assert all(isinstance(u, str) for u in v.links.values())


def test_a_high_cvss_with_low_epss_is_not_exploitable():
    v = _verdict_from(HIGH_CVSS_LOW_EPSS)
    assert v.priority == "Medium" and not v.exploitable and v.cvss == 9.1


def test_null_links_are_tolerated():
    assert _verdict_from(HIGH_CVSS_LOW_EPSS).links == {}


def test_error_records_are_skipped():
    assert _verdict_from({"error": "upstream timeout"}) is None
    assert _verdict_from("nonsense") is None


def test_cve_ids_are_harvested_from_the_rule_and_its_aliases():
    f = sca("GHSA-xxxx-yyyy", aliases=["CVE-2021-44228", "cve-2020-1234"])
    assert cve_ids(f) == ["CVE-2021-44228", "CVE-2020-1234"]
    assert cve_ids(sca("CKV_DOCKER_3")) == []


def _stub(monkeypatch, responses, calls=None):
    def fake_post(url, payload, api_key, timeout):
        if calls is not None:
            calls.append(payload["cve_ids"])
        return {c: responses[c] for c in payload["cve_ids"] if c in responses}
    monkeypatch.setattr(enrich, "_post", fake_post)


def test_annotate_attaches_data_without_touching_severity(monkeypatch):
    _stub(monkeypatch, {"CVE-2021-44228": LOG4SHELL})
    f = sca("CVE-2021-44228", severity="medium")
    result = apply([f], "http://svc")
    assert f.severity == "medium" and f.scanner_severity == ""
    assert f.priority == "Critical" and f.kev and f.exploitable
    assert result.exploitable == 1 and result.reprioritized == 0


def test_reprioritize_replaces_severity_and_keeps_the_original(monkeypatch):
    _stub(monkeypatch, {"CVE-2021-44228": LOG4SHELL})
    f = sca("CVE-2021-44228", severity="medium")
    result = apply([f], "http://svc", reprioritize=True)
    assert f.severity == "critical" and f.scanner_severity == "medium"
    assert result.reprioritized == 1


def test_reprioritize_can_lower_a_severity(monkeypatch):
    """A CVSS 9.1 with negligible EPSS is exactly what should stop failing builds."""
    _stub(monkeypatch, {"CVE-2025-43859": HIGH_CVSS_LOW_EPSS})
    f = sca("CVE-2025-43859", severity="critical")
    apply([f], "http://svc", reprioritize=True)
    assert f.severity == "medium" and f.scanner_severity == "critical"


def test_reprioritize_never_talks_down_a_malicious_package(monkeypatch):
    """debug@4.4.2 (CVE-2025-59144) is malware; a low EPSS does not change that."""
    _stub(monkeypatch, {"CVE-2025-43859": HIGH_CVSS_LOW_EPSS})
    f = sca("CVE-2025-43859", severity="critical")
    f.malicious = True
    apply([f], "http://svc", reprioritize=True)
    assert f.severity == "critical" and f.scanner_severity == ""


def test_the_most_urgent_cve_wins_when_a_finding_carries_several(monkeypatch):
    _stub(monkeypatch, {"CVE-2025-43859": HIGH_CVSS_LOW_EPSS,
                        "CVE-2021-44228": LOG4SHELL})
    f = sca("CVE-2025-43859", aliases=["CVE-2021-44228"])
    apply([f], "http://svc")
    assert f.priority == "Critical" and f.exploitable


def test_lookups_are_batched_and_deduplicated(monkeypatch):
    calls = []
    ids = [f"CVE-2020-{i:04d}" for i in range(1, 121)]
    _stub(monkeypatch, {}, calls)
    findings = [sca(i) for i in ids] + [sca(ids[0])]      # one duplicate
    apply(findings, "http://svc")
    assert [len(c) for c in calls] == [50, 50, 20]        # 120 unique, not 121


def test_a_service_failure_degrades_instead_of_raising(monkeypatch):
    def boom(*a, **kw):
        raise OSError("connection refused")
    monkeypatch.setattr(enrich, "_post", boom)
    f = sca("CVE-2021-44228", severity="high")
    result = apply([f], "http://svc")
    assert "connection refused" in result.error
    assert f.severity == "high" and f.priority == ""      # untouched


def test_findings_without_a_cve_never_trigger_a_request(monkeypatch):
    def boom(*a, **kw):
        raise AssertionError("should not be called")
    monkeypatch.setattr(enrich, "_post", boom)
    assert apply([sca("CKV_DOCKER_3")], "http://svc") == EnrichResult(verdicts={})


def test_config_reads_the_key_from_the_environment_only(monkeypatch):
    monkeypatch.setenv("MY_KEY", "s3cret")
    cfg = config_from({"enrich": {"cve_paas": {"enabled": True,
                                               "api_key_env": "MY_KEY"}}})
    assert cfg["api_key"] == "s3cret" and cfg["enabled"] is True
    assert cfg["mode"] == "annotate"          # safe default


def test_config_rejects_an_unknown_mode():
    with pytest.raises(ValueError, match="Invalid enrich.cve_paas.mode"):
        config_from({"enrich": {"cve_paas": {"mode": "guess"}}})


def test_config_defaults_to_disabled():
    assert config_from({})["enabled"] is False


def test_a_critical_verdict_is_exploitable_even_without_detail_flags():
    """Critical is the contract: KEV or PoC or Nuclei template. Trust it."""
    v = _verdict_from({"Priority": "Critical", "Details": {"CVSS": 7.5}})
    assert v.exploitable and not v.kev and not v.poc


def test_a_medium_verdict_is_not_exploitable():
    assert not _verdict_from(HIGH_CVSS_LOW_EPSS).exploitable
