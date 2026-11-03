"""License policy over a real Trivy 0.74 `--scanners license --list-all-pkgs`
report (tests/fixtures/trivy/trivy-license.json: npm and composer lockfiles,
dual licenses, a Maven pom resolved online, go.mod and Cargo.lock)."""
from pathlib import Path

import pytest

from licenses import Policy, evaluate, policy_from, verdict
from schema import validate

REPORT = Path(__file__).resolve().parent / "fixtures" / "trivy" / "trivy-license.json"


def _by_package(policy):
    findings, stats = evaluate(REPORT, policy)
    return {f.package: f for f in findings}, stats


def test_denied_licenses_become_sca_findings_with_a_license_rule():
    found, stats = _by_package(Policy(deny=["GPL-3.0", "AGPL-*"]))
    f = found["gplv3@1.0.0"]          # declared "GPLv3", normalised by Trivy
    assert (f.tool, f.category, f.rule_id, f.severity) == \
        ("trivy", "sca", "LICENSE:GPL-3.0-only", "high")
    assert f.file == "node/package-lock.json" and f.line == 23 and f.severity_stated
    assert f.url == "https://spdx.org/licenses/GPL-3.0-only.html"
    assert "agpl@1.0.0" in found
    # a plain id covers its -or-later spelling ("GPL-3.0+" in composer.json)
    assert {"legacy/gpl@1.0.0", "single/gpl@1.0.0"} <= set(found)
    assert stats.denied == len(found)


def test_a_dual_license_with_an_allowed_alternative_is_not_denied():
    found, _ = _by_package(Policy(deny=["GPL-3.0"]))
    assert "dual/or-array@1.0.0" not in found      # composer: MIT or GPL-3.0-only
    assert "or-expr@1.0.0" not in found            # npm: (MIT OR GPL-3.0-only)
    assert found["and-expr@1.0.0"].rule_id == "LICENSE:MIT AND GPL-3.0-only"


def test_warn_is_reported_without_gating_and_severity_is_configurable():
    found, stats = _by_package(Policy(deny=["AGPL-*"], warn=["GPL-*"], severity="critical"))
    assert found["agpl@1.0.0"].severity == "critical"
    assert found["gplv3@1.0.0"].severity == "info" and stats.warned >= 1
    assert "licenses.warn" in found["gplv3@1.0.0"].message


def test_packages_without_license_data_are_counted_not_passed():
    _, stats = _by_package(Policy(deny=["GPL-*"]))
    assert stats.unlicensed >= 2
    assert {"gomod", "cargo"} <= set(stats.unlicensed_ecosystems)


@pytest.mark.parametrize("licenses,patterns,hit", [
    (["GPL-2.0-only WITH Classpath-exception-2.0"], ["GPL-2.0-only"], False),
    (["GPL-2.0-only WITH Classpath-exception-2.0"], ["GPL-2.0*"], True),
    (["(MIT OR (Apache-2.0 AND GPL-3.0-only))"], ["GPL-3.0"], False),
    (["(GPL-3.0-only OR AGPL-3.0-only)"], ["GPL-3.0", "AGPL-3.0"], True),
    (["gpl-3.0-only"], ["GPL-3.0"], True),                 # case-insensitive
    (["LGPL-3.0-only"], ["GPL-3.0"], False),               # not a prefix match
    (["SEE LICENSE IN LICENSE.md"], ["*GPL*"], False),
])
def test_spdx_expressions(licenses, patterns, hit):
    assert bool(verdict(licenses, patterns)) is hit


def test_policy_is_read_from_the_config_block():
    p = policy_from({"licenses": {"deny": ["AGPL-3.0"], "severity": "Critical"}})
    assert p.active and p.deny == ["AGPL-3.0"] and p.severity == "critical"
    assert not policy_from({}).active


@pytest.mark.parametrize("block,fragment", [
    ({"deny": "GPL-3.0"}, "licenses.deny: expected a list"),
    ({"deny": ["GPL-3.0"], "severity": "severe"}, "licenses.severity"),
    ({"denied": ["GPL-3.0"]}, "did you mean 'deny'"),
    ("GPL-3.0", "licenses: expected a mapping"),
])
def test_license_config_errors_are_caught(block, fragment):
    problems = validate({"licenses": block})
    assert len(problems) == 1 and fragment in problems[0]


def test_a_valid_license_block_passes():
    assert validate({"licenses": {"deny": ["AGPL-*"], "warn": ["LGPL-*"],
                                  "severity": "high"}}) == []
