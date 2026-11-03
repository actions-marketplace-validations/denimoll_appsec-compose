import json

import pytest

from coverage import _count_components, analyse


def write(tmp_path, name, body=""):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def sbom(tmp_path, name, data):
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    (reports / name).write_text(json.dumps(data))
    return str(reports)


CDX_EMPTY = {"metadata": {"component": {"name": "/code"}}, "components": []}
CDX_FULL = {"components": [{"name": "flask"}, {"name": "requests"}]}
SPDX_ROOT_ONLY = {
    "packages": [{"SPDXID": "SPDXRef-DocumentRoot-Directory--code", "name": "/code"}],
    "relationships": [{"relationshipType": "DESCRIBES",
                       "relatedSpdxElement": "SPDXRef-DocumentRoot-Directory--code"}],
}


def test_spdx_root_package_is_not_a_dependency():
    """An empty SPDX SBOM still lists the scanned directory — it must not count."""
    assert _count_components(SPDX_ROOT_ONLY) == 0


def test_spdx_counts_real_packages():
    data = dict(SPDX_ROOT_ONLY)
    data["packages"] = SPDX_ROOT_ONLY["packages"] + [{"SPDXID": "SPDXRef-1", "name": "flask"}]
    assert _count_components(data) == 1


def test_cyclonedx_root_lives_in_metadata_and_is_excluded():
    assert _count_components(CDX_EMPTY) == 0
    assert _count_components(CDX_FULL) == 2


def test_unpinned_requirements_are_named_precisely(tmp_path):
    code = tmp_path / "code"
    write(tmp_path, "code/requirements.txt", "requests>=2.31.0\nfastapi>=0.100.0\n")
    reports = sbom(tmp_path, "sbom.trivy.cdx.json", CDX_EMPTY)

    result = analyse(str(code), reports, {"trivy"}, set())
    assert [w.kind for w in result.warnings] == ["sca-unpinned-requirements"]
    assert "requirements.txt" in result.warnings[0].message
    assert "osv" in result.warnings[0].advice
    assert result.sbom_components == 0
    assert result.ecosystems == ["python"]


def test_pinned_requirements_with_components_is_silent(tmp_path):
    code = tmp_path / "code"
    write(tmp_path, "code/requirements.txt", "requests==2.31.0\n")
    reports = sbom(tmp_path, "sbom.trivy.cdx.json", CDX_FULL)
    assert analyse(str(code), reports, {"trivy"}, set()).warnings == []


def test_a_project_with_no_manifests_is_silent(tmp_path):
    code = tmp_path / "code"
    write(tmp_path, "code/app.py", "print(1)")
    reports = sbom(tmp_path, "sbom.trivy.cdx.json", CDX_EMPTY)
    assert analyse(str(code), reports, {"trivy"}, set()).warnings == []


def test_other_ecosystems_get_the_generic_warning(tmp_path):
    code = tmp_path / "code"
    write(tmp_path, "code/go.mod", "module x\n")
    reports = sbom(tmp_path, "sbom.trivy.cdx.json", CDX_EMPTY)
    result = analyse(str(code), reports, {"trivy"}, set())
    assert [w.kind for w in result.warnings] == ["sca-no-components"]
    assert "go" in result.warnings[0].message


def test_excluded_directories_are_not_walked(tmp_path):
    code = tmp_path / "code"
    write(tmp_path, "code/node_modules/dep/package.json", "{}")
    reports = sbom(tmp_path, "sbom.trivy.cdx.json", CDX_EMPTY)
    assert analyse(str(code), reports, {"trivy"}, {"node_modules"}).manifests == []


def test_no_sca_engine_enabled_means_no_opinion(tmp_path):
    code = tmp_path / "code"
    write(tmp_path, "code/requirements.txt", "requests>=2.31.0\n")
    reports = sbom(tmp_path, "sbom.trivy.cdx.json", CDX_EMPTY)
    assert analyse(str(code), reports, {"semgrep"}, set()).warnings == []


def test_image_mode_is_skipped(tmp_path):
    code = tmp_path / "code"
    write(tmp_path, "code/requirements.txt", "requests>=2.31.0\n")
    reports = sbom(tmp_path, "sbom.trivy.cdx.json", CDX_EMPTY)
    assert analyse(str(code), reports, {"trivy"}, set(), image_mode=True).warnings == []


def test_sbom_off_with_no_lockfile_is_flagged_as_unverifiable(tmp_path):
    code = tmp_path / "code"
    write(tmp_path, "code/requirements.txt", "requests>=2.31.0\n")
    (tmp_path / "reports").mkdir()
    result = analyse(str(code), str(tmp_path / "reports"), {"trivy"}, set())
    assert [w.kind for w in result.warnings] == ["sca-unverifiable"]


def test_a_lockfile_makes_a_missing_sbom_acceptable(tmp_path):
    code = tmp_path / "code"
    write(tmp_path, "code/requirements.txt", "requests>=2.31.0\n")
    write(tmp_path, "code/poetry.lock", "")
    (tmp_path / "reports").mkdir()
    assert analyse(str(code), str(tmp_path / "reports"), {"trivy"}, set()).warnings == []


@pytest.mark.parametrize("body,flagged", [
    ("requests==2.31.0\n", False),
    ("requests>=2.31.0\n", True),
    ("requests~=2.31.0\n", True),
    ("requests\n", True),
    ("# comment\n-r other.txt\n", False),          # no requirement lines at all
    ("requests>=2.31.0\nflask==1.0\n", False),     # mixed: some are resolvable
])
def test_requirements_pinning_detection(tmp_path, body, flagged):
    code = tmp_path / "code"
    write(tmp_path, "code/requirements.txt", body)
    reports = sbom(tmp_path, "sbom.trivy.cdx.json", CDX_EMPTY)
    kinds = [w.kind for w in analyse(str(code), reports, {"trivy"}, set()).warnings]
    assert ("sca-unpinned-requirements" in kinds) is flagged


def test_sca_findings_prove_coverage_even_with_an_empty_sbom(tmp_path):
    """OSV reports on ranges that Trivy/Syft cannot express as SBOM components."""
    code = tmp_path / "code"
    write(tmp_path, "code/requirements.txt", "requests>=2.31.0\n")
    reports = sbom(tmp_path, "sbom.trivy.cdx.json", CDX_EMPTY)
    result = analyse(str(code), reports, {"trivy", "osv"}, set(), sca_findings=2)
    assert result.warnings == []


def test_unpinned_advice_only_offers_osv_and_only_once(tmp_path):
    """Grype shares Syft's exact-version requirement, so it is not an answer here."""
    code = tmp_path / "code"
    write(tmp_path, "code/requirements.txt", "requests>=2.31.0\n")
    reports = sbom(tmp_path, "sbom.trivy.cdx.json", CDX_EMPTY)

    without_osv = analyse(str(code), reports, {"trivy"}, set()).warnings[0].advice
    assert "`osv`" in without_osv and "`grype`" not in without_osv

    with_osv = analyse(str(code), reports, {"trivy", "osv"}, set()).warnings[0].advice
    assert "enable" not in with_osv          # nothing left to suggest
    assert "Pin the versions" in with_osv and "lock file" in with_osv


def test_generic_advice_never_recommends_an_engine_already_enabled(tmp_path):
    code = tmp_path / "code"
    write(tmp_path, "code/go.mod", "module x\n")
    reports = sbom(tmp_path, "sbom.trivy.cdx.json", CDX_EMPTY)

    assert "`osv`" in analyse(str(code), reports, {"trivy"}, set()).warnings[0].advice
    with_osv = analyse(str(code), reports, {"trivy", "osv"}, set()).warnings[0].advice
    assert "`grype`" in with_osv and "`osv`" not in with_osv
    with_all = analyse(str(code), reports, {"trivy", "osv", "grype"}, set())
    assert "enable the" not in with_all.warnings[0].advice


def test_manifests_are_listed_even_when_sca_found_something(tmp_path):
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "composer.json").write_text("{}")
    (tmp_path / "api" / "composer.lock").write_text("{}")
    cov = analyse(str(tmp_path), str(tmp_path), {"trivy"}, set(), sca_findings=1)
    assert cov.manifests == ["api/composer.json"] and cov.ecosystems == ["php"]
    assert cov.warnings == []              # findings prove the manifests were read


def test_findings_silence_the_unverifiable_warning_too(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==1.0\n")
    assert analyse(str(tmp_path), str(tmp_path), {"trivy"}, set(), sca_findings=2).warnings == []
