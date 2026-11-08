import json

from datetime import date

import pytest

import baseline as bl
from normalize import Finding
from suppress import apply


def f(**kw):
    base = dict(tool="trivy", category="sca", rule_id="CVE-1", severity="high",
                message="m", file="app.py", line=1, package="flask@1.0")
    base.update(kw)
    return Finding(**base)


def test_rule_glob_matches_aliases_too():
    finding = f(rule_id="GHSA-xxxx", aliases=["CVE-2018-1000656"])
    kept, suppressed, _ = apply([finding], [{"rule": "CVE-2018-1000656",
                                          "reason": "accepted"}])
    assert kept == [] and suppressed[0].reason == "accepted"


def test_all_present_fields_must_match():
    entry = [{"rule": "CVE-1", "category": "secrets", "reason": "r"}]
    kept, suppressed, _ = apply([f()], entry)      # category differs
    assert len(kept) == 1 and suppressed == []


def test_file_glob():
    kept, _, _ = apply([f(file="tests/fixture.py")], [{"file": "tests/*", "reason": "r"}])
    assert kept == []


def test_empty_entry_never_matches_everything():
    kept, suppressed, _ = apply([f()], [{"reason": "oops"}])
    assert len(kept) == 1 and suppressed == []


def test_no_rules_is_a_passthrough():
    kept, suppressed, _ = apply([f()], [])
    assert len(kept) == 1 and suppressed == []


def fp(finding, code_dir=None):
    bl.assign([finding], code_dir)
    return finding.fingerprint


def _repo(root, name, text):
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(text)
    return str(root)


def test_fingerprint_is_tool_independent():
    assert fp(f(tool="trivy")) == fp(f(tool="grype"))


def test_fingerprint_ignores_the_code_mount_prefix():
    assert fp(f(file="/code/app.py")) == fp(f(file="app.py"))


def test_sast_fingerprint_survives_the_code_moving_down(tmp_path):
    before = _repo(tmp_path / "a",
                   "app.py", "import os\nos.system(cmd)\n")
    after = _repo(tmp_path / "b",
                  "app.py", "import os\n\n# new comment\nos.system(cmd)\n")
    sast = dict(tool="semgrep", category="sast", rule_id="py.exec", package=None)
    assert fp(f(**sast, line=2), before) == fp(f(**sast, line=4), after)


def test_sast_fingerprint_changes_when_the_flagged_code_changes(tmp_path):
    repo = _repo(tmp_path, "app.py", "os.system(a)\nos.system(b)\n")
    sast = dict(tool="semgrep", category="sast", rule_id="py.exec", package=None)
    assert fp(f(**sast, line=1), repo) != fp(f(**sast, line=2), repo)


def test_identical_lines_get_distinct_fingerprints(tmp_path):
    repo = _repo(tmp_path, "app.py", "eval(x)\neval(x)\n")
    sast = dict(tool="semgrep", category="sast", rule_id="py.eval", package=None)
    pair = [f(**sast, line=1), f(**sast, line=2)]
    bl.assign(pair, repo)
    assert pair[0].fingerprint != pair[1].fingerprint


def test_unreadable_source_falls_back_to_the_line_number():
    sast = dict(tool="semgrep", category="sast", rule_id="r", package=None)
    assert fp(f(**sast, line=1)) != fp(f(**sast, line=2))


def test_sca_fingerprint_ignores_version_and_alias_set():
    a = f(rule_id="GHSA-x", aliases=["CVE-1"], package="flask@1.0", line=None)
    b = f(rule_id="CVE-1", aliases=[], package="flask@1.1", line=None)
    assert fp(a) == fp(b)
    assert fp(f(package="@scope/pkg@1.0")) != fp(f(package="@other/pkg@1.0"))


def test_secret_value_never_shapes_the_fingerprint(tmp_path):
    a = _repo(tmp_path / "a",
              "cfg.py", 'TOKEN = "hunter2"\n')
    b = _repo(tmp_path / "b",
              "cfg.py", '\nTOKEN = "s3cr3t-rotated-value"\n')
    secret = dict(category="secrets", package=None, file="cfg.py")
    assert (fp(f(**secret, tool="gitleaks", rule_id="generic", line=1), a)
            == fp(f(**secret, tool="trufflehog", rule_id="th.x", line=2), b))


def test_secret_span_is_masked_when_the_engine_gives_one(tmp_path):
    repo = _repo(tmp_path, "cfg.py", "key=AKIAABCD x\n")
    finding = f(category="secrets", package=None, file="cfg.py", line=1,
                column=5, end_column=13)
    other = _repo(tmp_path / "o",
                  "cfg.py", "key=AKIAZZZZ x\n")
    assert fp(finding, repo) == fp(f(**{**vars(finding), "fingerprint": ""}), other)


def test_source_reads_stay_inside_the_repo(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "link.txt").symlink_to(outside)
    assert bl._Source(str(repo)).line("link.txt", 1) is None


def test_classify_splits_new_known_and_counts_fixed():
    known, new = f(rule_id="CVE-1"), f(rule_id="CVE-2")
    bl.assign([known, new])
    accepted = bl.Baseline({known.fingerprint, "stale-fingerprint"})
    delta = bl.classify([known, new], accepted)
    assert delta.known == [known] and delta.new == [new] and delta.fixed == 1
    assert not delta.legacy


def test_a_v1_baseline_is_matched_with_v1_fingerprints():
    known, new = f(rule_id="CVE-1"), f(rule_id="CVE-2")
    bl.assign([known, new])
    legacy = bl.Baseline({bl.legacy_fingerprint(known)}, version=1)
    delta = bl.classify([known, new], legacy)
    assert delta.known == [known] and delta.new == [new] and delta.legacy


def test_a_versionless_file_loads_as_v1(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text('{"fingerprints": ["abc"]}')
    assert bl.load(str(path)) == bl.Baseline({"abc"}, version=1)


def test_save_then_load_roundtrips(tmp_path):
    path = str(tmp_path / "baseline.json")
    a, b = f(), f(line=None)
    bl.assign([a])
    bl.assign([b])
    assert bl.save(path, [a, b]) == 1          # same finding twice dedupes
    loaded = bl.load(path)
    assert loaded.fingerprints == {a.fingerprint}
    assert loaded.entries[a.fingerprint]["rule_id"] == a.rule_id     # 1.6: what it was
    assert json.loads(open(path).read())["version"] == bl.FINGERPRINT_VERSION


def test_load_tolerates_a_missing_or_corrupt_baseline(tmp_path):
    assert bl.load(str(tmp_path / "nope.json")).fingerprints == set()
    corrupt = tmp_path / "bad.json"
    corrupt.write_text("{oops")
    assert bl.load(str(corrupt)).fingerprints == set()


def test_an_ignore_entry_can_name_one_finding_by_fingerprint():
    a, b = f(rule_id="CVE-1"), f(rule_id="CVE-2")
    bl.assign([a, b])
    kept, suppressed, _ = apply([a, b], [{"fingerprint": a.fingerprint,
                                          "reason": "triaged: false positive"}])
    assert kept == [b] and suppressed[0].finding is a


# --- suppression expiry ---------------------------------------------------

def _entry(expires):
    return [{"rule": "CVE-1", "reason": "accepted for now", "expires": expires}]


def test_an_unexpired_entry_still_suppresses():
    kept, suppressed, expired = apply([f()], _entry("2099-01-01"),
                                      today=date(2026, 8, 23))
    assert kept == [] and len(suppressed) == 1 and expired == []


def test_an_expired_entry_stops_suppressing_and_is_reported():
    kept, suppressed, expired = apply([f()], _entry("2026-01-01"),
                                      today=date(2026, 8, 23))
    assert len(kept) == 1 and suppressed == []
    assert [e.expires for e in expired] == ["2026-01-01"]
    assert "rule=CVE-1" in expired[0].label


def test_expiry_is_inclusive_of_its_last_day():
    kept, _, expired = apply([f()], _entry("2026-08-23"), today=date(2026, 8, 23))
    assert kept == [] and expired == []


def test_yaml_may_hand_us_a_real_date_object():
    kept, _, expired = apply([f()], _entry(date(2026, 1, 1)), today=date(2026, 8, 23))
    assert len(kept) == 1 and len(expired) == 1


def test_a_malformed_expiry_is_rejected_loudly():
    with pytest.raises(ValueError, match="expected YYYY-MM-DD"):
        apply([f()], _entry("soon"), today=date(2026, 8, 23))


def test_entries_without_an_expiry_are_unaffected():
    kept, suppressed, expired = apply([f()], [{"rule": "CVE-1", "reason": "r"}],
                                      today=date(2026, 8, 23))
    assert kept == [] and len(suppressed) == 1 and expired == []


def test_hidden_directories_are_read_for_content(tmp_path):
    _repo(tmp_path / ".github", "ci.yml", "uses: a@v1\n")
    assert bl._Source(str(tmp_path)).line("/code/.github/ci.yml", 1) == "uses: a@v1"


def test_legacy_fingerprint_keeps_its_v1_path_shape():
    # v1 baselines were written with the dot of ".github" stripped.
    assert (bl.legacy_fingerprint(f(file=".github/ci.yml"))
            == bl.legacy_fingerprint(f(file="github/ci.yml")))
