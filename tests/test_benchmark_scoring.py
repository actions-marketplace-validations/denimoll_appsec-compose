"""The benchmark's matching rules decide every number in benchmark/RESULTS.md."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "benchmark"))

import report  # noqa: E402
import scoring  # noqa: E402
import synthetic_secrets  # noqa: E402

CSV = """# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1
BenchmarkTest00001,pathtraver,true,22
BenchmarkTest00002,pathtraver,false,22
BenchmarkTest00003,crypto,true,327
BenchmarkTest00004,crypto,false,327
BenchmarkTest00005,sqli,true,89
"""
TESTDIR = "src/main/java/org/owasp/benchmark/testcode"


def sast(file, *cwes, category="sast"):
    return {"category": category, "file": f"{TESTDIR}/{file}", "cwe": list(cwes)}


def test_expected_results_parse():
    exp = scoring.parse_expected_results(CSV)
    assert exp["BenchmarkTest00001"] == {"category": "pathtraver", "real": True, "cwe": 22}
    assert exp["BenchmarkTest00004"]["real"] is False
    assert len(exp) == 5


def test_benchmark_confusion_matrix_and_score():
    exp = scoring.parse_expected_results(CSV)
    findings = [
        sast("BenchmarkTest00001.java", "CWE-23"),   # relative traversal counts as 22
        sast("BenchmarkTest00002.java", "CWE-22"),   # flagged a safe case -> FP
        sast("BenchmarkTest00003.java", "CWE-326"),  # 326 counts as weak crypto (327)
        sast("BenchmarkTest00005.java", "CWE-79"),   # wrong CWE: SQLi case stays FN
    ]
    r = scoring.score_owasp_benchmark(exp, findings)
    pt, cr, sq = (r["categories"][k] for k in ("pathtraver", "crypto", "sqli"))
    assert (pt["tp"], pt["fp"], pt["fn"], pt["tn"]) == (1, 1, 0, 0)
    assert (cr["tp"], cr["fp"], cr["fn"], cr["tn"]) == (1, 0, 0, 1)
    assert (sq["tp"], sq["fn"]) == (0, 1)
    assert pt["score"] == 0.0 and cr["score"] == 1.0
    assert sq["fpr"] is None and sq["score"] is None   # no false cases in this toy set
    assert r["totals"]["tp"] == 2 and r["totals"]["fp"] == 1


def test_benchmark_ignores_other_files_categories_and_duplicates():
    exp = scoring.parse_expected_results(CSV)
    findings = [
        {"category": "sast", "file": "src/main/java/org/owasp/benchmark/helpers/Utils.java",
         "cwe": ["CWE-22"]},                                  # helper: ignored
        sast("BenchmarkTest00001.java", "CWE-22", category="secrets"),  # not SAST
        sast("BenchmarkTest00003.java", "CWE-327"),
        sast("BenchmarkTest00003.java", "CWE-327"),           # duplicate: one TP
    ]
    r = scoring.score_owasp_benchmark(exp, findings)
    assert r["categories"]["pathtraver"]["tp"] == 0
    assert r["categories"]["crypto"]["tp"] == 1


def test_benchmark_test_name():
    assert scoring.benchmark_test_of(f"{TESTDIR}/BenchmarkTest02740.java") == "BenchmarkTest02740"
    assert scoring.benchmark_test_of(f"{TESTDIR}/BenchmarkTest02740.html") is None
    assert scoring.benchmark_test_of("") is None
    # BenchmarkPython: same names, .py files, same expected-results format.
    assert scoring.benchmark_test_of("testcode/BenchmarkTest01230.py") == "BenchmarkTest01230"
    assert scoring.benchmark_test_of("testcode/BenchmarkTest01230.pyc") is None


def test_benchmark_python_categories_pass_through_unmapped_cwes():
    # Python-only categories (code injection 94, deserialization 502, open
    # redirect 601, XXE 611) are absent from the translation table, so they
    # score on their own CWE — and CWE-95 (eval) does not count as 94, as on
    # the official scorecard.
    exp = scoring.parse_expected_results(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,codeinj,true,94\nBenchmarkTest00002,codeinj,true,94\n"
        "BenchmarkTest00003,deserialization,true,502\n")
    findings = [{"category": "sast", "file": "testcode/BenchmarkTest00001.py", "cwe": ["CWE-94"]},
                {"category": "sast", "file": "testcode/BenchmarkTest00002.py", "cwe": ["CWE-95"]},
                {"category": "sast", "file": "testcode/BenchmarkTest00003.py", "cwe": ["CWE-502"]}]
    r = scoring.score_owasp_benchmark(exp, findings)
    assert (r["categories"]["codeinj"]["tp"], r["categories"]["codeinj"]["fn"]) == (1, 1)
    assert r["categories"]["deserialization"]["tp"] == 1
    # The labelled diagnostic map credits the eval finding; the official one does not.
    lenient = scoring.score_owasp_benchmark(exp, findings, scoring.PYTHON_LENIENT_CWE_MAP)
    assert lenient["categories"]["codeinj"]["tp"] == 2
    assert scoring.BENCHMARK_CWE_MAP.get(95) is None and scoring.BENCHMARK_CWE_MAP[327] == 327


def _cve(cve, line=10, cwes=("CWE-078",), files=("lib/a.js",), fix_elsewhere=False):
    return {"cve": cve, "category": scoring.cve_category(list(cwes)), "cwes": list(cwes),
            "pre": f"{cve}/pre", "post": f"{cve}/post", "files": list(files),
            "weaknesses": [{"file": files[0], "line": line}], "fix_elsewhere": fix_elsewhere}


def _hit(path, line, rule="r1", end=None, cwe=("CWE-78",)):
    return {"category": "sast", "file": path, "line": line, "end_line": end or line,
            "rule_id": rule, "cwe": list(cwe)}


def test_cve_pairs_detection_and_fix_recognition():
    cases = [_cve("CVE-1"), _cve("CVE-2"), _cve("CVE-3"), _cve("CVE-4", fix_elsewhere=True)]
    findings = [
        # CVE-1: on target, gone after the fix -> TP, TN (recognized).
        _hit("CVE-1/pre/lib/a.js", 10),
        # CVE-2: on target, same rule still fires after the fix -> TP, FP.
        _hit("CVE-2/pre/lib/a.js", 10), _hit("CVE-2/post/lib/a.js", 12),
        # CVE-3: right file, wrong line -> FN; its post-patch hit is no FP.
        _hit("CVE-3/pre/lib/a.js", 30), _hit("CVE-3/post/lib/a.js", 30),
        # CVE-4: file unchanged by the fix, so the rule fires on both.
        _hit("CVE-4/pre/lib/a.js", 10), _hit("CVE-4/post/lib/a.js", 10),
        # Not SAST: never counts, even on target.
        {"category": "secrets", "file": "CVE-3/pre/lib/a.js", "line": 10, "rule_id": "s"},
    ]
    r = scoring.score_cve_pairs(cases, findings)
    t = r["totals"]
    assert (t["cves"], t["tp"], t["fn"], t["fp"], t["tn"]) == (4, 3, 1, 2, 2)
    assert t["tpr"] == 0.75 and t["fpr"] == 0.5 and t["score"] == 0.25
    assert t["precision"] == 0.6 and t["fp_fix_elsewhere"] == 1 and t["cwe_matched"] == 3
    assert r["outcome"] == {"CVE-1": "recognized", "CVE-2": "not-recognized",
                            "CVE-3": "missed", "CVE-4": "not-recognized"}
    assert set(r["categories"]) == {"cmdi"}


def test_cve_pairs_recognition_needs_an_on_target_rule_to_drop():
    case = _cve("CVE-1")
    findings = [_hit("CVE-1/pre/lib/a.js", 10, rule="sink"),
                _hit("CVE-1/pre/lib/a.js", 40, rule="noise"),   # off target: not counted
                _hit("CVE-1/post/lib/a.js", 11, rule="sink")]
    assert scoring.score_cve_pairs([case], findings)["outcome"]["CVE-1"] == "not-recognized"
    # Two hits before, one after: the rule fires less often -> recognized.
    findings.append(_hit("CVE-1/pre/lib/a.js", 20, rule="sink"))
    assert scoring.score_cve_pairs([case], findings)["outcome"]["CVE-1"] == "recognized"


def test_cve_pairs_span_match_and_category():
    case = _cve("CVE-1", line=12, cwes=("CWE-079", "CWE-116"))
    multi = [_hit("CVE-1/pre/lib/a.js", 10, end=14, cwe=("CWE-79",))]
    assert scoring.score_cve_pairs([case], multi)["totals"]["tp"] == 0          # official: start line
    span = scoring.score_cve_pairs([case], multi, match="span")["totals"]
    assert span["tp"] == 1 and span["cwe_matched"] == 1
    assert scoring.cve_category(["CWE-400", "CWE-730"]) == "redos"
    assert scoring.cve_category(["CWE-078", "CWE-088"]) == "cmdi"
    assert scoring.cve_category(["CWE-915", "CWE-094"]) == "protopollution"
    assert scoring.cve_category(["CWE-020"]) == "other"
    assert scoring.cve_category([]) == "other"


def test_semgrep_crash_is_detected_despite_successful_sarif(tmp_path):
    import json

    import bench
    native = tmp_path / "native"
    native.mkdir()

    def sarif(*notes):
        (native / "semgrep.sarif").write_text(json.dumps({"runs": [{
            "tool": {"driver": {"rules": []}}, "results": [],
            "invocations": [{"executionSuccessful": True,
                             "toolExecutionNotifications": list(notes)}]}]}))
    killed = {"level": "error", "message": {"text": "Error while running rules: \n"
              "  You are seeing this because the engine was killed.\n"}}
    timeout = {"level": "warning", "message": {"text": "Timeout when running r on f.js"}}
    sarif(timeout)
    assert bench.semgrep_crash(tmp_path) is None
    assert bench.semgrep_notifications(tmp_path) == {"timeouts": 1, "syntax_errors": 0, "other": 0}
    sarif(timeout, killed)
    assert bench.semgrep_crash(tmp_path) == "You are seeing this because the engine was killed."
    assert bench.semgrep_crash(tmp_path / "missing") is None


def test_ossf_corpus_build_pairs_files_and_drops_unfetchable(tmp_path):
    import json

    import ossf_cve
    cves = tmp_path / "CVEs"
    cves.mkdir()

    def record(cve, repo, path):
        (cves / f"{cve}.json").write_text(json.dumps({
            "CVE": cve, "state": "PUBLISHED", "repository": f"https://github.com/{repo}.git",
            "prePatch": {"commit": "a" * 40, "weaknesses": [
                {"location": {"file": path, "line": 3}, "explanation": "x"}]},
            "postPatch": {"commit": "b" * 40}, "CWEs": ["CWE-078"]}))
    record("CVE-1", "o/fixed", "/index.js")          # leading "/" = repo root
    record("CVE-2", "o/same", "lib/a.js")
    record("CVE-3", "o/gone", "lib/a.js")
    bodies = {"o/fixed/" + "a" * 40: b"bad", "o/fixed/" + "b" * 40: b"good",
              "o/same/" + "a" * 40: b"same", "o/same/" + "b" * 40: b"same"}

    class NotFound(Exception):
        code = 404

    def fetch(url):
        owner, repo, commit = url.split("/")[3:6]
        if f"{owner}/{repo}/{commit}" not in bodies:
            raise NotFound(url)
        return bodies[f"{owner}/{repo}/{commit}"]

    files, cases, excluded = ossf_cve.build(cves, tmp_path / "dl", fetch)
    assert files == {"CVE-1/pre/index.js": b"bad", "CVE-1/post/index.js": b"good",
                     "CVE-2/pre/lib/a.js": b"same", "CVE-2/post/lib/a.js": b"same"}
    assert [(c["cve"], c["fix_elsewhere"], c["category"]) for c in cases] == [
        ("CVE-1", False, "cmdi"), ("CVE-2", True, "cmdi")]
    assert [e["cve"] for e in excluded] == ["CVE-3"]

    # Everything is cached now, 404s included: a rebuild asks the network nothing.
    def offline(url):
        raise AssertionError(url)
    assert ossf_cve.build(cves, tmp_path / "dl", offline)[0] == files

    # Anything but a 404 fails the build instead of silently shrinking the corpus.
    record("CVE-4", "o/flaky", "x.js")
    def flaky(url):
        raise RuntimeError("curl: (6) Could not resolve host")
    try:
        ossf_cve.build(cves, tmp_path / "dl", flaky)
    except RuntimeError:
        pass
    else:
        raise AssertionError("a network error must not be cached as a 404")


LABELS = [
    {"file": "a.py", "line_start": 3, "line_end": 3, "label": "secret", "kind": "aws"},
    {"file": "key.pem", "line_start": 1, "line_end": 27, "label": "secret", "kind": "pem"},
    {"file": "a.py", "line_start": 5, "line_end": 5, "label": "secret", "kind": "generic"},
    {"file": "a.py", "line_start": 8, "line_end": 8, "label": "decoy", "kind": "example"},
    {"file": "a.py", "line_start": 9, "line_end": 9, "label": "decoy", "kind": "uuid"},
]


def secret(file, line, *tools):
    return {"category": "secrets", "file": file, "line": line,
            "tool": tools[0], "tools": list(tools)}


def test_secrets_scoring():
    findings = [
        secret("a.py", 3, "gitleaks", "trivy"),
        secret("key.pem", 1, "gitleaks"),       # start of a multi-line span
        secret("a.py", 8, "trufflehog"),        # decoy flagged
        secret("a.py", 12, "gitleaks"),         # unlabelled line
        secret("a.py", 12, "trivy"),            # same line again: one FP
    ]
    r = scoring.score_secrets(LABELS, findings)
    assert (r["tp"], r["fn"], r["fp_decoy"], r["tn"], r["fp_unlabeled"]) == (2, 1, 1, 1, 1)
    assert r["recall"] == round(2 / 3, 4)
    assert r["precision"] == 0.5          # 2 TP vs 1 decoy + 1 unlabelled
    assert r["by_kind"]["pem"] == {"label": "secret", "total": 1, "hit": 1}

    gl = scoring.score_secrets(LABELS, findings, tool="gitleaks")
    assert (gl["tp"], gl["fp_decoy"], gl["fp_unlabeled"]) == (2, 0, 1)
    th = scoring.score_secrets(LABELS, findings, tool="trufflehog")
    assert (th["tp"], th["fp_decoy"]) == (0, 1)


def test_synthetic_corpus_is_deterministic_and_labels_point_at_lines():
    files_a, labels_a = synthetic_secrets.build()
    files_b, labels_b = synthetic_secrets.build()
    assert files_a == files_b and labels_a == labels_b
    assert synthetic_secrets.build(seed=1)[0] != files_a
    for lab in labels_a:
        lines = files_a[lab["file"]].split("\n")
        assert 1 <= lab["line_start"] <= lab["line_end"] <= len(lines)
        assert lines[lab["line_start"] - 1].strip(), lab
    # Default excludes (dist/, build/, vendor/ …) would silently hide a file.
    assert not any(p.split("/")[0] in {"dist", "build", "vendor", "target", "node_modules"}
                   for p in files_a)
    assert {lab["label"] for lab in labels_a} == {"secret", "decoy"}


TRUTH = [
    {"ecosystem": "PyPI", "name": "PyYAML", "version": "5.3.1", "advisories": [
        {"id": "GHSA-8q59-q68h-6hv4", "aliases": ["CVE-2020-14343", "PYSEC-2021-142"]},
        {"id": "PYSEC-2021-142", "aliases": ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"]},
    ]},
    {"ecosystem": "npm", "name": "lodash", "version": "4.17.15", "advisories": [
        {"id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"]},
        {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"]},
    ]},
]


def test_sca_clusters_aliases_and_matches_package():
    findings = [
        # Trivy names the CVE; OSV lists GHSA + PYSEC for it: one vulnerability.
        {"category": "sca", "rule_id": "CVE-2020-14343", "aliases": [],
         "package": "pyyaml@5.3.1"},
        # Right CVE, wrong package: not credited to lodash.
        {"category": "sca", "rule_id": "CVE-2021-23337", "aliases": [],
         "package": "lodash.template@4.5.0"},
        {"category": "sca", "rule_id": "CVE-2099-0001", "aliases": [], "package": "lodash@4.17.15"},
        {"category": "sca", "rule_id": "GHSA-p6mc-m468-83gw", "aliases": [], "package": "lodash@4.17.15"},
    ]
    r = scoring.score_sca(TRUTH, findings)
    assert r["ecosystems"]["PyPI"] == {"packages": 1, "expected": 1, "detected": 1, "recall": 1.0}
    assert r["ecosystems"]["npm"]["detected"] == 1 and r["ecosystems"]["npm"]["expected"] == 2
    assert r["missed"] == ["lodash@4.17.15: CVE-2021-23337"]
    assert "lodash@4.17.15: CVE-2099-0001" in r["outside_truth"]
    assert r["recall"] == round(2 / 3, 4)


def test_sca_package_name_normalization():
    assert scoring.normalize_package("PyPI", "Jinja_2.x") == "jinja-2-x"
    assert scoring.normalize_package("Go", "github.com/Foo/bar") == "github.com/Foo/bar"
    finding = {"category": "sca", "rule_id": "CVE-1", "aliases": [], "package": "@scope/pkg@1.0.0"}
    truth = [{"ecosystem": "npm", "name": "@scope/pkg", "version": "1.0.0",
              "advisories": [{"id": "GHSA-x", "aliases": ["CVE-1"]}]}]
    assert scoring.score_sca(truth, [finding])["detected"] == 1


def test_sca_grype_maven_artifact_name_and_uppercase_alias():
    truth = [{"ecosystem": "Maven", "name": "com.fasterxml.jackson.core:jackson-databind",
              "version": "2.9.8",
              "advisories": [{"id": "GHSA-5ww9-j83m-q7qx", "aliases": ["CVE-2019-12086"]}]}]
    grype = {"category": "sca", "rule_id": "CVE-2099-1", "aliases": ["GHSA-5WW9-J83M-Q7QX"],
             "package": "jackson-databind@2.9.8"}
    assert scoring.score_sca(truth, [grype])["detected"] == 1
    other = {**grype, "package": "jackson-core@2.9.8"}
    assert scoring.score_sca(truth, [other])["detected"] == 0


def test_markdown_section_is_replaced_in_place(tmp_path):
    md = tmp_path / "RESULTS.md"
    md.write_text(f"# Title\n\nhand-written intro\n\n{report.BEGIN}\nold\n{report.END}\n\nhand-written tail\n")
    results = {"generated": "2026-01-01T00:00:00Z", "appsec_compose": "1.2.0",
               "appsec_compose_commit": "abc", "host": {"platform": "x", "docker": "y"},
               "suites": {}}
    report.update_markdown(md, results)
    text = md.read_text()
    assert "old" not in text
    assert text.startswith("# Title\n\nhand-written intro")
    assert text.rstrip().endswith("hand-written tail")
    assert "Generated 2026-01-01T00:00:00Z" in text
