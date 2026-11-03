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
