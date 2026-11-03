"""Score an appsec-compose findings.json against a corpus' ground truth.

Pure functions only — no I/O beyond what the caller hands in — so the matching
rules that decide every number in RESULTS.md are unit-tested
(tests/test_benchmark_scoring.py) rather than trusted.

Four scorers, one per corpus kind:

- `score_owasp_benchmark` — SAST, against OWASP Benchmark's
  expectedresults-*.csv (per test case: category, real vulnerability, CWE);
  the Java and the Python Benchmark share the format and the scorer.
- `score_cve_pairs`       — SAST, against real CVEs given as a vulnerable
  (pre-patch) and a fixed (post-patch) version of the same file, with the
  vulnerable line labelled (OpenSSF CVE Benchmark, JavaScript/TypeScript).
- `score_secrets`         — secrets, against line-labelled true secrets and
  decoys.
- `score_sca`             — SCA, against the advisories OSV lists for each
  pinned package@version.
"""
from __future__ import annotations

import csv
import io
import re
from collections import Counter, defaultdict
from pathlib import PurePosixPath

# ---------------------------------------------------------------------------
# SAST — OWASP Benchmark
# ---------------------------------------------------------------------------

# CWE -> the Benchmark CWE it counts as. Copied from the official scorer's
# Semgrep reader (OWASP-Benchmark/BenchmarkUtils, SemgrepReader.translate, at
# the commit pinned in corpora.json), so a Semgrep finding counts here exactly
# when it would count on the official scorecard. CWEs not listed map to
# themselves; one that matches no Benchmark category simply never scores.
BENCHMARK_CWE_MAP = {
    22: 22, 23: 22, 35: 22,                 # path traversal
    78: 78,                                 # command injection
    79: 79, 80: 79,                         # XSS
    89: 89,                                 # SQL injection
    90: 90,                                 # LDAP injection
    326: 327, 327: 327, 329: 327, 696: 327,  # weak crypto
    328: 328,                               # weak hash
    330: 330, 338: 330,                     # weak randomness
    501: 501,                               # trust boundary
    614: 614,                               # insecure cookie
    643: 643,                               # XPath injection
}

# NOT the official rule — a diagnostic for BenchmarkPython only. Semgrep's
# Python rules tag `eval`/`exec` CWE-95 and weak hashes (md5/sha1) CWE-327, so
# under the official table they can never score in the code-injection (94) or
# weak-hash (328) categories, however right the finding is. Scoring once more
# with these two equivalences separates "Semgrep did not see it" from "Semgrep
# saw it under a neighbouring CWE". (327 -> 328 is safe here only because the
# Python Benchmark has no weak-cipher category for it to steal from.)
PYTHON_LENIENT_CWE_MAP = {**BENCHMARK_CWE_MAP, 95: 94, 327: 328}

# BenchmarkJava names its test cases BenchmarkTestNNNNN.java, BenchmarkPython
# BenchmarkTestNNNNN.py; both expected-results files key on the bare name.
_TEST_NAME = re.compile(r"^(BenchmarkTest\d+)\.(?:java|py)$")


def parse_expected_results(text: str) -> dict[str, dict]:
    """Parse expectedresults-*.csv: `# test name, category, real vulnerability, cwe`."""
    expected: dict[str, dict] = {}
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].lstrip().startswith("#"):
            continue
        name, category, real, cwe = (c.strip() for c in row[:4])
        expected[name] = {"category": category, "real": real.lower() == "true",
                          "cwe": int(cwe)}
    return expected


def benchmark_test_of(path: str) -> str | None:
    """`.../testcode/BenchmarkTest00042.java` (or `.py`) -> `BenchmarkTest00042`."""
    m = _TEST_NAME.match(PurePosixPath(path or "").name)
    return m.group(1) if m else None


def _cwe_number(cwe: str) -> int | None:
    m = re.match(r"^CWE-(\d+)$", str(cwe).strip(), re.IGNORECASE)
    return int(m.group(1)) if m else None


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def score_owasp_benchmark(expected: dict[str, dict], findings: list[dict],
                          cwe_map: dict[int, int] = BENCHMARK_CWE_MAP) -> dict:
    """Per-category TP/FP/FN/TN, TPR, FPR and the Benchmark score (TPR - FPR).

    Matching rule (the same one the official scorer applies): a test case is
    *flagged* when at least one SAST finding is located in its own source file
    (`BenchmarkTestNNNNN.java`) and carries a CWE that maps to the test case's
    CWE. Then:

        real vulnerability + flagged  -> TP     not real + flagged  -> FP
        real vulnerability + silent   -> FN     not real + silent   -> TN

    Findings in any other file (helpers, HTML, build files) are ignored, as is
    a finding in a test file whose CWE belongs to a different category.
    """
    flagged: dict[str, set[int]] = defaultdict(set)
    for f in findings:
        if f.get("category") != "sast":
            continue
        test = benchmark_test_of(f.get("file", ""))
        if test is None or test not in expected:
            continue
        for raw in f.get("cwe") or []:
            n = _cwe_number(raw)
            if n is not None:
                flagged[test].add(cwe_map.get(n, n))

    per_cat: dict[str, dict] = {}
    for name, case in expected.items():
        c = per_cat.setdefault(case["category"], {"cwe": case["cwe"], "tp": 0, "fp": 0,
                                                  "fn": 0, "tn": 0})
        hit = case["cwe"] in flagged.get(name, ())
        key = ("tp" if hit else "fn") if case["real"] else ("fp" if hit else "tn")
        c[key] += 1

    for c in per_cat.values():
        c["tpr"] = _ratio(c["tp"], c["tp"] + c["fn"])
        c["fpr"] = _ratio(c["fp"], c["fp"] + c["tn"])
        c["score"] = (round(c["tpr"] - c["fpr"], 4)
                      if c["tpr"] is not None and c["fpr"] is not None else None)

    cats = sorted(per_cat)
    # The Benchmark scorecard's headline is the unweighted mean over categories
    # (a category with no real or no fake cases has no rate and is left out).
    def mean(key: str) -> float | None:
        vals = [per_cat[k][key] for k in cats if per_cat[k][key] is not None]
        return round(sum(vals) / len(vals), 4) if vals else None

    totals = {k: sum(per_cat[c][k] for c in cats) for k in ("tp", "fp", "fn", "tn")}
    return {
        "categories": {k: per_cat[k] for k in cats},
        "average": {"tpr": mean("tpr"), "fpr": mean("fpr"), "score": mean("score")},
        "totals": {**totals,
                   "tpr": _ratio(totals["tp"], totals["tp"] + totals["fn"]),
                   "fpr": _ratio(totals["fp"], totals["fp"] + totals["tn"]),
                   "precision": _ratio(totals["tp"], totals["tp"] + totals["fp"])},
        "test_cases": len(expected),
    }


# ---------------------------------------------------------------------------
# SAST — real CVEs as vulnerable/fixed pairs (OpenSSF CVE Benchmark)
# ---------------------------------------------------------------------------

# A CVE lists several CWEs (CWE-079 + CWE-116, CWE-400 + CWE-730, ...); the
# category is the most specific class among them, tried in this order, so
# every CVE lands in exactly one row of the per-category table.
CVE_CATEGORIES = [
    ("protopollution", {915, 1321}),
    ("cmdi", {77, 78, 88}),
    ("codeinj", {94, 95}),
    ("sqli", {89}),
    ("ssrf", {918}),
    ("pathtraver", {22, 23, 35, 36, 73, 99}),
    ("redirect", {601}),
    ("xss", {79, 80, 116}),
    ("redos", {400, 730, 1333}),
]


def cve_category(cwes) -> str:
    nums = {n for n in (_cwe_number(c) if isinstance(c, str) else c for c in cwes)
            if n is not None}
    for name, members in CVE_CATEGORIES:
        if nums & members:
            return name
    return "other"


def _on_target(f: dict, targets: set[tuple[str, int]], match: str) -> bool:
    line = f.get("line")
    if line is None:
        return False
    if match == "line":
        return (f.get("file"), line) in targets
    end = f.get("end_line") or line
    return any(f.get("file") == path and line <= t <= end for path, t in targets)


def score_cve_pairs(cases: list[dict], findings: list[dict], match: str = "line") -> dict:
    """Detection on the vulnerable version, recognition of the fix.

    A case is one CVE: `{cve, category, cwes, pre, post, files, weaknesses}`.
    `pre`/`post` are the corpus directories holding the pre-patch and the
    post-patch copy of the same `files`; `weaknesses` are `{file, line}` in the
    pre-patch copy. The rule is the OpenSSF CVE Benchmark's own:

    - *detected*   — a SAST finding starts exactly on a weakness line
      (`match="span"`: the weakness line lies inside the finding's span);
      the rules of those findings are the case's *on-target rules*;
    - *recognized* — at least one on-target rule fires fewer times on the
      post-patch files than on the pre-patch ones.

    As a confusion matrix, each CVE is one real case (the vulnerable version)
    and one safe look-alike (its fix):

        detected                 -> TP      missed               -> FN
        detected, not recognized -> FP      otherwise            -> TN

    so TPR = detected / CVEs, FPR = fixes still flagged / CVEs and the score
    TPR - FPR = fixes recognized / CVEs. The CWE is *not* part of the rule
    (it is not in OpenSSF's either); `cwe_matched` counts detections where an
    on-target finding also names one of the CVE's CWEs.
    """
    sast = [f for f in findings if f.get("category") == "sast"]
    by_file: dict[str, list[dict]] = defaultdict(list)
    for f in sast:
        by_file[f.get("file", "")].append(f)

    per_cat: dict[str, dict] = {}
    outcome: dict[str, str] = {}
    for case in cases:
        pre = [f"{case['pre']}/{p}" for p in case["files"]]
        post = [f"{case['post']}/{p}" for p in case["files"]]
        targets = {(f"{case['pre']}/{w['file']}", w["line"]) for w in case["weaknesses"]}
        hits = [f for p in pre for f in by_file.get(p, []) if _on_target(f, targets, match)]
        rules = {f.get("rule_id") for f in hits}
        before = Counter(f.get("rule_id") for p in pre for f in by_file.get(p, []))
        after = Counter(f.get("rule_id") for p in post for f in by_file.get(p, []))
        detected = bool(rules)
        recognized = detected and any(after[r] < before[r] for r in rules)
        want = {cve_n for cve_n in (_cwe_number(c) for c in case["cwes"]) if cve_n}
        cwe_hit = any(_cwe_number(c) in want for f in hits for c in (f.get("cwe") or []))

        c = per_cat.setdefault(case["category"], {"cves": 0, "tp": 0, "fn": 0, "fp": 0,
                                                  "tn": 0, "cwe_matched": 0,
                                                  "fp_fix_elsewhere": 0, "file_flagged": 0})
        c["cves"] += 1
        # Diagnostic, not a detection: the vulnerable file has *some* finding,
        # on any line, of any rule — the ceiling of a file-level rule.
        c["file_flagged"] += int(any(by_file.get(p) for p in pre))
        c["tp" if detected else "fn"] += 1
        c["fp" if detected and not recognized else "tn"] += 1
        c["cwe_matched"] += int(cwe_hit)
        # An FP the corpus forces: the labelled file is byte-identical after the fix.
        c["fp_fix_elsewhere"] += int(detected and not recognized and bool(case.get("fix_elsewhere")))
        outcome[case["cve"]] = ("recognized" if recognized else
                                "not-recognized" if detected else "missed")

    def rates(c: dict) -> dict:
        tpr, fpr = _ratio(c["tp"], c["cves"]), _ratio(c["fp"], c["cves"])
        return {**c, "tpr": tpr, "fpr": fpr,
                "score": round(tpr - fpr, 4) if tpr is not None else None,
                "precision": _ratio(c["tp"], c["tp"] + c["fp"])}

    cats = {k: rates(per_cat[k]) for k in sorted(per_cat)}
    totals = rates({k: sum(c[k] for c in per_cat.values())
                    for k in ("cves", "tp", "fn", "fp", "tn", "cwe_matched", "fp_fix_elsewhere",
                              "file_flagged")})
    return {"categories": cats, "totals": totals, "match": match,
            "test_cases": len(cases), "outcome": dict(sorted(outcome.items()))}


# ---------------------------------------------------------------------------
# Secrets — line-labelled corpus
# ---------------------------------------------------------------------------

def _label_hit(label: dict, f: dict) -> bool:
    line = f.get("line")
    return (f.get("file") == label["file"] and line is not None
            and label["line_start"] <= line <= label["line_end"])


def score_secrets(labels: list[dict], findings: list[dict],
                  tool: str | None = None, category: str = "secrets") -> dict:
    """Recall over true secrets, precision over everything flagged.

    A label is `{file, line_start, line_end, kind, label: "secret"|"decoy"}`.
    A finding hits a label when it is in the same file and its start line falls
    inside the label's line span (a PEM key spans several lines). Then:

        secret hit -> TP     secret missed -> FN
        decoy  hit -> FP     decoy  missed -> TN

    Flagged lines that carry no label at all are counted as `fp_unlabeled`
    (distinct file:line) and are part of precision: the corpus is built so that
    every line not labelled is ordinary code. Several findings on one label
    count once. `tool` restricts to findings that engine reported (a merged
    finding lists every engine in `tools`).
    """
    picked = [f for f in findings
              if f.get("category") == category
              and (tool is None or tool in (f.get("tools") or [f.get("tool")]))]

    hit_labels: set[int] = set()
    unlabeled: set[tuple[str, int | None]] = set()
    for f in picked:
        matched = [i for i, lab in enumerate(labels) if _label_hit(lab, f)]
        if matched:
            hit_labels.update(matched)
        else:
            unlabeled.add((f.get("file", ""), f.get("line")))

    by_kind: dict[str, dict] = {}
    tp = fn = fp = tn = 0
    for i, lab in enumerate(labels):
        hit = i in hit_labels
        k = by_kind.setdefault(lab["kind"], {"label": lab["label"], "total": 0, "hit": 0})
        k["total"] += 1
        k["hit"] += int(hit)
        if lab["label"] == "secret":
            tp, fn = tp + hit, fn + (not hit)
        else:
            fp, tn = fp + hit, tn + (not hit)

    flagged_fp = fp + len(unlabeled)
    return {
        "tp": tp, "fn": fn, "fp_decoy": fp, "tn": tn,
        "fp_unlabeled": len(unlabeled),
        "recall": _ratio(tp, tp + fn),
        "precision": _ratio(tp, tp + flagged_fp),
        "decoy_fpr": _ratio(fp, fp + tn),
        "findings": len(picked),
        "by_kind": dict(sorted(by_kind.items())),
        "unlabeled": sorted(f"{p}:{n}" for p, n in unlabeled),
    }


# ---------------------------------------------------------------------------
# SCA — advisories per pinned package
# ---------------------------------------------------------------------------

def normalize_package(ecosystem: str, name: str) -> str:
    """Compare package names the way each ecosystem does (PEP 503 for PyPI)."""
    name = name.strip()
    if ecosystem.lower() == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem.lower() in ("npm", "rubygems", "maven"):
        return name.lower()
    return name


def _same_package(eco: str, truth_name: str, found: str) -> bool:
    want, got = normalize_package(eco, truth_name), normalize_package(eco, found)
    if want == got:
        return True
    # Grype names a Maven package by artifactId alone ("jackson-databind"),
    # Trivy and OSV by group:artifact; the artifactId is what both share.
    return eco.lower() == "maven" and ":" not in got and want.rsplit(":", 1)[-1] == got


def _finding_package_name(f: dict) -> str | None:
    pkg = f.get("package")
    if not pkg:
        return None
    # "name@version"; npm scopes start with "@", so split on the last "@".
    return pkg.rsplit("@", 1)[0] if "@" in pkg[1:] else pkg


def cluster_advisories(advisories: list[dict]) -> list[set[str]]:
    """Merge advisories that alias each other into one vulnerability.

    OSV lists one vulnerability several times (GHSA-…, PYSEC-…, CVE-… as
    aliases), and a scanner reports it under any one of those ids. Recall is
    counted per vulnerability, not per id, or a duplicate would count twice.
    """
    clusters: list[set[str]] = []
    for adv in advisories:
        ids = {i.upper() for i in (adv["id"], *adv.get("aliases", []))}
        merged = [c for c in clusters if c & ids]
        for c in merged:
            clusters.remove(c)
            ids |= c
        clusters.append(ids)
    return clusters


def score_sca(truth: list[dict], findings: list[dict]) -> dict:
    """Recall of the expected advisories, per ecosystem.

    `truth` is one entry per pinned package: `{ecosystem, name, version,
    advisories: [{id, aliases}]}`. An expected vulnerability (an alias cluster)
    is *detected* when an SCA finding names one of its ids — as `rule_id` or
    in `aliases` — and, when the finding names a package, it is this package.

    Precision is not computed: a finding outside the OSV snapshot is not
    necessarily wrong (the engines' databases are newer, older or broader than
    the snapshot). Those are reported as `outside_truth` for inspection.
    """
    sca = [f for f in findings if f.get("category") == "sca"]
    per_eco: dict[str, dict] = {}
    missed: list[str] = []
    claimed: set[int] = set()

    for pkg in truth:
        eco = pkg["ecosystem"]
        e = per_eco.setdefault(eco, {"packages": 0, "expected": 0, "detected": 0})
        e["packages"] += 1
        for cluster in cluster_advisories(pkg["advisories"]):
            e["expected"] += 1
            hit = False
            for i, f in enumerate(sca):
                # Ids compare case-insensitively: Grype upper-cases GHSA aliases.
                ids = {i.upper() for i in (f.get("rule_id", ""), *(f.get("aliases") or []))}
                if not ids & cluster:
                    continue
                name = _finding_package_name(f)
                if name is not None and not _same_package(eco, pkg["name"], name):
                    continue
                hit = True
                claimed.add(i)
            if hit:
                e["detected"] += 1
            else:
                missed.append(f"{pkg['name']}@{pkg['version']}: {min(cluster)}")

    for e in per_eco.values():
        e["recall"] = _ratio(e["detected"], e["expected"])
    exp = sum(e["expected"] for e in per_eco.values())
    det = sum(e["detected"] for e in per_eco.values())
    outside = sorted({f"{f.get('package') or f.get('file')}: {f.get('rule_id')}"
                      for i, f in enumerate(sca) if i not in claimed})
    return {
        "ecosystems": dict(sorted(per_eco.items())),
        "expected": exp, "detected": det, "recall": _ratio(det, exp),
        "missed": missed, "outside_truth": outside,
        "findings": len(sca),
    }
