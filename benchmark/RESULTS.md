# appsec-compose benchmark

What the default scan catches, what it misses, and how often it cries wolf —
measured on corpora with known answers, so the numbers can be checked rather
than believed. If appsec-compose is the first step of a security review (by a
person or an AI agent), the reviewer needs to know which classes of problem it
has already covered and which it has not even looked at. This page is that
answer, including the parts that do not flatter the tool.

Machine-readable: [`results.json`](results.json). Harness: [`bench.py`](bench.py).

## Reproduce

```bash
python3 benchmark/bench.py                    # all suites, all profiles
python3 benchmark/bench.py --profile default  # only the shipped defaults
python3 benchmark/bench.py --suite sast       # one suite: sast (Java), sast-python,
                                              # sast-js, secrets, sca
python3 benchmark/bench.py --rescore          # re-score the last run, no scan
python3 benchmark/bench.py --refresh-sca-truth  # re-snapshot OSV (changes the truth!)
```

Needs what `run.sh` needs (Docker, Python 3.9+, PyYAML) plus network access.
Corpora and run reports go to `~/.cache/appsec-compose-bench` (override with
`--cache` or `APPSEC_BENCH_CACHE`) — never into the repository: they hold
deliberately vulnerable code and credential-shaped strings, which this repo's
own scan would (rightly) fail on. Each scan runs through the real `./run.sh`
with `--name bench-<suite>-<profile>`, and the `appsec-bench-*` collector
images are removed afterwards (`--keep-images` keeps them).

The scan config is derived at run time from the shipped `scan-config.yml`:
same engine versions, same defaults, narrowed to the engines a suite measures,
report-only (`fail_on: none`), no suppressions, no baseline, no enrichment.
"Default" always means the engine set and rules a fresh clone runs; anything
else is labelled opt-in.

## Methodology

### SAST — OWASP Benchmark for Java

[OWASP Benchmark](https://owasp.org/www-project-benchmark/) 1.2 is 2,740 small
servlets, each either a real vulnerability or a deliberately safe look-alike
(sanitised input, dead branch, constant data), labelled in
`expectedresults-1.2.csv` with category and CWE. It is the standard yardstick
for Java SAST and was built to punish both silence and noise.

**Matching rule.** A test case is *flagged* when a SAST finding lies in its own
file (`BenchmarkTestNNNNN.java`) and carries a CWE that maps to the case's CWE.
Real + flagged = TP, real + silent = FN, safe + flagged = FP, safe + silent =
TN. The CWE equivalences (e.g. CWE-23 → 22, CWE-326 → 327, CWE-338 → 330) are
copied from the official scorer's Semgrep reader (BenchmarkUtils
`SemgrepReader.translate`, pinned commit in [`corpora.json`](corpora.json)), so a
finding counts here exactly when it would on the official scorecard. Our
findings carry `cwe` parsed from Semgrep's rule tags.

**Score.** Per category: TPR (recall), FPR, and the Benchmark score TPR − FPR
(0 = no better than guessing, 100 = perfect). The headline is the unweighted
mean over the 11 categories, as on the official scorecard.

**Limits of the rule.** It is file-level: a finding anywhere in the file with
the right CWE counts, even on a different line than the flaw. One deviation
from the official reader: it takes only the *first* CWE tag of a rule, we
accept any (Semgrep rules rarely carry two). Findings outside test files —
helpers, the HTML/JS front end — are not scored at all, so noise there is
invisible in the score (it is counted separately as total SAST findings).

### SAST — OWASP Benchmark for Python

[BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython)
(GPL-3.0) is the same design in Python: 1,230 Flask views, each a real
vulnerability or a safe look-alike, labelled in `expectedresults-0.1.csv` in
the same four-column format with a CWE per case. Upstream calls 0.1 a
preliminary release and publishes it as the head of `main`, so a commit is
pinned in [`corpora.json`](corpora.json).

**Same scorer, same CWE map.** The Java matching rule, score and CWE
translation table apply unchanged; only the file name is `.py`. Four of its 14
categories do not exist in the Java Benchmark — code injection (CWE-94),
insecure deserialization (502), open redirect (601) and XXE (611). The
official Semgrep reader has no translation for them, so they score on exactly
that CWE, here as on the official scorecard. The one place this bites:
Semgrep's Python `eval`/`exec` rules tag CWE-95 ("eval injection"), which does
not count for a CWE-94 case. That is upstream's rule, kept as is; the code
injection row below reads lower than a human reviewer would score it.

**Limits.** Category sizes are uneven and some are small (SQL injection has 5
real and 11 safe cases), so a single test case moves a small category's score
by 10–20 points; read the per-category rows as direction, not decimals.

### SAST — OpenSSF CVE Benchmark (JavaScript/TypeScript)

**Choosing a corpus.** There is no OWASP Benchmark for JavaScript (the
OWASP-Benchmark organisation has Java, Python and the scorer only), and NIST
SARD's Juliet suites are C/C++, Java and C#. Of the JS/TS datasets that exist:
[RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark) (Apache-2.0)
labels vulnerable lines in 74 JS/TS repositories, but its JS/TS half has no
false-positive traps yet and is mostly intentionally vulnerable apps (NodeGoat,
DVNA, Juice Shop…) and LLM-generated ones — recall only. SecBench.js and x.js
are exploit-validated npm vulnerabilities without safe counterparts.
[BenchProctor](https://github.com/TheAuditorTool/BenchProctor) (Apache-2.0) is
template-generated, 1.5 GB, from one vendor, with releases halted — a
synthetic suite either way. The
[OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark)
(MIT) has the property that matters: 223 **real** JS/TS CVEs, each with the
vulnerable line labelled at the last vulnerable commit **and** the fix commit,
so the safe look-alike is the maintainers' actual patch rather than one we
wrote. That makes it discriminating without being synthetic, so no synthetic
JS suite was built.

**Corpus.** [`ossf_cve.py`](ossf_cve.py) reads the metadata at the pinned
commit and fetches each labelled file at both commits from
`raw.githubusercontent.com` (addressed by SHA, so immutable) into
`<CVE>/pre/…` and `<CVE>/post/…`; one scan covers all of them. CVEs whose file
cannot be fetched any more (repository deleted or history rewritten) are listed
and left out.

**Matching rule — OpenSSF's own.** A CVE is *detected* when a SAST finding
starts exactly on a labelled line; the rules of those findings are its
*on-target rules*. The fix is *recognized* when at least one on-target rule
fires fewer times on the fixed file than on the vulnerable one. As a confusion
matrix, each CVE is one real case and one safe case: detected = TP, missed =
FN, detected but the fix not recognized = FP (the fixed code is still
flagged), otherwise TN. So TPR = detected / CVEs, FPR = fixes still flagged /
CVEs, and the score TPR − FPR is simply *fixes recognized / CVEs*. Precision =
TP / (TP + FP) is over these pairs, not over every finding.

**Deviations, and why they are small for Semgrep CE.** (1) Only the labelled
files are scanned, not the whole repository: Semgrep CE's taint analysis does
not cross files, so the rest of the repository cannot change what it reports
in these files; it does change upstream's "recognized", which counts a rule's
alerts over the whole repository — a fix that moves code to another file is
recognized here and not upstream. (2) In 24 of the 220 CVEs the fix left the
labelled file byte-identical (validation added in a caller, a dependency
bumped): no file-local tool can tell the two versions apart, so a detection
there is necessarily an FP (`fp_fix_elsewhere` in `results.json`). (3) The CWE
is not part of the rule (it is not upstream either); the "CWE agrees" column
counts detections whose on-target finding also names one of the CVE's CWEs.
(4) Exact start line is strict for multi-line matches; a "span match" variant
(the labelled line lies anywhere inside the finding) is reported alongside.

**Limits.** Real CVEs are dominated by library code — parsers, template
engines, `lodash`-style utilities — where the "source" is a function argument,
not an HTTP request. Semgrep's taint rules start from framework sources
(`req.query`, …), so this corpus is hard for any rule pack by construction,
and its numbers are not comparable with OWASP Benchmark's. The 223 CVEs are
also unevenly spread: XSS and ReDoS are two fifths of them, SQL injection
and SSRF a handful.

### SAST rule-pack profiles

For Python and JS/TS each profile is a separate scan of the same corpus with a
different `scanners.semgrep.rules`: the shipped default (`p/default`), `auto`
(`p/default` plus the packs [stack detection](../scripts/render-env.py) picks:
`p/python`; `p/javascript` + `p/typescript`), each relevant registry pack
**alone** (what its rules find by themselves), and a ceiling with
every pack added to `p/default`. "Rules loaded" is what Semgrep itself reports
in its SARIF, across all languages. `p/typescript` is the same rule set as
`p/javascript` (identical rule ids), so it is not measured separately.

### Secrets — synthetic, labelled (SYNTHETIC)

No openly licensed, line-labelled real-world corpus fits. Samsung
[CredData](https://github.com/Samsung/CredData) (Apache-2.0 metadata) is the
right idea, but it is assembled by cloning ~300 repositories (19M lines), and it
*obfuscates* every value — fixed-format keys become provider example values,
which Gitleaks deliberately allowlists — so a pattern scanner's score on it
measures the obfuscation as much as the scanner. SecretBench is access-on-request
under a data agreement.

So the corpus is generated by [`synthetic_secrets.py`](synthetic_secrets.py)
(seeded, byte-for-byte reproducible, tree digest recorded below): random values
in 20+ real credential formats placed in realistic files (settings modules,
`.env`, CI config, k8s Secrets, a GCP service-account JSON, Terraform, JDBC
URLs), plus decoys a careless scanner flags (AWS documentation example keys,
placeholders, env-var references, masked values, checksums, commit SHAs, UUIDs,
npm integrity hashes, a public key, a data URI). Every value is random; none was
ever a live credential.

**Matching rule.** A finding hits a label when it is in the same file and its
start line is inside the label's span (a PEM key spans lines). Secret hit = TP,
secret missed = FN, decoy hit = FP, decoy silent = TN, and a finding on an
unlabelled line is an FP too (every unlabelled line is ordinary code).
Precision = TP / (TP + all FPs). Scored on findings the collector files under
`secrets`, merged across engines, and per engine.

The opt-in TruffleHog profile runs TruffleHog as shipped — with verification
on, so it sends each candidate to the provider's API to test it. Here those are
random values that were never valid; on a real repository that is a network
call carrying your credential to its issuer, which is worth knowing before
enabling it. **Changed** in 744144b: TruffleHog now runs with
`--no-verification` unless `scanners.trufflehog.verify: true`; the TruffleHog
numbers here were measured with verification on.

**Limits.** Synthetic means the formats are the ones we thought of: the corpus
says how a scanner handles *these* shapes, not how common each shape is in the
wild. Recall on provider-prefixed tokens is close to a regex self-test; the
informative rows are the unprefixed ones (passwords in URLs, base64 in k8s
Secrets, generic `password=`) and the decoys.

### SCA — pinned vulnerable packages vs. OSV

[`sca_corpus.py`](sca_corpus.py) writes 26 packages pinned to known-vulnerable
versions into the files real projects carry: `requirements.txt`,
`package-lock.json`, `go.mod`, `gradle.lockfile`, `Gemfile.lock`. The truth is
every non-withdrawn advisory [OSV](https://osv.dev) lists for each
package@version, snapshotted in [`sca_truth.json`](sca_truth.json) with the date
it was taken.

**Matching rule.** OSV lists one vulnerability under several ids (GHSA, PYSEC,
GO-, CVE as aliases), so advisories are first merged into alias clusters; one
cluster = one expected vulnerability. It is detected when an SCA finding names
any id in the cluster (as `rule_id` or alias) for the same package (PEP 503
name normalisation for PyPI). Recall = detected / expected.

**Limits.** Precision is not computed: a finding outside the snapshot is not
necessarily wrong — the engines read their own databases (Trivy DB, Grype DB,
OSV live), built on other days and from other sources. Recall is therefore a
statement about *two dates*: the OSV snapshot and the engine DB dates recorded
under Provenance. Re-running later moves the numbers; that is the point of
recording the dates.

### IaC — skipped

No labelled IaC corpus maps onto these engines without inventing the mapping.
TerraGoat, KICS-style test fixtures and similar repos are deliberately
misconfigured, but their "answers" are either undocumented or written in one
tool's rule vocabulary (a KICS query id), and Checkov and Trivy flag the same
resource line for a dozen unrelated policies — so a location match would count
the wrong rule as a hit. Building a defensible cross-tool rule mapping is the
prerequisite; until then, IaC has no number here rather than a weak one.

## Results

<!-- results:begin (generated by benchmark/bench.py — do not edit by hand) -->

### SAST — OWASP Benchmark for Java 1.2

Corpus: [OWASP-Benchmark/BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) at `1fa16b84f77a438a7b7c929f0e67b947b0766861` (tree sha256 `201e75c419ff03de…`), 2740 test cases.

| Profile | Rules loaded | Avg TPR | Avg FPR | Benchmark score | Precision (all cases) | SAST findings | Runtime |
|---|--:|--:|--:|--:|--:|--:|--:|
| Semgrep, p/default (shipped default) | 1074 | 88.1% | 44.1% | **+44.0** | 69.3% | 3251 | 157 s |
| Semgrep, p/default + `auto` stack packs (opt-in) | 1076 | 88.1% | 44.1% | **+44.0** | 69.3% | 3252 | 193 s |

**Semgrep, p/default (shipped default)** — per category:

| Category | TP | FN | FP | TN | TPR | FPR | Score |
|---|--:|--:|--:|--:|--:|--:|--:|
| Command injection (CWE-78) | 117 | 9 | 109 | 16 | 92.9% | 87.2% | +5.7 |
| Weak cipher (CWE-327) | 130 | 0 | 0 | 116 | 100.0% | 0.0% | +100.0 |
| Weak hash (CWE-328) | 89 | 40 | 0 | 107 | 69.0% | 0.0% | +69.0 |
| LDAP injection (CWE-90) | 26 | 1 | 28 | 4 | 96.3% | 87.5% | +8.8 |
| Path traversal (CWE-22) | 120 | 13 | 106 | 29 | 90.2% | 78.5% | +11.7 |
| Insecure cookie (CWE-614) | 36 | 0 | 0 | 31 | 100.0% | 0.0% | +100.0 |
| SQL injection (CWE-89) | 253 | 19 | 170 | 62 | 93.0% | 73.3% | +19.7 |
| Trust boundary (CWE-501) | 43 | 40 | 18 | 25 | 51.8% | 41.9% | +10.0 |
| Weak randomness (CWE-330) | 218 | 0 | 0 | 275 | 100.0% | 0.0% | +100.0 |
| XPath injection (CWE-643) | 14 | 1 | 13 | 7 | 93.3% | 65.0% | +28.3 |
| Cross-site scripting (CWE-79) | 202 | 44 | 108 | 101 | 82.1% | 51.7% | +30.4 |
| **All (micro)** | 1248 | 167 | 552 | 773 | 88.2% | 41.7% | +46.5 |

SAST findings in the whole report: 3251 (by severity: high 571, medium 2680).

**Semgrep, p/default + `auto` stack packs (opt-in)** — per category:

| Category | TP | FN | FP | TN | TPR | FPR | Score |
|---|--:|--:|--:|--:|--:|--:|--:|
| Command injection (CWE-78) | 117 | 9 | 109 | 16 | 92.9% | 87.2% | +5.7 |
| Weak cipher (CWE-327) | 130 | 0 | 0 | 116 | 100.0% | 0.0% | +100.0 |
| Weak hash (CWE-328) | 89 | 40 | 0 | 107 | 69.0% | 0.0% | +69.0 |
| LDAP injection (CWE-90) | 26 | 1 | 28 | 4 | 96.3% | 87.5% | +8.8 |
| Path traversal (CWE-22) | 120 | 13 | 106 | 29 | 90.2% | 78.5% | +11.7 |
| Insecure cookie (CWE-614) | 36 | 0 | 0 | 31 | 100.0% | 0.0% | +100.0 |
| SQL injection (CWE-89) | 253 | 19 | 170 | 62 | 93.0% | 73.3% | +19.7 |
| Trust boundary (CWE-501) | 43 | 40 | 18 | 25 | 51.8% | 41.9% | +10.0 |
| Weak randomness (CWE-330) | 218 | 0 | 0 | 275 | 100.0% | 0.0% | +100.0 |
| XPath injection (CWE-643) | 14 | 1 | 13 | 7 | 93.3% | 65.0% | +28.3 |
| Cross-site scripting (CWE-79) | 202 | 44 | 108 | 101 | 82.1% | 51.7% | +30.4 |
| **All (micro)** | 1248 | 167 | 552 | 773 | 88.2% | 41.7% | +46.5 |

SAST findings in the whole report: 3252 (by severity: high 572, medium 2680).

### SAST — OWASP Benchmark for Python 0.1

Corpus: [OWASP-Benchmark/BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) at `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (tree sha256 `f60f2d3de30431f2…`), 1230 test cases.

| Profile | Rules loaded | Avg TPR | Avg FPR | Benchmark score | Precision (all cases) | Score if CWE-95→94, 327→328 (not official) | SAST findings | Runtime |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| Semgrep, p/default (shipped default) | 1074 | 26.0% | 19.1% | **+6.9** | 51.8% | +10.7 | 1300 | 22 s |
| Semgrep, p/default + `auto` stack packs (opt-in) | 1105 | 26.0% | 19.1% | **+6.9** | 51.8% | +12.4 | 1317 | 19 s |
| Semgrep, p/python alone | 151 | 7.6% | 8.5% | **-0.8** | 54.5% | +4.6 | 184 | 8 s |
| Semgrep, p/flask alone | 18 | 1.1% | 0.0% | **+1.1** | 100.0% | +1.1 | 19 | 6 s |
| Semgrep, p/django alone (control: not a Django app) | 28 | 1.8% | 0.5% | **+1.3** | 60.0% | +1.3 | 864 | 8 s |
| Semgrep, p/security-audit alone | 225 | 25.8% | 24.1% | **+1.7** | 51.3% | +5.4 | 409 | 8 s |
| Semgrep, p/owasp-top-ten alone | 560 | 7.6% | 8.5% | **-0.8** | 54.5% | +4.6 | 184 | 12 s |
| Semgrep, p/default + every pack above (ceiling) | 1157 | 33.2% | 26.3% | **+6.9** | 47.1% | +12.4 | 1430 | 22 s |

Benchmark score (TPR − FPR) per category and profile:

| Category | default | auto | python | flask | django | security-audit | owasp-top-ten | all |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| Command injection (CWE-78) | -46.2 | -46.2 | -46.2 | +15.4 | +0.0 | -46.2 | -46.2 | -46.2 |
| Code injection (CWE-94) | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| Insecure deserialization (CWE-502) | +66.7 | +66.7 | +33.3 | +0.0 | +16.7 | +66.7 | +33.3 | +66.7 |
| Weak hash (CWE-328) | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| LDAP injection (CWE-90) | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| Path traversal (CWE-22) | +1.1 | +1.1 | +1.1 | +0.0 | +1.1 | +0.0 | +1.1 | +1.1 |
| Open redirect (CWE-601) | +2.9 | +2.9 | +0.0 | +0.0 | +0.0 | +2.9 | +0.0 | +2.9 |
| Insecure cookie (CWE-614) | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| SQL injection (CWE-89) | +100.0 | +100.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +100.0 |
| Trust boundary (CWE-501) | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| Weak randomness (CWE-330) | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| XPath injection (CWE-643) | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |
| Cross-site scripting (CWE-79) | -27.6 | -27.6 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | -27.6 |
| XML external entities (CWE-611) | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 | +0.0 |

**Semgrep, p/default (shipped default)** — per category:

| Category | TP | FN | FP | TN | TPR | FPR | Score |
|---|--:|--:|--:|--:|--:|--:|--:|
| Command injection (CWE-78) | 7 | 6 | 7 | 0 | 53.8% | 100.0% | -46.2 |
| Code injection (CWE-94) | 0 | 20 | 0 | 33 | 0.0% | 0.0% | +0.0 |
| Insecure deserialization (CWE-502) | 18 | 0 | 12 | 24 | 100.0% | 33.3% | +66.7 |
| Weak hash (CWE-328) | 0 | 71 | 0 | 80 | 0.0% | 0.0% | +0.0 |
| LDAP injection (CWE-90) | 0 | 16 | 0 | 13 | 0.0% | 0.0% | +0.0 |
| Path traversal (CWE-22) | 2 | 63 | 2 | 101 | 3.1% | 1.9% | +1.1 |
| Open redirect (CWE-601) | 1 | 12 | 1 | 20 | 7.7% | 4.8% | +2.9 |
| Insecure cookie (CWE-614) | 24 | 0 | 15 | 0 | 100.0% | 100.0% | +0.0 |
| SQL injection (CWE-89) | 5 | 0 | 0 | 11 | 100.0% | 0.0% | +100.0 |
| Trust boundary (CWE-501) | 0 | 18 | 0 | 19 | 0.0% | 0.0% | +0.0 |
| Weak randomness (CWE-330) | 0 | 99 | 0 | 227 | 0.0% | 0.0% | +0.0 |
| XPath injection (CWE-643) | 0 | 51 | 0 | 135 | 0.0% | 0.0% | +0.0 |
| Cross-site scripting (CWE-79) | 0 | 31 | 16 | 42 | 0.0% | 27.6% | -27.6 |
| XML external entities (CWE-611) | 0 | 8 | 0 | 20 | 0.0% | 0.0% | +0.0 |
| **All (micro)** | 57 | 395 | 53 | 725 | 12.6% | 6.8% | +5.8 |

SAST findings in the whole report: 1300 (by severity: high 130, medium 1170).

**Semgrep, p/default + `auto` stack packs (opt-in)** — per category:

| Category | TP | FN | FP | TN | TPR | FPR | Score |
|---|--:|--:|--:|--:|--:|--:|--:|
| Command injection (CWE-78) | 7 | 6 | 7 | 0 | 53.8% | 100.0% | -46.2 |
| Code injection (CWE-94) | 0 | 20 | 0 | 33 | 0.0% | 0.0% | +0.0 |
| Insecure deserialization (CWE-502) | 18 | 0 | 12 | 24 | 100.0% | 33.3% | +66.7 |
| Weak hash (CWE-328) | 0 | 71 | 0 | 80 | 0.0% | 0.0% | +0.0 |
| LDAP injection (CWE-90) | 0 | 16 | 0 | 13 | 0.0% | 0.0% | +0.0 |
| Path traversal (CWE-22) | 2 | 63 | 2 | 101 | 3.1% | 1.9% | +1.1 |
| Open redirect (CWE-601) | 1 | 12 | 1 | 20 | 7.7% | 4.8% | +2.9 |
| Insecure cookie (CWE-614) | 24 | 0 | 15 | 0 | 100.0% | 100.0% | +0.0 |
| SQL injection (CWE-89) | 5 | 0 | 0 | 11 | 100.0% | 0.0% | +100.0 |
| Trust boundary (CWE-501) | 0 | 18 | 0 | 19 | 0.0% | 0.0% | +0.0 |
| Weak randomness (CWE-330) | 0 | 99 | 0 | 227 | 0.0% | 0.0% | +0.0 |
| XPath injection (CWE-643) | 0 | 51 | 0 | 135 | 0.0% | 0.0% | +0.0 |
| Cross-site scripting (CWE-79) | 0 | 31 | 16 | 42 | 0.0% | 27.6% | -27.6 |
| XML external entities (CWE-611) | 0 | 8 | 0 | 20 | 0.0% | 0.0% | +0.0 |
| **All (micro)** | 57 | 395 | 53 | 725 | 12.6% | 6.8% | +5.8 |

SAST findings in the whole report: 1317 (by severity: high 130, medium 1187).

### SAST — OpenSSF CVE Benchmark (JavaScript/TypeScript)

Corpus: [ossf-cve-benchmark/ossf-cve-benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark) metadata at `91c59fd54b2b768c0f310bb0027d2ac59cdf74d4`; the labelled files of 220 of its 223 CVEs at their vulnerable and fix commits (440 files, tree sha256 `57e8981c781812a2…`). In 24 CVEs the fix left the labelled file byte-identical (fixed in another file).

Not scored (labelled file not fetchable at a pinned commit): CVE-2016-1000229 (`linxiaowu66/swagger-ui`), CVE-2018-8035 (`apache/uima-ducc`), CVE-2019-12041 (`probablyup/markdown-to-jsx`).

| Profile | Rules loaded | TPR (detected) | FPR (fix still flagged) | Score (fixes recognized) | Precision | Span match: TPR / score | Detected, CWE agrees | SAST findings | Runtime |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| Semgrep, p/default (shipped default) | 1074 | 10.9% (24) | 5.9% (13) | **+5.0** | 64.9% | 11.4% / +5.5 | 19 | 509 | 110 s |
| Semgrep, p/default + `auto` stack packs (opt-in) | 1075 | 10.9% (24) | 5.9% (13) | **+5.0** | 64.9% | 11.4% / +5.5 | 19 | 507 | 104 s |
| Semgrep, p/javascript alone (= p/typescript) | 74 | 3.2% (7) | 2.7% (6) | **+0.4** | 53.8% | 3.6% / +0.9 | 6 | 62 | 52 s |
| Semgrep, p/nodejs alone | 36 | 0.0% (0) | 0.0% (0) | **+0.0** | — | 0.0% / +0.0 | 0 | 34 | 46 s |
| Semgrep, p/expressjs alone | 71 | 3.2% (7) | 2.7% (6) | **+0.4** | 53.8% | 3.6% / +0.9 | 6 | 62 | 52 s |
| Semgrep, p/react alone | 4 | 2.3% (5) | 1.8% (4) | **+0.4** | 55.6% | 2.3% / +0.4 | 5 | 13 | 12 s |
| Semgrep, p/nodejsscan alone | 114 | 3.2% (7) | 1.8% (4) | **+1.4** | 63.6% | 5.9% / +2.3 | 3 | 323 | 146 s |
| Semgrep, p/security-audit alone | 225 | 4.5% (10) | 2.7% (6) | **+1.8** | 62.5% | 4.5% / +1.8 | 10 | 51 | 24 s |
| Semgrep, p/default + p/nodejsscan | 1188 | 13.2% (29) | 6.8% (15) | **+6.4** | 65.9% | 15.9% / +7.7 | 21 | 783 | 221 s |
| Semgrep, p/default + every pack above (ceiling) | 1204 | 13.2% (29) | 6.8% (15) | **+6.4** | 65.9% | 15.9% / +7.7 | 21 | 757 | 244 s |

Per category — detected / fix recognized, of CVEs:

| Category | CVEs | default | auto | javascript | nodejs | expressjs | react | nodejsscan | security-audit | default-nodejsscan | all |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| Command injection | 25 | 8 / 4 | 8 / 4 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 6 / 4 | 8 / 4 | 8 / 4 |
| Code injection | 14 | 1 / 1 | 1 / 1 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 1 / 1 | 1 / 1 |
| Other | 28 | 1 / 0 | 1 / 0 | 1 / 0 | 0 / 0 | 1 / 0 | 0 / 0 | 2 / 2 | 0 / 0 | 3 / 2 | 3 / 2 |
| Path traversal | 29 | 2 / 1 | 2 / 1 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 2 / 0 | 0 / 0 | 3 / 1 | 3 / 1 |
| Prototype pollution | 23 | 1 / 1 | 1 / 1 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 1 / 1 | 1 / 1 |
| Open redirect | 7 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| ReDoS | 31 | 2 / 1 | 2 / 1 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 2 / 1 | 2 / 1 |
| SQL injection | 4 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 1 / 0 | 0 / 0 | 1 / 0 | 1 / 0 |
| SSRF | 3 | 1 / 0 | 1 / 0 | 1 / 0 | 0 / 0 | 1 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 1 / 0 | 1 / 0 |
| Cross-site scripting | 56 | 8 / 3 | 8 / 3 | 5 / 1 | 0 / 0 | 5 / 1 | 5 / 1 | 2 / 1 | 4 / 0 | 9 / 4 | 9 / 4 |

### Secrets — synthetic labelled corpus (SYNTHETIC)

Corpus: `benchmark/synthetic_secrets.py` v1, seed 20261102: 17 files, 26 labelled secrets, 20 decoys (tree sha256 `14bdfdfa2eefe102…`).

| Profile | Recall | Precision | Decoys flagged | Unlabelled FPs | Runtime |
|---|--:|--:|--:|--:|--:|
| Gitleaks + Trivy (shipped default) | 88.5% (23/26) | 95.8% | 1/20 | 0 | 2 s |
| ↳ gitleaks alone | 88.5% (23/26) | 95.8% | 1/20 | 0 |  |
| ↳ trivy alone | 57.7% (15/26) | 100.0% | 0/20 | 0 |  |
| Gitleaks + Trivy + TruffleHog (opt-in) | 92.3% (24/26) | 96.0% | 1/20 | 0 | 3 s |
| ↳ gitleaks alone | 88.5% (23/26) | 95.8% | 1/20 | 0 |  |
| ↳ trivy alone | 57.7% (15/26) | 100.0% | 0/20 | 0 |  |
| ↳ trufflehog alone | 53.8% (14/26) | 100.0% | 0/20 | 0 |  |

Detected per kind (a decoy "detected" is a false positive):

| Kind | Label | Gitleaks + Trivy (shipped default) | Gitleaks + Trivy + TruffleHog (opt-in) |
|---|--:|--:|--:|
| anthropic-api-key | secret | 1/1 | 1/1 |
| aws-access-key-id | secret | 1/1 | 1/1 |
| aws-docs-example | decoy | 0/2 | 0/2 |
| aws-secret-access-key | secret | 1/1 | 1/1 |
| azure-storage-key | secret | 1/1 | 1/1 |
| checksum | decoy | 0/2 | 0/2 |
| commit-sha | decoy | 0/1 | 0/1 |
| connection-string-password | secret | 1/1 | 1/1 |
| data-uri | decoy | 0/1 | 0/1 |
| django-secret-key | secret | 0/1 | 0/1 |
| env-reference | decoy | 0/2 | 0/2 |
| gcp-service-account-key | secret | 1/1 | 1/1 |
| generic-api-secret | secret | 1/1 | 1/1 |
| generic-password | secret | 2/2 | 2/2 |
| github-fine-grained-pat | secret | 1/1 | 1/1 |
| github-pat | secret | 1/1 | 1/1 |
| gitlab-pat | secret | 1/1 | 1/1 |
| google-api-key | secret | 1/1 | 1/1 |
| integrity-hash | decoy | 0/1 | 0/1 |
| jwt | secret | 1/1 | 1/1 |
| k8s-secret-base64 | secret | 1/1 | 1/1 |
| keyword-not-secret | decoy | 0/2 | 0/2 |
| low-entropy-password | decoy | 0/1 | 0/1 |
| masked | decoy | 0/1 | 0/1 |
| npm-token | secret | 1/1 | 1/1 |
| openai-api-key | secret | 1/1 | 1/1 |
| placeholder | decoy | 0/2 | 0/2 |
| public-key | decoy | 0/1 | 0/1 |
| rsa-private-key | secret | 1/1 | 1/1 |
| sendgrid-api-key | secret | 1/1 | 1/1 |
| slack-bot-token | secret | 1/1 | 1/1 |
| slack-webhook | secret | 1/1 | 1/1 |
| stripe-secret-key | secret | 1/1 | 1/1 |
| template-variable | decoy | 0/2 | 0/2 |
| test-vector | decoy | 1/1 | 1/1 |
| twilio-api-key | secret | 1/1 | 1/1 |
| url-embedded-password | secret | 0/2 | 1/2 |
| uuid | decoy | 0/1 | 0/1 |

### SCA — pinned vulnerable packages vs. OSV

Corpus: 26 packages pinned in `go/go.mod`, `jvm/gradle.lockfile`, `node/package-lock.json`, `python/requirements.txt`, `ruby/Gemfile.lock` (tree sha256 `7c5c1e9b79cb007e…`). Truth: OSV snapshot taken 2026-11-02T19:01:53Z.

| Ecosystem | Packages | Trivy (shipped default) | Trivy + Grype + OSV-Scanner (opt-in) |
|---|--:|--:|--:|
| Go | 5 | 100.0% (13/13) | 100.0% (13/13) |
| Maven | 5 | 100.0% (83/83) | 100.0% (83/83) |
| PyPI | 7 | 98.5% (128/130) | 100.0% (130/130) |
| RubyGems | 3 | 100.0% (80/80) | 100.0% (80/80) |
| npm | 6 | 97.4% (38/39) | 97.4% (38/39) |
| **All** | 26 | **99.1%** (342/345) | **99.7%** (344/345) |

- **Trivy (shipped default)**: 354 SCA findings, 12 not in the OSV snapshot, 3 expected advisories missed; runtime 2 s.
- **Trivy + Grype + OSV-Scanner (opt-in)**: 390 SCA findings, 15 not in the OSV snapshot, 1 expected advisories missed; runtime 8 s.

### Reading cost

What `review-brief.md` costs a reader (≈ tokens; findings with code, and one line each), and what `min_confidence: medium` — dropping LOW-confidence rules from the gate — would trade on the SAST suites.

| Suite | Brief | With code | One line | Low-confidence | With `min_confidence: medium` |
|---|--:|--:|--:|--:|--:|
| sast | ~41,292 | 42 | 3209 | 591 | score +44.0 → +26.8, TPR 88.1% → 68.9%, FPR 44.1% → 42.1% |
| secrets | ~3,446 | 28 | 3 | — | — |
| sca | ~10,677 | 0 | 0 | — | — |
| sast-js | ~19,872 | 39 | 470 | 447 | detected 24 → 7 |
| sast-python | ~19,943 | 37 | 1263 | 297 | score +6.9 → -0.8, TPR 26.0% → 7.6%, FPR 19.1% → 8.5% |

### Provenance

Generated 2026-11-07T12:39:02Z by appsec-compose 1.4.0 (commit `88b1b3977a77`) on macOS-27.0.1-arm64-arm-64bit-Mach-O, Docker 28.2.2.

| Engine | Image (digest-pinned) |
|---|--:|
| gitleaks | `zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` |
| grype | `anchore/grype@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea` |
| osv | `ghcr.io/google/osv-scanner@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0` |
| semgrep | `semgrep/semgrep@sha256:2e45517a85e13a9cca14a2a00df6bb48affd66b8ebfae1b0991cd57578362fb0` |
| trivy | `aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c` |
| trufflehog | `trufflesecurity/trufflehog@sha256:0d003fc3abc4e1565eca8462b992001314de51451e96e3c44de80d116794d5d1` |

Vulnerability DB dates:

- sast/default: findings.json provenance says `{}`; cache after the run: `{}`
- sast/auto: findings.json provenance says `{}`; cache after the run: `{}`
- secrets/default: findings.json provenance says `{'trivy': '2026-11-07T06:54:25.084761873Z'}`; cache after the run: `{'trivy': '2026-11-07T06:54:25.084761873Z'}`
- secrets/trufflehog: findings.json provenance says `{'trivy': '2026-11-07T06:54:25.084761873Z'}`; cache after the run: `{'trivy': '2026-11-07T06:54:25.084761873Z'}`
- sca/default: findings.json provenance says `{'trivy': '2026-11-07T06:54:25.084761873Z'}`; cache after the run: `{'trivy': '2026-11-07T06:54:25.084761873Z'}`
- sca/all: findings.json provenance says `{'trivy': '2026-11-07T06:54:25.084761873Z', 'grype': '2026-11-07T00:20:09Z'}`; cache after the run: `{'trivy': '2026-11-07T06:54:25.084761873Z', 'grype': '2026-11-07T00:20:09Z'}`
- sast-js/default: findings.json provenance says `{}`; cache after the run: `{}`
- sast-js/auto: findings.json provenance says `{}`; cache after the run: `{}`
- sast-js/javascript: findings.json provenance says `{}`; cache after the run: `{}`
- sast-js/nodejs: findings.json provenance says `{}`; cache after the run: `{}`
- sast-js/expressjs: findings.json provenance says `{}`; cache after the run: `{}`
- sast-js/react: findings.json provenance says `{}`; cache after the run: `{}`
- sast-js/nodejsscan: findings.json provenance says `{}`; cache after the run: `{}`
- sast-js/security-audit: findings.json provenance says `{}`; cache after the run: `{}`
- sast-js/default-nodejsscan: findings.json provenance says `{}`; cache after the run: `{}`
- sast-js/all: findings.json provenance says `{}`; cache after the run: `{}`
- sast-python/default: findings.json provenance says `{}`; cache after the run: `{}`
- sast-python/auto: findings.json provenance says `{}`; cache after the run: `{}`
- sast-python/python: findings.json provenance says `{}`; cache after the run: `{}`
- sast-python/flask: findings.json provenance says `{}`; cache after the run: `{}`
- sast-python/django: findings.json provenance says `{}`; cache after the run: `{}`
- sast-python/security-audit: findings.json provenance says `{}`; cache after the run: `{}`
- sast-python/owasp-top-ten: findings.json provenance says `{}`; cache after the run: `{}`
- sast-python/all: findings.json provenance says `{}`; cache after the run: `{}`

<!-- results:end -->

## Where appsec-compose is weak

Read against the run above. When the numbers move, re-read this.

**SAST finds the flaw but cannot tell when it is safe.** Recall is high on
every injection class (≈ 90–96%), but so is the false-positive rate: command
injection, LDAP injection, path traversal and SQL injection all flag 70–90% of
the *safe* cases too, which puts their Benchmark scores near zero (+6 to +20).
The safe variants in the Benchmark are the ones that need inter-procedural or
value-sensitive reasoning — a sanitiser in a helper class, a branch that is
never taken, a value overwritten with a constant — and Semgrep CE's taint mode
is intra-file and path-insensitive. The categories that score +100 (weak
cipher, weak randomness, insecure cookie) are the ones a single API call
decides. Practically: treat a SAST injection finding as "a reviewer must look
here", not as a confirmed bug; roughly one in three flagged test cases overall
is a safe one.

**SAST misses what is indirect.** Weak hashing misses ~31% of real cases — the
algorithm name comes from a properties file, not a literal. Trust-boundary
violations are found barely more often than safe cases are flagged (+10).
Stored/reflected XSS misses ~18%.

**Python SAST is far weaker than Java SAST** (+6.9 against +44.0, same
engine, same scorer). Per category it is coverage, not tuning: weak
randomness, XPath injection, LDAP injection, trust boundary and XXE (CWE-611
cases) get **no** true positive from any pack measured — there is no Python
rule for `random` used for security values, and the XML rule that fires
(`use-defused-xml-parse`, CWE-611) fires on the XPath cases, not the XXE ones.
Where rules exist they rarely tell safe from unsafe: command injection flags
all 7 safe cases (FPR 100%), the cookie rule (`secure-set-cookie`) wants
`secure`, `httponly` and `samesite` all set, so it fires on every `set_cookie`
in the corpus — the Benchmark's safe cases set `secure=True` and nothing else
(100% / 100%, plus a CWE-614 finding in most other test files, whose GET
handlers set a cookie too) — and the XSS rule fires
only on safe cases (0 TP, 16 FP). SQL injection (+100) and deserialization
(+67) are the two categories that work. Two zeros are a labelling artefact,
not blindness: Semgrep tags `eval`/`exec` CWE-95 and md5/sha1 CWE-327, which
the official scorer does not credit to code injection (94) or weak hash (328).
Re-scored with those two equivalences (the "not official" column) the default
gets weak hash 37/71 with no FP, but code injection stays at zero score — the
eval rule flags every one of the 53 cases, safe or not.

**Python packs: `auto` is worth it, nothing else is.** `auto` adds `p/python`
(31 more rules, about a second) and leaves the official score unchanged — but
those rules raise weak-hash recall from 37 to 54 of 71 with no false positive,
which only the not-official column can show (+10.7 → +12.4). Every other pack
is a subset of `p/default` + `p/python` or adds noise as fast as signal:
`p/security-audit` alone matches the default's TPR at a higher FPR, and the
ceiling (every pack) buys +7.2 points of TPR with +7.2 of FPR — score
unchanged, 130 more findings. `p/owasp-top-ten` gives byte-identical results
to `p/python` on this corpus (same scores, same 184 findings). `p/flask`
(18 rules) finds two command-injection cases on a Flask
corpus; `p/django` is the control and finds nearly nothing.

**JS/TS: on real CVEs Semgrep CE finds about one in nine, and recognizes the
fix in one in twenty.** The default detects 24 of 220 CVEs on the labelled
line and goes quiet after the fix in 11 of them (score +5.0); a finding
*somewhere* in the vulnerable file exists for 92. That gap is the corpus'
nature: most of these CVEs are library code (template engines, parsers,
`lodash`-style helpers) where the tainted value is a function argument, and
Semgrep's taint rules start from framework sources such as `req.query`.
Command injection (8 of 25) and XSS (8 of 56) are the best classes; prototype
pollution (1 of 23), ReDoS (2 of 31), path traversal (2 of 29) and open
redirect (0 of 7) are close to invisible, although `p/default` has a rule for
each — they fire 34, 46 and 91 times in the vulnerable files, on other lines. For an
agent's review this means: a clean Semgrep run on a JS library says almost
nothing about these classes.

**JS/TS packs: only `p/nodejsscan` adds anything, at a price.** `p/javascript`
(= `p/typescript`), `p/nodejs`, `p/expressjs`, `p/react` and
`p/security-audit` add only a handful of JS rules that `p/default` lacks, and
those detect nothing here, so `auto` — which adds `p/javascript` + `p/typescript` — changes
nothing. `p/nodejsscan` is 114 rules that are *not* in `p/default`; on top of
it, it detects 5 more CVEs (24 → 29) and recognizes 3 more fixes (+5.0 →
+6.4), but costs 233 more findings (+44%), 64 rule timeouts (against 13) and
roughly twice the runtime. A candidate for an opt-in "deep" tier, not for the
default.

**Semgrep can die and look like a clean scan.** In the first JS run the
`auto` profile reported 0 findings: semgrep-core had been killed (out of
memory: an 8 GB Docker VM with 11 CPUs, Semgrep's default parallelism, and
bundled files such as `lodash.js`; the same profile succeeded on re-run). Semgrep still wrote a valid SARIF —
`executionSuccessful: true`, no results — and said so only in an error-level
tool notification. The collector does not read notifications, so the run
passed with "0 SAST findings", even with `strict: true`. The benchmark now
detects this and re-runs (none of the runs above needed it), but a user's
scan has no such guard. Also in these runs: Semgrep's per-rule timeouts on
large files (13 with the default, 64–68 with `p/nodejsscan`) make two
identical scans differ by a few findings (default 526 vs `auto` 507 with the
same JS rules).

**`auto` adds nothing for Java.** Stack detection adds `p/java`, which is
already inside `p/default`: two extra rules, identical results. It is not a way
to get a better Java scan.

**Every Semgrep finding is reported as `medium` — so the default gate never
fails on SAST.** Semgrep's SARIF puts the level on the rule
(`defaultConfiguration.level`), not on each result; the collector reads only
the result's level and falls back to "warning" → medium. In the SAST run, 572
findings come from `error`-level rules (path traversal, command injection) and
all of them are `medium`, so `fail_on: high` lets every one through.
**Fixed** in 5b5f235 (a result without a level takes its rule's default, per
SARIF); the "by severity" lines above were measured before the fix. The
benchmark scores by CWE, not severity, so its numbers are unaffected.

**Trivy's secret findings are filed under `sca`.** Trivy runs
`--scanners vuln,secret` by default, but everything in `trivy-fs.sarif` is
categorised `sca`. So in the secrets run Trivy detected 15 of the 26 secrets
(row "trivy secrets (filed under `sca`)"), yet they appear as SCA findings: the
`secrets:` gate threshold does not apply to them, they are not de-duplicated
against Gitleaks (same secret, two findings), and they count as "SCA findings
exist" for the coverage check. The secrets numbers above count only what the
collector files as `secrets`. **Fixed** in 3c5890a: Trivy's secret results are filed
under `secrets`, take the secrets floor and merge with Gitleaks.

**Secrets: passwords inside URLs are invisible by default.**
`amqp://user:pass@host` and `postgres://user:pass@host` were missed by Gitleaks
and Trivy; only the opt-in TruffleHog caught the `postgres://` one. A
Django-style `SECRET_KEY` with punctuation was missed by every engine. Provider-prefixed tokens (AWS, GitHub, GitLab,
Slack, Stripe, OpenAI, Anthropic, npm, SendGrid, Twilio…) are caught reliably —
which on a synthetic corpus is close to a regex self-test, not a measurement of
real-world prevalence. Decoys were mostly ignored; the one decoy flagged was a
32-hex test vector next to the word `PASSWORD`.

**SCA recall is high because the corpus is easy for it.** Exact pins in lock
files are the best case for every engine. The opt-in engines close the
remaining gap (two Pillow advisories that only OSV/PYSEC carry). Findings
outside the truth are few: advisories newer or older than the snapshot's view
(e.g. `NSWG-ECO-516` for lodash, three nokogiri ids), plus — with OSV-Scanner —
*transitive* dependencies it resolves from `requirements.txt` (certifi, idna). What this suite does not show: version ranges
without a lock file (Trivy resolves nothing — the coverage check warns), vendored
or shaded jars, and reachability (every vulnerable package counts, used or not).

**Grype names Maven packages without the groupId** (**fixed** in 6b79790: the name now comes from the purl) (`jackson-databind@2.9.8`
vs Trivy/OSV `com.fasterxml.jackson.core:jackson-databind@2.9.8`), so with
Grype enabled every Maven vulnerability appears twice in `findings.json` —
cross-tool de-duplication keys on the package name. Grype also upper-cases GHSA
aliases. (The scorer tolerates both; the report does not.)

**Provenance DB dates are incomplete and partly wrong.** `findings.json`
records the Trivy DB date even for runs where Trivy did not run (the SAST runs
above), and never records Grype's: the date is read from
`cache/grype/*/metadata.json`, which Grype's v6 DB schema no longer writes (it
keeps `6/import.json`, whose source URL carries the build time). The dates are
also read *before* the scan, so a run that downloads a newer DB reports the
previous one. The benchmark reads the cache again after each run and shows both.
**Fixed** in d0848cb: dates are read after the scan, for the engines that ran,
including Grype v6.

**What this means for "profile → rule packs".** Per language, from these
numbers: Python → `p/default` + `p/python` (what `auto` already does); JS/TS →
`p/default` alone, with `p/nodejsscan` as the one opt-in for a deeper, slower,
noisier pass; Java → `p/default` alone. Framework packs (`p/flask`,
`p/django`, `p/expressjs`, `p/react`, `p/nodejs`) and `p/security-audit` /
`p/owasp-top-ten` should not be added by a profile: they are subsets of what
already runs or trade precision for recall one-for-one. The bigger lesson is
the ceiling: across every pack the registry offers for these languages, the
best Python profile moves the score by 0 points and the best JS one by 1.4.
Rule-pack selection is not where SAST quality comes from here; the gaps above
(no rule at all for half the Python categories, file-local taint, framework-
only sources) need custom rules in `semgrep-rules/` or a different engine,
and a profile feature should be judged by a benchmark row, not by pack names.

**Not measured at all:** IaC (see above), container images, git history,
SAST languages other than Java, Python and JS/TS (Go, Ruby, PHP, C#…), and
frameworks other than Flask on Python, business logic and authorization — which is
most of what an actual security review is about. Silence from appsec-compose
in those areas is not evidence of anything.

**Run conditions.** Runtimes are wall-clock on a developer laptop with other
Docker workloads running at the same time and warm engine caches; they show
order of magnitude, not throughput.
