# Speed

How long appsec-compose takes on real codebases with the shipped defaults: median of repeated runs after a warm-up (databases cached, collector image built). Engines run in parallel, so a scan costs what its slowest engine costs. Re-run with `python3 benchmark/speed.py`; method in its docstring.

appsec-compose 1.4.0 · 2026-11-04T19:58:37Z · macOS-27.0.1-arm64-arm-64bit-Mach-O · 11 CPUs (Docker: 11 CPUs, 7.7 GB) · load average at start 2.29, 2.32, 2.48

| Corpus | Files | Mode | Median | Range | Scanners | Slowest engines |
|---|---|---|---|---|---|---|
| juice-shop @ `717f5efa886b` | 1,468 | full | **14.7 s** | 13.9–15.1 s | 13 s | semgrep 12.6 s, checkov 8 s, trivy 4.9 s |
| juice-shop @ `717f5efa886b` | 2 changed | diff | **5.2 s** | 5.1–5.2 s | 4 s | semgrep 3.2 s, gitleaks 0.1 s |
| django @ `5bd95c57a279` | 7,097 | full | **34.3 s** | 33.4–38.0 s | 31 s | semgrep 31.2 s, trivy 18.5 s, checkov 13.6 s |
| django @ `5bd95c57a279` | 2 changed | diff | **5.4 s** | 5.3–5.7 s | 3 s | semgrep 3.2 s, gitleaks 0.1 s |

Per engine (median seconds):

| Corpus | Mode | checkov | gitleaks | semgrep | trivy | zizmor |
|---|---|---|---|---|---|---|
| juice-shop | full | 8.0 | 4.2 | 12.6 | 4.9 | 2.5 |
| juice-shop | diff | — | 0.1 | 3.2 | — | — |
| django | full | 13.6 | 6.4 | 31.2 | 18.5 | 3.2 |
| django | diff | — | 0.1 | 3.2 | — | — |

Each engine alone vs. side by side in the full scan (seconds):

| Corpus | Engine | Alone | In the full scan |
|---|---|---|---|
| juice-shop | semgrep | 9.9 | 12.6 |
| juice-shop | trivy | 2.6 | 4.9 |
| juice-shop | gitleaks | 3.3 | 4.2 |
| juice-shop | checkov | 3.6 | 8.0 |
| juice-shop | zizmor | 0.6 | 2.5 |
| django | semgrep | 26.0 | 31.2 |
| django | trivy | 9.3 | 18.5 |
| django | gitleaks | 5.5 | 6.4 |
| django | checkov | 9.4 | 13.6 |
| django | zizmor | 1.2 | 3.2 |

Numbers from one machine under its own load; compare runs from the same machine, not across machines. Diff mode: one existing file edited and one new file added, uncommitted, `--diff HEAD`.
