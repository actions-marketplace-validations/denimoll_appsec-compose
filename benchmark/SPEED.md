# Speed

How long appsec-compose takes on real codebases with the shipped defaults: median of repeated runs after a warm-up (databases cached, collector image built). Engines run in parallel, so a scan costs what its slowest engine costs. Re-run with `python3 benchmark/speed.py`; method in its docstring.

appsec-compose 1.2.0 · 2026-11-03T18:00:51Z · macOS-27.0.1-arm64-arm-64bit-Mach-O · 11 CPUs (Docker: 11 CPUs, 7.7 GB) · load average at start 3.22, 3.74, 4.73

| Corpus | Files | Mode | Median | Range | Scanners | Slowest engines |
|---|---|---|---|---|---|---|
| juice-shop @ `717f5efa886b` | 1,468 | full | **13.7 s** | 13.6–13.7 s | 12 s | semgrep 11.8 s, trivy 5.9 s, checkov 5.6 s |
| juice-shop @ `717f5efa886b` | 2 changed | diff | **4.7 s** | 4.7–4.9 s | 4 s | semgrep 2.9 s, gitleaks 0.1 s |
| django @ `5bd95c57a279` | 7,097 | full | **34.6 s** | 31.9–34.9 s | 32 s | semgrep 31.7 s, trivy 19.2 s, checkov 12.6 s |
| django @ `5bd95c57a279` | 2 changed | diff | **4.9 s** | 4.8–5.1 s | 4 s | semgrep 3 s, gitleaks 0.1 s |

Per engine (median seconds):

| Corpus | Mode | checkov | gitleaks | semgrep | trivy | zizmor |
|---|---|---|---|---|---|---|
| juice-shop | full | 5.6 | 4.2 | 11.8 | 5.9 | 3.6 |
| juice-shop | diff | — | 0.1 | 2.9 | — | — |
| django | full | 12.6 | 6.7 | 31.7 | 19.2 | 3.5 |
| django | diff | — | 0.1 | 3.0 | — | — |

Each engine alone vs. side by side in the full scan (seconds):

| Corpus | Engine | Alone | In the full scan |
|---|---|---|---|
| juice-shop | semgrep | 9.9 | 11.8 |
| juice-shop | trivy | 2.5 | 5.9 |
| juice-shop | gitleaks | 3.1 | 4.2 |
| juice-shop | checkov | 4.1 | 5.6 |
| juice-shop | zizmor | 0.6 | 3.6 |
| django | semgrep | 24.3 | 31.7 |
| django | trivy | 8.9 | 19.2 |
| django | gitleaks | 5.3 | 6.7 |
| django | checkov | 9.2 | 12.6 |
| django | zizmor | 1.1 | 3.5 |

Numbers from one machine under its own load; compare runs from the same machine, not across machines. Diff mode: one existing file edited and one new file added, uncommitted, `--diff HEAD`.
