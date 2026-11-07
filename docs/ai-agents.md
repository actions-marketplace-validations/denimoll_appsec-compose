# AI agents

Driving scans and triage from an AI agent. Back to the [README](../README.md).

## Driving it from an AI agent (MCP)

[`appsec_mcp/`](../appsec_mcp/README.md) is an MCP server (stdio) over the same
CLI and `findings.json`: an agent calls `scan`, pages through `findings`, reads
one `finding` with its code (secrets masked), and records a verdict with
`suppress` — an `ignore:` entry with a reason and an expiry in the project's
`.appsec-compose.yml`. Install and register it:

```bash
appsec-compose mcp --setup        # once: a private venv with the pinned MCP SDK
claude mcp add --scope user appsec-compose -- appsec-compose mcp
```

Any other MCP client takes the same command (`"command": "appsec-compose",
"args": ["mcp"]`). Details and the recommended agent workflow:
[appsec_mcp/README.md](../appsec_mcp/README.md).

## The review loop

The scanners do the pattern matching; the agent's time is best spent on what
they cannot see. A run gives it both halves:

1. **Scan** — `scan(path)` over MCP, or `appsec-compose scan <path> --json`
   from a shell: the verdict, counts and the report paths.
2. **Read the brief** — [`review-brief.md`](reports.md#review-briefmd--hand-off-to-a-reviewer)
   lists the scope and the **blind spots**: unscanned categories, unresolved
   manifests, cross-file data flow, authorization and business logic. Those
   are where a manual review starts.
3. **Triage what gates** — `components(path)` for dependencies (one upgrade
   per package usually clears a whole component), `findings(path, gating_only=true)`
   for code, secrets and IaC, then
   `finding(path, fingerprint)` for the flagged code in context. A real issue
   is fixed in code; a false positive or an accepted risk is recorded with
   `suppress(path, fingerprint, reason, expires)`.
4. **Iterate on the change** — `scan(path, diff_base="origin/main")`
   re-checks only what the branch touched, in seconds
   ([diff mode](usage.md#diff-mode-scan-only-what-a-change-touched)).

Without MCP the same loop works from a shell: `--json` for the verdict,
`findings.json` for the findings (stable [`fingerprint`s](configuration.md#baseline-gate-on-new-findings)),
and `ignore:` entries by fingerprint in `.appsec-compose.yml`.

## Spending fewer tokens

The scan is deterministic and free; the agent's reading is what costs. Out of
the box the brief already folds what a reader would otherwise pay for twice —
repeats of one rule, non-gating low-confidence rules — into one line each, and
says what it costs before anyone opens it (`metrics.brief.approx_tokens` in the
JSON result, `brief_tokens` from the MCP `scan`). From there:

| Setting | Effect | When |
|---|---|---|
| `--min-confidence medium` (`min_confidence:` in config, `min_confidence` on MCP `scan`) | Semgrep's LOW-confidence rules stop gating and move to one-line entries | a first pass; a large or legacy codebase; whenever the brief is long |
| `--diff origin/main` | only what the branch changed is scanned, gated and briefed | reviewing a change, re-checking a fix |
| baseline (`--update-baseline` once) | gate on new findings only; the backlog is marked, not re-triaged | a codebase with a known backlog |
| `fail_on:` per category | e.g. `iac: none` keeps lint-grade IaC off the gate | a category the review does not cover |

None of these hides a finding: everything stays in `findings.json` and the
summaries. They decide what gates and what the brief spends code on.
