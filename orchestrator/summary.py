"""Render human-readable summaries (Markdown + HTML) from the scan."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment

from components import group
from config import SEVERITY_ORDER
from dedup import DedupStats
from normalize import Finding, ScanResult
from policy import PolicyResult

# Severities shown high -> low in the summary.
_DISPLAY_ORDER = list(reversed(SEVERITY_ORDER))
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

_MD_TEMPLATE = """# appsec-compose report

_Generated: {{ generated }} UTC_

**Policy:** fail_on = `{{ policy.label }}` -> **{{ verdict }}**
({{ policy.breaching }} finding(s) at/above threshold)
{% if scope %}

**Scope: {{ scope.label() }}.** Only the changed files were scanned and gated; unchanged code was not scanned, and effects of the change on it are not covered.{% if scope.dropped %} {{ scope.dropped }} raw finding(s) outside the changed files were dropped.{% endif %} {{ changed_line_count }} finding(s) sit on a changed line (Δ).
{% for name, reason in scope.skipped_engines | dictsort %}- {{ name }} not run: {{ reason }}
{% endfor %}
{% endif %}
{% if stats.removed %}
_Deduplicated: {{ total }} unique of {{ stats.raw }} raw findings ({{ stats.removed }} merged)._
{% endif %}
{% if suppressed_count %}
_Suppressed by ignore rules: {{ suppressed_count }} (excluded from the gate)._
{% endif %}
{% if delta %}
_Baseline: **{{ delta.new | length }} new**, {{ delta.known | length }} known{% if delta.fixed is not none %}, {{ delta.fixed }} fixed{% endif %} (gate applies to new only)._
{% endif %}
{% if enrichment and enrichment.requested %}
_Exploitability: {{ enrichment.resolved }}/{{ enrichment.requested }} CVE(s) resolved via CVE-PaaS, **{{ enrichment.exploitable }} exploitable** (KEV / public PoC / Nuclei template){% if enrichment.reprioritized %}, {{ enrichment.reprioritized }} reprioritized{% endif %}._
{% endif %}
{% if expired %}
## Expired suppressions

{% for e in expired %}- `{{ e.label }}` expired {{ e.expires }} — its findings count again.
{% endfor %}
{% endif %}
{% if coverage and coverage.warnings %}
## ⚠ SCA coverage

{% for w in coverage.warnings %}- {{ w.message }}
  **{{ w.advice }}**
{% endfor %}

{% endif %}
## Totals by severity

| {{ sev_order | join(" | ") }} | Total |
|{{ "---|" * (sev_order | length + 1) }}
| {% for s in sev_order %}{{ policy.severity_counts[s] }} | {% endfor %}{{ total }} |

## By category

{% for cat, n in category_counts %}- **{{ cat }}**: {{ n }}
{% endfor %}
## By tool

{% for tool, n in tool_counts %}- **{{ tool }}**: {{ n }}
{% endfor %}
## Reports

- Found: {{ reports_found | join(", ") or "none" }}
- Missing: {{ reports_missing | join(", ") or "none" }}
- Errored: {{ reports_errored | join("; ") or "none" }}

{% if components %}
## Vulnerable components ({{ components | length }})

{{ sca_count }} SCA finding(s) in {{ components | length }} package(s); each finding is still gated, suppressed and baselined on its own.

| Severity | Component | Vulnerabilities | Upgrade to | Declared in |
|---|---|---|---|---|
{% for c in components %}| {{ c.severity }}{% if c.malicious %} **MALICIOUS**{% elif c.exploitable %} (exploitable){% endif %} | `{{ c.package }}` | {{ c.findings | length }}: {% for s, n in c.counts.items() %}{{ n }} {{ s }}{% if not loop.last %}, {% endif %}{% endfor %} | {% if c.upgrade_to %}**{{ c.upgrade_to }}**{% elif not c.fixed_in %}no fix known{% else %}no single version — see below{% endif %}{% if c.unfixed and c.fixed_in %} ({{ c.unfixed }} without a fix){% endif %} | {{ c.files | join(", ") }} |
{% endfor %}

{% for c in components %}
<details><summary><code>{{ c.package }}</code> — {{ c.findings | length }} vulnerabilit{{ "y" if c.findings | length == 1 else "ies" }}</summary>

{% for f in c.findings %}- **{{ f.severity }}**{% if f.is_new %} 🆕{% endif %} `{{ f.rule_id }}`{% if f.aliases %} ({{ f.aliases | join(", ") }}){% endif %}{% if f.fixed_version %} — fixed in {{ f.fixed_version }}{% endif %}{% if f.malicious %} — **MALICIOUS**{% elif f.kev %} — KEV{% endif %}{% if f.url %} [↗]({{ f.url }}){% endif %}
{% endfor %}

</details>
{% endfor %}

{% endif %}
## Findings ({{ shown_count }}{% if total > shown_count + sca_count %} of {{ total - sca_count }}{% endif %}{% if components %}, besides the components above{% endif %})

{% if top_findings %}| Severity | Exploit | Tools | Category | Rule | Location |
|---|---|---|---|---|---|
{% for f in top_findings %}| {{ f.severity }}{% if f.is_new %} 🆕{% endif %}{% if f.on_changed_line %} Δ{% endif %} | {% if f.malicious %}**MALICIOUS**{% elif f.kev %}KEV{% elif f.poc %}PoC{% elif f.nuclei %}nuclei{% elif f.epss is not none %}EPSS {{ "%.2f" | format(f.epss) }}{% else %}—{% endif %} | {{ f.tools | join(", ") }} | {{ f.category }} | `{{ f.rule_id }}`{% if f.url %} [↗]({{ f.url }}){% endif %} | {{ f.file }}{% if f.line %}:{{ f.line }}{% endif %} |
{% endfor %}{% else %}_No findings._
{% endif %}
## Provenance

_appsec-compose {{ provenance.appsec_compose }} · {{ provenance.target }} target{% if provenance.offline %} · offline{% endif %}{% if scope %} · {{ scope.label() }}{% endif %}_

{% if timing_label %}Time: {{ timing_label }}{% if brief_label %} · {{ brief_label }}{% endif %}

{% endif %}
{% for tool, ref in provenance.engines.items() %}- **{{ tool }}**: `{{ ref }}`
{% endfor %}
{% if provenance.databases %}
{% for db, date in provenance.databases.items() %}- {{ db }} database updated {{ date }}
{% endfor %}
{% endif %}

> Native reports per tool are in `reports/native/`.
"""

_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>appsec-compose report</title>
<style>
 :root{
   --bg:#f4f6fb; --card:#fff; --ink:#1b2230; --muted:#5b6678; --line:#e3e8f0;
   --crit:#b3122b; --high:#d9531e; --med:#c98a00; --low:#1f6feb; --info:#7a8699;
   --pass:#1a7f37; --fail:#cf222e; --accent:#4451f0;
 }
 @media (prefers-color-scheme:dark){
   :root{--bg:#0d1117;--card:#161b22;--ink:#e6edf3;--muted:#9aa5b1;--line:#283040}
 }
 *{box-sizing:border-box}
 body{font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
   margin:0;background:var(--bg);color:var(--ink)}
 .wrap{max-width:1040px;margin:0 auto;padding:0 20px 56px}
 header{background:linear-gradient(135deg,#2b2f6f,#4451f0);color:#fff;padding:26px 0 22px;margin-bottom:24px}
 header .wrap{padding-top:0;padding-bottom:0}
 .brand{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:700;letter-spacing:.2px}
 .brand .dot{width:11px;height:11px;border-radius:50%;background:#aab4ff}
 .sub{opacity:.82;font-size:12.5px;margin-top:4px}
 .pill{display:inline-flex;align-items:center;gap:7px;padding:6px 13px;border-radius:999px;
   font-weight:700;font-size:13px;margin-top:14px}
 .pill.pass{background:rgba(255,255,255,.16);color:#d7ffe2}
 .pill.fail{background:#fff;color:var(--fail)}
 .pill .big{font-size:14px}
 h2{font-size:15px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);
   margin:30px 0 12px;font-weight:700}
 .cards{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}
 @media(max-width:720px){.cards{grid-template-columns:repeat(3,1fr)}}
 .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 14px 12px;
   box-shadow:0 1px 2px rgba(20,30,60,.04)}
 .card .n{font-size:26px;font-weight:750;line-height:1}
 .card .l{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-top:7px}
 .card.total .n{color:var(--accent)}
 .card.s-critical{border-top:3px solid var(--crit)} .card.s-critical .n{color:var(--crit)}
 .card.s-high{border-top:3px solid var(--high)} .card.s-high .n{color:var(--high)}
 .card.s-medium{border-top:3px solid var(--med)} .card.s-medium .n{color:var(--med)}
 .card.s-low{border-top:3px solid var(--low)} .card.s-low .n{color:var(--low)}
 .card.s-info{border-top:3px solid var(--info)} .card.s-info .n{color:var(--info)}
 .bar{display:flex;height:14px;border-radius:7px;overflow:hidden;margin:6px 0 2px;background:var(--line)}
 .bar i{display:block;height:100%}
 .bar .b-critical{background:var(--crit)} .bar .b-high{background:var(--high)}
 .bar .b-medium{background:var(--med)} .bar .b-low{background:var(--low)} .bar .b-info{background:var(--info)}
 .panels{display:grid;grid-template-columns:1fr 1fr;gap:18px}
 @media(max-width:720px){.panels{grid-template-columns:1fr}}
 .panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
 .panel h3{margin:0 0 10px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
 .row{display:flex;align-items:center;gap:10px;margin:7px 0}
 .row .k{flex:0 0 96px;font-weight:600;text-transform:capitalize}
 .row .t{flex:1;height:9px;border-radius:5px;background:var(--line);overflow:hidden}
 .row .t i{display:block;height:100%;background:var(--accent);opacity:.85}
 .row .v{flex:0 0 34px;text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}
 .chips{display:flex;flex-wrap:wrap;gap:8px}
 .alert{background:var(--card);border:1px solid var(--med);border-left:4px solid var(--med);
   border-radius:10px;padding:14px 16px;margin:22px 0 0}
 .alert-t{font-weight:700;color:var(--med);margin-bottom:6px}
 .alert-a{margin-top:6px;color:var(--muted)}
 .expl{display:inline-block;font-size:11px;font-weight:700;padding:1px 6px;border-radius:5px;
   margin:1px 2px 1px 0;white-space:nowrap}
 .expl.kev{background:var(--crit);color:#fff}
 .expl.poc{background:var(--high);color:#fff}
 .expl.epss{background:transparent;color:var(--muted);border:1px solid var(--line);font-weight:600}
 .chip{font-size:12px;padding:4px 10px;border-radius:999px;border:1px solid var(--line);background:var(--card)}
 .chip.ok{border-color:#bce3c8;color:var(--pass)} .chip.warn{border-color:#f3d2a6;color:#9a6700}
 .chip.err{border-color:#f0bcc2;color:var(--fail)}
 table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
   border-radius:12px;overflow:hidden}
 thead th{position:sticky;top:0;background:var(--card);text-align:left;font-size:11px;
   text-transform:uppercase;letter-spacing:.5px;color:var(--muted);padding:11px 12px;border-bottom:1px solid var(--line)}
 td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
 tbody tr:last-child td{border-bottom:0}
 tbody tr:nth-child(even){background:rgba(127,140,170,.05)}
 .sev{display:inline-block;min-width:62px;text-align:center;color:#fff;font-weight:700;font-size:11px;
   text-transform:uppercase;letter-spacing:.4px;padding:3px 8px;border-radius:6px}
 .sev-critical{background:var(--crit)} .sev-high{background:var(--high)}
 .sev-medium{background:var(--med)} .sev-low{background:var(--low)} .sev-info{background:var(--info)}
 .filters{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
 .filters button{font:inherit;font-size:12.5px;padding:5px 12px;border:1px solid var(--line);
   background:var(--card);color:var(--ink);border-radius:999px;cursor:pointer;text-transform:capitalize}
 .filters button.active{background:var(--accent);color:#fff;border-color:var(--accent)}
 .badge-chg{display:inline-block;background:transparent;color:var(--accent);border:1px solid var(--accent);
   font-size:10px;font-weight:700;padding:1px 5px;border-radius:5px;margin-left:6px;vertical-align:middle}
 .badge-new{display:inline-block;background:var(--accent);color:#fff;font-size:10px;font-weight:700;
   padding:2px 6px;border-radius:5px;margin-left:6px;vertical-align:middle;letter-spacing:.3px}
 tr.new td:first-child{box-shadow:inset 3px 0 var(--accent)}
 details.d>summary{cursor:pointer;color:var(--accent);font-size:12px;list-style:none}
 details.d>summary::-webkit-details-marker{display:none}
 details.d p{margin:.45rem 0 0;color:var(--muted);font-size:12.5px;max-width:52ch;white-space:normal}
 details.d a{color:var(--accent)}
 table.inner{margin:.4rem 0 0;width:auto} table.inner td{padding:.2rem .5rem;border:0;vertical-align:top}
 code,.loc{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
 .loc{color:var(--muted)} .tool{font-weight:600}
 footer{color:var(--muted);font-size:12px;margin-top:26px}
</style></head><body>
<header><div class="wrap">
  <div class="brand"><span class="dot"></span>appsec-compose</div>
  <div class="sub">appsec-compose {{ provenance.appsec_compose }} &middot; generated {{ generated }} UTC &middot; policy fail_on = {{ policy.label }}{% if stats.removed %} &middot; {{ total }} unique of {{ stats.raw }} ({{ stats.removed }} merged){% endif %}{% if suppressed_count %} &middot; {{ suppressed_count }} suppressed{% endif %}{% if delta %} &middot; {{ delta.new | length }} new / {{ delta.known | length }} known{% if delta.fixed is not none %} / {{ delta.fixed }} fixed{% endif %}{% endif %}{% if scope %} &middot; {{ scope.label() }}{% endif %}{% if enrichment and enrichment.exploitable %} &middot; {{ enrichment.exploitable }} exploitable{% endif %}{% if timing_label %} &middot; {{ timing_label }}{% endif %}{% if brief_label %} &middot; {{ brief_label }}{% endif %}</div>
  <div class="pill {{ 'fail' if policy.exit_code else 'pass' }}">
    <span class="big">{{ '✗' if policy.exit_code else '✓' }} {{ verdict }}</span>
    &middot; {{ policy.breaching }} at/above threshold
  </div>
</div></header>

<div class="wrap">

{% if scope %}
<div class="alert">
  <div class="alert-t">Diff scan &mdash; {{ scope.files | length }} changed file(s) vs <code>{{ scope.base }}</code></div>
  <div>Only the files changed since merge-base <code>{{ scope.merge_base[:12] }}</code> were scanned and gated. Unchanged code was not scanned, and effects of the change on it are not covered.{% if scope.dropped %} {{ scope.dropped }} raw finding(s) outside the changed files were dropped.{% endif %} {{ changed_line_count }} finding(s) sit on a changed line (<span class="badge-chg">&Delta; line</span>).</div>
  {% if scope.skipped_engines %}<div class="alert-a">Not run: {% for name, reason in scope.skipped_engines | dictsort %}{{ name }} ({{ reason }}){% if not loop.last %}; {% endif %}{% endfor %}</div>{% endif %}
</div>
{% endif %}
{% if coverage and coverage.warnings %}
{% for w in coverage.warnings %}
<div class="alert">
  <div class="alert-t">&#9888; SCA coverage gap</div>
  <div>{{ w.message }}</div>
  <div class="alert-a">{{ w.advice }}</div>
</div>
{% endfor %}
{% endif %}
{% if expired %}
<div class="alert">
  <div class="alert-t">&#9888; Expired suppressions</div>
  {% for e in expired %}
  <div><code>{{ e.label }}</code> expired {{ e.expires }} &mdash; its findings count again.</div>
  {% endfor %}
  <div class="alert-a">Re-argue the risk and set a new <code>expires</code>, or drop the entry.</div>
</div>
{% endif %}
{% if enrichment and enrichment.error %}
<div class="alert">
  <div class="alert-t">&#9888; Exploitability data unavailable</div>
  <div>CVE-PaaS could not be reached: {{ enrichment.error }}</div>
  <div class="alert-a">Severities are the scanners' own; no exploitability gate was applied.</div>
</div>
{% endif %}
<h2>Severity overview</h2>
<div class="cards">
  <div class="card total"><div class="n">{{ total }}</div><div class="l">Total</div></div>
  {% for s in sev_order %}
  <div class="card s-{{ s }}"><div class="n">{{ policy.severity_counts[s] }}</div><div class="l">{{ s }}</div></div>
  {% endfor %}
</div>
{% if total %}
<div class="bar">
  {% for s in sev_order %}{% set c = policy.severity_counts[s] %}{% if c %}<i class="b-{{ s }}" style="width:{{ '%.2f'|format(c / total * 100) }}%"></i>{% endif %}{% endfor %}
</div>
{% endif %}

<h2>Breakdown</h2>
<div class="panels">
  <div class="panel"><h3>By category</h3>
    {% for cat, n in category_counts %}
    <div class="row"><span class="k">{{ cat }}</span>
      <span class="t"><i style="width:{{ '%.1f'|format(n / total * 100 if total else 0) }}%"></i></span>
      <span class="v">{{ n }}</span></div>
    {% else %}<p class="loc">No findings.</p>{% endfor %}
  </div>
  <div class="panel"><h3>By tool</h3>
    {% for tool, n in tool_counts %}
    <div class="row"><span class="k">{{ tool }}</span>
      <span class="t"><i style="width:{{ '%.1f'|format(n / total * 100 if total else 0) }}%"></i></span>
      <span class="v">{{ n }}</span></div>
    {% else %}<p class="loc">No findings.</p>{% endfor %}
  </div>
</div>

<h2>Reports</h2>
<div class="chips">
  {% for r in reports_found %}<span class="chip ok">✓ {{ r }}</span>{% endfor %}
  {% for r in reports_missing %}<span class="chip warn">– {{ r }}</span>{% endfor %}
  {% for r in reports_errored %}<span class="chip err">! {{ r }}</span>{% endfor %}
  {% if not reports_found and not reports_missing and not reports_errored %}<span class="chip">none</span>{% endif %}
</div>

{% if components %}
<h2>Vulnerable components <span style="text-transform:none;color:var(--muted);font-weight:400">({{ components | length }} package(s), {{ sca_count }} finding(s))</span></h2>
<table>
  <thead><tr><th>Severity</th><th>Component</th><th>Vulnerabilities</th><th>Upgrade to</th><th>Declared in</th></tr></thead>
  <tbody>
  {% for c in components %}
    <tr{% if c.findings | selectattr("is_new") | list %} class="new"{% endif %}>
      <td><span class="sev sev-{{ c.severity }}">{{ c.severity }}</span>{% if c.malicious %} <span class="expl kev" title="an advisory says this package is malware">MALICIOUS</span>{% elif c.exploitable %} <span class="expl kev" title="at least one vulnerability is known exploited or has a public exploit">exploitable</span>{% endif %}</td>
      <td><code>{{ c.name }}</code><br><span class="loc">{{ c.version }}</span></td>
      <td>
        <details class="d"><summary>{{ c.findings | length }} &mdash; {% for s, n in c.counts.items() %}{{ n }} {{ s }}{% if not loop.last %}, {% endif %}{% endfor %}</summary>
          <table class="inner">
          {% for f in c.findings %}
            <tr><td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span>{% if f.is_new %}<span class="badge-new">NEW</span>{% endif %}</td>
                <td>{% if f.url %}<a href="{{ f.url }}" target="_blank" rel="noopener noreferrer"><code>{{ f.rule_id }}</code></a>{% else %}<code>{{ f.rule_id }}</code>{% endif %}{% if f.aliases %}<br><span class="loc">{{ f.aliases | join(", ") }}</span>{% endif %}</td>
                <td class="loc">{% if f.fixed_version %}fixed in {{ f.fixed_version }}{% else %}no fix known{% endif %}</td>
                <td>{% if f.malicious %}<span class="expl kev">MALICIOUS</span>{% endif %}{% if f.kev %}<span class="expl kev">KEV</span>{% endif %}{% if f.poc %}<span class="expl poc">PoC</span>{% endif %}{% if f.epss is not none %}<span class="expl epss">EPSS {{ "%.2f" | format(f.epss) }}</span>{% endif %}</td></tr>
          {% endfor %}
          </table>
        </details>
      </td>
      <td>{% if c.upgrade_to %}<b>{{ c.upgrade_to }}</b>{% elif not c.fixed_in %}<span class="loc">no fix known</span>{% else %}<span class="loc" title="the fixes listed per vulnerability cannot be compared into one version">no single version</span>{% endif %}{% if c.unfixed and c.fixed_in %}<br><span class="loc">{{ c.unfixed }} without a fix</span>{% endif %}</td>
      <td class="loc">{{ c.files | join(", ") }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<h2>Findings <span style="text-transform:none;color:var(--muted);font-weight:400">({{ shown_count }}{% if total > shown_count + sca_count %} of {{ total - sca_count }}{% endif %}{% if components %}, besides the components above{% endif %})</span></h2>
{% if top_findings %}
<div class="filters" id="filters">
  <button class="active" data-f="all">All ({{ shown_count }})</button>
  {% for cat, n in filter_cats %}<button data-f="{{ cat }}">{{ cat }} ({{ n }})</button>{% endfor %}
</div>
<table>
  <thead><tr><th>Severity</th><th>Exploit</th><th>Tools</th><th>Category</th><th>Rule</th><th>Location</th><th>Detail</th></tr></thead>
  <tbody>
  {% for f in top_findings %}
    <tr data-cat="{{ f.category }}"{% if f.is_new %} class="new"{% endif %}>
      <td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span>{% if f.is_new %}<span class="badge-new">NEW</span>{% endif %}{% if f.on_changed_line %}<span class="badge-chg" title="on a line the change added or modified">&Delta; line</span>{% endif %}</td>
      <td>
        {% if f.malicious %}<span class="expl kev" title="the advisory says this package is malware, not a vulnerable release">MALICIOUS</span>{% endif %}
        {% if f.kev %}<span class="expl kev" title="CISA Known Exploited Vulnerabilities">KEV</span>{% endif %}
        {% if f.poc %}<span class="expl poc" title="public proof of concept">PoC</span>{% endif %}
        {% if f.nuclei %}<span class="expl poc" title="Nuclei template exists">nuclei</span>{% endif %}
        {% if f.epss is not none %}<span class="expl epss" title="probability of exploitation in the wild">EPSS {{ "%.2f" | format(f.epss) }}</span>{% endif %}
        {% if not f.malicious and not f.kev and not f.poc and not f.nuclei and f.epss is none %}<span class="loc">&mdash;</span>{% endif %}
      </td>
      <td class="tool">{{ f.tools | join(", ") }}</td>
      <td>{{ f.category }}</td>
      <td><code>{{ f.rule_id }}</code>{% if f.aliases %}<br><span class="loc">{{ f.aliases | join(", ") }}</span>{% endif %}</td>
      <td class="loc">{{ f.file }}{% if f.line %}:{{ f.line }}{% endif %}</td>
      <td>{% if f.description or f.url %}<details class="d"><summary>ⓘ details</summary><p>{% if f.description %}{{ f.description | truncate(360, True) }}{% endif %}{% if f.url %}{% if f.description %}<br>{% endif %}<a href="{{ f.url }}" target="_blank" rel="noopener noreferrer">advisory ↗</a>{% endif %}</p></details>{% else %}<span class="loc">—</span>{% endif %}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}<p class="loc">No findings 🎉</p>{% endif %}

<footer>Native per-tool reports are in <code>reports/native/</code>;
consolidated machine output in <code>reports/findings.json</code>.</footer>

</div>
<script>
(function () {
  var bar = document.getElementById('filters');
  if (!bar) return;
  bar.addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    var f = b.getAttribute('data-f');
    bar.querySelectorAll('button').forEach(function (x) {
      x.classList.toggle('active', x === b);
    });
    document.querySelectorAll('tbody tr').forEach(function (tr) {
      tr.style.display = (f === 'all' || tr.getAttribute('data-cat') === f) ? '' : 'none';
    });
  });
})();
</script>
</body></html>
"""

_TOP_N = 1000


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-_RANK[f.severity], f.category, f.file))


def timing_label(timings: dict | None) -> str:
    """"took 20 s (scanners 18 s: semgrep 18 s, checkov 13 s, trivy 5 s)"."""
    if not timings:
        return ""
    parts = []
    if timings.get("total_s") is not None:
        parts.append(f"took {timings['total_s']} s")
    engines = timings.get("engines") or {}
    slowest = ", ".join(f"{e} {s:g} s" for e, s in list(engines.items())[:3])
    if timings.get("scanners_s") is not None:
        parts.append(f"(scanners {timings['scanners_s']} s" + (f": {slowest})" if slowest else ")"))
    elif slowest:
        parts.append(f"({slowest})")
    return " ".join(parts)


def _context(result: ScanResult, policy: PolicyResult, findings: list[Finding],
             stats: DedupStats, suppressed_count: int, delta,
             coverage=None, enrichment=None, expired=None,
             provenance=None, scope=None) -> dict:
    total = sum(policy.severity_counts.values())
    # SCA is shown per component; the findings table holds everything else.
    components = group(findings)
    sca_count = sum(len(c.findings) for c in components)
    top = _sort_findings([f for f in findings if f.category != "sca"])[:_TOP_N]
    # Filter chips are derived from the rows actually shown, so a filter can
    # never come up empty (e.g. when a category falls outside the display cap).
    shown = Counter(f.category for f in top)
    filter_cats = sorted(shown.items())
    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "policy": policy,
        "stats": stats,
        "suppressed_count": suppressed_count,
        "delta": delta,
        "coverage": coverage,
        "enrichment": enrichment,
        "expired": expired or [],
        "provenance": provenance or {},
        "timing_label": timing_label((provenance or {}).get("timings")),
        "scope": scope,
        "changed_line_count": sum(1 for f in findings
                                  if getattr(f, "on_changed_line", None)),
        "verdict": "FAIL" if policy.exit_code else "PASS",
        "sev_order": _DISPLAY_ORDER,
        "total": total,
        "category_counts": sorted(policy.category_counts.items()),
        "tool_counts": sorted(policy.tool_counts.items()),
        "reports_found": result.reports_found,
        "reports_missing": result.reports_missing,
        "reports_errored": result.reports_errored,
        "top_findings": top,
        "components": components,
        "sca_count": sca_count,
        "filter_cats": filter_cats,
        "shown_count": len(top),
        "top_n": _TOP_N,
    }


def render(result: ScanResult, policy: PolicyResult, findings: list[Finding],
           stats: DedupStats, out_dir: str = "/reports",
           suppressed_count: int = 0, delta=None, coverage=None,
           enrichment=None, expired=None, provenance=None, scope=None,
           brief_tokens: int | None = None) -> None:
    # Markdown: HTML-escaping would corrupt it. The HTML report below escapes.
    env = Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)  # nosemgrep: direct-use-of-jinja2
    ctx = _context(result, policy, findings, stats, suppressed_count, delta,
                   coverage, enrichment, expired, provenance, scope)
    ctx["brief_label"] = (f"review-brief.md ~{brief_tokens / 1000:.1f}k tokens"
                          if brief_tokens and brief_tokens >= 1000
                          else f"review-brief.md ~{brief_tokens} tokens" if brief_tokens else "")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.md").write_text(env.from_string(_MD_TEMPLATE).render(**ctx))

    html_env = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)  # nosemgrep: direct-use-of-jinja2
    (out / "summary.html").write_text(html_env.from_string(_HTML_TEMPLATE).render(**ctx))
