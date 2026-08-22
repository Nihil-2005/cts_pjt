"""Risk Intelligence Dashboard — Clean, professional dark theme.

Generates a self-contained HTML file with:
  - Chart.js 4  — horizontal bar charts, line chart
  - D3 v7       — force-directed attack-path graph
  - Vanilla JS  — App object architecture, no global pollution

All libraries loaded from cdnjs.cloudflare.com (works offline after
first browser cache).  Data is injected as a single JSON constant so
the file is fully self-contained after generation.
"""
from __future__ import annotations

import html as html_lib
import json
import os
from typing import Any, Dict, List, Optional

from .models import Finding, RunSummary


# ─────────────────────── data serialisation ──────────────────────────────────

def _esc(s: Any) -> str:
    return html_lib.escape(str(s) if s is not None else "")


def _serialize_findings(ranked: List[Finding]) -> List[Dict]:
    out = []
    for i, f in enumerate(ranked):
        sb = f.score_breakdown or {}
        out.append({
            "rank":                i + 1,
            "score":               f.score or 0,
            "priority":            f.priority or "",
            "sla_hours":           f.sla_hours or 0,
            "owner":               f.owner or "",
            "product":             f.product or "",
            "scanner":             f.scanner or "",
            "title":               f.title or "",
            "severity":            f.severity or "",
            "cve":                 f.cve or "",
            "cwe":                 f.cwe or "",
            "endpoint":            f.endpoint or "",
            "parameter":           f.parameter or "",
            "epss_score":          round(float(f.epss_score or 0), 4),
            "epss_percentile":     round(float(f.epss_percentile or 0), 4),
            "epss_trend":          round(float(f.epss_trend or 0), 4),
            "kev":                 bool(f.kev),
            "kev_date":            f.kev_date or "",
            "exploit_available":   bool(f.exploit_available),
            "exploit_source":      f.exploit_source or "",
            "escalation_potential": round(float(f.escalation_potential or 0), 3),
            "description":         (f.description or "")[:400],
            "package":             f.package or "",
            "fixed_version":       f.fixed_version or "",
            "ai_fp_probability":   sb.get("ai_fp_probability", ""),
            "ai_fp_reason":        sb.get("ai_fp_reason", ""),
            "ai_remediation":      sb.get("ai_remediation", ""),
            "score_components":    sb.get("components", {}),
            "score_drivers":       sb.get("drivers", []),
            "remediation":         [
                {"kind": s.get("kind", ""), "text": (s.get("text", ""))[:250]}
                for s in (f.remediation_suggestions or [])[:5]
            ],
        })
    return out


def _serialize_quarantine(findings: List[Finding]) -> List[Dict]:
    return [
        {
            "product": f.product or "",
            "scanner": f.scanner or "",
            "title":   (f.title or "")[:80],
            "severity": f.severity or "",
            "reason":  f.quarantine_reason or "",
            "cve":     f.cve or "",
        }
        for f in findings if f.status == "quarantined"
    ]


# ─────────────────────────── HTML template ───────────────────────────────────

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Risk Intelligence Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet" media="print" onload="this.media='all'">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js" defer></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js" defer></script>
<style>
/* ═══════════════════ 1. DESIGN TOKENS ═══════════════════ */
:root{
  --bg-base:#0B0D12;--bg-elevated:#111318;--bg-surface:#16181F;--bg-hover:#1A1D26;
  --border-subtle:rgba(255,255,255,0.04);--border-default:rgba(255,255,255,0.07);--border-active:rgba(255,255,255,0.12);
  --text-primary:#E8EAED;--text-secondary:#9CA3AF;--text-tertiary:#6B7280;--text-muted:#4B5563;
  --risk-critical:#EF4444;--risk-high:#F59E0B;--risk-medium:#EAB308;--risk-low:#22C55E;--risk-info:#3B82F6;--risk-neutral:#6B7280;
  --space-1:4px;--space-2:8px;--space-3:12px;--space-4:16px;--space-5:20px;--space-6:24px;--space-8:32px;--space-10:40px;--space-12:48px;
  --text-2xs:0.625rem;--text-xs:0.6875rem;--text-sm:0.786rem;--text-base:0.875rem;
  --text-md:1rem;--text-lg:1.125rem;--text-xl:1.5rem;--text-2xl:1.875rem;
  --font-sans:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;
  --font-mono:'JetBrains Mono','SF Mono',monospace;
  --risk-info-hover:#2563eb;
}

/* ═══════════════════ 2. RESET & BASE ═══════════════════ */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:var(--font-sans);background:var(--bg-base);color:var(--text-primary);min-height:100vh;line-height:1.4;-webkit-font-smoothing:antialiased;font-size:var(--text-base)}
:focus-visible{outline:2px solid var(--risk-info);outline-offset:2px}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg-base)}
::-webkit-scrollbar-thumb{background:var(--bg-hover);border-radius:3px}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:0.01ms!important;transition-duration:0.01ms!important}}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}
@media print{.app-header,.tab-nav,.header-actions,.toast-container{display:none!important}.page{display:block!important;padding:0!important;max-width:none!important}.card{break-inside:avoid;page-break-inside:avoid;border:1px solid #ddd;background:#fff;color:#000}.kpi-value,.score-num,.text-primary{color:#000!important}.dimmed,.text-secondary,.text-tertiary,.text-muted{color:#555!important}}

/* ═══════════════════ 3. LAYOUT ═══════════════════ */
.page{display:none;padding:var(--space-6);max-width:1400px;margin:0 auto}
.page.active{display:block}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:var(--space-4)}
.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:var(--space-4)}

/* ═══════════════════ 4. COMPONENTS ═══════════════════ */

/* --- Header --- */
.app-header{position:sticky;top:0;z-index:100;background:var(--bg-base);border-bottom:1px solid var(--border-subtle);padding:0 var(--space-6);display:flex;align-items:center;gap:var(--space-4);height:48px}
.header-brand{display:flex;align-items:center;gap:var(--space-2);flex-shrink:0}
.header-brand svg{color:var(--risk-info);width:16px;height:16px}
.header-brand-text{font-size:var(--text-md);font-weight:600;color:var(--text-primary);white-space:nowrap}
.header-meta{display:flex;align-items:center;gap:var(--space-2);flex:1;overflow:hidden;white-space:nowrap;font-size:var(--text-xs);color:var(--text-tertiary)}
.header-meta .p1-count{color:var(--risk-critical)}
.header-meta .p2-count{color:var(--risk-high)}
.tab-nav{display:flex;gap:2px;overflow-x:auto;flex-shrink:0;scrollbar-width:none}
.tab-nav::-webkit-scrollbar{display:none}
.tab-btn{padding:var(--space-2) var(--space-3);border:none;cursor:pointer;font-size:var(--text-xs);font-weight:500;color:var(--text-tertiary);background:transparent;transition:color 150ms;white-space:nowrap;font-family:var(--font-sans);position:relative}
.tab-btn::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;background:transparent}
.tab-btn:hover{color:var(--text-secondary)}
.tab-btn.active{color:var(--text-primary)}
.tab-btn.active::after{background:var(--risk-info)}

/* --- Cards --- */
.card{background:var(--bg-elevated);border:1px solid var(--border-subtle);border-radius:8px;padding:var(--space-5);transition:border-color 150ms}
.card:hover{border-color:var(--border-default)}
.card-header{display:flex;align-items:center;gap:var(--space-2);margin-bottom:var(--space-4);font-size:var(--text-xs);font-weight:500;color:var(--text-secondary)}

/* --- KPI --- */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:var(--space-4);margin-bottom:var(--space-6)}
.kpi-value{font-size:var(--text-xl);font-weight:700;line-height:1.2;color:var(--text-primary);font-variant-numeric:tabular-nums}
.kpi-label{font-size:var(--text-xs);font-weight:500;color:var(--text-secondary);margin-top:var(--space-2)}
.kpi-sub{font-size:var(--text-xs);color:var(--text-tertiary);margin-top:var(--space-1)}

/* --- Buttons --- */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:var(--space-2);padding:var(--space-2) var(--space-4);border-radius:6px;font-size:var(--text-xs);font-weight:600;font-family:var(--font-sans);cursor:pointer;border:1px solid transparent;transition:all 150ms;text-decoration:none;line-height:1.4}
.btn-primary{background:var(--risk-info);color:#fff;border-color:var(--risk-info)}
.btn-primary:hover{background:var(--risk-info-hover);border-color:var(--risk-info-hover)}
.btn-secondary{background:var(--bg-surface);color:var(--text-secondary);border-color:var(--border-default)}
.btn-secondary:hover{background:var(--bg-hover);color:var(--text-primary);border-color:var(--border-active)}
.btn-sm{padding:var(--space-2) var(--space-3);font-size:var(--text-xs)}

/* --- Badges --- */
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;text-transform:uppercase;white-space:nowrap;line-height:1.4}
.b-p1{background:rgba(239,68,68,0.1);color:var(--risk-critical)}
.b-p2{background:rgba(245,158,11,0.1);color:var(--risk-high)}
.b-p3{background:rgba(234,179,8,0.1);color:var(--risk-medium)}
.b-p4{background:rgba(107,114,128,0.1);color:var(--text-tertiary)}
.b-critical{background:rgba(239,68,68,0.08);color:var(--risk-critical)}
.b-high{background:rgba(245,158,11,0.08);color:var(--risk-high)}
.b-medium{background:rgba(234,179,8,0.08);color:var(--risk-medium)}
.b-low{background:rgba(34,197,94,0.08);color:var(--risk-low)}
.b-info-sev{background:rgba(107,114,128,0.08);color:var(--text-secondary)}

/* --- Table --- */
.table-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--border-subtle)}
.data-table{width:100%;border-collapse:separate;border-spacing:0;font-size:var(--text-base)}
.data-table thead th{background:var(--bg-surface);color:var(--text-tertiary);padding:10px 12px;text-align:left;font-weight:600;font-size:var(--text-xs);white-space:nowrap;border-bottom:1px solid var(--border-subtle);position:sticky;top:0;z-index:10}
.data-table thead th[data-col]{cursor:pointer}
.data-table thead th:hover{color:var(--text-secondary)}
.data-table thead th.sorted{color:var(--risk-info)}
.sort-arrow{font-size:9px;margin-left:3px;opacity:0}
.data-table thead th:hover .sort-arrow{opacity:0.5}
.data-table thead th.sorted .sort-arrow{opacity:1;color:var(--risk-info)}
.data-table tbody tr{border-bottom:1px solid var(--border-subtle);transition:background 150ms;cursor:pointer;min-height:44px}
.data-table tbody tr:hover td{background:var(--bg-hover)}
.data-table tbody tr.expanded td{background:var(--bg-surface)}
.data-table td{padding:10px 12px;vertical-align:middle;color:var(--text-secondary)}

/* --- Inputs --- */
.input{background:var(--bg-surface);border:1px solid var(--border-default);border-radius:6px;padding:8px 12px;color:var(--text-primary);font-size:var(--text-base);font-family:var(--font-sans);outline:none;transition:border-color 150ms;width:100%}
.input:focus{border-color:var(--risk-info)}
.input::placeholder{color:var(--text-tertiary)}
select.input{cursor:pointer}
select.input option{background:var(--bg-elevated);color:var(--text-primary)}
.form-label{font-size:var(--text-xs);font-weight:500;color:var(--text-secondary);margin-bottom:4px;display:block}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--space-4);max-width:700px}

/* --- Toast --- */
.toast-container{position:fixed;top:var(--space-4);right:var(--space-4);z-index:1000;display:flex;flex-direction:column;gap:var(--space-2);pointer-events:none}
.toast{display:flex;align-items:center;gap:var(--space-2);padding:10px 16px;border-radius:8px;background:var(--bg-elevated);border:1px solid var(--border-default);font-size:var(--text-xs);color:var(--text-secondary);pointer-events:auto;max-width:400px;animation:toastIn .2s ease,toastOut .2s ease 4.8s forwards}
.toast-success{border-color:rgba(34,197,94,0.2)}
.toast-error{border-color:rgba(239,68,68,0.2)}
.toast-info{border-color:rgba(59,130,246,0.2)}
@keyframes toastIn{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:translateX(0)}}
@keyframes toastOut{to{opacity:0;transform:translateX(16px)}}

/* --- Empty State --- */
.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:var(--space-10) var(--space-5);text-align:center;color:var(--text-muted)}
.empty-state-title{font-size:var(--text-base);font-weight:600;color:var(--text-secondary);margin-top:var(--space-3)}
.empty-state-desc{font-size:var(--text-xs);color:var(--text-tertiary);margin-top:var(--space-1)}

/* --- Utility --- */
.mono{font-family:var(--font-mono);font-variant-numeric:tabular-nums}
.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}
.dimmed{color:var(--text-muted)}
.no-wrap{white-space:nowrap}
.hidden{display:none}
.text-critical{color:var(--risk-critical)}.text-low{color:var(--risk-low)}
.mb-4{margin-bottom:var(--space-4)}.mb-6{margin-bottom:var(--space-6)}

/* ═══════════════════ 5. PAGES ═══════════════════ */

/* --- Findings --- */
.filter-row{display:flex;gap:var(--space-2);align-items:center;flex-wrap:wrap;margin-bottom:var(--space-4)}
.filter-row .input{max-width:280px}
.filter-row select.input{width:140px}
.result-count{margin-left:auto;font-size:var(--text-xs);color:var(--text-tertiary);white-space:nowrap}
.score-num{font-family:var(--font-mono);font-weight:600;font-size:13px;font-variant-numeric:tabular-nums}
.detail-row{display:none}
.detail-row.open{display:table-row}
.detail-panel{padding:var(--space-5);background:var(--bg-surface);border-top:1px solid var(--border-subtle);display:grid;grid-template-columns:repeat(2,1fr);gap:var(--space-6)}
@media(max-width:700px){.detail-panel{grid-template-columns:1fr}}
.detail-section-title{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:var(--space-3)}
.detail-row-item{display:flex;gap:var(--space-2);margin-bottom:var(--space-2);font-size:var(--text-xs);line-height:1.5}
.detail-key{color:var(--text-tertiary);flex-shrink:0;width:120px;font-weight:600}
.detail-val{color:var(--text-secondary);word-break:break-word}
.detail-val a{color:var(--risk-info);text-decoration:none}
.detail-val a:hover{text-decoration:underline}
.ai-box{grid-column:1/-1;border-left:3px solid var(--risk-info);background:var(--bg-surface);padding:var(--space-4);border-radius:0 6px 6px 0}
.ai-label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--risk-info);margin-bottom:var(--space-2)}
.ai-content{font-size:var(--text-base);line-height:1.7;color:var(--text-secondary)}
.rem-list{list-style:none}
.rem-list li{padding:var(--space-1) 0;font-size:var(--text-xs);border-bottom:1px solid var(--border-subtle);display:flex;gap:var(--space-2);color:var(--text-secondary)}
.rem-list li:last-child{border:none}
.rem-kind{font-size:10px;font-weight:600;text-transform:uppercase;color:var(--text-muted);flex-shrink:0;margin-top:1px}
.cve-link{color:var(--risk-info);text-decoration:none;font-family:var(--font-mono);font-size:11px}
.cve-link:hover{text-decoration:underline}

/* --- Attack Paths --- */
#ap-container{position:relative;border-radius:8px;overflow:hidden;background:var(--bg-elevated)}
#ap-svg{display:block;width:100%}
.ap-legend{display:flex;gap:var(--space-4);margin-bottom:var(--space-3);font-size:var(--text-xs);color:var(--text-secondary)}
.ap-legend span{display:flex;align-items:center;gap:var(--space-2)}
.ap-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.ap-tooltip{position:absolute;pointer-events:none;display:none;background:var(--bg-surface);border:1px solid var(--border-default);border-radius:6px;padding:8px 12px;font-size:var(--text-xs);color:var(--text-primary);max-width:220px;z-index:10}
.ap-controls{display:flex;gap:var(--space-2);align-items:center;margin-bottom:var(--space-3)}

/* --- Quarantine --- */
.q-note{font-size:var(--text-xs);color:var(--text-tertiary);margin-bottom:var(--space-4)}

/* --- Control --- */
.control-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--space-5)}
.status-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;display:inline-block}

/* --- Lifecycle --- */
.lc-summary{font-size:var(--text-xs);color:var(--text-tertiary);margin-bottom:var(--space-4);padding:var(--space-3) 0;border-bottom:1px solid var(--border-subtle)}
.status-border{border-left:3px solid transparent;padding-left:var(--space-3)}

/* --- Dedup --- */
.dedup-line{font-size:var(--text-xs);color:var(--text-tertiary);padding:var(--space-3) 0;margin-bottom:var(--space-4)}

/* --- Integrations --- */
.integration-fields{display:grid;grid-template-columns:1fr 1fr;gap:var(--space-4);max-width:700px}

/* ═══════════════════ 6. RESPONSIVE ═══════════════════ */
@media(max-width:900px){
  .app-header{flex-wrap:wrap;height:auto;padding:var(--space-3) var(--space-4);gap:var(--space-2)}
  .tab-nav{width:100%;overflow-x:auto}
  .grid-3,.grid-2,.control-grid{grid-template-columns:1fr}
  .detail-panel{grid-template-columns:1fr}
  .kpi-grid{grid-template-columns:repeat(auto-fill,minmax(140px,1fr))}
  .page{padding:var(--space-4)}
  .integration-fields{grid-template-columns:1fr}
}
@media(max-width:600px){
  .kpi-grid{grid-template-columns:1fr}
  .filter-row{flex-direction:column;align-items:stretch}
  .filter-row .input{max-width:none}
  .filter-row select.input{width:100%}
}
</style>
</head>
<body>

<!-- ═══════════════════ HEADER ═══════════════════ -->
<header class="app-header">
  <div class="header-brand">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    <span class="header-brand-text">Risk Intelligence</span>
  </div>
  <div class="header-meta" id="run-meta"></div>
  <nav class="tab-nav" role="tablist">
    <button class="tab-btn active" id="tab-overview" data-page="overview" role="tab" aria-selected="true" aria-controls="page-overview">Overview</button>
    <button class="tab-btn" id="tab-findings" data-page="findings" role="tab" aria-selected="false" aria-controls="page-findings">Findings <span id="tc-findings"></span></button>
    <button class="tab-btn" id="tab-attackpaths" data-page="attackpaths" role="tab" aria-selected="false" aria-controls="page-attackpaths">Attack Paths <span id="tc-paths"></span></button>
    <button class="tab-btn" id="tab-quarantine" data-page="quarantine" role="tab" aria-selected="false" aria-controls="page-quarantine">Quarantine <span id="tc-quarantine"></span></button>
    <button class="tab-btn" id="tab-products" data-page="products" role="tab" aria-selected="false" aria-controls="page-products">Products <span id="tc-products"></span></button>
    <button class="tab-btn" id="tab-control" data-page="control" role="tab" aria-selected="false" aria-controls="page-control">Control</button>
    <button class="tab-btn" id="tab-lifecycle" data-page="lifecycle" role="tab" aria-selected="false" aria-controls="page-lifecycle">Lifecycle <span id="tc-lifecycle"></span></button>
    <button class="tab-btn" id="tab-dedup" data-page="dedup" role="tab" aria-selected="false" aria-controls="page-dedup">Dedup</button>
    <button class="tab-btn" id="tab-integrations" data-page="integrations" role="tab" aria-selected="false" aria-controls="page-integrations">Integrations</button>
  </nav>
</header>

<!-- ═══════════════════ OVERVIEW ═══════════════════ -->
<main id="page-overview" class="page active" role="tabpanel" aria-labelledby="tab-overview">
  <h2 class="sr-only">Key Metrics</h2>
  <div class="card mb-6" id="exec-brief-card" style="display:none">
    <div class="card-header" style="cursor:pointer" onclick="this.nextElementSibling.classList.toggle('hidden')">Executive Brief &#9662;</div>
    <div class="hidden" style="padding-top:var(--space-3);font-size:var(--text-xs);line-height:1.7;color:var(--text-secondary)"><p id="exec-brief-text"></p></div>
  </div>
  <div class="kpi-grid" id="kpi-grid"></div>
  <div class="grid-3 mb-6">
    <div class="card"><div class="card-header">Priority Distribution</div><div style="height:200px"><canvas id="c-priority" aria-label="Priority distribution chart"></canvas></div></div>
    <div class="card"><div class="card-header">Severity Breakdown</div><div style="height:200px"><canvas id="c-severity" aria-label="Severity breakdown chart"></canvas></div></div>
    <div class="card"><div class="card-header">Scanner Coverage</div><div style="height:200px"><canvas id="c-scanner" aria-label="Scanner coverage chart"></canvas></div></div>
  </div>
  <div class="grid-2">
    <div class="card"><div class="card-header">Noise Reduction Pipeline</div><div style="height:200px"><canvas id="c-noise" aria-label="Noise reduction chart"></canvas></div></div>
    <div class="card"><div class="card-header">Risk Over Time</div><div style="height:200px"><canvas id="c-history" aria-label="Risk trend chart"></canvas></div></div>
  </div>
</main>

<!-- ═══════════════════ FINDINGS ═══════════════════ -->
<main id="page-findings" class="page" role="tabpanel" aria-labelledby="tab-findings">
  <div class="filter-row">
    <input id="tbl-search" class="input" placeholder="Search title, CVE, CWE, endpoint...">
    <select id="f-priority" class="input" style="width:140px"><option value="">All priorities</option></select>
    <select id="f-severity" class="input" style="width:140px"><option value="">All severities</option></select>
    <select id="f-scanner" class="input" style="width:140px"><option value="">All scanners</option></select>
    <select id="f-kev" class="input" style="width:140px"><option value="">KEV filter</option><option value="kev">KEV only</option><option value="exploit">Exploit available</option></select>
    <button class="btn btn-secondary btn-sm" onclick="App.findings.exportCSV()">Export CSV</button>
    <span class="result-count" id="result-badge">-- findings</span>
  </div>
  <div class="table-wrap"><table class="data-table"><thead id="tbl-head"><tr><th style="width:40px">#</th><th style="width:90px">Score</th><th style="width:80px">Priority</th><th style="width:80px">Severity</th><th>Title</th><th style="width:100px">Product</th><th style="width:80px">Scanner</th><th style="width:130px">CVE</th><th style="width:50px">KEV</th><th style="width:60px">EPSS</th><th style="width:50px">SLA</th></tr></thead><tbody id="tbl-body"></tbody></table></div>
</main>

<!-- ═══════════════════ ATTACK PATHS ═══════════════════ -->
<main id="page-attackpaths" class="page" role="tabpanel" aria-labelledby="tab-attackpaths">
  <div class="card">
    <div class="card-header">Attack Path Graph</div>
    <div class="ap-legend">
      <span><span class="ap-dot" style="background:var(--risk-critical)"></span> High-impact target</span>
      <span><span class="ap-dot" style="background:var(--risk-info)"></span> Entry point</span>
      <span><span class="ap-dot" style="background:var(--text-tertiary)"></span> Intermediate</span>
    </div>
    <div class="ap-controls">
      <select id="ap-product" class="input" style="width:180px"></select>
      <button class="btn btn-secondary btn-sm" onclick="App.attackPaths.reset()">Reset zoom</button>
    </div>
    <div id="ap-container"><svg id="ap-svg" width="100%" height="480"></svg><div class="ap-tooltip" id="ap-tooltip"></div></div>
  </div>
</main>

<!-- ═══════════════════ QUARANTINE ═══════════════════ -->
<main id="page-quarantine" class="page" role="tabpanel" aria-labelledby="tab-quarantine">
  <p class="q-note">Quarantined findings remain auditable. They are excluded from scoring.</p>
  <div class="table-wrap"><table class="data-table"><thead><tr><th>Product</th><th>Scanner</th><th>Severity</th><th>Title</th><th>CVE</th><th>Reason</th></tr></thead><tbody id="q-body"></tbody></table></div>
</main>

<!-- ═══════════════════ PRODUCTS ═══════════════════ -->
<main id="page-products" class="page" role="tabpanel" aria-labelledby="tab-products">
  <div class="card mb-6">
    <div class="card-header">Managed Products</div>
    <div id="products-table-wrap"></div>
  </div>
  <div class="card">
    <div class="card-header">Add New Product</div>
    <div class="form-grid">
      <div><label class="form-label">Product ID</label><input id="ap-id" class="input" placeholder="my_app"></div>
      <div><label class="form-label">Display Name</label><input id="ap-name" class="input" placeholder="My App"></div>
      <div><label class="form-label">Target URL</label><input id="ap-url" class="input" placeholder="https://myapp.com"></div>
      <div><label class="form-label">GitHub Repo</label><input id="ap-repo" class="input" placeholder="org/repo"></div>
      <div><label class="form-label">Owner</label><input id="ap-owner" class="input" placeholder="appsec-team"></div>
      <div><label class="form-label">Criticality (1-10)</label><input id="ap-crit" type="number" min="1" max="10" value="5" class="input"></div>
      <div><label class="form-label">Sensitivity (1-10)</label><input id="ap-sens" type="number" min="1" max="10" value="5" class="input"></div>
      <div><label class="form-label">Trivy Image</label><input id="ap-trivy" class="input" placeholder="org/app:tag"></div>
      <div style="grid-column:1/-1;display:flex;gap:var(--space-2);margin-top:var(--space-2)">
        <button class="btn btn-primary" onclick="App.products.add()">Save Product</button>
        <span id="ap-msg" style="font-size:var(--text-xs);align-self:center"></span>
      </div>
    </div>
  </div>
</main>

<!-- ═══════════════════ CONTROL CENTER ═══════════════════ -->
<main id="page-control" class="page" role="tabpanel" aria-labelledby="tab-control">
  <div class="control-grid">
    <div class="card">
      <div class="card-header">System Status</div>
      <div id="app-status-list"></div>
    </div>
    <div class="card">
      <div class="card-header">Quick Actions</div>
      <div style="display:flex;flex-direction:column;gap:var(--space-2)">
        <button class="btn btn-primary" onclick="App.control.runPipeline()">Run Pipeline</button>
        <button class="btn btn-secondary" onclick="App.control.scanAll()">Scan All Products</button>
        <button class="btn btn-secondary" onclick="App.control.createTickets()">Create GitHub Issues</button>
        <button class="btn btn-secondary" onclick="App.control.checkDocker()">Check Docker Status</button>
      </div>
    </div>
  </div>
  <div class="card" style="margin-top:var(--space-5)">
    <div class="card-header">Scanner Progress</div>
    <div id="scanner-progress">
      <div class="empty-state" style="padding:var(--space-5)"><p class="empty-state-desc">No active scans</p></div>
    </div>
  </div>
</main>

<!-- ═══════════════════ LIFECYCLE ═══════════════════ -->
<main id="page-lifecycle" class="page" role="tabpanel" aria-labelledby="tab-lifecycle">
  <div class="lc-summary" id="lc-summary"></div>
  <div class="card mb-6">
    <div class="card-header">Vulnerability Lifecycle</div>
    <div id="lc-table-wrap"></div>
  </div>
  <div class="card">
    <div class="card-header">SLA Breach Monitor</div>
    <div id="lc-breached-list"></div>
  </div>
</main>

<!-- ═══════════════════ DEDUP ═══════════════════ -->
<main id="page-dedup" class="page" role="tabpanel" aria-labelledby="tab-dedup">
  <div class="dedup-line" id="dedup-summary-line"></div>
  <div class="grid-2 mb-6">
    <div class="card"><div class="card-header">Findings per Scanner</div><div style="height:200px"><canvas id="c-dedup-scanner" aria-label="Findings per scanner chart"></canvas></div></div>
    <div class="card"><div class="card-header">Top Overlaps</div><div style="height:200px"><canvas id="c-dedup-overlap" aria-label="Cross-scanner overlap chart"></canvas></div></div>
  </div>
  <div class="card">
    <div class="card-header">Overlap Details</div>
    <div id="dedup-overlap-table"></div>
  </div>
</main>

<!-- ═══════════════════ INTEGRATIONS ═══════════════════ -->
<main id="page-integrations" class="page" role="tabpanel" aria-labelledby="tab-integrations">
  <div class="grid-2 mb-6">
    <div class="card"><div class="card-header">AI Enrichment</div><div class="integration-fields"><div><label class="form-label">Groq API Key</label><input id="ak-groq" class="input" type="password" placeholder="gsk_..."></div><div><label class="form-label">NVD API Key</label><input id="ak-nvd" class="input" type="password" placeholder="Optional"></div></div></div>
    <div class="card"><div class="card-header">GitHub</div><div class="integration-fields"><div><label class="form-label">Token</label><input id="ak-github" class="input" type="password" placeholder="ghp_..."></div></div></div>
    <div class="card"><div class="card-header">Jira</div><div class="integration-fields"><div><label class="form-label">URL</label><input id="ak-jira-url" class="input" placeholder="https://org.atlassian.net"></div><div><label class="form-label">Username</label><input id="ak-jira-user" class="input" placeholder="user@company.com"></div><div><label class="form-label">Token</label><input id="ak-jira-token" class="input" type="password" placeholder="ATATT..."></div><div><label class="form-label">Project Key</label><input id="ak-jira-project" class="input" placeholder="SEC"></div></div></div>
    <div class="card"><div class="card-header">DefectDojo</div><div class="integration-fields"><div><label class="form-label">URL</label><input id="ak-dd-url" class="input" placeholder="http://localhost:8080"></div><div><label class="form-label">API Key</label><input id="ak-dd-key" class="input" type="password"></div></div></div>
  </div>
  <div style="margin-bottom:var(--space-6)">
    <button class="btn btn-primary" onclick="App.integrations.saveKeys()">Save All Keys</button>
    <span id="apikey-status" style="font-size:var(--text-xs);margin-left:var(--space-2)"></span>
  </div>
  <div class="grid-2 mb-6">
    <div class="card"><div class="card-header">Jira Integration</div><div style="display:flex;gap:var(--space-2);margin-bottom:var(--space-3)"><button class="btn btn-secondary btn-sm" onclick="App.integrations.testJira()">Test Connection</button><button class="btn btn-primary btn-sm" onclick="App.integrations.createJira()">Create Issues</button></div><div id="jira-status"></div></div>
    <div class="card"><div class="card-header">DefectDojo</div><div style="display:flex;gap:var(--space-2);margin-bottom:var(--space-3)"><button class="btn btn-secondary btn-sm" onclick="App.integrations.testDD()">Test Connection</button><button class="btn btn-primary btn-sm" onclick="App.integrations.importDD()">Import Findings</button></div><div id="dd-status"></div></div>
  </div>
  <div class="card">
    <div class="card-header">Exports</div>
    <div style="display:flex;gap:var(--space-3);flex-wrap:wrap">
      <a class="btn btn-secondary" href="/api/exports/sarif" target="_blank" download>SARIF</a>
      <a class="btn btn-secondary" href="/api/exports/cyclonedx" target="_blank" download>CycloneDX SBOM</a>
      <a class="btn btn-secondary" href="/api/exports/defectdojo" target="_blank" download>DefectDojo JSON</a>
    </div>
  </div>
</main>

<!-- ═══════════════════ DATA ═══════════════════ -->
<script>const DASH=__DASH_JSON__;</script>
<script>
/* ═══════════════════════ APP ═══════════════════════ */
const OP={high:'.8',med:'.7',low:'.5',dim:'.4'};
const CHART_COLORS={
  critical:'rgba(239,68,68,'+OP.high+')',high:'rgba(245,158,11,'+OP.high+')',medium:'rgba(234,179,8,'+OP.high+')',
  low:'rgba(34,197,94,'+OP.high+')',info:'rgba(107,114,128,'+OP.dim+')',
  infoBar:'rgba(59,130,246,'+OP.med+')',infoBarDim:'rgba(59,130,246,'+OP.low+')',
  scannerBar:'rgba(59,130,246,'+OP.med+')',overlapBar:'rgba(245,158,11,'+OP.med+')',
  line:['#3B82F6','#22C55E','#EAB308','#EF4444','#F59E0B'],
  arrow:{low:'rgba(34,197,94,'+OP.med+')',med:'rgba(234,179,8,'+OP.high+')',high:'rgba(239,68,68,'+OP.high+')'}
};
const TABLE_COLUMNS=[
  {k:'rank',label:'#',w:'40px',sortable:true,dir:-1},
  {k:'score',label:'Score',w:'90px',sortable:true,dir:-1},
  {k:'priority',label:'Priority',w:'80px',sortable:true,dir:-1,customSort:function(a,b){return parseInt((a||'P0').slice(1))-parseInt((b||'P0').slice(1));}},
  {k:'severity',label:'Severity',w:'80px',sortable:true,dir:-1},
  {k:'title',label:'Title',w:'',sortable:false},
  {k:'product',label:'Product',w:'100px',sortable:true,dir:1},
  {k:'scanner',label:'Scanner',w:'80px',sortable:true,dir:1},
  {k:'cve',label:'CVE',w:'130px',sortable:false},
  {k:'kev',label:'KEV',w:'50px',sortable:true,dir:-1},
  {k:'epss_score',label:'EPSS',w:'60px',sortable:true,dir:-1},
  {k:'sla_hours',label:'SLA',w:'50px',sortable:true,dir:-1}
];

const App={
  state:{currentTab:'overview',apInited:false,ws:null,wsRetries:0,openDetail:null},
  hasChart:false,

  init(){
    this.data=DASH;
    this.buildHeader();
    this.initTabs();
    this.initKeyboard();
    this.initCharts();
    this.overview.init();
    this.findings.init();
    this.buildQuarantine();
    this.buildProducts();
    this.lifecycle.init();
    this.dedup.init();
    if(location.hash)this.switchTab(location.hash.slice(1));
    // Executive brief
    var brief=App.data.executive_brief;
    if(brief){var card=App.$('exec-brief-card');var text=App.$('exec-brief-text');if(card&&text){card.style.display='block';text.textContent=brief;}}
  },

  $(id){return document.getElementById(id)},
  esc(s){return(s||'').toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');},
  tooltipText(s){return(s||'').toString().replace(/&/g,'&amp;').replace(/"/g,'&quot;');},
  scoreColor(v){return v>=80?'#EF4444':v>=60?'#F59E0B':v>=40?'#EAB308':'#22C55E';},
  scoreClass(v){return v>=80?'text-critical':v>=60?'':v>=40?'':'text-low';},
  priClass(p){return({P1:'b-p1',P2:'b-p2',P3:'b-p3',P4:'b-p4'}[p]||'b-p4');},
  sevClass(s){return({critical:'b-critical',high:'b-high',medium:'b-medium',low:'b-low',info:'b-info-sev'}[s]||'b-info-sev');},
  pct(n){return n!=null?(n*100).toFixed(1)+'%':'-';},
  gridColor:'rgba(255,255,255,0.03)',

  toast(msg,type){
    type=type||'info';
    var c=this._toastContainer;
    if(!c){c=document.createElement('div');c.className='toast-container';document.body.appendChild(c);this._toastContainer=c;}
    var t=document.createElement('div');
    t.className='toast toast-'+type;
    t.innerHTML='<span>'+this.esc(msg)+'</span>';
    c.appendChild(t);
    setTimeout(function(){if(t.parentNode)t.remove();},5000);
  },

  apiFetch(url,opts){
    opts=opts||{};
    opts.headers=Object.assign({'Content-Type':'application/json'},opts.headers||{});
    return fetch(url,opts).then(function(r){
      if(r.status===401){window.location.href='/';return{};}
      return r.json();
    }).catch(function(){return{error:'Network error'};});
  },

  buildHeader(){
    var S=this.data.summary;
    var meta=this.$('run-meta');
    if(!meta)return;
    var parts=[S.run_date?S.run_date.substring(0,16):'-'];
    if(S.products)parts.push(S.products.length+' products');
    if(S.p1>0)parts.push('<span class="p1-count">'+S.p1+' P1</span>');
    if(S.p2>0)parts.push('<span class="p2-count">'+S.p2+' P2</span>');
    meta.innerHTML=parts.join(' \u00b7 ');
    var tf=this.$('tc-findings');if(tf)tf.textContent='('+S.final_findings+')';
    var tq=this.$('tc-quarantine');if(tq)tq.textContent='('+S.quarantined+')';
  },

  initTabs(){
    var self=this;
    document.querySelectorAll('.tab-btn').forEach(function(btn){
      btn.addEventListener('click',function(){self.switchTab(btn.dataset.page);});
    });
    window.addEventListener('hashchange',function(){
      var h=location.hash.slice(1);if(h&&h!==self.state.currentTab&&document.querySelector('.tab-btn[data-page="'+h+'"]'))self.switchTab(h);
    });
  },
  switchTab(page){
    var self=this;
    document.querySelectorAll('.tab-btn').forEach(function(b){
      b.classList.toggle('active',b.dataset.page===page);
      b.setAttribute('aria-selected',b.dataset.page===page?'true':'false');
    });
    document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
    var pg=self.$('page-'+page);if(pg)pg.classList.add('active');
    self.state.currentTab=page;
    if(location.hash.slice(1)!==page){history.replaceState(null,null,'#'+page);}
    if(page==='attackpaths'&&!self.state.apInited){self.attackPaths.init();self.state.apInited=true;}
    if(page==='control'){self.control.loadStatus();self.control.connectWS();self.control.loadJobs();}
  },

  // TODO: extend for future modal system
  initKeyboard(){
    document.addEventListener('keydown',function(e){
      if(e.key==='Escape'){
        document.querySelectorAll('.detail-row.open').forEach(function(r){r.classList.remove('open');});
        document.querySelectorAll('.data-row.expanded').forEach(function(r){r.classList.remove('expanded');});
        App.state.openDetail=null;
      }
      if(e.key==='/'&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)){
        e.preventDefault();var s=App.$('tbl-search');if(s)s.focus();
      }
    });
  },    initCharts(){
    var self=this;
    if(typeof Chart!=='undefined'){self.overview.initCharts();return;}
    // Poll for Chart.js to load (max 10s, 200ms intervals)
    var n=0;var iv=setInterval(function(){
      n++;if(typeof Chart!=='undefined'){clearInterval(iv);self.overview.initCharts();}
      if(n>50)clearInterval(iv);
    },200);
  },

  /* ═══ OVERVIEW ═══ */
  overview:{
    init(){
      var S=App.data.summary;
      var noiseRm=S.raw_findings>0?parseFloat(((S.raw_findings-S.final_findings)/S.raw_findings*100).toFixed(1)):0;
      var cards=[
        {v:S.raw_findings,l:'Raw Findings',sub:'Before processing',color:''},
        {v:S.unique_findings,l:'After Dedup',sub:S.dedup_pct+'% removed',color:''},
        {v:S.quarantined,l:'Quarantined',sub:'False positives / accepted',color:''},
        {v:S.final_findings,l:'Active Findings',sub:'Prioritized & scored',color:''},
        {v:S.p1+S.p2,l:'Critical + High',sub:S.p1+' P1 \u00b7 '+S.p2+' P2',color:S.p1>0?'text-critical':''},
        {v:S.avg_score,l:'Avg Risk Score',sub:'Top: '+S.top_score,color:''},
        {v:noiseRm,l:'Noise Reduction',sub:'Raw to final',color:'text-low',isPercent:true}
      ];
      var grid=App.$('kpi-grid');if(!grid)return;
      grid.innerHTML=cards.map(function(c,i){
        var vColor=c.color?' class="'+c.color+'"':'';
        return '<div class="card"><div class="kpi-value" id="kv-'+i+'"'+vColor+'>'+(typeof c.v==='number'?'0':c.v)+'</div><div class="kpi-label">'+c.l+'</div><div class="kpi-sub">'+c.sub+'</div></div>';
      }).join('');
      // Only animate visible KPIs using IntersectionObserver
      cards.forEach(function(c,i){
        if(typeof c.v!=='number')return;
        var el=App.$('kv-'+i);if(!el)return;
        if(typeof IntersectionObserver!=='undefined'){
          var obs=new IntersectionObserver(function(entries){
            if(entries[0].isIntersecting){App.overview.animateCount(el,c.v,c.suffix||'');obs.disconnect();}
          },{threshold:0.1});
          obs.observe(el);
        }else{
          App.overview.animateCount(el,c.v,c.suffix||'');
        }
      });
    },
    animateCount(el,target,suffix){
      if(!el)return;
      var dur=1200,start=performance.now();
      var isFloat=target%1!==0;
      function tick(now){
        var p=Math.min((now-start)/dur,1);
      var ease=1-Math.pow(1-p,3);
        var val=ease*target;
        var text=isFloat?val.toFixed(1):Math.round(val).toLocaleString();
        el.textContent=suffix?text+suffix:text;
        if(p<1)requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    },
    initCharts(){
      if(typeof Chart==='undefined')return;
      App.hasChart=true;
      try{
        var S=App.data.summary,F=App.data.findings,H=App.data.history;
        var hBarOpts={indexAxis:'y',scales:{x:{grid:{color:App.gridColor},ticks:{font:{size:10},color:'#9CA3AF'}},y:{grid:{display:false},ticks:{font:{size:10},color:'#9CA3AF'}}},plugins:{legend:{display:false}}};
        // Priority horizontal bar
        var pe=App.$('c-priority');
        if(pe)new Chart(pe,{type:'bar',data:{labels:['P1 Critical','P2 High','P3 Medium','P4 Low'],datasets:[{data:[S.p1,S.p2,S.p3,S.p4],backgroundColor:[CHART_COLORS.critical,CHART_COLORS.high,CHART_COLORS.medium,CHART_COLORS.info],borderWidth:0,borderRadius:4}]},options:hBarOpts});
        // Severity horizontal bar
        var se=App.$('c-severity');
        if(se){
          var sc={critical:0,high:0,medium:0,low:0,info:0};
          F.forEach(function(f){sc[f.severity]=(sc[f.severity]||0)+1;});
          var sl=['critical','high','medium','low','info'];
          new Chart(se,{type:'bar',data:{labels:sl.map(function(s){return s.charAt(0).toUpperCase()+s.slice(1);}),datasets:[{data:sl.map(function(s){return sc[s]||0;}),backgroundColor:[CHART_COLORS.critical,CHART_COLORS.high,CHART_COLORS.medium,CHART_COLORS.low,CHART_COLORS.info],borderWidth:0,borderRadius:4}]},options:hBarOpts});
        }
        // Scanner coverage
        var sce=App.$('c-scanner');
        if(sce){
          var sm={};F.forEach(function(f){sm[f.scanner]=(sm[f.scanner]||0)+1;});
          var sk=Object.keys(sm).sort(function(a,b){return sm[b]-sm[a];});
          new Chart(sce,{type:'bar',data:{labels:sk,datasets:[{data:sk.map(function(k){return sm[k];}),backgroundColor:CHART_COLORS.scannerBar,borderWidth:0,borderRadius:4}]},options:hBarOpts});
        }
        // Noise reduction vertical bar
        var ne=App.$('c-noise');
        if(ne)new Chart(ne,{type:'bar',data:{labels:['Raw','Dedup','Filtered','Active'],datasets:[{data:[S.raw_findings,S.unique_findings,S.unique_findings-S.quarantined,S.final_findings],backgroundColor:[CHART_COLORS.infoBar,CHART_COLORS.infoBarDim,CHART_COLORS.medium,CHART_COLORS.low],borderWidth:0,borderRadius:4}]},options:{plugins:{legend:{display:false}},scales:{y:{grid:{color:App.gridColor},ticks:{font:{size:10},color:'#9CA3AF'}},x:{grid:{display:false},ticks:{font:{size:10},color:'#9CA3AF'}}}}});
        // Risk over time line
        var he=App.$('c-history');
        if(he){
          var prods=Object.keys(H);
          var hds=[];
          prods.forEach(function(prod,idx){
            var runs=H[prod];if(!runs||runs.length<1)return;
            hds.push({label:prod,data:runs.map(function(r){return{x:r.run_date,y:r.avg_score};}),borderColor:CHART_COLORS.line[idx%5],backgroundColor:'transparent',tension:.4,pointRadius:4,borderWidth:2});
          });
          if(hds.length>0){
            new Chart(he,{type:'line',data:{datasets:hds},options:{plugins:{legend:{display:prods.length>1,position:'bottom',labels:{font:{size:10},color:'#9CA3AF'}}},scales:{x:{type:'category',grid:{color:App.gridColor},ticks:{font:{size:10},color:'#9CA3AF'}},y:{grid:{color:App.gridColor},ticks:{font:{size:10},color:'#9CA3AF'},min:0,max:100}}}});
          }else{
            he.parentElement.innerHTML='<div class="empty-state" style="height:200px"><p class="empty-state-desc">Need 2+ runs for trend data</p></div>';
          }
        }
      }catch(e){console.error('initCharts:',e);}
    }
  },

  /* ═══ FINDINGS ═══ */
  findings:{
    _sortCol:'score',_sortDir:-1,_search:'',_fPri:'',_fSev:'',_fScan:'',_fKev:'',
    _searchEl:null,_fPriEl:null,_fSevEl:null,_fScanEl:null,_fKevEl:null,
    _filteredCache:null,_cacheKey:'',
    init(){
      var self=this;
      this._searchEl=App.$('tbl-search');
      this._fPriEl=App.$('f-priority');
      this._fSevEl=App.$('f-severity');
      this._fScanEl=App.$('f-scanner');
      this._fKevEl=App.$('f-kev');
      var F=App.data.findings;
      var thead=App.$('tbl-head');if(!thead)return;
      thead.innerHTML='<tr>'+TABLE_COLUMNS.map(function(c){
        return '<th style="'+(c.w?'width:'+c.w:'')+'" '+(c.sortable?'data-col="'+c.k+'"':'')+'>'+c.label+(c.sortable?'<span class="sort-arrow">\u2195</span>':'')+'</th>';
      }).join('')+'</tr>';
      // Populate filter dropdowns with correct sort
      var priorities=[...new Set(F.map(function(f){return f.priority;}))].sort(function(a,b){return parseInt(a.slice(1))-parseInt(b.slice(1));});
      var severities=['critical','high','medium','low','info'];
      var scanners=[...new Set(F.map(function(f){return f.scanner;}))].sort();
      [['f-priority',priorities],['f-severity',severities],['f-scanner',scanners]].forEach(function(arr){
        var sel=App.$(arr[0]);if(!sel)return;
        arr[1].forEach(function(v){var o=document.createElement('option');o.value=v;o.textContent=v;sel.appendChild(o);});
      });
      // Event delegation for sort headers
      thead.addEventListener('click',function(e){
        var th=e.target.closest('th[data-col]');if(!th)return;
        var col=TABLE_COLUMNS.find(function(c){return c.k===th.dataset.col;});
        if(!col)return;
        if(self._sortCol===th.dataset.col){self._sortDir*=-1;}
        else{self._sortCol=th.dataset.col;        self._sortDir=col.dir!=null?col.dir:-1;}
        document.querySelectorAll('#tbl-head th').forEach(function(t){t.classList.remove('sorted');var a=t.querySelector('.sort-arrow');if(a)a.textContent='\u2195';});
        th.classList.add('sorted');var arrow=th.querySelector('.sort-arrow');if(arrow)arrow.textContent=self._sortDir===-1?'\u2193':'\u2191';
        self._invalidateCache();self.render();
      });
      if(this._searchEl)this._searchEl.addEventListener('input',function(e){self._search=e.target.value;self._invalidateCache();clearTimeout(self._searchTimer);self._searchTimer=setTimeout(function(){self.render();},300);});
      this._fPriEl.addEventListener('change',function(e){self._fPri=e.target.value;self._invalidateCache();self.render();});
      this._fSevEl.addEventListener('change',function(e){self._fSev=e.target.value;self._invalidateCache();self.render();});
      this._fScanEl.addEventListener('change',function(e){self._fScan=e.target.value;self._invalidateCache();self.render();});
      this._fKevEl.addEventListener('change',function(e){self._fKev=e.target.value;self._invalidateCache();self.render();});
      this.render();
    },
    _invalidateCache(){this._filteredCache=null;this._cacheKey='';},
    getFiltered(){
      var F=App.data.findings,q=this._search.toLowerCase(),self=this;
      var key=this._search+'\x00'+this._fPri+'\x00'+this._fSev+'\x00'+this._fScan+'\x00'+this._fKev;
      if(this._filteredCache!==null&&this._cacheKey===key)return this._filteredCache;
      var result=F.filter(function(f){
        if(self._fPri&&f.priority!==self._fPri)return false;
        if(self._fSev&&f.severity!==self._fSev)return false;
        if(self._fScan&&f.scanner!==self._fScan)return false;
        if(self._fKev==='kev'&&!f.kev)return false;
        if(self._fKev==='exploit'&&!f.exploit_available)return false;
        if(q)return(f.title+f.cve+f.cwe+f.endpoint+f.product).toLowerCase().includes(q);
        return true;
      }).sort(function(a,b){
        var col=TABLE_COLUMNS.find(function(c){return c.k===self._sortCol;});
        if(col&&col.customSort)return col.customSort(a[self._sortCol],b[self._sortCol])*self._sortDir;
        var av=a[self._sortCol],bv=b[self._sortCol];
        if(typeof av==='number')return(av-bv)*self._sortDir;
        return String(av).localeCompare(String(bv))*self._sortDir;
      });
      this._filteredCache=result;this._cacheKey=key;
      return result;
    },
    render(){
      var rows=this.getFiltered();
      var rb=App.$('result-badge');if(rb)rb.textContent=rows.length+' of '+App.data.findings.length+' findings';
      var tb=App.$('tbl-body');if(tb)tb.innerHTML=rows.map(this.renderRow).join('');
    },
    renderRow(f){
      var sc=App.scoreColor(f.score);
      var epssStr=f.epss_score>0?(f.epss_score*100).toFixed(1)+'%':'-';
      var title=f.title||'';
      var truncated=title.length>50?title.substring(0,50)+'...':title;
      var detailHtml=this.renderDetail(f);
      return '<tr class="data-row" data-rank="'+f.rank+'" onclick="App.findings.toggleDetail(this)">'+
        '<td class="mono dimmed" style="font-size:11px">'+f.rank+'</td>'+
        '<td><span class="score-num" style="color:'+sc+'">'+f.score+'</span></td>'+
        '<td><span class="badge '+App.priClass(f.priority)+'">'+App.esc(f.priority)+'</span></td>'+
        '<td><span class="badge '+App.sevClass(f.severity)+'">'+App.esc(f.severity)+'</span></td>'+
        '<td><span class="truncate" style="max-width:300px;color:var(--text-primary);font-weight:500" title="'+App.tooltipText(title)+'">'+App.esc(truncated)+'</span></td>'+
        '<td class="truncate" style="max-width:100px">'+App.esc(f.product)+'</td>'+
        '<td class="dimmed" style="font-size:11px">'+App.esc(f.scanner)+'</td>'+
        '<td>'+(f.cve?'<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/'+App.esc(f.cve)+'" target="_blank" onclick="event.stopPropagation()">'+App.esc(f.cve)+'</a>':'<span class="dimmed">\u2014</span>')+'</td>'+
        '<td>'+(f.kev?'<span style="color:var(--risk-critical);font-weight:600;font-size:11px">KEV</span>':'<span class="dimmed">\u2014</span>')+'</td>'+
        '<td class="mono" style="font-size:11px;color:var(--text-secondary)">'+epssStr+'</td>'+
        '<td class="mono dimmed" style="font-size:11px">'+f.sla_hours+'h</td>'+
        '</tr><tr class="detail-row" id="detail-'+f.rank+'"><td colspan="11">'+detailHtml+'</td></tr>';
    },
    renderDetail(f){
      var sb=f.score_components||{};
      var comps=Object.entries(sb).map(function(kv){return '<span style="margin-right:10px"><span class="dimmed">'+kv[0]+':</span> <b>'+kv[1]+'</b></span>';}).join('');
      var drivers=(f.score_drivers||[]).map(function(d){return '<span style="margin-right:8px;color:var(--risk-medium)">\u2022 '+App.esc(d)+'</span>';}).join('');
      var rems=(f.remediation||[]).map(function(r){return '<li><span class="rem-kind">'+App.esc(r.kind)+'</span> '+App.esc(r.text)+'</li>';}).join('');
      var aiRem=f.ai_remediation?'<div class="ai-box"><div class="ai-label">AI Remediation</div><div class="ai-content">'+App.esc(f.ai_remediation)+'</div></div>':'';
      return '<div class="detail-panel"><div class="detail-section"><div class="detail-section-title">Finding Details</div>'+
        '<div class="detail-row-item"><span class="detail-key">Endpoint</span><span class="detail-val">'+App.esc(f.endpoint||'\u2014')+(f.parameter?' ('+App.esc(f.parameter)+')':'')+'</span></div>'+
        '<div class="detail-row-item"><span class="detail-key">EPSS</span><span class="detail-val">'+App.pct(f.epss_score)+' (pct '+App.pct(f.epss_percentile)+')</span></div>'+
        '<div class="detail-row-item"><span class="detail-key">KEV</span><span class="detail-val">'+(f.kev?'In CISA KEV ('+App.esc(f.kev_date)+')':'Not in KEV')+'</span></div>'+
        '<div class="detail-row-item"><span class="detail-key">Exploit</span><span class="detail-val">'+(f.exploit_available?'Yes \u2014 '+App.esc(f.exploit_source):'Not found')+'</span></div>'+
        '<div class="detail-row-item"><span class="detail-key">Owner</span><span class="detail-val">'+App.esc(f.owner||'\u2014')+' \u00b7 SLA '+f.sla_hours+'h</span></div>'+
        '<div style="margin-top:var(--space-3);color:var(--text-secondary);font-size:var(--text-xs);line-height:1.6">'+App.esc(f.description)+'</div></div>'+
        '<div class="detail-section"><div class="detail-section-title">Score Breakdown</div>'+
        '<div style="font-size:var(--text-xs);margin-bottom:var(--space-3);line-height:2">'+(comps||'<span class="dimmed">no breakdown</span>')+'</div>'+
        '<div style="margin-bottom:var(--space-3)">'+drivers+'</div>'+
        '<div class="detail-section-title">Remediation Steps</div>'+
        '<ul class="rem-list">'+(rems||'<li class="dimmed">No remediation data</li>')+'</ul></div>'+aiRem+'</div>';
    },
    toggleDetail(tr){
      var rank=tr.dataset.rank;var detail=App.$('detail-'+rank);if(!detail)return;
      var wasOpen=detail.classList.contains('open');
      // Close any previously open detail (including same row if re-clicked)
      if(App.state.openDetail){App.state.openDetail.classList.remove('open');var prevRow=App.state.openDetail.previousElementSibling;if(prevRow)prevRow.classList.remove('expanded');}
      // Only open if this row wasn't already open (toggle behavior)
      if(!wasOpen){detail.classList.add('open');tr.classList.add('expanded');App.state.openDetail=detail;}
      else{App.state.openDetail=null;}
    },
    exportCSV(){
      var rows=this.getFiltered();
      if(!rows.length){App.toast('No findings to export','info');return;}
      var headers=['Rank','Score','Priority','Severity','Title','Product','Scanner','CVE','KEV','EPSS','SLA','Owner'];
      var csvRows=[headers.join(',')];
      function csvEscape(val){
        var s=String(val==null?'':val);
        // CSV injection prevention: prefix formula-like fields with single quote
        if(/^[=+\-@\t\r]/.test(s))s="'"+s;
        if(s.indexOf(',')!==-1||s.indexOf('"')!==-1||s.indexOf('\n')!==-1)s='"'+s.replace(/"/g,'""')+'"';
        return s;
      }
      rows.forEach(function(f){
        csvRows.push([f.rank,f.score,f.priority,f.severity,csvEscape(f.title),csvEscape(f.product),f.scanner,f.cve||'',f.kev?'YES':'NO',(f.epss_score*100).toFixed(1),f.sla_hours,csvEscape(f.owner)].join(','));
      });
      var blob=new Blob([csvRows.join('\n')],{type:'text/csv'});
      var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='findings_export.csv';a.click();
      setTimeout(function(){URL.revokeObjectURL(a.href);},10000);
      App.toast('Exported '+rows.length+' findings','success');
    }
  },

  /* ═══ ATTACK PATHS ═══ */
  attackPaths:{
    zoom:null,svgRoot:null,
    _ro:null,_resizeTimer:null,
    init(){
      if(typeof d3==='undefined'||d3.version===undefined||typeof d3.forceSimulation!=='function'){
        App.$('ap-container').innerHTML='<div class="empty-state"><p class="empty-state-desc">D3.js not loaded.</p></div>';
        return;
      }
      var AP=App.data.attack_paths;var products=Object.keys(AP);
      if(!products.length){
        App.$('ap-container').innerHTML='<div class="empty-state"><p class="empty-state-title">No Attack Paths</p><p class="empty-state-desc">No attack paths found in this run.</p></div>';
        return;
      }
      var tp=App.$('tc-paths');if(tp)tp.textContent='('+Object.values(AP).reduce(function(a,v){return a+v.length;},0)+')';
      var sel=App.$('ap-product');
      if(sel){
        sel.innerHTML=products.map(function(p){return '<option value="'+App.esc(p)+'">'+App.esc(p)+'</option>';}).join('');
        var self=this;
        sel.addEventListener('change',function(){self.render(sel.value);});
      }
      // ResizeObserver to re-render on container size changes
      var container=App.$('ap-container');
      if(container&&typeof ResizeObserver!=='undefined'){
        this._ro=new ResizeObserver(function(){
          var s=App.$('ap-product');
          if(s&&s.value){
            if(self._resizeTimer)clearTimeout(self._resizeTimer);
            self._resizeTimer=setTimeout(function(){self.render(s.value);},300);
          }
        });
        this._ro.observe(container);
      }
      this.render(products[0]);
    },
    render(product){
      var paths=App.data.attack_paths[product]||[];
      var svgEl=App.$('ap-svg'),tooltip=App.$('ap-tooltip'),container=App.$('ap-container');
      if(!svgEl)return;
      // Clear SVG via innerHTML for performance (d3.selectAll('*').remove() is slower)
      svgEl.innerHTML='';
      // Note: if container is hidden (display:none), clientWidth=0; fallback to 900
      if(!paths.length){svgEl.innerHTML='<text x="50%" y="50%" text-anchor="middle" fill="#4B5563" dy=".3em">No paths for this product</text>';return;}
      // HIGH_IMPACT is hardcoded here — document as known limitation (should come from config)
      var HIGH_IMPACT=['CWE-89','CWE-79','CWE-78','CWE-22','CWE-434','CWE-918','CWE-502','CWE-611','CWE-287','CWE-306'];
      var nodeSet=new Map();
      paths.forEach(function(p){
        if(!nodeSet.has(p.from_cwe))nodeSet.set(p.from_cwe,{id:String(p.from_cwe),group:HIGH_IMPACT.includes(p.from_cwe)?1:0});
        if(!nodeSet.has(p.to_cwe))nodeSet.set(p.to_cwe,{id:String(p.to_cwe),group:HIGH_IMPACT.includes(p.to_cwe)?2:0});
      });
      var nodes=[...nodeSet.values()];
      var links=paths.map(function(p){return{source:String(p.from_cwe),target:String(p.to_cwe),prob:p.probability,desc:p.description||''};});
      var W=svgEl.parentElement.clientWidth||900,H=480;
      svgEl.setAttribute('viewBox','0 0 '+W+' '+H);
      var svg=d3.select('#ap-svg');var g=svg.append('g');
      this.zoom=d3.zoom().scaleExtent([.3,3]).on('zoom',function(e){g.attr('transform',e.transform);});
      svg.call(this.zoom);this.svgRoot=svg;
      var defs=svg.append('defs');
      // refX should match max node radius (28) + stroke (1.5) + gap
      var arrowRefX=32;
      ['low','med','high'].forEach(function(t,i){
        defs.append('marker').attr('id','arr-'+t).attr('viewBox','0 -4 8 8').attr('refX',arrowRefX).attr('refY',0).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto').append('path').attr('d','M0,-4L8,0L0,4').attr('fill',[CHART_COLORS.arrow.low,CHART_COLORS.arrow.med,CHART_COLORS.arrow.high][i]);
      });
      var probClass=function(p){return p>.6?'high':p>.3?'med':'low';};
      var probColor=function(p){return p>.6?CHART_COLORS.arrow.high:p>.3?CHART_COLORS.arrow.med:CHART_COLORS.arrow.low;};
      var link=g.append('g').selectAll('line').data(links).join('line').attr('stroke',function(d){return probColor(d.prob);}).attr('stroke-width',function(d){return 1+d.prob*2;}).attr('stroke-opacity',.7).attr('marker-end',function(d){return 'url(#arr-'+probClass(d.prob)+')';});
      var linkLabel=g.append('g').selectAll('text').data(links).join('text').text(function(d){return parseFloat(d.prob).toFixed(2);}).attr('font-size',9).attr('fill','#6B7280').attr('text-anchor','middle');
      var nodeG=g.append('g').selectAll('g').data(nodes).join('g').call(d3.drag().on('start',function(e,d){if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;}).on('drag',function(e,d){d.fx=e.x;d.fy=e.y;}).on('end',function(e,d){if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}));
      nodeG.append('circle').attr('r',function(d){return d.group===2?28:d.group===1?24:20;}).attr('fill',function(d){return d.group===2?'rgba(239,68,68,.12)':d.group===1?'rgba(59,130,246,.12)':'rgba(107,114,128,.08)';}).attr('stroke',function(d){return d.group===2?'#EF4444':d.group===1?'#3B82F6':'#6B7280';}).attr('stroke-width',1.5);
      nodeG.append('text').text(function(d){return d.id.replace('CWE-','');}).attr('text-anchor','middle').attr('dy','0.35em').attr('font-size',10).attr('font-weight',600).attr('fill','#E8EAED');
      // Use clientX/clientY for correct tooltip positioning relative to container
      nodeG.on('mouseover',function(e,d){if(tooltip){tooltip.style.display='block';tooltip.innerHTML='<b>'+d.id+'</b><br>'+(d.group===2?'High-impact target':d.group===1?'Entry point':'Intermediate');}}).on('mousemove',function(e){if(!container||!tooltip)return;var r=container.getBoundingClientRect();tooltip.style.left=(e.clientX-r.left+12)+'px';tooltip.style.top=(e.clientY-r.top-30)+'px';}).on('mouseout',function(){if(tooltip)tooltip.style.display='none';});
      link.on('mouseover',function(e,d){if(tooltip){tooltip.style.display='block';var srcId=typeof d.source==='object'&&d.source!==null?d.source.id:String(d.source);var tgtId=typeof d.target==='object'&&d.target!==null?d.target.id:String(d.target);tooltip.innerHTML='<b>'+srcId+' to '+tgtId+'</b><br>Probability: '+parseFloat(d.prob).toFixed(2);}}).on('mousemove',function(e){if(!container||!tooltip)return;var r=container.getBoundingClientRect();tooltip.style.left=(e.clientX-r.left+12)+'px';tooltip.style.top=(e.clientY-r.top-30)+'px';}).on('mouseout',function(){if(tooltip)tooltip.style.display='none';});
      var sim=d3.forceSimulation(nodes).force('link',d3.forceLink(links).id(function(d){return d.id;}).distance(function(d){return 100+d.prob*60;})).force('charge',d3.forceManyBody().strength(-350)).force('center',d3.forceCenter(W/2,H/2)).force('collision',d3.forceCollide(35)).alphaDecay(0.02).velocityDecay(0.3);
      sim.on('tick',function(){
        link.attr('x1',function(d){return d.source.x;}).attr('y1',function(d){return d.source.y;}).attr('x2',function(d){return d.target.x;}).attr('y2',function(d){return d.target.y;});
        linkLabel.attr('x',function(d){return(d.source.x+d.target.x)/2;}).attr('y',function(d){return(d.source.y+d.target.y)/2-6;});
        nodeG.attr('transform',function(d){return 'translate('+d.x+','+d.y+')';});
      });
    },
    reset(){if(this.svgRoot)this.svgRoot.transition().duration(500).call(this.zoom.transform,d3.zoomIdentity);}
  },

  /* ═══ QUARANTINE ═══ */    buildQuarantine(){
    var Q=App.data.quarantine;var qb=App.$('q-body');if(!qb)return;
    qb.innerHTML='';
    if(!Q.length){qb.innerHTML='<tr><td colspan="6"><div class="empty-state" style="padding:var(--space-5)"><p class="empty-state-title">No Quarantined Findings</p></div></td></tr>';return;}
    qb.innerHTML=Q.map(function(q){
      return '<tr><td>'+App.esc(q.product)+'</td><td>'+App.esc(q.scanner)+'</td><td><span class="badge '+App.sevClass(q.severity)+'">'+App.esc(q.severity)+'</span></td><td>'+App.esc(q.title)+'</td><td>'+(q.cve?'<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/'+App.esc(q.cve)+'" target="_blank">'+App.esc(q.cve)+'</a>':'<span class="dimmed">\u2014</span>')+'</td><td class="dimmed" style="font-size:11px">'+App.esc(q.reason)+'</td></tr>';
    }).join('');
  },

  /* ═══ PRODUCTS ═══ */
  products:{
    init(){
      var P=App.data.products||{};var keys=Object.keys(P);
      var tp=App.$('tc-products');if(tp)tp.textContent='('+keys.length+')';
      if(!keys.length){
        App.$('products-table-wrap').innerHTML='<div class="empty-state"><p class="empty-state-title">No Products Configured</p><p class="empty-state-desc">Add one using the form below.</p></div>';
        return;
      }
      // Pre-compute findingsByProduct to avoid O(n*m) inside map
      var findingsByProduct={};
      App.data.findings.forEach(function(f){
        if(!f.product)return;
        if(!findingsByProduct[f.product])findingsByProduct[f.product]={total:0,p1:0,p2:0};
        findingsByProduct[f.product].total++;
        if(f.priority==='P1')findingsByProduct[f.product].p1++;
        if(f.priority==='P2')findingsByProduct[f.product].p2++;
      });
      var rows=keys.map(function(k){
        var p=P[k];var fc=findingsByProduct[k]||{total:0,p1:0,p2:0};
        return '<tr><td><strong>'+App.esc(p.display_name||k)+'</strong><br><span class="dimmed" style="font-size:11px">'+App.esc(k)+'</span></td><td class="mono" style="font-size:11px">'+App.esc(p.url||'\u2014')+'</td><td class="dimmed" style="font-size:11px">'+App.esc(p.owner||'\u2014')+'</td><td class="mono" style="font-size:11px">'+(p.asset_criticality||5)+'/10</td><td class="mono" style="font-size:11px">'+fc.total+'</td><td>'+(fc.p1>0?'<span class="badge b-p1">'+fc.p1+'</span>':'')+(fc.p2>0?' <span class="badge b-p2">'+fc.p2+'</span>':'')+'</td><td><button class="btn btn-secondary btn-sm" data-scan="'+App.esc(k)+'">Scan</button></td></tr>';
      }).join('');
      var ptw=App.$('products-table-wrap');
      ptw.innerHTML='<table class="data-table"><thead><tr><th>Product</th><th>URL</th><th>Owner</th><th>Criticality</th><th>Findings</th><th>P1/P2</th><th>Actions</th></tr></thead><tbody>'+rows+'</tbody></table>';
      // Event delegation for scan buttons
      ptw.addEventListener('click',function(e){
        var btn=e.target.closest('[data-scan]');if(btn)App.products.scan(btn.dataset.scan);
      });
    },
    add(){
      var id=(App.$('ap-id').value||'').trim();var name=(App.$('ap-name').value||'').trim()||id;var url=(App.$('ap-url').value||'').trim();
      var repo=(App.$('ap-repo').value||'').trim();var owner=(App.$('ap-owner').value||'').trim();
      var crit=parseInt(App.$('ap-crit').value)||5;var sens=parseInt(App.$('ap-sens').value)||5;
      var trivy=(App.$('ap-trivy').value||'').trim();
      if(!id||!url){var m=App.$('ap-msg');if(m){m.textContent='Product ID and URL are required';m.style.color='#EF4444';}return;}
      App.apiFetch('/api/products',{method:'POST',body:JSON.stringify({product_id:id,display_name:name,url:url,github_repo:repo,owner:owner||'unassigned',asset_criticality:crit,data_sensitivity:sens})}).then(function(data){
        var m2=App.$('ap-msg');if(m2){m2.textContent=data.status==='created'?'Product saved!':'Updated';m2.style.color='#22C55E';}
      }).catch(function(){
        App.data.products=App.data.products||{};
        App.data.products[id]={display_name:name,owner:owner||'unassigned',asset_criticality:crit,url:url,github_repo:repo};
        var m3=App.$('ap-msg');if(m3){m3.textContent='Saved locally';m3.style.color='#EAB308';}
      });
      ['ap-id','ap-name','ap-url','ap-repo','ap-owner','ap-trivy'].forEach(function(fid){var el=App.$(fid);if(el)el.value='';});
      this.init();
    },
    scan(id){
      App.toast('Starting scan for '+id+'...','info');
      App.apiFetch('/api/scans/start',{method:'POST',body:JSON.stringify({product:id})}).then(function(data){
        App.toast('Scan started. '+(data.jobs||[]).length+' scanner(s) queued.','success');
      }).catch(function(e){App.toast('Scan failed: '+(e.message||'Network error'),'error');});
    }
  },

  /* ═══ CONTROL ═══ */
  control:{
    loadStatus(){
      App.apiFetch('/api/products').then(function(data){
        if(data.error){App.$('app-status-list').innerHTML='<p class="dimmed" style="font-size:var(--text-xs)">API not available in standalone mode.</p>';return;}
        var el=App.$('app-status-list');if(!el)return;
        var products=data.products||{};var statuses=data.app_statuses||{};var keys=Object.keys(products);
        if(!keys.length){el.innerHTML='<p class="dimmed" style="font-size:var(--text-xs)">No products configured.</p>';return;}
        el.innerHTML=keys.map(function(k){
          var p=products[k];var s=statuses[k]||{};var isUp=s.status==='up';
          var dotColor=isUp?'#22C55E':'#EF4444';
          return '<div style="display:flex;align-items:center;gap:var(--space-2);padding:var(--space-2) 0;border-bottom:1px solid var(--border-subtle);font-size:var(--text-xs)"><span class="status-dot" style="background:'+dotColor+'"></span><span style="flex:1"><strong style="color:var(--text-primary)">'+App.esc(p.display_name||k)+'</strong> <span class="dimmed">'+App.esc(p.url||'')+'</span></span><span class="dimmed">'+(isUp?'UP ('+s.response_time_ms+'ms)':'DOWN')+'</span></div>';
        }).join('');
      }).catch(function(){App.$('app-status-list').innerHTML='<p class="dimmed" style="font-size:var(--text-xs)">API not available.</p>';});
    },
    connectWS(){
      if(typeof WebSocket==='undefined'||App.state.wsRetries>=5)return;
      var self=this;
      var proto=location.protocol==='https:'?'wss:':'ws:';
      try{
        App.state.ws=new WebSocket(proto+'//'+location.host+'/ws/live');
        App.state.wsRetries=0;
        App.state.ws.onmessage=function(e){try{var msg=JSON.parse(e.data);if(msg.type==='scan_update')self.handleScanUpdate(msg.data);}catch(x){}};
        App.state.ws.onclose=function(){App.state.wsRetries++;setTimeout(function(){self.connectWS();},5000);};
        App.state.ws.onerror=function(){};
      }catch(x){App.state.wsRetries++;}
    },
    handleScanUpdate(job){
      var el=App.$('scanner-progress');if(!el)return;
      var existing=el.querySelector('[data-job="'+job.job_id+'"]');
      if(!existing){el.innerHTML='';existing=document.createElement('div');existing.setAttribute('data-job',job.job_id);el.appendChild(existing);}
      var statusColors={pending:'#6B7280',running:'#3B82F6',completed:'#22C55E',failed:'#EF4444'};
      var sc=statusColors[job.status]||'#6B7280';
      // Elapsed assumes started_at is in seconds (Unix timestamp)
      var elapsed=job.started_at?(job.finished_at||Date.now()/1000)-job.started_at:0;
      existing.innerHTML='<div style="display:flex;align-items:center;gap:var(--space-3);padding:var(--space-2) 0;border-bottom:1px solid var(--border-subtle)"><span class="status-dot" style="background:'+sc+'"></span><div style="flex:1"><div style="font-size:var(--text-xs);font-weight:500;color:var(--text-primary)">'+App.esc(job.product)+' / '+App.esc(job.scanner)+'</div><div class="dimmed" style="font-size:10px">'+App.esc(job.target_url)+'</div></div><div style="text-align:right"><span style="font-size:10px;color:'+sc+'">'+job.status+'</span><div class="dimmed" style="font-size:10px">'+elapsed.toFixed(1)+'s</div></div></div>';
    },
    loadJobs(){
      App.apiFetch('/api/scans/jobs').then(function(data){
        if(data.jobs&&data.jobs.length){
          var el=App.$('scanner-progress');if(!el)return;
          el.innerHTML=data.jobs.map(function(job){
            var statusColors={pending:'#6B7280',running:'#3B82F6',completed:'#22C55E',failed:'#EF4444'};
            var sc=statusColors[job.status]||'#6B7280';
            var elapsed=job.started_at?(job.finished_at||Date.now()/1000)-job.started_at:0;
            return '<div data-job="'+job.job_id+'" style="display:flex;align-items:center;gap:var(--space-3);padding:var(--space-2) 0;border-bottom:1px solid var(--border-subtle)"><span class="status-dot" style="background:'+sc+'"></span><div style="flex:1"><div style="font-size:var(--text-xs);font-weight:500;color:var(--text-primary)">'+App.esc(job.product)+' / '+App.esc(job.scanner)+'</div></div><span style="font-size:10px;color:'+sc+'">'+job.status+'</span></div>';
          }).join('');
        }
      }).catch(function(){});
    },
    scanAll(){
      App.toast('Starting scan for all products...','info');
      App.apiFetch('/api/products').then(function(data){
        var products=data.products||{};
        // Use allSettled so one failure doesn't kill all scans
        Promise.allSettled(Object.keys(products).map(function(pid){
          return App.apiFetch('/api/scans/start',{method:'POST',body:JSON.stringify({product:pid})});
        })).then(function(){
          App.toast('Scans started for all products.','success');
        });
      }).catch(function(e){App.toast('Failed: '+(e.message||'Network error'),'error');});
    },
    runPipeline(){
      App.toast('Running pipeline...','info');
      App.apiFetch('/api/pipeline/run',{method:'POST',body:JSON.stringify({})}).then(function(){
        App.toast('Pipeline started. Check status periodically.','success');
      }).catch(function(e){App.toast('Pipeline failed: '+(e.message||'Network error'),'error');});
    },
    createTickets(){
      App.toast('Creating GitHub Issues...','info');
      App.apiFetch('/api/tickets/create?threshold=60',{method:'POST'}).then(function(data){
        var results=data.results||{};var total=0;Object.values(results).forEach(function(r){total+=(r.created||0);});
        App.toast('Created '+total+' Issues.','success');
      }).catch(function(e){App.toast('Failed: '+(e.message||'Network error'),'error');});
    },
    checkDocker(){
      App.toast('Checking Docker...','info');
      App.apiFetch('/api/scanners/status').then(function(data){
        if(data.docker_available){App.toast('Docker running. Active jobs: '+data.active_jobs,'success');}
        else{App.toast('Docker not available.','error');}
      }).catch(function(e){App.toast('Cannot connect: '+(e.message||'Network error'),'error');});
    }
  },

  /* ═══ LIFECYCLE ═══ */
  lifecycle:{
    init(){
      var LC=App.data.lifecycle||{};
      var tracked=LC.findings||[];
      var statusCounts=LC.status_counts||{};
      var overdueCount=LC.overdue_count||0;
      var openCount=(statusCounts.open||0);
      var inProgCount=(statusCounts.in_progress||0);
      var fixedCount=((statusCounts.fixed||0)+(statusCounts.verified||0));
      // Summary line
      var sl=App.$('lc-summary');
      if(sl)sl.innerHTML='Tracking <span style="color:var(--text-primary);font-weight:600">'+tracked.length+'</span> \u00b7 <span style="color:var(--risk-high);font-weight:600">'+openCount+'</span> open \u00b7 <span style="color:var(--risk-info);font-weight:600">'+inProgCount+'</span> in progress \u00b7 <span style="color:var(--risk-low);font-weight:600">'+fixedCount+'</span> fixed \u00b7 <span style="color:var(--risk-critical);font-weight:600">'+overdueCount+'</span> breached';
      var tcl=App.$('tc-lifecycle');if(tcl)tcl.textContent='('+tracked.length+')';
      // Table
      if(tracked.length>0){
        var statusConfig={open:{color:'#F59E0B',border:'#F59E0B'},in_progress:{color:'#3B82F6',border:'#3B82F6'},fixed:{color:'#22C55E',border:'#22C55E'},verified:{color:'#22D3EE',border:'#22D3EE'},accepted:{color:'#6B7280',border:'#6B7280'},false_positive:{color:'#EF4444',border:'#EF4444'},risk_accepted:{color:'#6B7280',border:'#6B7280'}};
        var now=new Date();
        var rows=tracked.slice(0,100).map(function(f){
          var sc=statusConfig[f.status]||{color:'#6B7280',border:'#6B7280'};
          var isBreach=f.sla_deadline&&new Date(f.sla_deadline)<now&&(f.status==='open'||f.status==='in_progress');
          return '<tr><td>'+App.esc(f.product)+'</td><td><span class="badge '+App.sevClass(f.severity)+'">'+App.esc(f.severity)+'</span></td><td class="truncate" style="max-width:200px;color:var(--text-primary);font-weight:500">'+App.esc(f.title)+'</td><td class="no-wrap">'+(f.cve?App.esc(f.cve):'<span class="dimmed">\u2014</span>')+'</td><td><span class="status-border" style="border-color:'+sc.border+';color:'+sc.color+';font-size:11px">'+f.status.replace('_',' ')+'</span></td><td class="no-wrap" style="font-size:11px;'+(isBreach?'color:var(--risk-critical);font-weight:700':'color:var(--text-muted)')+'">'+(isBreach?'BREACHED':'OK')+'</td><td class="dimmed" style="font-size:11px">'+App.esc(f.owner||'\u2014')+'</td></tr>';
        }).join('');
        App.$('lc-table-wrap').innerHTML='<table class="data-table"><thead><tr><th>Product</th><th>Severity</th><th>Title</th><th>CVE</th><th>Status</th><th>SLA</th><th>Owner</th></tr></thead><tbody>'+rows+'</tbody></table>';
      }else{
        App.$('lc-table-wrap').innerHTML='<div class="empty-state"><p class="empty-state-title">No Lifecycle Data</p><p class="empty-state-desc">Run the pipeline to start tracking.</p></div>';
      }
      // SLA breaches
      var overdue=LC.overdue_findings||[];
      var lcbl=App.$('lc-breached-list');
      if(overdue.length){
        var shown=overdue.slice(0,20);
        lcbl.innerHTML=shown.map(function(f){
          return '<div style="display:flex;align-items:center;gap:var(--space-2);padding:var(--space-2) 0;border-bottom:1px solid var(--border-subtle);font-size:var(--text-xs)"><span style="color:var(--risk-critical);font-weight:700">!</span><span style="flex:1"><strong style="color:var(--text-primary)">'+App.esc((f.title||'').substring(0,60))+'</strong> <span class="dimmed">'+App.esc(f.product)+'</span></span><span class="badge b-p1">BREACHED</span></div>';
        }).join('')+(overdue.length>20?'<p class="dimmed" style="font-size:var(--text-xs);padding:var(--space-2);text-align:center">+ '+(overdue.length-20)+' more</p>':'');
      }else{
        lcbl.innerHTML='<p class="dimmed" style="font-size:var(--text-xs);padding:var(--space-3)">No SLA breaches detected.</p>';
      }
    }
  },

  /* ═══ DEDUP ═══ */
  dedup:{
    init(){
      var S=App.data.summary;
      var DA=App.data.dedup_analytics||{};
      var overlapCount=(DA.cross_scanner_redundancy||[]).length;
      // Summary line
      var sl=App.$('dedup-summary-line');
      if(sl)sl.innerHTML='<span style="font-size:var(--text-xs);color:var(--text-tertiary)"><strong style="color:var(--text-primary)">'+S.raw_findings+'</strong> raw \u2192 <strong style="color:var(--text-primary)">'+S.unique_findings+'</strong> unique ('+S.dedup_pct+'% dedup) \u00b7 <strong style="color:var(--risk-medium)">'+overlapCount+'</strong> overlaps found</span>';
      // DRY: shared scannerCounts computation
      var scannerCounts=DA.per_scanner_counts||{};
      if(Object.keys(scannerCounts).length===0){
        var scanMap={};App.data.findings.forEach(function(f){scanMap[f.scanner]=(scanMap[f.scanner]||0)+1;});scannerCounts=scanMap;
      }
      var scanKeys=Object.keys(scannerCounts).filter(function(k){return scannerCounts[k]>0;}).sort(function(a,b){return scannerCounts[b]-scannerCounts[a];});
      if(App.hasChart&&App.$('c-dedup-scanner')){
        new Chart(App.$('c-dedup-scanner'),{type:'bar',data:{labels:scanKeys,datasets:[{data:scanKeys.map(function(k){return scannerCounts[k];}),backgroundColor:CHART_COLORS.scannerBar,borderWidth:0,borderRadius:4}]},options:{indexAxis:'y',scales:{x:{grid:{color:App.gridColor},ticks:{font:{size:10},color:'#9CA3AF'}},y:{grid:{display:false},ticks:{font:{size:10},color:'#9CA3AF'}}},plugins:{legend:{display:false}}}});
      }
      var overlaps=DA.cross_scanner_redundancy||[];
      if(App.hasChart&&App.$('c-dedup-overlap')){
        if(overlaps.length>0){
          var top=overlaps.slice(0,10);
          new Chart(App.$('c-dedup-overlap'),{type:'bar',data:{labels:top.map(function(o){return(o.cve||o.vulnerability||'').substring(0,25);}),datasets:[{data:top.map(function(o){return(o.scanners_found_it||[]).length;}),backgroundColor:CHART_COLORS.overlapBar,borderWidth:0,borderRadius:4}]},options:{indexAxis:'y',scales:{x:{grid:{color:App.gridColor},ticks:{font:{size:10},color:'#9CA3AF'}},y:{grid:{display:false},ticks:{font:{size:10},color:'#9CA3AF'}}},plugins:{legend:{display:false}}}});
        }else{
          // Hide canvas instead of destroying it (data may arrive later)
          App.$('c-dedup-overlap').parentElement.innerHTML='<div class="card-header">Top Overlaps</div><div class="empty-state" style="height:200px"><p class="empty-state-desc">No cross-scanner overlaps</p></div>';
        }
      }
      // Overlap table
      var ot=App.$('dedup-overlap-table');
      if(ot&&overlaps.length>0){
        ot.innerHTML='<table class="data-table"><thead><tr><th>CVE</th><th>Scanners</th><th>Vulnerability</th><th>Product</th></tr></thead><tbody>'+overlaps.map(function(o){
          return '<tr><td>'+(o.cve?'<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/'+App.esc(o.cve)+'" target="_blank">'+App.esc(o.cve)+'</a>':'<span class="dimmed">\u2014</span>')+'</td><td style="font-size:11px">'+(o.scanners_found_it||[]).join(', ')+'</td><td class="truncate" style="max-width:200px">'+App.esc(o.vulnerability||'\u2014')+'</td><td class="dimmed" style="font-size:11px">'+App.esc(o.product||'\u2014')+'</td></tr>';
        }).join('')+'</tbody></table>';
      }
    }
  },

  /* ═══ INTEGRATIONS ═══ */
  integrations:{
    _fieldMap:[
      {el:'ak-groq',key:'groq_api_key'},{el:'ak-nvd',key:'nvd_api_key'},
      {el:'ak-github',key:'github_token'},{el:'ak-jira-url',key:'jira_url'},
      {el:'ak-jira-user',key:'jira_user'},{el:'ak-jira-token',key:'jira_token'},
      {el:'ak-jira-project',key:'jira_project'},{el:'ak-dd-url',key:'defectdojo_url'},
      {el:'ak-dd-key',key:'defectdojo_api_key'}
    ],
    _apiCall(action,endpoint,method,elId,successMsg,body){
      var el=App.$(elId);if(!el)return Promise.resolve();
      el.innerHTML='<span class="dimmed">'+action+'...</span>';
      var opts={method:method||'GET'};
      if(body)opts.body=JSON.stringify(body);
      return App.apiFetch(endpoint,opts).then(function(data){
        if(data.error){el.innerHTML='<span style="color:#EF4444">'+App.esc(data.error)+'</span>';return data;}
        el.innerHTML='<span style="color:#22C55E">'+App.esc(successMsg(data))+'</span>';
        return data;
      }).catch(function(e){el.innerHTML='<span style="color:#EF4444">'+App.esc(e.message||'Network error')+'</span>';});
    },
    saveKeys(){
      var keys={};
      this._fieldMap.forEach(function(f){
        var val=App.$(f.el);
        if(val&&val.value&&val.value.trim())keys[f.key]=val.value.trim();
      });
      return this._apiCall('Saving','/api/config/keys','POST','apikey-status',function(){return 'Saved! Restart server to apply.';},keys);
    },
    testJira(){return this._apiCall('Testing','/api/jira/test','GET','jira-status',function(d){return d.connected?'Connected to '+App.esc(d.url||'Jira'):App.esc(d.error||'Not configured');});},
    createJira(){return this._apiCall('Creating','/api/jira/create?threshold=60','POST','jira-status',function(d){return 'Created '+(d.created||0)+' issues';});},
    testDD(){return this._apiCall('Testing','/api/defectdojo/test','GET','dd-status',function(d){return d.connected?'Connected to '+App.esc(d.url||'DefectDojo'):App.esc(d.error||'Not configured');});},
    importDD(){return this._apiCall('Importing','/api/defectdojo/import?product_name=all','POST','dd-status',function(d){return App.esc(d.message||'Imported');});}
  }
};

// Cleanup on page unload
window.addEventListener('beforeunload',function(){
  if(App.attackPaths._ro)App.attackPaths._ro.disconnect();
  if(App.state.ws){App.state.ws.close();App.state.ws=null;}
});

if(document.readyState!=='loading'){App.init();}else{document.addEventListener('DOMContentLoaded',App.init);}
</script>
</body>
</html>"""


# ─────────────────────────── build dashboard ──────────────────────────────────

def build_dashboard(
    path: str,
    all_findings: List[Finding],
    ranked: List[Finding],
    summary: RunSummary,
    attack_paths: Dict[str, List],
    history: Dict[str, List],
    quarantine: List[Finding],
    executive_brief: str = "",
    products_config: Optional[Dict] = None,
) -> None:
    """Write the self-contained HTML dashboard."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    # Load lifecycle data from DB
    lifecycle_data = {"findings": [], "status_counts": {}, "overdue_count": 0, "overdue_findings": []}
    lifecycle_db_path = os.path.join(os.path.dirname(path) or '.', 'lifecycle.db')
    if os.path.exists(lifecycle_db_path):
        try:
            from .lifecycle import LifecycleManager
            lc = LifecycleManager(lifecycle_db_path)
            lifecycle_data = lc.get_dashboard_data()
            lc.close()
        except Exception:
            pass

    # Load dedup analytics from noise_reduction.json
    dedup_analytics = {}
    noise_json_path = os.path.join(os.path.dirname(path) or '.', 'noise_reduction.json')
    if os.path.exists(noise_json_path):
        try:
            with open(noise_json_path) as nf:
                dedup_analytics = json.load(nf)
        except Exception:
            pass

    dash_data = {
        "summary": summary.to_dict(),
        "findings": _serialize_findings(ranked),
        "attack_paths": attack_paths,
        "history": history,
        "quarantine": _serialize_quarantine(all_findings),
        "executive_brief": executive_brief,
        "products": products_config or {},
        "lifecycle": lifecycle_data,
        "dedup_analytics": dedup_analytics,
    }
    json_str = json.dumps(dash_data, ensure_ascii=True)
    # Robust XSS prevention — escape all HTML-significant chars in JSON
    json_str = json_str.replace("</script>", r"<\/script>")
    json_str = json_str.replace("</SCRIPT>", r"<\/SCRIPT>")
    json_str = json_str.replace("<!--", r"<\!--")
    json_str = json_str.replace("-->", r"--\>")
    # Replace < with \u003c to prevent breaking out of script tags
    # This replaces ALL < in JSON values -- safe for security data where < is rare
    json_str = json_str.replace("<", "\\u003c")
    html = _HTML_TEMPLATE.replace("__DASH_JSON__", json_str)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
