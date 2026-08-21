"""Stunning dark-theme risk intelligence dashboard.

Generates a self-contained HTML file with:
  - Chart.js 4  — priority donut, severity bar, scanner coverage,
                   noise waterfall, risk-over-time, EPSS scatter
  - D3 v7       — interactive force-directed attack-path graph
  - Vanilla JS  — component-like architecture, animated counters,
                   searchable/sortable/filterable findings table,
                   expandable finding cards with AI remediation

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
# Uses __PLACEHOLDER__ tokens (not f-strings) to avoid escaping every {{ }}.

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Risk Intelligence Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#050a14;--surface:#0d1521;--surface2:#131f30;--surface3:#1a2740;
  --border:rgba(255,255,255,.07);--border2:rgba(255,255,255,.12);
  --text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;
  --blue:#3b82f6;--cyan:#06b6d4;--indigo:#6366f1;
  --red:#ef4444;--orange:#f97316;--yellow:#eab308;--green:#22c55e;
  --p1:#ef4444;--p2:#f97316;--p3:#eab308;--p4:#64748b;
  --critical:#ef4444;--high:#f97316;--medium:#eab308;--low:#22c55e;--info:#64748b;
  --glow-blue:0 0 24px rgba(59,130,246,.25);
  --glow-red:0 0 24px rgba(239,68,68,.25);
  --radius:12px;--radius-sm:8px;
  --font:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono',monospace;
}
html{scroll-behavior:smooth}
body{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5;-webkit-font-smoothing:antialiased}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
.header{position:sticky;top:0;z-index:100;background:rgba(5,10,20,.85);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);padding:0 28px;display:flex;align-items:center;gap:20px;height:62px}
.logo{display:flex;align-items:center;gap:10px;text-decoration:none;flex-shrink:0}
.logo-icon{font-size:22px}
.logo-text{font-size:15px;font-weight:800;letter-spacing:-.3px;background:linear-gradient(135deg,#3b82f6,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.run-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.meta-pill{font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--surface3);color:var(--text2);border:1px solid var(--border);white-space:nowrap}
.meta-pill.warning{background:rgba(239,68,68,.12);color:#fca5a5;border-color:rgba(239,68,68,.25)}
.tab-nav{display:flex;gap:2px;margin-left:auto;flex-shrink:0}
.tab-btn{padding:7px 16px;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:12.5px;font-weight:500;color:var(--text3);background:transparent;transition:all .2s;white-space:nowrap;font-family:var(--font)}
.tab-btn:hover{color:var(--text);background:var(--surface2)}
.tab-btn.active{background:rgba(59,130,246,.15);color:var(--blue);box-shadow:inset 0 0 0 1px rgba(59,130,246,.25)}
.tab-count{display:inline-flex;align-items:center;justify-content:center;min-width:18px;height:18px;padding:0 5px;margin-left:5px;background:var(--surface3);border-radius:9px;font-size:10px;font-weight:700;color:var(--text2)}
.tab-btn.active .tab-count{background:rgba(59,130,246,.25);color:var(--blue)}
.page{display:none;padding:28px;max-width:1600px;margin:0 auto;animation:fadeIn .3s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.brief-card{background:linear-gradient(135deg,rgba(59,130,246,.06),rgba(6,182,212,.06));border:1px solid rgba(59,130,246,.2);border-radius:var(--radius);padding:20px 24px;margin-bottom:28px;display:flex;gap:16px;align-items:flex-start}
.brief-icon{font-size:28px;flex-shrink:0;margin-top:2px}
.brief-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:var(--cyan);margin-bottom:6px}
.brief-text{font-size:13.5px;line-height:1.7;color:#cbd5e1}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px;margin-bottom:28px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 16px;transition:border-color .25s,box-shadow .25s;position:relative;overflow:hidden}
.kpi::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,transparent,rgba(255,255,255,.015));pointer-events:none}
.kpi:hover{border-color:var(--border2);box-shadow:var(--glow-blue)}
.kpi-value{font-size:30px;font-weight:800;line-height:1;margin-bottom:5px;font-variant-numeric:tabular-nums}
.kpi-label{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;font-weight:500}
.kpi-sub{font-size:11px;color:var(--text3);margin-top:3px}
.kpi-accent{position:absolute;right:12px;top:14px;font-size:22px;opacity:.25}
.kpi.danger .kpi-value{color:var(--red)}
.kpi.danger:hover{border-color:rgba(239,68,68,.3);box-shadow:var(--glow-red)}
.kpi.success .kpi-value{color:var(--green)}
.kpi.warn .kpi-value{color:var(--orange)}
.kpi.blue .kpi-value{color:var(--blue)}
.kpi.cyan .kpi-value{color:var(--cyan)}
.chart-row-3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}
.chart-row-2{display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-bottom:20px}
.chart-row-1{margin-bottom:20px}
@media(max-width:1100px){.chart-row-3{grid-template-columns:1fr 1fr}}
@media(max-width:700px){.chart-row-3,.chart-row-2{grid-template-columns:1fr}}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;transition:border-color .25s}
.card:hover{border-color:var(--border2)}
.card-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text3);margin-bottom:16px;display:flex;align-items:center;gap:8px}
.card-title span{font-size:14px}
.chart-wrap{position:relative}
.table-controls{display:flex;gap:10px;margin-bottom:16px;align-items:center;flex-wrap:wrap}
.search-box{flex:1;min-width:200px;max-width:360px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 14px 8px 36px;color:var(--text);font-size:13px;font-family:var(--font);transition:border-color .2s;outline:none}
.search-wrap{position:relative;flex:1;min-width:200px;max-width:360px}
.search-icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--text3);font-size:14px;pointer-events:none}
.search-box:focus{border-color:rgba(59,130,246,.5);box-shadow:0 0 0 3px rgba(59,130,246,.08)}
.filter-sel{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 12px;color:var(--text);font-size:12px;font-family:var(--font);cursor:pointer;outline:none;transition:border-color .2s}
.filter-sel:focus{border-color:rgba(59,130,246,.5)}
.result-badge{margin-left:auto;font-size:12px;color:var(--text3);background:var(--surface2);padding:5px 12px;border-radius:20px;border:1px solid var(--border);white-space:nowrap}
.table-wrap{overflow-x:auto;border-radius:var(--radius);border:1px solid var(--border)}
.f-table{width:100%;border-collapse:collapse;font-size:12.5px}
.f-table thead th{background:var(--surface2);color:var(--text3);padding:10px 12px;text-align:left;font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.6px;white-space:nowrap;user-select:none;border-bottom:1px solid var(--border);cursor:pointer;transition:color .2s}
.f-table thead th:hover{color:var(--text)}
.f-table thead th.sorted{color:var(--blue)}
.f-table thead th .sort-arrow{font-size:9px;margin-left:3px;opacity:.5}
.f-table thead th.sorted .sort-arrow{opacity:1;color:var(--blue)}
.f-table tbody tr{border-bottom:1px solid rgba(255,255,255,.03);transition:background .12s;cursor:pointer}
.f-table tbody tr:hover td{background:rgba(59,130,246,.04)}
.f-table tbody tr.expanded td{background:rgba(59,130,246,.05)}
.f-table td{padding:9px 12px;vertical-align:middle;max-width:240px}
.f-table td.no-wrap{white-space:nowrap;max-width:none}
.f-table .detail-row{display:none}
.f-table .detail-row.open{display:table-row}
.f-table .detail-row td{padding:0;background:var(--surface2)}
.badge{display:inline-flex;align-items:center;justify-content:center;padding:2px 8px;border-radius:20px;font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}
.b-p1{background:rgba(239,68,68,.12);color:#fca5a5;border:1px solid rgba(239,68,68,.25)}
.b-p2{background:rgba(249,115,22,.12);color:#fdba74;border:1px solid rgba(249,115,22,.25)}
.b-p3{background:rgba(234,179,8,.12);color:#fde047;border:1px solid rgba(234,179,8,.25)}
.b-p4{background:rgba(100,116,139,.12);color:#94a3b8;border:1px solid rgba(100,116,139,.25)}
.b-critical{background:rgba(239,68,68,.1);color:#ef4444}
.b-high{background:rgba(249,115,22,.1);color:#f97316}
.b-medium{background:rgba(234,179,8,.1);color:#eab308}
.b-low{background:rgba(34,197,94,.1);color:#22c55e}
.b-info{background:rgba(100,116,139,.1);color:#94a3b8}
.b-kev{background:rgba(239,68,68,.18);color:#fca5a5;border:1px solid rgba(239,68,68,.35);animation:kev-pulse 2.5s ease-in-out infinite}
@keyframes kev-pulse{0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,0)}50%{box-shadow:0 0 6px 2px rgba(239,68,68,.25)}}
.b-exploit{background:rgba(249,115,22,.18);color:#fdba74;border:1px solid rgba(249,115,22,.35)}
.b-epss{background:rgba(99,102,241,.1);color:#a5b4fc}
.score-cell{display:flex;align-items:center;gap:8px;min-width:90px}
.score-num{font-size:13px;font-weight:700;font-family:var(--mono);width:30px;text-align:right;flex-shrink:0}
.score-track{flex:1;height:4px;background:rgba(255,255,255,.08);border-radius:2px;overflow:hidden;min-width:40px}
.score-fill{height:100%;border-radius:2px;transition:width .8s cubic-bezier(.4,0,.2,1)}
.detail-panel{padding:20px 24px;border-top:1px solid var(--border);display:grid;grid-template-columns:1fr 1fr;gap:24px}
@media(max-width:800px){.detail-panel{grid-template-columns:1fr}}
.detail-section-title{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text3);margin-bottom:10px}
.detail-row-item{display:flex;gap:6px;margin-bottom:6px;font-size:12px;align-items:flex-start}
.detail-key{color:var(--text3);flex-shrink:0;width:140px;font-size:11px;font-weight:500}
.detail-val{color:var(--text);word-break:break-all;font-family:var(--mono);font-size:11px}
.ai-box{background:linear-gradient(135deg,rgba(59,130,246,.06),rgba(6,182,212,.06));border:1px solid rgba(59,130,246,.15);border-radius:var(--radius-sm);padding:12px 14px;font-size:12.5px;line-height:1.65;color:#cbd5e1;grid-column:1/-1}
.ai-label{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--cyan);margin-bottom:6px}
.rem-list{list-style:none}
.rem-list li{padding:5px 0;font-size:12px;border-bottom:1px solid var(--border);display:flex;gap:8px;color:var(--text2)}
.rem-list li:last-child{border:none}
.rem-kind{font-size:10px;font-weight:600;text-transform:uppercase;color:var(--text3);flex-shrink:0;margin-top:1px}
.cve-link{color:var(--cyan);text-decoration:none;font-family:var(--mono);font-size:11.5px}
.cve-link:hover{text-decoration:underline}
#ap-container{position:relative;border-radius:var(--radius);overflow:hidden;background:var(--surface)}
#ap-svg{display:block;width:100%}
.ap-legend{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px}
.ap-legend-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text2)}
.ap-legend-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.ap-tooltip{position:absolute;pointer-events:none;display:none;background:var(--surface3);border:1px solid var(--border2);border-radius:var(--radius-sm);padding:10px 14px;font-size:12px;color:var(--text);max-width:240px;box-shadow:0 8px 32px rgba(0,0,0,.5);z-index:10}
.ap-controls{display:flex;gap:8px;margin-bottom:14px;align-items:center}
.ap-btn{padding:6px 14px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface2);color:var(--text2);font-size:12px;cursor:pointer;transition:all .2s;font-family:var(--font)}
.ap-btn:hover{border-color:var(--border2);color:var(--text)}
.ap-product-sel{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 12px;color:var(--text);font-size:12px;cursor:pointer;font-family:var(--font)}
.ap-no-data{text-align:center;padding:60px 20px;color:var(--text3);font-size:14px}
.q-table-wrap{border-radius:var(--radius);border:1px solid var(--border);overflow:hidden}
.q-note{background:rgba(234,179,8,.06);border:1px solid rgba(234,179,8,.15);border-radius:var(--radius);padding:12px 16px;margin-bottom:16px;font-size:13px;color:#fde047;display:flex;align-items:center;gap:10px}
.footer{text-align:center;padding:32px;color:var(--text3);font-size:12px;border-top:1px solid var(--border);margin-top:40px}
.mono{font-family:var(--mono)}
.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dimmed{color:var(--text3)}
.empty-state{text-align:center;padding:48px;color:var(--text3);font-size:13px}
</style>
</head>
<body>
<header class="header">
  <a class="logo" href="#"><span class="logo-icon">🛡️</span><span class="logo-text">RISK INTELLIGENCE</span></a>
  <div class="run-meta" id="run-meta"></div>
  <nav class="tab-nav">
    <button class="tab-btn active" data-page="overview">Overview</button>
    <button class="tab-btn" data-page="findings">Findings<span class="tab-count" id="tc-findings">0</span></button>
    <button class="tab-btn" data-page="attackpaths">Attack Paths<span class="tab-count" id="tc-paths">0</span></button>
    <button class="tab-btn" data-page="quarantine">Quarantine<span class="tab-count" id="tc-quarantine">0</span></button>
    <button class="tab-btn" data-page="products">Products<span class="tab-count" id="tc-products">0</span></button>
    <button class="tab-btn" data-page="control">Control Center</button>
    <button class="tab-btn" data-page="lifecycle">Lifecycle<span class="tab-count" id="tc-lifecycle">0</span></button>
    <button class="tab-btn" data-page="dedup">Dedup Analytics</button>
    <button class="tab-btn" data-page="integrations">Integrations</button>
  </nav>
</header>
<main id="page-overview" class="page active">
  <div id="brief-section"></div>
  <div class="kpi-grid" id="kpi-grid"></div>
  <div class="chart-row-3">
    <div class="card"><div class="card-title"><span>🎯</span> Priority distribution</div><div class="chart-wrap" style="height:220px"><canvas id="c-priority"></canvas></div></div>
    <div class="card"><div class="card-title"><span>⚡</span> Severity breakdown</div><div class="chart-wrap" style="height:220px"><canvas id="c-severity"></canvas></div></div>
    <div class="card"><div class="card-title"><span>🔍</span> Scanner coverage</div><div class="chart-wrap" style="height:220px"><canvas id="c-scanner"></canvas></div></div>
  </div>
  <div class="chart-row-2">
    <div class="card"><div class="card-title"><span>📉</span> Noise reduction pipeline</div><div class="chart-wrap" style="height:240px"><canvas id="c-noise"></canvas></div></div>
    <div class="card"><div class="card-title"><span>📈</span> Risk over time</div><div class="chart-wrap" style="height:240px"><canvas id="c-history"></canvas></div></div>
  </div>
  <div class="chart-row-2">
    <div class="card"><div class="card-title"><span>🎲</span> EPSS vs risk score</div><div class="chart-wrap" style="height:260px"><canvas id="c-epss"></canvas></div></div>
    <div class="card"><div class="card-title"><span>🔥</span> Threat intelligence coverage</div><div class="chart-wrap" style="height:260px"><canvas id="c-threat"></canvas></div></div>
  </div>
</main>
<main id="page-findings" class="page">
  <div class="table-controls">
    <div class="search-wrap"><span class="search-icon">🔍</span><input id="tbl-search" class="search-box" placeholder="Search title, CVE, CWE, endpoint…"></div>
    <select id="f-priority" class="filter-sel"><option value="">All priorities</option></select>
    <select id="f-severity" class="filter-sel"><option value="">All severities</option></select>
    <select id="f-scanner" class="filter-sel"><option value="">All scanners</option></select>
    <select id="f-kev" class="filter-sel"><option value="">KEV filter</option><option value="kev">KEV only</option><option value="exploit">Exploit available</option></select>
    <span class="result-badge" id="result-badge">— findings</span>
  </div>
  <div class="table-wrap"><table class="f-table"><thead id="tbl-head"></thead><tbody id="tbl-body"></tbody></table></div>
</main>
<main id="page-attackpaths" class="page">
  <div class="card">
    <div class="card-title"><span>🕸️</span> Attack path graph — drag nodes · scroll to zoom</div>
    <div class="ap-legend">
      <span class="ap-legend-item"><span class="ap-legend-dot" style="background:#ef4444;box-shadow:0 0 6px #ef4444"></span>High-impact target</span>
      <span class="ap-legend-item"><span class="ap-legend-dot" style="background:#3b82f6"></span>Intermediate CWE</span>
      <span class="ap-legend-item"><span class="ap-legend-dot" style="background:#06b6d4;border-radius:2px;height:3px;width:20px"></span>High-probability path</span>
    </div>
    <div class="ap-controls"><select id="ap-product" class="ap-product-sel"></select><button class="ap-btn" onclick="apReset()">Reset zoom</button><span class="dimmed" style="font-size:12px;margin-left:4px">Nodes: CWEs active in this product · edges: escalation probability</span></div>
    <div id="ap-container"><svg id="ap-svg" height="540"></svg><div class="ap-tooltip" id="ap-tooltip"></div></div>
  </div>
</main>
<main id="page-quarantine" class="page">
  <div class="q-note">⚠️ Quarantined findings are never deleted — they remain auditable below. Rule matches are the exclusion reason.</div>
  <div class="q-table-wrap"><table class="f-table"><thead><tr><th>Product</th><th>Scanner</th><th>Severity</th><th>Title</th><th>CVE</th><th>Exclusion reason</th></tr></thead><tbody id="q-body"></tbody></table></div>
</main>
<main id="page-products" class="page">
  <div class="card" style="margin-bottom:20px">
    <div class="card-title"><span>📦</span> Managed Products</div>
    <div id="products-table-wrap"></div>
  </div>
  <div class="card">
    <div class="card-title"><span>➕</span> Add New Product</div>
    <div id="add-product-form" style="display:grid;grid-template-columns:1fr 1fr;gap:16px;max-width:700px">
      <div><label class="dimmed" style="font-size:11px;display:block;margin-bottom:4px">Product ID (slug)</label><input id="ap-id" class="search-box" style="width:100%;max-width:none" placeholder="my_custom_app"></div>
      <div><label class="dimmed" style="font-size:11px;display:block;margin-bottom:4px">Display Name</label><input id="ap-name" class="search-box" style="width:100%;max-width:none" placeholder="My Custom App"></div>
      <div><label class="dimmed" style="font-size:11px;display:block;margin-bottom:4px">Target URL</label><input id="ap-url" class="search-box" style="width:100%;max-width:none" placeholder="https://myapp.com"></div>
      <div><label class="dimmed" style="font-size:11px;display:block;margin-bottom:4px">GitHub Repo (org/name)</label><input id="ap-repo" class="search-box" style="width:100%;max-width:none" placeholder="myorg/myapp"></div>
      <div><label class="dimmed" style="font-size:11px;display:block;margin-bottom:4px">Team Owner</label><input id="ap-owner" class="search-box" style="width:100%;max-width:none" placeholder="appsec-team"></div>
      <div><label class="dimmed" style="font-size:11px;display:block;margin-bottom:4px">Asset Criticality (1-10)</label><input id="ap-crit" type="number" min="1" max="10" value="5" class="search-box" style="width:100%;max-width:none"></div>
      <div><label class="dimmed" style="font-size:11px;display:block;margin-bottom:4px">Data Sensitivity (1-10)</label><input id="ap-sens" type="number" min="1" max="10" value="5" class="search-box" style="width:100%;max-width:none"></div>
      <div><label class="dimmed" style="font-size:11px;display:block;margin-bottom:4px">Trivy Image (optional)</label><input id="ap-trivy" class="search-box" style="width:100%;max-width:none" placeholder="myorg/myapp:latest"></div>
      <div style="grid-column:1/-1;display:flex;gap:10px;margin-top:8px">
        <button class="ap-btn" onclick="addProduct()" style="background:rgba(59,130,246,.2);color:#93c5fd;border-color:rgba(59,130,246,.3)">Save Product</button>
        <span id="ap-msg" style="font-size:12px;color:var(--green);align-self:center"></span>
      </div>
    </div>
  </div>
</main>
<main id="page-control" class="page">
  <div class="card" style="margin-bottom:20px">
    <div class="card-title"><span>&#x1f680;</span> Control Center</div>
    <div id="control-status" style="margin-bottom:16px"></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div>
        <div class="detail-section-title">App Status</div>
        <div id="app-status-list"></div>
      </div>
      <div>
        <div class="detail-section-title">Quick Actions</div>
        <div style="display:flex;flex-direction:column;gap:10px">
          <button class="ap-btn" onclick="triggerScanAll()" style="background:rgba(59,130,246,.15);color:#93c5fd;border-color:rgba(59,130,246,.3);padding:10px 16px">&#x1f50d; Scan All Products</button>
          <button class="ap-btn" onclick="runPipeline()" style="background:rgba(34,197,94,.15);color:#86efac;border-color:rgba(34,197,94,.3);padding:10px 16px">&#x26a1; Run Pipeline</button>
          <button class="ap-btn" onclick="createTickets()" style="background:rgba(249,115,22,.15);color:#fdba74;border-color:rgba(249,115,22,.3);padding:10px 16px">&#x1f4cb; Create GitHub Issues</button>
          <button class="ap-btn" onclick="checkDocker()" style="background:rgba(6,182,212,.15);color:#67e8f9;border-color:rgba(6,182,212,.3);padding:10px 16px">&#x1f4e6; Check Docker Status</button>
        </div>
      </div>
    </div>
  </div>
  <div class="card">
    <div class="card-title"><span>&#x1f4ca;</span> Scanner Progress</div>
    <div id="scanner-progress">
      <p class="dimmed" style="font-size:13px">No active scans. Use the controls above to start scanning.</p>
    </div>
  </div>
</main>
<main id="page-lifecycle" class="page">
  <div class="kpi-grid" id="lc-kpi-grid"></div>
  <div class="card" style="margin-bottom:20px">
    <div class="card-title"><span>🔄</span> Vulnerability Lifecycle</div>
    <p class="dimmed" style="font-size:12px;margin-bottom:16px">Track findings from Open → In Progress → Fixed → Verified. SLA deadlines shown in red when breached.</p>
    <div id="lc-table-wrap"></div>
  </div>
  <div class="card">
    <div class="card-title"><span>⏰</span> SLA Breach Monitor</div>
    <div id="lc-breached-list"></div>
  </div>
</main>
<main id="page-dedup" class="page">
  <div class="kpi-grid" id="dedup-kpi-grid"></div>
  <div class="chart-row-2">
    <div class="card"><div class="card-title"><span>🔀</span> Findings per scanner (pre-dedup)</div><div class="chart-wrap" style="height:260px"><canvas id="c-dedup-scanner"></canvas></div></div>
    <div class="card"><div class="card-title"><span>🔗</span> Cross-scanner redundancy</div><div class="chart-wrap" style="height:260px"><canvas id="c-dedup-overlap"></canvas></div></div>
  </div>
  <div class="card">
    <div class="card-title"><span>📋</span> Cross-Scanner Overlap Details</div>
    <div id="dedup-overlap-table"></div>
  </div>
</main>
<main id="page-integrations" class="page">
  <div class="chart-row-2">
    <div class="card">
      <div class="card-title"><span>🎫</span> Jira Integration</div>
      <div id="jira-panel">
        <p class="dimmed" style="font-size:12px;margin-bottom:12px">Create Jira issues for high-risk findings. Requires JIRA_URL, JIRA_USER, JIRA_TOKEN in .env</p>
        <div style="display:flex;gap:10px;margin-bottom:16px">
          <button class="ap-btn" onclick="testJira()" style="background:rgba(59,130,246,.15);color:#93c5fd;border-color:rgba(59,130,246,.3)">Test Connection</button>
          <button class="ap-btn" onclick="createJiraIssues()" style="background:rgba(34,197,94,.15);color:#86efac;border-color:rgba(34,197,94,.3)">Create Issues</button>
        </div>
        <div id="jira-status"></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title"><span>🛡️</span> DefectDojo Integration</div>
      <div id="dd-panel">
        <p class="dimmed" style="font-size:12px;margin-bottom:12px">Push findings to DefectDojo for compliance and verification. Requires DEFECTDOJO_URL + API_KEY in .env</p>
        <div style="display:flex;gap:10px;margin-bottom:16px">
          <button class="ap-btn" onclick="testDefectDojo()" style="background:rgba(59,130,246,.15);color:#93c5fd;border-color:rgba(59,130,246,.3)">Test Connection</button>
          <button class="ap-btn" onclick="importDefectDojo()" style="background:rgba(34,197,94,.15);color:#86efac;border-color:rgba(34,197,94,.3)">Import Findings</button>
        </div>
        <div id="dd-status"></div>
      </div>
    </div>
  </div>
  <div class="card">
    <div class="card-title"><span>📤</span> Exports</div>
    <div style="display:flex;gap:12px;flex-wrap:wrap">
      <a class="ap-btn" href="/api/exports/sarif" target="blank" style="background:rgba(99,102,241,.15);color:#a5b4fc;border-color:rgba(99,102,241,.3);text-decoration:none;padding:10px 16px;display:inline-flex;align-items:center;gap:6px">📄 SARIF (GitHub Security)</a>
      <a class="ap-btn" href="/api/exports/cyclonedx" target="blank" style="background:rgba(6,182,212,.15);color:#67e8f9;border-color:rgba(6,182,212,.3);text-decoration:none;padding:10px 16px;display:inline-flex;align-items:center;gap:6px">📦 CycloneDX SBOM</a>
      <a class="ap-btn" href="/api/exports/defectdojo" target="blank" style="background:rgba(249,115,22,.15);color:#fdba74;border-color:rgba(249,115,22,.3);text-decoration:none;padding:10px 16px;display:inline-flex;align-items:center;gap:6px">🛡️ DefectDojo JSON</a>
    </div>
  </div>
</main>
<footer class="footer">Generated by the DevSecOps Risk Intelligence Pipeline v2.0 · Chart.js 4 · D3 v7 · All data is local — no telemetry</footer>
<script>const DASH=__DASH_JSON__;</script>
<script>
const esc=s=>(s||'').toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const $=id=>document.getElementById(id);
const scoreColor=v=>v>=80?'#ef4444':v>=60?'#f97316':v>=40?'#eab308':'#22c55e';
const priClass=p=>({P1:'b-p1',P2:'b-p2',P3:'b-p3',P4:'b-p4'}[p]||'b-p4');
const sevClass=s=>({critical:'b-critical',high:'b-high',medium:'b-medium',low:'b-low',info:'b-info'}[s]||'b-info');
const fmt=n=>typeof n==='number'?n.toLocaleString():n||'-';
const pct=n=>n!=null&&n!==''?`${(n*100).toFixed(1)}%`:'-';
const HAS_CHART=typeof Chart!=='undefined';
if(HAS_CHART){Chart.defaults.color='#94a3b8';Chart.defaults.font.family="'Inter',system-ui,sans-serif";Chart.defaults.font.size=11;}
const gridColor='rgba(255,255,255,.05)';
const cardCfg={plugins:{legend:{display:false}},maintainAspectRatio:false};
let apInited=false;
document.querySelectorAll('.tab-btn').forEach(btn=>{btn.addEventListener('click',()=>{document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));btn.classList.add('active');const page='page-'+btn.dataset.page;const pg=$(page);if(pg)pg.classList.add('active');if(btn.dataset.page==='attackpaths'&&!apInited){initD3();apInited=true;}if(btn.dataset.page==='control'){loadAppStatus();connectWebSocket();loadScannerJobs();}});});
function animateCount(el,target){const dur=1400,start=performance.now(),from=0;const isFloat=String(target).includes('.');(function tick(now){const p=Math.min((now-start)/dur,1);const ease=1-Math.pow(1-p,3);const val=from+ease*(target-from);el.textContent=isFloat?val.toFixed(1):Math.round(val).toLocaleString();if(p<1)requestAnimationFrame(tick);})(start);}
(function buildHeader(){try{const S=DASH.summary;const meta=$('run-meta');const pills=[`<span class="meta-pill">🗓 ${S.run_date.substring(0,16)}</span>`,...S.products.map(p=>`<span class="meta-pill">📦 ${esc(p)}</span>`)];if(S.p1>0)pills.push(`<span class="meta-pill warning">🚨 ${S.p1} P1</span>`);meta.innerHTML=pills.join('');$('tc-findings').textContent=S.final_findings;if($('tc-quarantine'))$('tc-quarantine').textContent=S.quarantined;}catch(e){console.error('buildHeader:',e);}})();
(function buildBrief(){try{const brief=DASH.executive_brief;if(!brief){const bs=$('brief-section');if(bs)bs.style.display='none';return;}const bs=$('brief-section');if(bs)bs.innerHTML=`<div class="brief-card"><div class="brief-icon">🤖</div><div><div class="brief-label">AI Executive Brief</div><div class="brief-text">${esc(brief)}</div></div></div>`;}catch(e){console.error('buildBrief:',e);}})();
(function buildKPIs(){try{const S=DASH.summary;const noiseRm=S.raw_findings>0?((S.raw_findings-S.final_findings)/S.raw_findings*100).toFixed(1):0;const cards=[{v:S.raw_findings,l:'Raw findings',sub:'before any processing',cls:'blue',icon:'📥'},{v:S.unique_findings,l:'After dedup',sub:`${S.dedup_pct}% duplicates removed`,cls:'cyan',icon:'🔀'},{v:S.quarantined,l:'Quarantined',sub:'FP / accepted risk',cls:'',icon:'🚫'},{v:S.final_findings,l:'Active findings',sub:'prioritised & scored',cls:'warn',icon:'🎯'},{v:S.p1+S.p2,l:'P1 + P2 tickets',sub:`${S.p1} critical · ${S.p2} high`,cls:'danger',icon:'🚨'},{v:S.avg_score,l:'Avg risk score',sub:`top score: ${S.top_score}`,cls:'',icon:'📊'},{v:noiseRm+'%',l:'Noise removed',sub:'raw → final reduction',cls:'success',icon:'📉'}];const grid=$('kpi-grid');if(!grid)return;grid.innerHTML=cards.map((c,i)=>`<div class="kpi ${c.cls}"><span class="kpi-accent">${c.icon}</span><div class="kpi-value" id="kv-${i}">${typeof c.v==='number'?'0':c.v}</div><div class="kpi-label">${c.l}</div><div class="kpi-sub">${c.sub}</div></div>`).join('');cards.forEach((c,i)=>{if(typeof c.v==='number')animateCount($(`kv-${i}`),c.v);});}catch(e){console.error('buildKPIs:',e);}})();
(function initCharts(){if(!HAS_CHART)return;try{const S=DASH.summary,F=DASH.findings,H=DASH.history;
new Chart($('c-priority'),{type:'doughnut',data:{labels:['P1 Critical','P2 High','P3 Medium','P4 Low'],datasets:[{data:[S.p1,S.p2,S.p3,S.p4],backgroundColor:['#ef4444','#f97316','#eab308','#64748b'],borderWidth:0,hoverOffset:6,borderRadius:4}]},options:{...cardCfg,cutout:'68%',plugins:{legend:{display:true,position:'bottom',labels:{color:'#94a3b8',boxWidth:10,boxHeight:10,padding:12}},tooltip:{callbacks:{label:ctx=>`${ctx.label}: ${ctx.raw} findings`}}}}});
const sevCounts={critical:0,high:0,medium:0,low:0,info:0};F.forEach(f=>sevCounts[f.severity]=(sevCounts[f.severity]||0)+1);const sevLabels=['critical','high','medium','low','info'];
new Chart($('c-severity'),{type:'bar',data:{labels:sevLabels.map(s=>s.charAt(0).toUpperCase()+s.slice(1)),datasets:[{data:sevLabels.map(s=>sevCounts[s]||0),backgroundColor:['rgba(239,68,68,.8)','rgba(249,115,22,.8)','rgba(234,179,8,.8)','rgba(34,197,94,.8)','rgba(100,116,139,.8)'],borderWidth:0,borderRadius:4}]},options:{...cardCfg,indexAxis:'y',scales:{x:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},y:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>`${ctx.raw} findings`}}}}});
const scanMap={};F.forEach(f=>scanMap[f.scanner]=(scanMap[f.scanner]||0)+1);const scanKeys=Object.keys(scanMap).sort((a,b)=>scanMap[b]-scanMap[a]);
new Chart($('c-scanner'),{type:'bar',data:{labels:scanKeys,datasets:[{data:scanKeys.map(k=>scanMap[k]),backgroundColor:'rgba(6,182,212,.7)',borderWidth:0,borderRadius:4}]},options:{...cardCfg,indexAxis:'y',scales:{x:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},y:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false}}}});
new Chart($('c-noise'),{type:'bar',data:{labels:['Raw findings','After dedup','After filtering','Active'],datasets:[{label:'Findings',data:[S.raw_findings,S.unique_findings,S.unique_findings-S.quarantined,S.final_findings],backgroundColor:['rgba(59,130,246,.7)','rgba(6,182,212,.7)','rgba(234,179,8,.7)','rgba(34,197,94,.7)'],borderWidth:0,borderRadius:6}]},options:{...cardCfg,scales:{y:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},x:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>`${ctx.raw.toLocaleString()} findings`}}}}});
const colors=['#3b82f6','#06b6d4','#6366f1','#22c55e','#f97316'];const products=Object.keys(H);const histDatasets=[];products.forEach((prod,idx)=>{const runs=H[prod];if(!runs||runs.length<1)return;histDatasets.push({label:prod,data:runs.map(r=>({x:r.run_date,y:r.avg_score})),borderColor:colors[idx%colors.length],backgroundColor:'transparent',tension:.4,pointRadius:4,pointHoverRadius:6,borderWidth:2});});if(histDatasets.length){new Chart($('c-history'),{type:'line',data:{datasets:histDatasets},options:{...cardCfg,scales:{x:{type:'category',grid:{color:gridColor},ticks:{color:'#94a3b8',maxRotation:30}},y:{grid:{color:gridColor},ticks:{color:'#94a3b8'},title:{display:true,text:'Avg score',color:'#64748b'}}},plugins:{legend:{display:products.length>1,position:'bottom',labels:{color:'#94a3b8'}}}}});}else{$('c-history').parentElement.innerHTML='<p class="empty-state">Need 2+ pipeline runs to show trend.</p>';}
const epssData=F.filter(f=>f.epss_score>0&&f.score>0).map(f=>({x:parseFloat((f.epss_score*100).toFixed(2)),y:f.score,label:f.title,kev:f.kev,sev:f.severity}));
new Chart($('c-epss'),{type:'scatter',data:{datasets:[{label:'Findings',data:epssData,backgroundColor:epssData.map(p=>p.kev?'rgba(239,68,68,.75)':p.sev==='critical'?'rgba(239,68,68,.5)':p.sev==='high'?'rgba(249,115,22,.5)':p.sev==='medium'?'rgba(234,179,8,.5)':'rgba(34,197,94,.35)'),pointRadius:5,pointHoverRadius:8}]},options:{...cardCfg,scales:{x:{title:{display:true,text:'EPSS score (%)',color:'#64748b'},grid:{color:gridColor},ticks:{color:'#94a3b8'}},y:{title:{display:true,text:'Risk score',color:'#64748b'},grid:{color:gridColor},ticks:{color:'#94a3b8'},min:0,max:100}},plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>{const d=ctx.raw;return[`${d.label.substring(0,40)}`,`EPSS: ${d.x}%  Score: ${d.y}`,d.kev?'⚠️ In CISA KEV':''];}}}}}});
const kevCount=F.filter(f=>f.kev).length;const exploitCount=F.filter(f=>f.exploit_available&&!f.kev).length;const epssHighCount=F.filter(f=>f.epss_score>.3&&!f.kev&&!f.exploit_available).length;const noIntelCount=F.length-kevCount-exploitCount-epssHighCount;
new Chart($('c-threat'),{type:'doughnut',data:{labels:['CISA KEV (confirmed exploit)','Exploit-DB match','EPSS > 30%','No active intel'],datasets:[{data:[kevCount,exploitCount,epssHighCount,noIntelCount],backgroundColor:['rgba(239,68,68,.85)','rgba(249,115,22,.8)','rgba(234,179,8,.7)','rgba(100,116,139,.4)'],borderWidth:0,hoverOffset:6,borderRadius:4}]},options:{...cardCfg,cutout:'60%',plugins:{legend:{display:true,position:'bottom',labels:{color:'#94a3b8',boxWidth:10,boxHeight:10,padding:10}}}}});})();
(function initTable(){const F=DASH.findings;const priorities=[...new Set(F.map(f=>f.priority))].sort();const severities=[...new Set(F.map(f=>f.severity))].sort();const scanners=[...new Set(F.map(f=>f.scanner))].sort();[['f-priority',priorities],['f-severity',severities],['f-scanner',scanners]].forEach(([id,vals])=>{const sel=$(id);vals.forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;sel.appendChild(o);});});const COLS=[{k:'rank',label:'#',w:'40px',sortable:true},{k:'score',label:'Score',w:'110px',sortable:true},{k:'priority',label:'Priority',w:'80px',sortable:true},{k:'sla_hours',label:'SLA',w:'60px',sortable:true},{k:'product',label:'Product',w:'100px',sortable:true},{k:'scanner',label:'Scanner',w:'80px',sortable:true},{k:'severity',label:'Severity',w:'80px',sortable:true},{k:'title',label:'Title',w:'',sortable:false},{k:'cve',label:'CVE',w:'140px',sortable:false},{k:'kev',label:'KEV',w:'60px',sortable:true},{k:'epss_score',label:'EPSS',w:'70px',sortable:true},{k:'cwe',label:'CWE',w:'90px',sortable:false}];$('tbl-head').innerHTML='<tr>'+COLS.map(c=>`<th style="${c.w?'width:'+c.w:''}" ${c.sortable?`data-col="${c.k}"`:''}>${c.label}${c.sortable?'<span class="sort-arrow">↕</span>':''}</th>`).join('')+'</tr>';let sortCol='score',sortDir=-1,search='',fPri='',fSev='',fScan='',fKev='';function getFiltered(){const q=search.toLowerCase();return F.filter(f=>{if(fPri&&f.priority!==fPri)return false;if(fSev&&f.severity!==fSev)return false;if(fScan&&f.scanner!==fScan)return false;if(fKev==='kev'&&!f.kev)return false;if(fKev==='exploit'&&!f.exploit_available)return false;if(q)return(f.title+f.cve+f.cwe+f.endpoint+f.product).toLowerCase().includes(q);return true;}).sort((a,b)=>{const av=a[sortCol],bv=b[sortCol];if(typeof av==='number')return(av-bv)*sortDir;return String(av).localeCompare(String(bv))*sortDir;});}function renderRow(f){const sc=scoreColor(f.score);const epssStr=f.epss_score>0?`${(f.epss_score*100).toFixed(1)}%`:'-';return`<tr class="data-row" data-rank="${f.rank}" onclick="toggleDetail(this)"><td class="no-wrap mono dimmed">${f.rank}</td><td class="no-wrap"><div class="score-cell"><span class="score-num" style="color:${sc}">${f.score}</span><div class="score-track"><div class="score-fill" style="width:${f.score}%;background:${sc}"></div></div></div></td><td class="no-wrap"><span class="badge ${priClass(f.priority)}">${esc(f.priority)}</span></td><td class="no-wrap dimmed mono" style="font-size:11px">${f.sla_hours}h</td><td class="truncate" style="max-width:100px">${esc(f.product)}</td><td class="no-wrap dimmed" style="font-size:11.5px">${esc(f.scanner)}</td><td class="no-wrap"><span class="badge ${sevClass(f.severity)}">${esc(f.severity)}</span></td><td style="max-width:300px"><span class="truncate" style="display:block">${esc(f.title)}</span></td><td class="no-wrap">${f.cve?`<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${esc(f.cve)}" target="_blank" onclick="event.stopPropagation()">${esc(f.cve)}</a>`:'-'}</td><td class="no-wrap">${f.kev?'<span class="badge b-kev">KEV</span>':f.exploit_available?'<span class="badge b-exploit">Exploit</span>':''}</td><td class="no-wrap mono" style="font-size:11px"><span class="badge b-epss">${epssStr}</span></td><td class="no-wrap mono dimmed" style="font-size:11px">${esc(f.cwe||'-')}</td></tr><tr class="detail-row" id="detail-${f.rank}"><td colspan="12">${renderDetail(f)}</td></tr>`;}function renderDetail(f){const sb=f.score_components||{};const comps=Object.entries(sb).map(([k,v])=>`<span style="margin-right:10px"><span class="dimmed">${k}:</span> <b>${v}</b></span>`).join('');const drivers=(f.score_drivers||[]).map(d=>`<span style="margin-right:8px;color:#fde047">⚡ ${esc(d)}</span>`).join('');const rems=(f.remediation||[]).map(r=>`<li><span class="rem-kind">${esc(r.kind)}</span> ${esc(r.text)}</li>`).join('');const aiRem=f.ai_remediation?`<div class="ai-box"><div class="ai-label">🤖 AI-generated remediation</div>${esc(f.ai_remediation)}</div>`:'';return`<div class="detail-panel"><div><div class="detail-section-title">Finding details</div><div class="detail-row-item"><span class="detail-key">Endpoint</span><span class="detail-val">${esc(f.endpoint||'-')}${f.parameter?' (param: '+esc(f.parameter)+')':''}</span></div><div class="detail-row-item"><span class="detail-key">EPSS score</span><span class="detail-val">${pct(f.epss_score)} (pct ${pct(f.epss_percentile)}, trend ${f.epss_trend>0?'+':''}${f.epss_trend})</span></div><div class="detail-row-item"><span class="detail-key">KEV status</span><span class="detail-val">${f.kev?'⚠️ In CISA KEV ('+esc(f.kev_date)+')':'Not in KEV'}</span></div><div class="detail-row-item"><span class="detail-key">Exploit</span><span class="detail-val">${f.exploit_available?'Yes — '+esc(f.exploit_source):'Not found'}</span></div><div class="detail-row-item"><span class="detail-key">Escalation potential</span><span class="detail-val">${f.escalation_potential}</span></div><div class="detail-row-item"><span class="detail-key">Owner</span><span class="detail-val">${esc(f.owner||'-')} · SLA ${f.sla_hours}h</span></div><div style="margin-top:12px;color:var(--text2);font-size:12px;line-height:1.6">${esc(f.description)}</div></div><div><div class="detail-section-title">Score breakdown</div><div style="font-size:12px;margin-bottom:10px;line-height:2">${comps||'<span class="dimmed">no breakdown</span>'}</div><div style="margin-bottom:12px">${drivers}</div><div class="detail-section-title">Remediation steps</div><ul class="rem-list">${rems||'<li class="dimmed">No remediation data</li>'}</ul></div>${aiRem}</div>`;}function render(){const rows=getFiltered();$('result-badge').textContent=`${rows.length} of ${F.length} findings`;$('tbl-body').innerHTML=rows.map(renderRow).join('');}document.querySelectorAll('#tbl-head th[data-col]').forEach(th=>{th.addEventListener('click',()=>{if(sortCol===th.dataset.col){sortDir*=-1;}else{sortCol=th.dataset.col;sortDir=-1;}document.querySelectorAll('#tbl-head th').forEach(t=>{t.classList.remove('sorted');const a=t.querySelector('.sort-arrow');if(a)a.textContent='↕';});th.classList.add('sorted');const arrow=th.querySelector('.sort-arrow');if(arrow)arrow.textContent=sortDir===-1?'↓':'↑';render();});});let searchTimer;$('tbl-search').addEventListener('input',e=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{search=e.target.value;render();},200);});$('f-priority').addEventListener('change',e=>{fPri=e.target.value;render();});$('f-severity').addEventListener('change',e=>{fSev=e.target.value;render();});$('f-scanner').addEventListener('change',e=>{fScan=e.target.value;render();});$('f-kev').addEventListener('change',e=>{fKev=e.target.value;render();});render();}catch(e){console.error('initTable:',e);}})();
function toggleDetail(tr){const rank=tr.dataset.rank;const detail=$('detail-'+rank);if(!detail)return;const isOpen=detail.classList.contains('open');document.querySelectorAll('.detail-row.open').forEach(r=>r.classList.remove('open'));document.querySelectorAll('.data-row.expanded').forEach(r=>r.classList.remove('expanded'));if(!isOpen){detail.classList.add('open');tr.classList.add('expanded');}}
(function buildQuarantine(){try{const Q=DASH.quarantine;const qb=$('q-body');if(!qb)return;qb.innerHTML=Q.length?Q.map(q=>`<tr><td>${esc(q.product)}</td><td>${esc(q.scanner)}</td><td><span class="badge ${sevClass(q.severity)}">${esc(q.severity)}</span></td><td>${esc(q.title)}</td><td>${q.cve?`<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${esc(q.cve)}" target="_blank">${esc(q.cve)}</a>`:'-'}</td><td class="dimmed" style="font-size:12px">${esc(q.reason)}</td></tr>`).join(''):'<tr><td colspan="6" class="empty-state">No findings quarantined this run.</td></tr>';}catch(e){console.error("buildQuarantine:",e);}})();
(function buildProducts(){try{const P=DASH.products||{};const keys=Object.keys(P);const tp=$('tc-products');if(tp)tp.textContent=keys.length;if(!keys.length){$('products-table-wrap').innerHTML='<p class="empty-state">No products configured. Add one below.</p>';return;}const rows=keys.map(k=>{const p=P[k];const findings=DASH.findings.filter(f=>f.product===k);const p1=findings.filter(f=>f.priority==='P1').length;const p2=findings.filter(f=>f.priority==='P2').length;const repo=p.github_repo||'<span class="dimmed">not set</span>';return`<tr><td><b>${esc(p.display_name||k)}</b><br><span class="dimmed" style="font-size:11px">${esc(k)}</span></td><td class="mono" style="font-size:12px">${esc(p.url||'-')}</td><td style="font-size:12px">${repo}</td><td class="dimmed" style="font-size:12px">${esc(p.owner||'-')}</td><td class="mono" style="font-size:12px">${p.asset_criticality||5}/10</td><td class="mono" style="font-size:12px">${findings.length} findings</td><td>${p1>0?`<span class="badge b-p1">${p1} P1</span>`:''}${p2>0?`<span class="badge b-p2">${p2} P2</span>`:''}</td><td><button class="ap-btn" onclick="scanProduct('${esc(k)}')">Scan</button></td></tr>`;}).join('');$('products-table-wrap').innerHTML=`<table class="f-table"><thead><tr><th>Product</th><th>URL</th><th>GitHub Repo</th><th>Owner</th><th>Criticality</th><th>Findings</th><th>P1/P2</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`;}catch(e){console.error("buildProducts:",e);}})();
function addProduct(){const id=$('ap-id').value.trim();const name=$('ap-name').value.trim()||id;const url=$('ap-url').value.trim();const repo=$('ap-repo').value.trim();const owner=$('ap-owner').value.trim();const crit=parseInt($('ap-crit').value)||5;const sens=parseInt($('ap-sens').value)||5;const trivy=$('ap-trivy').value.trim();if(!id||!url){$('ap-msg').textContent='Product ID and URL are required';$('ap-msg').style.color='#ef4444';return;}const scanners={nuclei:url,zap:url,wapiti:url};if(trivy)scanners.trivy=trivy;const product={display_name:name,owner:owner||'unassigned',asset_criticality:crit,business_impact:crit,exposure:8,control_effectiveness:3,data_sensitivity:sens,url:url,github_repo:repo,scanners:scanners};DASH.products=DASH.products||{};DASH.products[id]=product;$('tc-products').textContent=Object.keys(DASH.products).length;$('ap-msg').textContent='Product saved to dashboard data';$('ap-msg').style.color='#22c55e';$('ap-id').value='';$('ap-name').value='';$('ap-url').value='';$('ap-repo').value='';$('ap-owner').value='';$('ap-trivy').value='';buildProducts();}
function scanProduct(id){const m=$('ap-msg');if(m)m.textContent='Scan triggered for '+id+' (re-run pipeline to scan)';$('ap-msg').style.color='#3b82f6';}

// ─── Control Center: Live API + WebSocket ───────────────────────────────────
const API_TOKEN=localStorage.getItem('token')||'';
const API Headers={'Content-Type':'application/json','Authorization':'Bearer '+API_TOKEN};
let ws=null;

function apiFetch(url,opts={}){return fetch(url,{...opts,headers:{...API_HEADERS,...(opts.headers||{})}}).then(r=>{if(r.status===401){localStorage.removeItem('token');window.location.href='/';return r.json().then(d=>{throw new Error(d.detail||'Unauthorized');});}return r.json();});}

function updateControlStatus(msg,type){const el=$('control-status');if(!el)return;const colors={ok:'rgba(34,197,94,.15);color:#86efac;border:1px solid rgba(34,197,94,.3)',err:'rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.3)',info:'rgba(59,130,246,.15);color:#93c5fd;border:1px solid rgba(59,130,246,.3)',warn:'rgba(234,179,8,.15);color:#fde047;border:1px solid rgba(234,179,8,.3)'};el.innerHTML=`<div style="padding:10px 16px;border-radius:8px;font-size:13px;${colors[type]||colors.info}">${esc(msg)}</div>`;}

async function checkDocker(){updateControlStatus('Checking Docker...','info');try{const data=await apiFetch('/api/scanners/status');if(data.docker_available){updateControlStatus('Docker is running. Active jobs: '+data.active_jobs,'ok');}else{updateControlStatus('Docker is not available. Install Docker Desktop.','err');}}catch(e){updateControlStatus('Cannot connect to server: '+e.message,'err');}}

async function loadAppStatus(){try{const data=await apiFetch('/api/products');const el=$('app-status-list');if(!el)return;const products=data.products||{};const statuses=data.app_status||data.app_statuses||{};const keys=Object.keys(products);if(!keys.length){el.innerHTML='<p class="dimmed" style="font-size:12px">No products configured.</p>';return;}el.innerHTML=keys.map(k=>{const p=products[k];const s=statuses[k]||{};const isUp=s.status==='up';return`<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px"><span style="width:8px;height:8px;border-radius:50%;background:${isUp?'#22c55e':'#ef4444'};flex-shrink:0"></span><span style="flex:1"><b>${esc(p.display_name||k)}</b> <span class="dimmed">${esc(p.url||'')}</span></span><span class="dimmed">${isUp?'UP ('+s.response_time_ms+'ms)':'DOWN'}</span></div>`;}).join('');}catch(e){}}

function connectWebSocket(){const token=localStorage.getItem('token');if(!token||typeof WebSocket==='undefined')return;const proto=location.protocol==='https:'?'wss:':'ws:';try{ws=new WebSocket(proto+'//'+location.host+'/ws/live?token='+token);ws.onmessage=function(e){try{const msg=JSON.parse(e.data);if(msg.type==='scan_update')handleScanUpdate(msg.data);}catch(x){}};ws.onclose=function(){setTimeout(connectWebSocket,5000);};ws.onerror=function(){};}catch(x){}}

function handleScanUpdate(job){const el=$('scanner-progress');if(!el)return;let existing=el.querySelector('[data-job="'+job.job_id+'"]');if(!existing){el.innerHTML='';existing=document.createElement('div');existing.setAttribute('data-job',job.job_id);el.appendChild(existing);}const statusColors={pending:'#64748b',running:'#3b82f6',completed:'#22c55e',failed:'#ef4444'};const sc=statusColors[job.status]||'#64748b';const elapsed=job.started_at?(job.finished_at||Date.now()/1000)-job.started_at:0;existing.innerHTML=`<div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.03)"><span style="width:10px;height:10px;border-radius:50%;background:${sc};flex-shrink:0"></span><div style="flex:1"><div style="font-size:13px;font-weight:500">${esc(job.product)} / ${esc(job.scanner)}</div><div class="dimmed" style="font-size:11px">${esc(job.target_url)}</div></div><div style="text-align:right"><span class="badge" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">${job.status}</span><div class="dimmed" style="font-size:10px;margin-top:2px">${elapsed.toFixed(1)}s</div></div></div>`;}

async function triggerScanAll(){updateControlStatus('Starting scan for all products...','info');try{const data=await apiFetch('/api/products');const products=data.products||{};for(const pid of Object.keys(products)){try{await apiFetch('/api/scans/start',{method:'POST',body:JSON.stringify({product:pid})});}catch(x){}}updateControlStatus('Scans started for all products. Watch Scanner Progress below.','ok');loadScannerJobs();}catch(e){updateControlStatus('Failed: '+e.message,'err');}}

async function loadScannerJobs(){try{const data=await apiFetch('/api/scans/jobs');if(data.jobs&&data.jobs.length){const el=$('scanner-progress');if(!el)return;el.innerHTML=data.jobs.map(job=>{const statusColors={pending:'#64748b',running:'#3b82f6',completed:'#22c55e',failed:'#ef4444'};const sc=statusColors[job.status]||'#64748b';const elapsed=job.started_at?(job.finished_at||Date.now()/1000)-job.started_at:0;return`<div data-job="${job.job_id}" style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.03)"><span style="width:10px;height:10px;border-radius:50%;background:${sc};flex-shrink:0"></span><div style="flex:1"><div style="font-size:13px;font-weight:500">${esc(job.product)} / ${esc(job.scanner)}</div><div class="dimmed" style="font-size:11px">${esc(job.target_url)}</div></div><div style="text-align:right"><span class="badge" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">${job.status}</span><div class="dimmed" style="font-size:10px;margin-top:2px">${elapsed.toFixed(1)}s</div></div></div>`;}).join('');}}catch(x){}}

async function runPipeline(){updateControlStatus('Running 8-stage pipeline...','info');try{await apiFetch('/api/pipeline/run',{method:'POST',body:JSON.stringify({skip_enrich:true,skip_ai:true})});updateControlStatus('Pipeline started in background. Check status periodically.','ok');pollPipelineStatus();}catch(e){updateControlStatus('Pipeline failed: '+e.message,'err');}}

function pollPipelineStatus(){const check=async()=>{try{const data=await apiFetch('/api/pipeline/status');if(data.running){updateControlStatus('Pipeline is running...','info');setTimeout(check,3000);}else{updateControlStatus('Pipeline complete! Refresh to see updated results.','ok');}}catch(x){}};check();}

async function createTickets(){updateControlStatus('Creating GitHub Issues for findings above threshold...','info');try{const data=await apiFetch('/api/tickets/create?threshold=60',{method:'POST'});const results=data.results||{};const total=Object.values(results).reduce((a,r)=>a+(r.created||0),0);updateControlStatus('Created '+total+' GitHub Issues across '+Object.keys(results).length+' products.','ok');}catch(e){updateControlStatus('Ticket creation failed: '+e.message,'err');}}

// Auto-connect when Control Center tab is visible
document.querySelectorAll('.tab-btn').forEach(btn=>{if(btn.dataset.page==='control'){btn.addEventListener('click',()=>{loadAppStatus();connectWebSocket();loadScannerJobs();});}});

// Also auto-connect on page load (in case already on control tab)
if(API_TOKEN){setTimeout(()=>{loadAppStatus();connectWebSocket();loadScannerJobs();},1000);}
const HIGH_IMPACT=['CWE-89','CWE-79','CWE-78','CWE-22','CWE-434','CWE-918','CWE-502','CWE-611','CWE-287','CWE-306'];let apZoom,apSvgRoot;
function initD3(){const AP=DASH.attack_paths;const products=Object.keys(AP);if(!products.length){$('ap-container').innerHTML='<div class="ap-no-data">No attack paths found in this run.</div>';return;}const sel=$('ap-product');sel.innerHTML=products.map(p=>`<option value="${esc(p)}">${esc(p)}</option>`).join('');$('tc-paths').textContent=Object.values(AP).reduce((a,v)=>a+v.length,0);sel.addEventListener('change',()=>{apInited=false;renderD3(sel.value);});renderD3(products[0]);}
function renderD3(product){const paths=DASH.attack_paths[product]||[];const container=$('ap-container');const tooltip=$('ap-tooltip');const svgEl=$('ap-svg');svgEl.innerHTML='';if(!paths.length){svgEl.innerHTML='<text x="50%" y="50%" text-anchor="middle" fill="#64748b" dy=".3em">No paths for this product</text>';return;}const nodeSet=new Map();paths.forEach(p=>{if(!nodeSet.has(p.from_cwe))nodeSet.set(p.from_cwe,{id:p.from_cwe,group:HIGH_IMPACT.includes(p.from_cwe)?1:0});if(!nodeSet.has(p.to_cwe))nodeSet.set(p.to_cwe,{id:p.to_cwe,group:HIGH_IMPACT.includes(p.to_cwe)?2:0});});const nodes=[...nodeSet.values()];const links=paths.map(p=>({source:p.from_cwe,target:p.to_cwe,prob:p.probability,desc:p.description||''}));const W=svgEl.parentElement.clientWidth||900,H=540;svgEl.setAttribute('viewBox',`0 0 ${W} ${H}`);const svg=d3.select('#ap-svg');const g=svg.append('g');apZoom=d3.zoom().scaleExtent([.3,3]).on('zoom',e=>g.attr('transform',e.transform));svg.call(apZoom);apSvgRoot=svg;const defs=svg.append('defs');['low','med','high'].forEach((t,i)=>{defs.append('marker').attr('id','arr-'+t).attr('viewBox','0 -4 8 8').attr('refX',26).attr('refY',0).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto').append('path').attr('d','M0,-4L8,0L0,4').attr('fill',['rgba(34,197,94,.7)','rgba(234,179,8,.8)','rgba(239,68,68,.8)'][i]);});const probClass=p=>p>.6?'high':p>.3?'med':'low';const probColor=p=>p>.6?'rgba(239,68,68,.7)':p>.3?'rgba(234,179,8,.7)':'rgba(34,197,94,.6)';const link=g.append('g').selectAll('line').data(links).join('line').attr('stroke',d=>probColor(d.prob)).attr('stroke-width',d=>1+d.prob*3).attr('stroke-opacity',.7).attr('marker-end',d=>`url(#arr-${probClass(d.prob)})`);const linkLabel=g.append('g').selectAll('text').data(links).join('text').text(d=>`p=${d.prob}`).attr('font-size',9).attr('fill','#64748b').attr('text-anchor','middle');const nodeG=g.append('g').selectAll('g').data(nodes).join('g').call(d3.drag().on('start',(e,d)=>{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;}).on('drag',(e,d)=>{d.fx=e.x;d.fy=e.y;}).on('end',(e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}));const filter=defs.append('filter').attr('id','glow');filter.append('feGaussianBlur').attr('stdDeviation','4').attr('result','blur');const feMerge=filter.append('feMerge');feMerge.append('feMergeNode').attr('in','blur');feMerge.append('feMergeNode').attr('in','SourceGraphic');nodeG.append('circle').attr('r',d=>d.group===2?32:d.group===1?28:22).attr('fill',d=>d.group===2?'rgba(239,68,68,.15)':d.group===1?'rgba(249,115,22,.12)':'rgba(59,130,246,.12)').attr('stroke',d=>d.group===2?'#ef4444':d.group===1?'#f97316':'#3b82f6').attr('stroke-width',2).attr('filter','url(#glow)');nodeG.append('text').text(d=>d.id.replace('CWE-','')).attr('text-anchor','middle').attr('dy','-.2em').attr('font-size',10).attr('font-weight',700).attr('fill','#f1f5f9');nodeG.append('text').text('CWE').attr('text-anchor','middle').attr('dy','1em').attr('font-size',8).attr('fill','#64748b');nodeG.on('mouseover',(e,d)=>{tooltip.style.display='block';tooltip.innerHTML=`<b>${d.id}</b><br>${d.group===2?'🎯 High-impact exploitation target':d.group===1?'⚡ Attack entry point':'Intermediate escalation node'}`;}).on('mousemove',e=>{const r=container.getBoundingClientRect();tooltip.style.left=(e.clientX-r.left+12)+'px';tooltip.style.top=(e.clientY-r.top-30)+'px';}).on('mouseout',()=>{tooltip.style.display='none';});link.on('mouseover',(e,d)=>{tooltip.style.display='block';tooltip.innerHTML=`<b>${d.source.id} → ${d.target.id}</b><br>Probability: ${d.prob}<br>${esc(d.desc).substring(0,100)}`;}).on('mousemove',e=>{const r=container.getBoundingClientRect();tooltip.style.left=(e.clientX-r.left+12)+'px';tooltip.style.top=(e.clientY-r.top-30)+'px';}).on('mouseout',()=>{tooltip.style.display='none';});const sim=d3.forceSimulation(nodes).force('link',d3.forceLink(links).id(d=>d.id).distance(d=>100+d.prob*80)).force('charge',d3.forceManyBody().strength(-420)).force('center',d3.forceCenter(W/2,H/2)).force('collision',d3.forceCollide(45));sim.on('tick',()=>{link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);linkLabel.attr('x',d=>(d.source.x+d.target.x)/2).attr('y',d=>(d.source.y+d.target.y)/2-6);nodeG.attr('transform',d=>`translate(${d.x},${d.y})`);});}
function apReset(){if(apSvgRoot)apSvgRoot.transition().duration(500).call(apZoom.transform,d3.zoomIdentity);}

// ─── Lifecycle Tab ──────────────────────────────────────────────────────────
(function initLifecycle(){try{
  const F=DASH.findings;
  const statuses=['open','in_progress','fixed','verified','accepted'];
  const statusColors={open:'#f97316',in_progress:'#3b82f6',fixed:'#22c55e',verified:'#06b6d4',accepted:'#64748b'};
  // Simulated lifecycle status (in real app, fetched from /api/lifecycle/dashboard)
  const lcFindings=F.slice(0,30).map((f,i)=>({...f,lc_status:statuses[i%5],sla_deadline:i<5?'2026-08-22T00:00:00':'2026-08-25T00:00:00',breached:i<3}));
  const openCount=lcFindings.filter(f=>f.lc_status==='open').length;
  const inProgCount=lcFindings.filter(f=>f.lc_status==='in_progress').length;
  const fixedCount=lcFindings.filter(f=>f.lc_status==='fixed').length;
  const breachedCount=lcFindings.filter(f=>f.breached).length;
  const lckg=$('lc-kpi-grid');if(lckg)lckg.innerHTML=[
    {v:openCount,l:'Open',cls:'warn',icon:'🔓'},
    {v:inProgCount,l:'In Progress',cls:'blue',icon:'⏳'},
    {v:fixedCount,l:'Fixed / Verified',cls:'success',icon:'✅'},
    {v:breachedCount,l:'SLA Breached',cls:'danger',icon:'⏰'},
  ].map((c,i)=>`<div class="kpi ${c.cls}"><span class="kpi-accent">${c.icon}</span><div class="kpi-value" id="lcv-${i}">${c.v}</div><div class="kpi-label">${c.l}</div></div>`).join('');
  const tcl=$('tc-lifecycle');if(tcl)tcl.textContent=lcFindings.length;
  // Lifecycle table
  const rows=lcFindings.map(f=>`<tr><td>${esc(f.product)}</td><td><span class="badge ${sevClass(f.severity)}">${esc(f.severity)}</span></td><td style="max-width:200px" class="truncate">${esc(f.title)}</td><td class="no-wrap">${f.cve?esc(f.cve):'-'}</td><td class="no-wrap"><span class="badge" style="background:${statusColors[f.lc_status]}22;color:${statusColors[f.lc_status]};border:1px solid ${statusColors[f.lc_status]}44">${f.lc_status.replace('_',' ')}</span></td><td class="no-wrap ${f.breached?'':'dimmed'}" style="font-size:11px;${f.breached?'color:#ef4444;font-weight:600':''}">${f.breached?'BREACHED':'OK'}</td><td class="no-wrap" style="font-size:11px">${esc(f.owner||'-')}</td></tr>`).join('');
  const lctw=$('lc-table-wrap');if(lctw)lctw.innerHTML=`<table class="f-table"><thead><tr><th>Product</th><th>Severity</th><th>Title</th><th>CVE</th><th>Status</th><th>SLA</th><th>Owner</th></tr></thead><tbody>${rows}</tbody></table>`;
  // Breached list
  const breached=lcFindings.filter(f=>f.breached);
  const lcbl=$('lc-breached-list');if(lcbl)lcbl.innerHTML=breached.length?breached.map(f=>`<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px"><span style="color:#ef4444;font-weight:700">⏰</span><span style="flex:1"><b>${esc(f.title.substring(0,50))}</b> <span class="dimmed">${esc(f.product)}</span></span><span class="badge b-p1">SLA BREACHED</span></div>`).join(''):'<p class="dimmed" style="font-size:12px">No SLA breaches detected.</p>';
}catch(e){console.error('initLifecycle:',e);}})();

// ─── Dedup Analytics Tab ────────────────────────────────────────────────────
(function initDedup(){try{
  const F=DASH.findings;
  const S=DASH.summary;
  // KPIs
  const noiseRm=S.raw_findings>0?((S.raw_findings-S.final_findings)/S.raw_findings*100).toFixed(1):0;
  const dkg=$('dedup-kpi-grid');if(dkg)dkg.innerHTML=[
    {v:S.raw_findings,l:'Raw findings',cls:'blue',icon:'📥'},
    {v:S.unique_findings,l:'After dedup',cls:'cyan',icon:'🔀'},
    {v:S.dedup_pct+'%',l:'Dedup rate',cls:'success',icon:'📉'},
    {v:noiseRm+'%',l:'Total noise removed',cls:'',icon:'🎯'},
  ].map((c,i)=>`<div class="kpi ${c.cls}"><span class="kpi-accent">${c.icon}</span><div class="kpi-value" id="dv-${i}">${c.v}</div><div class="kpi-label">${c.l}</div></div>`).join('');
  // Scanner distribution chart
  const scanMap={};F.forEach(f=>scanMap[f.scanner]=(scanMap[f.scanner]||0)+1);
  const scanKeys=Object.keys(scanMap).sort((a,b)=>scanMap[b]-scanMap[a]);
  if($('c-dedup-scanner')){
    new Chart($('c-dedup-scanner'),{type:'bar',data:{labels:scanKeys,datasets:[{label:'Findings',data:scanKeys.map(k=>scanMap[k]),backgroundColor:['rgba(59,130,246,.7)','rgba(6,182,212,.7)','rgba(234,179,8,.7)','rgba(239,68,68,.7)','rgba(99,102,241,.7)'],borderWidth:0,borderRadius:6}]},options:{...cardCfg,scales:{y:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},x:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false}}}});
  }
  // Cross-scanner overlap (simulated from data)
  const cveGroups={};F.forEach(f=>{if(f.cve){cveGroups[f.cve]=cveGroups[f.cve]||[];cveGroups[f.cve].push(f.scanner);}});
  const overlaps=Object.entries(cveGroups).filter(([k,v])=>new Set(v).size>1);
  if($('c-dedup-overlap')){
    const overlapLabels=overlaps.slice(0,8).map(([k])=>k);
    const overlapCounts=overlaps.slice(0,8).map(([,v])=>new Set(v).size);
    new Chart($('c-dedup-overlap'),{type:'bar',data:{labels:overlapLabels,datasets:[{label:'Scanners detecting',data:overlapCounts,backgroundColor:'rgba(249,115,22,.7)',borderWidth:0,borderRadius:6}]},options:{...cardCfg,indexAxis:'y',scales:{x:{grid:{color:gridColor},ticks:{color:'#94a3b8'},title:{display:true,text:'# scanners',color:'#64748b'}},y:{grid:{display:false},ticks:{color:'#94a3b8',font:{family:"'JetBrains Mono',monospace",size:10}}}},plugins:{legend:{display:false}}}});
  }
  // Overlap table
  const overlapRows=overlaps.map(([cve,scanners])=>{const uniqueScanners=[...new Set(scanners)];const finding=F.find(f=>f.cve===cve);return`<tr><td class="no-wrap"><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${esc(cve)}" target="_blank">${esc(cve)}</a></td><td>${uniqueScanners.map(s=>`<span class="badge" style="background:rgba(6,182,212,.1);color:#67e8f9;margin-right:4px">${esc(s)}</span>`).join('')}</td><td style="max-width:200px" class="truncate">${finding?esc(finding.title):'-'}</td><td class="no-wrap">${finding?esc(finding.product):'-'}</td></tr>`;}).join('');
  const dot=$('dedup-overlap-table');if(dot)dot.innerHTML=overlapRows?`<table class="f-table"><thead><tr><th>CVE</th><th>Detecting Scanners</th><th>Vulnerability</th><th>Product</th></tr></thead><tbody>${overlapRows}</tbody></table>`:'<p class="dimmed" style="font-size:12px">No cross-scanner overlaps detected.</p>';
}catch(e){console.error('initDedup:',e);}})();

// ─── Integrations Tab ───────────────────────────────────────────────────────
async function testJira(){
  const el=$('jira-status');el.innerHTML='<span class="dimmed">Testing connection...</span>';
  try{const data=await apiFetch('/api/jira/test');el.innerHTML=data.connected?`<span style="color:#22c55e">✅ Connected to ${esc(data.url||'Jira')}</span>`:`<span style="color:#ef4444">❌ ${esc(data.error||'Not configured')}</span>`;}catch(e){el.innerHTML=`<span style="color:#ef4444">❌ ${esc(e.message)}</span>`;}
}
async function createJiraIssues(){
  const el=$('jira-status');el.innerHTML='<span class="dimmed">Creating issues...</span>';
  try{const data=await apiFetch('/api/jira/create?threshold=60',{method:'POST'});el.innerHTML=`<span style="color:#22c55e">✅ Created ${data.created||0} issues</span>`;}catch(e){el.innerHTML=`<span style="color:#ef4444">❌ ${esc(e.message)}</span>`;}
}
async function testDefectDojo(){
  const el=$('dd-status');el.innerHTML='<span class="dimmed">Testing connection...</span>';
  try{const data=await apiFetch('/api/defectdojo/test');el.innerHTML=data.connected?`<span style="color:#22c55e">✅ Connected to ${esc(data.url||'DefectDojo')}</span>`:`<span style="color:#ef4444">❌ ${esc(data.error||'Not configured')}</span>`;}catch(e){el.innerHTML=`<span style="color:#ef4444">❌ ${esc(e.message)}</span>`;}
}
async function importDefectDojo(){
  const el=$('dd-status');el.innerHTML='<span class="dimmed">Importing findings...</span>';
  try{const data=await apiFetch('/api/defectdojo/import?product_name=all',{method:'POST'});el.innerHTML=`<span style="color:#22c55e">✅ ${esc(data.message||'Imported')}</span>`;}catch(e){el.innerHTML=`<span style="color:#ef4444">❌ ${esc(e.message)}</span>`;}
}
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
    dash_data = {
        "summary": summary.to_dict(),
        "findings": _serialize_findings(ranked),
        "attack_paths": attack_paths,
        "history": history,
        "quarantine": _serialize_quarantine(all_findings),
        "executive_brief": executive_brief,
        "products": products_config or {},
    }
    json_str = json.dumps(dash_data)
    # Prevent XSS: escape </script> inside JSON so it cannot break out of the <script> block
    json_str = json_str.replace("</script>", r"<\/script>")
    json_str = json_str.replace("</SCRIPT>", r"<\/SCRIPT>")
    html = _HTML_TEMPLATE.replace("__DASH_JSON__", json_str)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
