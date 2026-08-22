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
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e1a;--bg-elevated:#0f1525;--surface:#131b2e;
  --surface-hover:#1a2338;--surface-active:#1e2942;
  --border:rgba(148,163,184,0.08);--border-strong:rgba(148,163,184,0.15);
  --text-primary:#f1f5f9;--text-secondary:#94a3b8;
  --text-tertiary:#64748b;--text-muted:#475569;
  --blue:#60a5fa;--blue-dim:rgba(96,165,250,0.12);
  --cyan:#22d3ee;--cyan-dim:rgba(34,211,238,0.12);
  --indigo:#818cf8;--indigo-dim:rgba(129,140,248,0.12);
  --red:#f87171;--red-dim:rgba(248,113,113,0.12);
  --red-glow:0 0 20px rgba(248,113,113,0.15);
  --orange:#fb923c;--orange-dim:rgba(251,146,60,0.12);
  --yellow:#facc15;--yellow-dim:rgba(250,204,21,0.12);
  --green:#4ade80;--green-dim:rgba(74,222,128,0.12);
  --p1-bg:rgba(248,113,113,0.1);--p1-text:#fca5a5;--p1-border:rgba(248,113,113,0.25);
  --p2-bg:rgba(251,146,60,0.1);--p2-text:#fdba74;--p2-border:rgba(251,146,60,0.25);
  --p3-bg:rgba(250,204,21,0.1);--p3-text:#fde047;--p3-border:rgba(250,204,21,0.25);
  --p4-bg:rgba(100,116,139,0.1);--p4-text:#94a3b8;--p4-border:rgba(100,116,139,0.25);
  --shadow-sm:0 1px 2px rgba(0,0,0,0.3);
  --shadow-md:0 4px 12px rgba(0,0,0,0.4);
  --shadow-lg:0 8px 32px rgba(0,0,0,0.5);
  --radius-sm:6px;--radius:10px;--radius-lg:14px;
  --font-sans:'Inter',system-ui,-apple-system,sans-serif;
  --font-mono:'JetBrains Mono','Fira Code',monospace;
  --transition-fast:150ms ease;--transition-base:250ms ease;
}
html{scroll-behavior:smooth}
body{font-family:var(--font-sans);background:var(--bg);color:var(--text-primary);min-height:100vh;line-height:1.5;-webkit-font-smoothing:antialiased}
*:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:0.01ms!important;transition-duration:0.01ms!important}}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--surface-active);border-radius:3px}

/* ─── App Header ─── */
.app-header{position:sticky;top:0;z-index:100;background:rgba(10,14,26,0.85);backdrop-filter:blur(24px) saturate(1.2);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;gap:20px;height:60px}
.header-brand{display:flex;align-items:center;gap:10px;flex-shrink:0}
.brand-icon{color:var(--blue)}
.brand-text{display:flex;align-items:baseline;gap:8px}
.brand-name{font-size:15px;font-weight:700;letter-spacing:-0.3px;color:var(--text-primary)}
.brand-version{font-size:11px;color:var(--text-muted);font-weight:500}
.header-meta{display:flex;align-items:center;gap:6px;flex-wrap:wrap;flex:1}
.meta-pill{font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--surface);color:var(--text-secondary);border:1px solid var(--border);white-space:nowrap}
.meta-pill.critical{background:var(--red-dim);color:var(--p1-text);border-color:var(--p1-border)}
.tab-nav{display:flex;gap:2px;margin-left:auto;flex-shrink:0}
.tab-btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border:none;border-radius:var(--radius-sm);cursor:pointer;font-size:12.5px;font-weight:500;color:var(--text-tertiary);background:transparent;transition:all var(--transition-fast);white-space:nowrap;font-family:var(--font-sans)}
.tab-btn:hover{color:var(--text-secondary);background:var(--surface)}
.tab-btn.active{background:var(--blue-dim);color:var(--blue);box-shadow:inset 0 0 0 1px rgba(96,165,250,0.2)}
.tab-count{display:inline-flex;align-items:center;justify-content:center;min-width:18px;height:18px;padding:0 5px;margin-left:4px;background:var(--surface-hover);border-radius:9px;font-size:10px;font-weight:700;color:var(--text-secondary)}
.tab-btn.active .tab-count{background:rgba(96,165,250,0.2);color:var(--blue)}
.header-actions{display:flex;gap:6px;flex-shrink:0}
.icon-btn{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface);color:var(--text-secondary);cursor:pointer;transition:all var(--transition-fast)}
.icon-btn:hover{background:var(--surface-hover);color:var(--text-primary);border-color:var(--border-strong)}

/* ─── Pages ─── */
.page{display:none;padding:28px;max-width:1600px;margin:0 auto;animation:fadeIn .3s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}

/* ─── Brief Card ─── */
.brief-card{background:linear-gradient(135deg,rgba(96,165,250,0.06),rgba(34,211,238,0.06));border:1px solid rgba(96,165,250,0.15);border-radius:var(--radius);padding:20px 24px;margin-bottom:28px;display:flex;gap:16px;align-items:flex-start}
.brief-icon{flex-shrink:0;margin-top:2px;color:var(--cyan)}
.brief-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:var(--cyan);margin-bottom:6px}
.brief-text{font-size:13.5px;line-height:1.7;color:var(--text-secondary)}

/* ─── KPI Cards ─── */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:16px;margin-bottom:28px}
.kpi-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;position:relative;overflow:hidden;transition:border-color var(--transition-base),box-shadow var(--transition-base)}
.kpi-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--blue),var(--cyan));opacity:0;transition:opacity var(--transition-base)}
.kpi-card:hover{border-color:var(--border-strong);box-shadow:var(--shadow-md)}
.kpi-card:hover::before{opacity:1}
.kpi-card.danger::before{background:linear-gradient(90deg,var(--red),var(--orange))}
.kpi-card.danger:hover{box-shadow:var(--red-glow)}
.kpi-card.success::before{background:linear-gradient(90deg,var(--green),var(--cyan))}
.kpi-card.warn::before{background:linear-gradient(90deg,var(--orange),var(--yellow))}
.kpi-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px}
.kpi-icon{width:36px;height:36px;border-radius:var(--radius-sm);display:flex;align-items:center;justify-content:center;background:var(--blue-dim);color:var(--blue)}
.kpi-card.danger .kpi-icon{background:var(--red-dim);color:var(--red)}
.kpi-card.success .kpi-icon{background:var(--green-dim);color:var(--green)}
.kpi-card.warn .kpi-icon{background:var(--orange-dim);color:var(--orange)}
.kpi-value{font-size:32px;font-weight:800;line-height:1;color:var(--text-primary);font-variant-numeric:tabular-nums;letter-spacing:-0.5px}
.kpi-label{font-size:11px;color:var(--text-tertiary);text-transform:uppercase;letter-spacing:0.8px;font-weight:600;margin-top:8px}
.kpi-sub{font-size:12px;color:var(--text-muted);margin-top:4px}

/* ─── Chart Cards ─── */
.chart-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;transition:border-color var(--transition-base)}
.chart-card:hover{border-color:var(--border-strong)}
.chart-header{display:flex;align-items:center;gap:8px;padding:16px 20px 0}
.chart-header svg{color:var(--text-tertiary)}
.chart-title{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.6px;color:var(--text-secondary)}
.chart-body{padding:12px 20px 20px;height:240px;position:relative}
.chart-row-3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}
.chart-row-2{display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-bottom:20px}
.chart-row-1{margin-bottom:20px}

/* ─── Table Controls ─── */
.table-controls{display:flex;gap:10px;margin-bottom:16px;align-items:center;flex-wrap:wrap}
.search-wrap{position:relative;flex:1;min-width:200px;max-width:360px}
.search-icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--text-muted);pointer-events:none}
.search-box{width:100%;background:var(--bg-elevated);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 14px 8px 36px;color:var(--text-primary);font-size:13px;font-family:var(--font-sans);transition:border-color var(--transition-fast);outline:none}
.search-box:focus{border-color:rgba(96,165,250,0.5);box-shadow:0 0 0 3px rgba(96,165,250,0.08)}
.search-box::placeholder{color:var(--text-muted)}
.filter-sel{background:var(--bg-elevated);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 12px;color:var(--text-primary);font-size:12px;font-family:var(--font-sans);cursor:pointer;outline:none;transition:border-color var(--transition-fast)}
.filter-sel:focus{border-color:rgba(96,165,250,0.5)}
.filter-sel option{background:var(--surface);color:var(--text-primary)}
.result-badge{margin-left:auto;font-size:12px;color:var(--text-tertiary);background:var(--surface);padding:5px 12px;border-radius:20px;border:1px solid var(--border);white-space:nowrap}

/* ─── Priority Band Bar ─── */
.priority-bar{display:flex;gap:16px;align-items:center;padding:12px 16px;margin-bottom:16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;flex-wrap:wrap}
.priority-item{display:flex;align-items:center;gap:6px;color:var(--text-secondary)}
.priority-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.priority-dot.p1{background:var(--red)}
.priority-dot.p2{background:var(--orange)}
.priority-dot.p3{background:var(--yellow)}
.priority-dot.p4{background:var(--text-muted)}

/* ─── Data Table ─── */
.table-wrap{overflow-x:auto;border-radius:var(--radius);border:1px solid var(--border)}
.data-table{width:100%;border-collapse:separate;border-spacing:0;font-size:12.5px}
.data-table thead th{background:var(--bg-elevated);color:var(--text-tertiary);padding:10px 14px;text-align:left;font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap;user-select:none;border-bottom:1px solid var(--border);cursor:pointer;transition:color var(--transition-fast);position:sticky;top:0;z-index:10}
.data-table thead th:hover{color:var(--text-secondary)}
.data-table thead th.sorted{color:var(--blue)}
.sort-arrow{font-size:9px;margin-left:3px;opacity:0.5}
.data-table thead th.sorted .sort-arrow{opacity:1;color:var(--blue)}
.data-table tbody tr{border-bottom:1px solid rgba(255,255,255,0.03);transition:background var(--transition-fast);cursor:pointer}
.data-table tbody tr:hover td{background:var(--surface-hover)}
.data-table tbody tr.expanded td{background:var(--surface-active)}
.data-table td{padding:10px 14px;vertical-align:middle;color:var(--text-secondary);max-width:240px}
.data-table td.primary{color:var(--text-primary);font-weight:500}
.data-table td.no-wrap{white-space:nowrap;max-width:none}

/* ─── Badges ─── */
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:20px;font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:0.6px;white-space:nowrap}
.badge::before{content:'';width:5px;height:5px;border-radius:50%;flex-shrink:0}
.b-p1{background:var(--p1-bg);color:var(--p1-text);border:1px solid var(--p1-border)}.b-p1::before{background:var(--red)}
.b-p2{background:var(--p2-bg);color:var(--p2-text);border:1px solid var(--p2-border)}.b-p2::before{background:var(--orange)}
.b-p3{background:var(--p3-bg);color:var(--p3-text);border:1px solid var(--p3-border)}.b-p3::before{background:var(--yellow)}
.b-p4{background:var(--p4-bg);color:var(--p4-text);border:1px solid var(--p4-border)}.b-p4::before{background:var(--text-muted)}
.b-critical{background:rgba(248,113,113,0.08);color:var(--red)}.b-critical::before{background:var(--red)}
.b-high{background:rgba(251,146,60,0.08);color:var(--orange)}.b-high::before{background:var(--orange)}
.b-medium{background:rgba(250,204,21,0.08);color:var(--yellow)}.b-medium::before{background:var(--yellow)}
.b-low{background:rgba(74,222,128,0.08);color:var(--green)}.b-low::before{background:var(--green)}
.b-info{background:rgba(100,116,139,0.08);color:var(--text-secondary)}.b-info::before{background:var(--text-muted)}
.b-kev{background:var(--red-dim);color:var(--p1-text);border:1px solid var(--p1-border)}.b-kev::before{background:var(--red)}
.b-exploit{background:var(--orange-dim);color:var(--p2-text);border:1px solid var(--p2-border)}.b-exploit::before{background:var(--orange)}
.b-epss{background:var(--indigo-dim);color:var(--indigo)}.b-epss::before{background:var(--indigo)}

/* ─── Score Bar ─── */
.score-cell{display:flex;align-items:center;gap:10px;min-width:90px}
.score-num{font-size:13px;font-weight:700;font-family:var(--font-mono);width:32px;text-align:right;flex-shrink:0}
.score-track{flex:1;height:5px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden;min-width:50px}
.score-fill{height:100%;border-radius:3px;transition:width .8s cubic-bezier(0.4,0,0.2,1)}

/* ─── Detail Panel ─── */
.detail-panel{padding:24px;border-top:1px solid var(--border);background:var(--bg-elevated);display:grid;grid-template-columns:repeat(3,1fr);gap:24px}
.detail-section{margin-bottom:20px}
.detail-section-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:12px;display:flex;align-items:center;gap:6px}
.detail-row-item{display:flex;gap:8px;margin-bottom:8px;font-size:12.5px;line-height:1.5}
.detail-key{color:var(--text-tertiary);flex-shrink:0;width:130px;font-size:11px;font-weight:600}
.detail-val{color:var(--text-secondary);word-break:break-word;font-family:var(--font-mono);font-size:11.5px}
.detail-val a{color:var(--blue);text-decoration:none}
.detail-val a:hover{text-decoration:underline}
.ai-box{grid-column:1/-1;background:linear-gradient(135deg,var(--blue-dim),var(--cyan-dim));border:1px solid rgba(96,165,250,0.15);border-radius:var(--radius);padding:16px 20px}
.ai-header{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.ai-header svg{color:var(--blue)}
.ai-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--blue)}
.ai-content{font-size:13px;line-height:1.7;color:var(--text-secondary)}
.rem-list{list-style:none}
.rem-list li{padding:5px 0;font-size:12px;border-bottom:1px solid var(--border);display:flex;gap:8px;color:var(--text-secondary)}
.rem-list li:last-child{border:none}
.rem-kind{font-size:10px;font-weight:600;text-transform:uppercase;color:var(--text-muted);flex-shrink:0;margin-top:1px}
.cve-link{color:var(--cyan);text-decoration:none;font-family:var(--font-mono);font-size:11.5px}
.cve-link:hover{text-decoration:underline}

/* ─── Attack Paths ─── */
#ap-container{position:relative;border-radius:var(--radius);overflow:hidden;background:var(--surface)}
#ap-svg{display:block;width:100%}
.ap-legend{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px}
.ap-legend-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text-secondary)}
.ap-legend-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.ap-tooltip{position:absolute;pointer-events:none;display:none;background:var(--surface-active);border:1px solid var(--border-strong);border-radius:var(--radius-sm);padding:10px 14px;font-size:12px;color:var(--text-primary);max-width:240px;box-shadow:var(--shadow-lg);z-index:10}
.ap-controls{display:flex;gap:8px;margin-bottom:14px;align-items:center}
.ap-btn{padding:6px 14px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface);color:var(--text-secondary);font-size:12px;cursor:pointer;transition:all var(--transition-fast);font-family:var(--font-sans)}
.ap-btn:hover{border-color:var(--border-strong);color:var(--text-primary)}
.ap-product-sel{background:var(--bg-elevated);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 12px;color:var(--text-primary);font-size:12px;cursor:pointer;font-family:var(--font-sans)}
.ap-no-data{text-align:center;padding:60px 20px;color:var(--text-muted);font-size:14px}

/* ─── Button Hierarchy ─── */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 18px;border-radius:var(--radius-sm);font-size:13px;font-weight:600;font-family:var(--font-sans);cursor:pointer;border:1px solid transparent;transition:all var(--transition-fast);text-decoration:none}
.btn-primary{background:var(--blue);color:#fff}
.btn-primary:hover{background:#3b82f6;box-shadow:0 0 0 3px var(--blue-dim)}
.btn-secondary{background:var(--surface-hover);color:var(--text-secondary);border-color:var(--border)}
.btn-secondary:hover{background:var(--surface-active);color:var(--text-primary);border-color:var(--border-strong)}
.btn-success{background:var(--green);color:#0f172a}
.btn-success:hover{background:#22c55e}
.btn-danger{background:var(--red);color:#fff}
.btn-danger:hover{background:#ef4444}
.btn-group{display:flex;flex-direction:column;gap:10px}
.btn-group .btn{justify-content:flex-start;width:100%}

/* ─── Control Center ─── */
.control-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.control-section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px}
.control-section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;color:var(--text-muted);margin-bottom:16px;display:flex;align-items:center;gap:6px}

/* ─── Quarantine ─── */
.q-table-wrap{border-radius:var(--radius);border:1px solid var(--border);overflow:hidden}
.q-note{background:rgba(250,204,21,0.06);border:1px solid rgba(250,204,21,0.15);border-radius:var(--radius);padding:12px 16px;margin-bottom:16px;font-size:13px;color:var(--yellow);display:flex;align-items:center;gap:10px}

/* ─── Toast Notifications ─── */
.toast-container{position:fixed;top:20px;right:20px;z-index:1000;display:flex;flex-direction:column;gap:8px;pointer-events:none}
.toast{display:flex;align-items:center;gap:10px;padding:12px 18px;border-radius:var(--radius);background:var(--surface);border:1px solid var(--border);box-shadow:var(--shadow-lg);font-size:13px;color:var(--text-secondary);pointer-events:auto;animation:toastIn 0.3s ease,toastOut 0.3s ease 4.7s forwards;max-width:400px}
.toast svg{flex-shrink:0}
.toast-success{border-color:rgba(74,222,128,0.2);background:rgba(74,222,128,0.05)}.toast-success svg{color:var(--green)}
.toast-error{border-color:rgba(248,113,113,0.2);background:rgba(248,113,113,0.05)}.toast-error svg{color:var(--red)}
.toast-info{border-color:rgba(96,165,250,0.2);background:rgba(96,165,250,0.05)}.toast-info svg{color:var(--blue)}
@keyframes toastIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}
@keyframes toastOut{to{opacity:0;transform:translateX(20px)}}

/* ─── Loading / Skeleton ─── */
.skeleton{background:linear-gradient(90deg,var(--surface) 25%,var(--surface-hover) 50%,var(--surface) 75%);background-size:200% 100%;animation:skeleton 1.5s ease-in-out infinite;border-radius:var(--radius-sm)}
@keyframes skeleton{0%{background-position:200% 0}100%{background-position:-200% 0}}
.skeleton-text{height:12px;margin-bottom:8px}
.skeleton-text.short{width:60%}

/* ─── Empty State ─── */
.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:48px 20px;text-align:center;color:var(--text-muted)}
.empty-state svg{width:48px;height:48px;color:var(--text-muted);opacity:0.3;margin-bottom:16px}
.empty-state-title{font-size:14px;font-weight:600;color:var(--text-secondary);margin-bottom:6px}
.empty-state-desc{font-size:13px;color:var(--text-tertiary)}

/* ─── Key Grid ─── */
.key-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.key-field{margin-bottom:10px}
.key-field label{display:block;font-size:11px;color:var(--text-tertiary);margin-bottom:4px;font-weight:600}
.key-field input{width:100%;padding:8px 12px;background:var(--bg-elevated);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;font-family:var(--font-mono);outline:none;transition:border-color var(--transition-fast)}
.key-field input:focus{border-color:rgba(96,165,250,0.5)}

/* ─── Integration Field Groups ─── */
.field-group{margin-bottom:20px}
.field-group label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;color:var(--text-tertiary);margin-bottom:8px}
.field-wrap{display:flex;flex-direction:column;gap:10px}

/* ─── Login Page ─── */
.login-page{min-height:100vh;display:flex;align-items:center;justify-content:center;background:radial-gradient(ellipse at top,rgba(96,165,250,0.08),transparent 60%),radial-gradient(ellipse at bottom,rgba(34,211,238,0.05),transparent 60%)}
.login-card{width:100%;max-width:400px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:40px;box-shadow:var(--shadow-lg)}
.login-brand{display:flex;align-items:center;gap:16px;margin-bottom:32px}
.login-brand svg{color:var(--blue)}
.login-brand-name{font-size:20px;font-weight:700;color:var(--text-primary)}
.login-brand-tagline{font-size:13px;color:var(--text-tertiary);margin-top:2px}
.login-form .field-group{margin-bottom:20px}
.input-wrap{display:flex;align-items:center;gap:10px;background:var(--bg-elevated);border:1px solid var(--border);border-radius:var(--radius-sm);padding:0 14px;transition:border-color var(--transition-fast)}
.input-wrap:focus-within{border-color:var(--blue)}
.input-wrap svg{color:var(--text-muted);flex-shrink:0}
.input-wrap input{flex:1;background:transparent;border:none;padding:12px 0;color:var(--text-primary);font-size:14px;outline:none}
.input-wrap input::placeholder{color:var(--text-muted)}
.login-btn{width:100%;margin-top:8px}
.login-error{margin-top:12px;padding:10px 14px;border-radius:var(--radius-sm);background:var(--red-dim);color:var(--p1-text);border:1px solid var(--p1-border);font-size:12px;display:none}
.login-footer{margin-top:24px;padding-top:20px;border-top:1px solid var(--border);display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text-muted)}
.login-footer svg{color:var(--green)}

/* ─── Footer ─── */
.footer{text-align:center;padding:32px;color:var(--text-muted);font-size:12px;border-top:1px solid var(--border);margin-top:40px}

/* ─── Utility ─── */
.mono{font-family:var(--font-mono)}
.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dimmed{color:var(--text-muted)}

/* ─── Responsive ─── */
@media(max-width:1200px){
  .chart-row-3{grid-template-columns:1fr 1fr}
  .detail-panel{grid-template-columns:1fr 1fr}
}
@media(max-width:900px){
  .app-header{flex-wrap:wrap;height:auto;padding:12px 16px;gap:12px}
  .tab-nav{width:100%;overflow-x:auto;margin-left:0;padding-bottom:4px}
  .tab-btn{white-space:nowrap}
  .chart-row-3,.chart-row-2,.control-grid{grid-template-columns:1fr}
  .detail-panel{grid-template-columns:1fr}
  .kpi-grid{grid-template-columns:repeat(2,1fr)}
  .page{padding:16px}
}
@media(max-width:600px){
  .kpi-grid{grid-template-columns:1fr}
  .priority-bar{flex-direction:column;align-items:flex-start;gap:8px}
}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet" media="print" onload="this.media='all'">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js" defer></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js" defer></script>
<!-- Icon Sprite Sheet — Lucide-style icons, 24x24 viewBox -->
<svg style="display:none">
  <defs>
    <symbol id="icon-shield" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-target" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="6" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="2" fill="currentColor"/></symbol>
    <symbol id="icon-zap" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8" fill="none" stroke="currentColor" stroke-width="2"/><line x1="21" y1="21" x2="16.65" y2="16.65" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
    <symbol id="icon-trend-down" viewBox="0 0 24 24"><polyline points="23 18 13.5 8.5 8.5 13.5 1 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="17 18 23 18 23 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-trend-up" viewBox="0 0 24 24"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="17 6 23 6 23 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-dice" viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="20" rx="4" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="8" cy="8" r="1.5" fill="currentColor"/><circle cx="16" cy="8" r="1.5" fill="currentColor"/><circle cx="8" cy="16" r="1.5" fill="currentColor"/><circle cx="16" cy="16" r="1.5" fill="currentColor"/></symbol>
    <symbol id="icon-flame" viewBox="0 0 24 24"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-network" viewBox="0 0 24 24"><circle cx="5" cy="6" r="3" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="19" cy="6" r="3" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="18" r="3" fill="none" stroke="currentColor" stroke-width="2"/><line x1="5" y1="9" x2="12" y2="15" stroke="currentColor" stroke-width="2"/><line x1="19" y1="9" x2="12" y2="15" stroke="currentColor" stroke-width="2"/></symbol>
    <symbol id="icon-alert" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="12" y1="9" x2="12" y2="13" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="12" y1="17" x2="12.01" y2="17" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
    <symbol id="icon-package" viewBox="0 0 24 24"><line x1="16.5" y1="9.4" x2="7.5" y2="4.21" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="3.27 6.96 12 12.01 20.73 6.96" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="12" y1="22.08" x2="12" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-rocket" viewBox="0 0 24 24"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-refresh" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2"/><polyline points="12 6 12 12 16 14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-shuffle" viewBox="0 0 24 24"><polyline points="16 3 21 3 21 8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="4" y1="20" x2="21" y2="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="21 16 21 21 16 21" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="15" y1="15" x2="21" y2="21" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="4" y1="4" x2="9" y2="9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-link" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-list" viewBox="0 0 24 24"><line x1="8" y1="6" x2="21" y2="6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="8" y1="12" x2="21" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="8" y1="18" x2="21" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="3" y1="6" x2="3.01" y2="6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="3" y1="12" x2="3.01" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="3" y1="18" x2="3.01" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
    <symbol id="icon-key" viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-ticket" viewBox="0 0 24 24"><path d="M2 9a3 3 0 0 1 0 6v2a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-2a3 3 0 0 1 0-6V7a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2Z" fill="none" stroke="currentColor" stroke-width="2"/><path d="M13 5v2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M13 17v2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M13 11v2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
    <symbol id="icon-shield-check" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="9 12 12 15 17 10" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-download" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="7 10 12 15 17 10" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="12" y1="15" x2="12" y2="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-file-text" viewBox="0 0 24 24"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="14 2 14 8 20 8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="16" y1="13" x2="8" y2="13" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="16" y1="17" x2="8" y2="17" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="10" y1="9" x2="8" y2="9" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
    <symbol id="icon-box" viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-activity" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-plus" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="5" y1="12" x2="19" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
    <symbol id="icon-play" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-check" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-x" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="6" y1="6" x2="18" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
    <symbol id="icon-chevron-down" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-external-link" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="15 3 21 3 21 9" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="10" y1="14" x2="21" y2="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-bot" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="5" r="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 7v4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="8" y1="16" x2="8.01" y2="16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="16" y1="16" x2="16.01" y2="16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
    <symbol id="icon-github" viewBox="0 0 24 24"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-trash" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-settings" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="2"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-bar-chart" viewBox="0 0 24 24"><line x1="12" y1="20" x2="12" y2="10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="18" y1="20" x2="18" y2="4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="6" y1="20" x2="6" y2="16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
    <symbol id="icon-unlock" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-lock" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-send" viewBox="0 0 24 24"><line x1="22" y1="2" x2="11" y2="13" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polygon points="22 2 15 22 11 13 2 9 22 2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-download-cloud" viewBox="0 0 24 24"><polyline points="8 17 12 21 16 17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="12" y1="12" x2="12" y2="21" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M20.88 18.09A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.29" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
    <symbol id="icon-arrow-right" viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="12 5 19 12 12 19" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
  </defs>
</svg>
<noscript><style>.page{display:block!important}.page:not(#page-overview){display:none!important}</style></noscript>
</head>
<body>
<!-- Toast container -->
<div class="toast-container"></div>

<header class="app-header">
  <div class="header-brand">
    <svg width="28" height="28" class="brand-icon"><use href="#icon-shield"/></svg>
    <div class="brand-text">
      <span class="brand-name">RISK INTELLIGENCE</span>
      <span class="brand-version">v2.0</span>
    </div>
  </div>
  <div class="header-meta" id="run-meta"></div>
  <nav class="tab-nav" role="tablist">
    <button class="tab-btn active" data-page="overview" role="tab" aria-selected="true">
      <svg width="14" height="14"><use href="#icon-activity"/></svg>
      Overview
    </button>
    <button class="tab-btn" data-page="findings" role="tab">
      <svg width="14" height="14"><use href="#icon-list"/></svg>
      Findings
      <span class="tab-count" id="tc-findings">0</span>
    </button>
    <button class="tab-btn" data-page="attackpaths" role="tab">
      <svg width="14" height="14"><use href="#icon-network"/></svg>
      Attack Paths
      <span class="tab-count" id="tc-paths">0</span>
    </button>
    <button class="tab-btn" data-page="quarantine" role="tab">
      <svg width="14" height="14"><use href="#icon-alert"/></svg>
      Quarantine
      <span class="tab-count" id="tc-quarantine">0</span>
    </button>
    <button class="tab-btn" data-page="products" role="tab">
      <svg width="14" height="14"><use href="#icon-package"/></svg>
      Products
      <span class="tab-count" id="tc-products">0</span>
    </button>
    <button class="tab-btn" data-page="control" role="tab">
      <svg width="14" height="14"><use href="#icon-rocket"/></svg>
      Control
    </button>
    <button class="tab-btn" data-page="lifecycle" role="tab">
      <svg width="14" height="14"><use href="#icon-refresh"/></svg>
      Lifecycle
      <span class="tab-count" id="tc-lifecycle">0</span>
    </button>
    <button class="tab-btn" data-page="dedup" role="tab">
      <svg width="14" height="14"><use href="#icon-shuffle"/></svg>
      Dedup
    </button>
    <button class="tab-btn" data-page="integrations" role="tab">
      <svg width="14" height="14"><use href="#icon-key"/></svg>
      Integrations
    </button>
  </nav>
  <div class="header-actions">
    <button class="icon-btn" title="Refresh data" aria-label="Refresh data" onclick="location.reload()">
      <svg width="16" height="16"><use href="#icon-refresh"/></svg>
    </button>
  </div>
</header>

<!-- ═══════════════════════ OVERVIEW ═══════════════════════ -->
<main id="page-overview" class="page active" role="tabpanel">
  <div id="brief-section"></div>
  <div class="kpi-grid" id="kpi-grid"></div>
  <div class="chart-row-3">
    <div class="chart-card">
      <div class="chart-header">
        <svg width="16" height="16"><use href="#icon-target"/></svg>
        <span class="chart-title">Priority Distribution</span>
      </div>
      <div class="chart-body"><canvas id="c-priority"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-header">
        <svg width="16" height="16"><use href="#icon-zap"/></svg>
        <span class="chart-title">Severity Breakdown</span>
      </div>
      <div class="chart-body"><canvas id="c-severity"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-header">
        <svg width="16" height="16"><use href="#icon-search"/></svg>
        <span class="chart-title">Scanner Coverage</span>
      </div>
      <div class="chart-body"><canvas id="c-scanner"></canvas></div>
    </div>
  </div>
  <div class="chart-row-2">
    <div class="chart-card">
      <div class="chart-header">
        <svg width="16" height="16"><use href="#icon-trend-down"/></svg>
        <span class="chart-title">Noise Reduction Pipeline</span>
      </div>
      <div class="chart-body"><canvas id="c-noise"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-header">
        <svg width="16" height="16"><use href="#icon-trend-up"/></svg>
        <span class="chart-title">Risk Over Time</span>
      </div>
      <div class="chart-body"><canvas id="c-history"></canvas></div>
    </div>
  </div>
  <div class="chart-row-2">
    <div class="chart-card">
      <div class="chart-header">
        <svg width="16" height="16"><use href="#icon-dice"/></svg>
        <span class="chart-title">EPSS vs Risk Score</span>
      </div>
      <div class="chart-body"><canvas id="c-epss"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-header">
        <svg width="16" height="16"><use href="#icon-flame"/></svg>
        <span class="chart-title">Threat Intelligence Coverage</span>
      </div>
      <div class="chart-body"><canvas id="c-threat"></canvas></div>
    </div>
  </div>
</main>

<!-- ═══════════════════════ FINDINGS ═══════════════════════ -->
<main id="page-findings" class="page" role="tabpanel">
  <div class="priority-bar">
    <span style="font-weight:600;color:var(--text-secondary)">Priority Bands:</span>
    <span class="priority-item"><span class="priority-dot p1"></span> P1 Critical (90+) &mdash; fix in 24h</span>
    <span class="priority-item"><span class="priority-dot p2"></span> P2 High (70-89) &mdash; fix in 3 days</span>
    <span class="priority-item"><span class="priority-dot p3"></span> P3 Medium (40-69) &mdash; fix in 1 week</span>
    <span class="priority-item"><span class="priority-dot p4"></span> P4 Low (&lt;40) &mdash; fix in 2 weeks</span>
  </div>
  <div class="table-controls">
    <div class="search-wrap">
      <svg width="16" height="16" class="search-icon"><use href="#icon-search"/></svg>
      <input id="tbl-search" class="search-box" placeholder="Search title, CVE, CWE, endpoint...">
    </div>
    <select id="f-priority" class="filter-sel"><option value="">All priorities</option></select>
    <select id="f-severity" class="filter-sel"><option value="">All severities</option></select>
    <select id="f-scanner" class="filter-sel"><option value="">All scanners</option></select>
    <select id="f-kev" class="filter-sel"><option value="">KEV filter</option><option value="kev">KEV only</option><option value="exploit">Exploit available</option></select>
    <button class="btn btn-secondary" style="font-size:12px;padding:7px 14px" onclick="exportCSV()" aria-label="Export findings as CSV">
      <svg width="14" height="14"><use href="#icon-download"/></svg>
      Export CSV
    </button>
    <span class="result-badge" id="result-badge">&mdash; findings</span>
  </div>
  <div class="table-wrap"><table class="data-table"><thead id="tbl-head"></thead><tbody id="tbl-body"></tbody></table></div>
</main>

<!-- ═══════════════════════ ATTACK PATHS ═══════════════════════ -->
<main id="page-attackpaths" class="page" role="tabpanel">
  <div class="chart-card">
    <div class="chart-header">
      <svg width="16" height="16"><use href="#icon-network"/></svg>
      <span class="chart-title">Attack Path Graph &mdash; drag nodes, scroll to zoom</span>
    </div>
    <div style="padding:12px 20px 0">
      <div class="ap-legend">
        <span class="ap-legend-item"><span class="ap-legend-dot" style="background:var(--red);box-shadow:0 0 6px var(--red)"></span>High-impact target</span>
        <span class="ap-legend-item"><span class="ap-legend-dot" style="background:var(--blue)"></span>Intermediate CWE</span>
        <span class="ap-legend-item"><span class="ap-legend-dot" style="background:var(--cyan);border-radius:2px;height:3px;width:20px"></span>High-probability path</span>
      </div>
      <div class="ap-controls"><select id="ap-product" class="ap-product-sel"></select><button class="ap-btn" onclick="apReset()">Reset zoom</button><span class="dimmed" style="font-size:12px;margin-left:4px">Nodes: CWEs active in this product &middot; edges: escalation probability</span></div>
    </div>
    <div id="ap-container" style="margin:0 20px 20px"><svg id="ap-svg" height="540"></svg><div class="ap-tooltip" id="ap-tooltip"></div></div>
  </div>
</main>

<!-- ═══════════════════════ QUARANTINE ═══════════════════════ -->
<main id="page-quarantine" class="page" role="tabpanel">
  <div class="q-note">
    <svg width="16" height="16" style="flex-shrink:0"><use href="#icon-alert"/></svg>
    Quarantined findings are never deleted &mdash; they remain auditable below. Rule matches are the exclusion reason.
  </div>
  <div class="q-table-wrap"><table class="data-table"><thead><tr><th>Product</th><th>Scanner</th><th>Severity</th><th>Title</th><th>CVE</th><th>Exclusion reason</th></tr></thead><tbody id="q-body"></tbody></table></div>
</main>

<!-- ═══════════════════════ PRODUCTS ═══════════════════════ -->
<main id="page-products" class="page" role="tabpanel">
  <div class="chart-card" style="margin-bottom:20px;padding:20px">
    <div class="chart-header" style="padding:0 0 16px">
      <svg width="16" height="16"><use href="#icon-package"/></svg>
      <span class="chart-title">Managed Products</span>
    </div>
    <div id="products-table-wrap"></div>
  </div>
  <div class="chart-card" style="padding:20px">
    <div class="chart-header" style="padding:0 0 16px">
      <svg width="16" height="16"><use href="#icon-plus"/></svg>
      <span class="chart-title">Add New Product</span>
    </div>
    <div id="add-product-form" style="display:grid;grid-template-columns:1fr 1fr;gap:16px;max-width:700px">
      <div class="field-group"><label for="ap-id">Product ID (slug)</label><input id="ap-id" class="search-box" style="width:100%;max-width:none" placeholder="my_custom_app"></div>
      <div class="field-group"><label for="ap-name">Display Name</label><input id="ap-name" class="search-box" style="width:100%;max-width:none" placeholder="My Custom App"></div>
      <div class="field-group"><label for="ap-url">Target URL</label><input id="ap-url" class="search-box" style="width:100%;max-width:none" placeholder="https://myapp.com"></div>
      <div class="field-group"><label for="ap-repo">GitHub Repo (org/name)</label><input id="ap-repo" class="search-box" style="width:100%;max-width:none" placeholder="myorg/myapp"></div>
      <div class="field-group"><label for="ap-owner">Team Owner</label><input id="ap-owner" class="search-box" style="width:100%;max-width:none" placeholder="appsec-team"></div>
      <div class="field-group"><label for="ap-crit">Asset Criticality (1-10)</label><input id="ap-crit" type="number" min="1" max="10" value="5" class="search-box" style="width:100%;max-width:none"></div>
      <div class="field-group"><label for="ap-sens">Data Sensitivity (1-10)</label><input id="ap-sens" type="number" min="1" max="10" value="5" class="search-box" style="width:100%;max-width:none"></div>
      <div class="field-group"><label for="ap-trivy">Trivy Image (optional)</label><input id="ap-trivy" class="search-box" style="width:100%;max-width:none" placeholder="myorg/myapp:latest"></div>
      <div style="grid-column:1/-1;display:flex;gap:10px;margin-top:8px">
        <button class="btn btn-primary" onclick="addProduct()">
          <svg width="16" height="16"><use href="#icon-check"/></svg>
          Save Product
        </button>
        <span id="ap-msg" style="font-size:12px;color:var(--green);align-self:center"></span>
      </div>
    </div>
  </div>
</main>

<!-- ═══════════════════════ CONTROL CENTER ═══════════════════════ -->
<main id="page-control" class="page" role="tabpanel">
  <div class="control-grid">
    <div class="control-section">
      <div class="control-section-title">
        <svg width="14" height="14"><use href="#icon-activity"/></svg>
        System Status
      </div>
      <div id="app-status-list"></div>
    </div>
    <div class="control-section">
      <div class="control-section-title">
        <svg width="14" height="14"><use href="#icon-rocket"/></svg>
        Quick Actions
      </div>
      <div class="btn-group">
        <button class="btn btn-secondary" onclick="triggerScanAll()">
          <svg width="16" height="16"><use href="#icon-search"/></svg>
          Scan All Products
        </button>
        <button class="btn btn-primary" onclick="runPipeline()">
          <svg width="16" height="16"><use href="#icon-play"/></svg>
          Run Pipeline
        </button>
        <button class="btn btn-secondary" onclick="createTickets()">
          <svg width="16" height="16"><use href="#icon-github"/></svg>
          Create GitHub Issues
        </button>
        <button class="btn btn-secondary" onclick="checkDocker()">
          <svg width="16" height="16"><use href="#icon-box"/></svg>
          Check Docker Status
        </button>
      </div>
    </div>
  </div>
  <div class="control-section" style="margin-top:20px">
    <div class="control-section-title">
      <svg width="14" height="14"><use href="#icon-bar-chart"/></svg>
      Scanner Progress
    </div>
    <div id="scanner-progress">
      <div class="empty-state">
        <svg width="32" height="32"><use href="#icon-search"/></svg>
        <p class="empty-state-desc">No active scans. Use the controls above to start scanning.</p>
      </div>
    </div>
  </div>
</main>

<!-- ═══════════════════════ LIFECYCLE ═══════════════════════ -->
<main id="page-lifecycle" class="page" role="tabpanel">
  <div class="kpi-grid" id="lc-kpi-grid"></div>
  <div class="chart-card" style="margin-bottom:20px;padding:20px">
    <div class="chart-header" style="padding:0 0 16px">
      <svg width="16" height="16"><use href="#icon-refresh"/></svg>
      <span class="chart-title">Vulnerability Lifecycle</span>
    </div>
    <p class="dimmed" style="font-size:12px;margin-bottom:16px">Track findings from Open &rarr; In Progress &rarr; Fixed &rarr; Verified. SLA deadlines shown in red when breached.</p>
    <div id="lc-table-wrap"></div>
  </div>
  <div class="chart-card" style="padding:20px">
    <div class="chart-header" style="padding:0 0 16px">
      <svg width="16" height="16"><use href="#icon-clock"/></svg>
      <span class="chart-title">SLA Breach Monitor</span>
    </div>
    <div id="lc-breached-list"></div>
  </div>
</main>

<!-- ═══════════════════════ DEDUP ANALYTICS ═══════════════════════ -->
<main id="page-dedup" class="page" role="tabpanel">
  <div class="kpi-grid" id="dedup-kpi-grid"></div>
  <div class="chart-row-2">
    <div class="chart-card">
      <div class="chart-header">
        <svg width="16" height="16"><use href="#icon-shuffle"/></svg>
        <span class="chart-title">Findings per Scanner (Pre-Dedup)</span>
      </div>
      <div class="chart-body"><canvas id="c-dedup-scanner"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-header">
        <svg width="16" height="16"><use href="#icon-link"/></svg>
        <span class="chart-title">Cross-Scanner Redundancy</span>
      </div>
      <div class="chart-body"><canvas id="c-dedup-overlap"></canvas></div>
    </div>
  </div>
  <div class="chart-card" style="padding:20px">
    <div class="chart-header" style="padding:0 0 16px">
      <svg width="16" height="16"><use href="#icon-list"/></svg>
      <span class="chart-title">Cross-Scanner Overlap Details</span>
    </div>
    <div id="dedup-overlap-table"></div>
  </div>
</main>

<!-- ═══════════════════════ INTEGRATIONS ═══════════════════════ -->
<main id="page-integrations" class="page" role="tabpanel">
  <div class="chart-card" style="margin-bottom:20px;padding:20px">
    <div class="chart-header" style="padding:0 0 16px">
      <svg width="16" height="16"><use href="#icon-key"/></svg>
      <span class="chart-title">API Key Configuration</span>
    </div>
    <p class="dimmed" style="font-size:12px;margin-bottom:16px">Configure API keys for threat intelligence, AI enrichment, and integrations. Keys are stored in .env and used by the pipeline.</p>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;max-width:900px">
      <div>
        <div class="control-section-title">AI Enrichment</div>
        <div class="field-group"><label for="ak-groq">Groq API Key (free at console.groq.com)</label><input id="ak-groq" class="search-box" style="width:100%;max-width:none" placeholder="gsk_..." type="password"></div>
        <div class="field-group"><label for="ak-nvd">NVD API Key (optional, increases rate limit)</label><input id="ak-nvd" class="search-box" style="width:100%;max-width:none" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" type="password"></div>
      </div>
      <div>
        <div class="control-section-title">GitHub (Auto-ticketing)</div>
        <div class="field-group"><label for="ak-github">GitHub Token (creates Issues for P1/P2)</label><input id="ak-github" class="search-box" style="width:100%;max-width:none" placeholder="ghp_xxx..." type="password"></div>
      </div>
      <div>
        <div class="control-section-title">Jira Integration</div>
        <div class="field-group"><label for="ak-jira-url">Jira URL</label><input id="ak-jira-url" class="search-box" style="width:100%;max-width:none" placeholder="https://yourorg.atlassian.net"></div>
        <div class="field-group"><label for="ak-jira-user">Username / Email</label><input id="ak-jira-user" class="search-box" style="width:100%;max-width:none" placeholder="user@company.com"></div>
        <div class="field-group"><label for="ak-jira-token">API Token</label><input id="ak-jira-token" class="search-box" style="width:100%;max-width:none" placeholder="ATATT..." type="password"></div>
        <div class="field-group"><label for="ak-jira-project">Project Key</label><input id="ak-jira-project" class="search-box" style="width:100%;max-width:none" placeholder="SEC"></div>
      </div>
      <div>
        <div class="control-section-title">DefectDojo (Hybrid)</div>
        <div class="field-group"><label for="ak-dd-url">DefectDojo URL</label><input id="ak-dd-url" class="search-box" style="width:100%;max-width:none" placeholder="http://localhost:8080"></div>
        <div class="field-group"><label for="ak-dd-key">API Key</label><input id="ak-dd-key" class="search-box" style="width:100%;max-width:none" placeholder="your-defectdojo-api-key" type="password"></div>
      </div>
    </div>
    <div style="margin-top:16px;display:flex;gap:10px;align-items:center">
      <button class="btn btn-success" onclick="saveApiKeys()">
        <svg width="16" height="16"><use href="#icon-check"/></svg>
        Save API Keys
      </button>
      <span id="apikey-status" style="font-size:12px"></span>
    </div>
  </div>
  <div class="chart-row-2">
    <div class="chart-card" style="padding:20px">
      <div class="chart-header" style="padding:0 0 16px">
        <svg width="16" height="16"><use href="#icon-ticket"/></svg>
        <span class="chart-title">Jira Integration</span>
      </div>
      <div id="jira-panel">
        <p class="dimmed" style="font-size:12px;margin-bottom:12px">Create Jira issues for high-risk findings.</p>
        <div style="display:flex;gap:10px;margin-bottom:16px">
          <button class="btn btn-secondary" onclick="testJira()">
            <svg width="14" height="14"><use href="#icon-search"/></svg>
            Test Connection
          </button>
          <button class="btn btn-success" onclick="createJiraIssues()">
            <svg width="14" height="14"><use href="#icon-plus"/></svg>
            Create Issues
          </button>
        </div>
        <div id="jira-status"></div>
      </div>
    </div>
    <div class="chart-card" style="padding:20px">
      <div class="chart-header" style="padding:0 0 16px">
        <svg width="16" height="16"><use href="#icon-shield-check"/></svg>
        <span class="chart-title">DefectDojo Hybrid</span>
      </div>
      <div id="dd-panel">
        <p class="dimmed" style="font-size:12px;margin-bottom:12px">Our pipeline scores + enriches (AI-powered). DefectDojo is the safety net that catches anything we miss. Push findings for compliance, audit trail, and remediation lifecycle tracking.</p>
        <div style="display:flex;gap:10px;margin-bottom:16px">
          <button class="btn btn-secondary" onclick="testDefectDojo()">
            <svg width="14" height="14"><use href="#icon-search"/></svg>
            Test Connection
          </button>
          <button class="btn btn-success" onclick="importDefectDojo()">
            <svg width="14" height="14"><use href="#icon-download"/></svg>
            Import Findings
          </button>
        </div>
        <div id="dd-status"></div>
      </div>
    </div>
  </div>
  <div class="chart-card" style="padding:20px">
    <div class="chart-header" style="padding:0 0 16px">
      <svg width="16" height="16"><use href="#icon-download"/></svg>
      <span class="chart-title">Exports</span>
    </div>
    <div style="display:flex;gap:12px;flex-wrap:wrap">
      <a class="btn btn-secondary" href="/api/exports/sarif" target="_blank">
        <svg width="16" height="16"><use href="#icon-file-text"/></svg>
        SARIF (GitHub Security)
      </a>
      <a class="btn btn-secondary" href="/api/exports/cyclonedx" target="_blank">
        <svg width="16" height="16"><use href="#icon-box"/></svg>
        CycloneDX SBOM
      </a>
      <a class="btn btn-secondary" href="/api/exports/defectdojo" target="_blank">
        <svg width="16" height="16"><use href="#icon-shield-check"/></svg>
        DefectDojo JSON
      </a>
    </div>
  </div>
</main>

<footer class="footer">Generated by the DevSecOps Risk Intelligence Pipeline v2.0 &middot; Chart.js 4 &middot; D3 v7 &middot; All data is local &mdash; no telemetry</footer>
<script>const DASH=__DASH_JSON__;</script>
<script>
const esc=s=>(s||'').toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');
const $=id=>document.getElementById(id);
const scoreColor=v=>v>=80?'#f87171':v>=60?'#fb923c':v>=40?'#facc15':'#4ade80';
const priClass=p=>({P1:'b-p1',P2:'b-p2',P3:'b-p3',P4:'b-p4'}[p]||'b-p4');
const sevClass=s=>({critical:'b-critical',high:'b-high',medium:'b-medium',low:'b-low',info:'b-info'}[s]||'b-info');
const fmt=n=>typeof n==='number'?n.toLocaleString():n||'-';
const pct=n=>n!=null&&n!==''?`${(n*100).toFixed(1)}%`:'-';
const gridColor='rgba(148,163,184,0.06)';
const cardCfg={plugins:{legend:{display:false}},maintainAspectRatio:false};
let apInited=false;
let HAS_CHART=false;

/* ─── Icon helper ─── */
function iconSvg(id,w,h){return '<svg width="'+(w||16)+'" height="'+(h||16)+'"><use href="#'+id+'"/></svg>';}

/* ─── Toast notifications ─── */
function showToast(message,type){
  type=type||'info';
  var container=document.querySelector('.toast-container');
  if(!container){container=document.createElement('div');container.className='toast-container';document.body.appendChild(container);}
  var icons={success:'icon-check',error:'icon-x',info:'icon-activity'};
  var toast=document.createElement('div');
  toast.className='toast toast-'+type;
  toast.innerHTML=iconSvg(icons[type]||'icon-activity')+'<span>'+esc(message)+'</span>';
  container.appendChild(toast);
  setTimeout(function(){if(toast.parentNode)toast.remove();},5000);
}
/* Keep legacy helper for backward compat — redirects to toast */
function updateControlStatus(msg,type){
  var map={ok:'success',err:'error',info:'info',warn:'info'};
  showToast(msg,map[type]||'info');
}

/* ─── Auth helpers ─── */
function apiHeaders(extra){return Object.assign({'Content-Type':'application/json'},extra||{});}
function apiFetch(url,opts){
  opts=opts||{};
  opts.headers=apiHeaders(opts.headers);
  return fetch(url,opts).then(function(r){
    if(r.status===401){window.location.href='/';return{};}
    return r.json();
  });
}

/* ─── Tab switching ─── */
document.querySelectorAll('.tab-btn').forEach(function(btn){
  btn.addEventListener('click',function(){
    document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');b.setAttribute('aria-selected','false');});
    document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
    btn.classList.add('active');
    btn.setAttribute('aria-selected','true');
    var page='page-'+btn.dataset.page;
    var pg=$(page);if(pg)pg.classList.add('active');
    if(btn.dataset.page==='attackpaths'&&!apInited){initD3();apInited=true;}
    if(btn.dataset.page==='control'){loadAppStatus();connectWebSocket();loadScannerJobs();}
    location.hash=btn.dataset.page;
  });
});

/* ─── URL hash navigation ─── */
function syncTabFromHash(){
  var hash=location.hash.replace('#','');
  if(hash){
    var btn=document.querySelector('.tab-btn[data-page="'+hash+'"]');
    if(btn)btn.click();
  }
}
window.addEventListener('hashchange',syncTabFromHash);
if(location.hash)syncTabFromHash();

/* ─── Keyboard navigation ─── */
document.addEventListener('keydown',function(e){
  if(e.key==='Escape'){
    document.querySelectorAll('.detail-row.open').forEach(function(r){r.classList.remove('open');});
    document.querySelectorAll('.data-row.expanded').forEach(function(r){r.classList.remove('expanded');});
  }
});

/* ─── Animate counter ─── */
function animateCount(el,target){
  if(!el)return;
  var dur=1400,start=performance.now();
  var isFloat=String(target).includes('.');
  function tick(now){
    var p=Math.min((now-start)/dur,1);
    var ease=1-Math.pow(1-p,3);
    var val=ease*target;
    el.textContent=isFloat?val.toFixed(1):Math.round(val).toLocaleString();
    if(p<1)requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

/* ─── SVG icon helper for JS ─── */
function svgIcon(id,sz){return '<svg width="'+(sz||16)+'" height="'+(sz||16)+'"><use href="#'+id+'"/></svg>';}

/* ─── Header ─── */
(function buildHeader(){
  try{
    var S=DASH.summary;var meta=$('run-meta');if(!meta)return;
    var pills=['<span class="meta-pill">'+esc(S.run_date.substring(0,16))+'</span>'];
    S.products.forEach(function(p){pills.push('<span class="meta-pill">'+esc(p)+'</span>');});
    if(S.p1>0)pills.push('<span class="meta-pill critical">P1: '+S.p1+'</span>');
    meta.innerHTML=pills.join('');
    var tc=$('tc-findings');if(tc)tc.textContent=S.final_findings;
    var tq=$('tc-quarantine');if(tq)tq.textContent=S.quarantined;
  }catch(e){console.error('buildHeader:',e);}
})();

/* ─── Brief ─── */
(function buildBrief(){
  try{
    var brief=DASH.executive_brief;
    if(!brief){var bs=$('brief-section');if(bs)bs.style.display='none';return;}
    var bs2=$('brief-section');
    if(bs2)bs2.innerHTML='<div class="brief-card"><div class="brief-icon">'+svgIcon('icon-bot',28)+'</div><div><div class="brief-label">AI Executive Brief</div><div class="brief-text">'+esc(brief)+'</div></div></div>';
  }catch(e){console.error('buildBrief:',e);}
})();

/* ─── KPIs ─── */
(function buildKPIs(){
  try{
    var S=DASH.summary;
    var noiseRm=S.raw_findings>0?((S.raw_findings-S.final_findings)/S.raw_findings*100).toFixed(1):0;
    var cards=[
      {v:S.raw_findings,l:'Raw Findings',sub:'Before processing',cls:'',icon:'icon-search',iconCls:''},
      {v:S.unique_findings,l:'After Deduplication',sub:S.dedup_pct+'% removed',cls:'',icon:'icon-shuffle',iconCls:''},
      {v:S.quarantined,l:'Quarantined',sub:'False positives / accepted risk',cls:'',icon:'icon-alert',iconCls:''},
      {v:S.final_findings,l:'Active Findings',sub:'Prioritized & scored',cls:'warn',icon:'icon-target',iconCls:''},
      {v:S.p1+S.p2,l:'Critical + High',sub:S.p1+' P1 \u00b7 '+S.p2+' P2',cls:'danger',icon:'icon-zap',iconCls:''},
      {v:S.avg_score,l:'Average Risk Score',sub:'Top: '+S.top_score,cls:'',icon:'icon-activity',iconCls:''},
      {v:noiseRm+'%',l:'Noise Reduction',sub:'Raw to final',cls:'success',icon:'icon-trend-down',iconCls:''}
    ];
    var grid=$('kpi-grid');if(!grid)return;
    grid.innerHTML=cards.map(function(c,i){
      return '<div class="kpi-card '+c.cls+'"><div class="kpi-header"><div class="kpi-icon">'+svgIcon(c.icon)+'</div></div><div class="kpi-value" id="kv-'+i+'">'+(typeof c.v==='number'?'0':c.v)+'</div><div class="kpi-label">'+c.l+'</div><div class="kpi-sub">'+c.sub+'</div></div>';
    }).join('');
    cards.forEach(function(c,i){if(typeof c.v==='number')animateCount($('kv-'+i),c.v);});
  }catch(e){console.error('buildKPIs:',e);}
})();

/* ─── Charts (wait for Chart.js to load) ─── */
function initCharts(){
  if(typeof Chart==='undefined')return;
  HAS_CHART=true;
  Chart.defaults.color='#94a3b8';
  Chart.defaults.font.family="'Inter',system-ui,sans-serif";
  Chart.defaults.font.size=11;
  try{
    var S=DASH.summary,F=DASH.findings,H=DASH.history;

    // Priority donut
    var priEl=$('c-priority');
    if(priEl){
      new Chart(priEl,{type:'doughnut',data:{labels:['P1 Critical (90+)','P2 High (70-89)','P3 Medium (40-69)','P4 Low (<40)'],datasets:[{data:[S.p1,S.p2,S.p3,S.p4],backgroundColor:['#f87171','#fb923c','#facc15','#64748b'],borderWidth:0,hoverOffset:6,borderRadius:4}]},options:{...cardCfg,cutout:'68%',plugins:{legend:{display:true,position:'bottom',labels:{color:'#94a3b8',boxWidth:10,boxHeight:10,padding:12}},tooltip:{callbacks:{label:function(ctx){return ctx.label+': '+ctx.raw+' findings';}}}}}});
    }

    // Severity bar
    var sevEl=$('c-severity');
    if(sevEl){
      var sevCounts={critical:0,high:0,medium:0,low:0,info:0};
      F.forEach(function(f){sevCounts[f.severity]=(sevCounts[f.severity]||0)+1;});
      var sevLabels=['critical','high','medium','low','info'];
      new Chart(sevEl,{type:'bar',data:{labels:sevLabels.map(function(s){return s.charAt(0).toUpperCase()+s.slice(1);}),datasets:[{data:sevLabels.map(function(s){return sevCounts[s]||0;}),backgroundColor:['rgba(248,113,113,.8)','rgba(251,146,60,.8)','rgba(250,204,21,.8)','rgba(74,222,128,.8)','rgba(100,116,139,.8)'],borderWidth:0,borderRadius:4}]},options:{...cardCfg,indexAxis:'y',scales:{x:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},y:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false},tooltip:{callbacks:{label:function(ctx){return ctx.raw+' findings';}}}}}});
    }

    // Scanner coverage
    var scanEl=$('c-scanner');
    if(scanEl){
      var scanMap={};F.forEach(function(f){scanMap[f.scanner]=(scanMap[f.scanner]||0)+1;});
      var scanKeys=Object.keys(scanMap).sort(function(a,b){return scanMap[b]-scanMap[a];});
      new Chart(scanEl,{type:'bar',data:{labels:scanKeys,datasets:[{data:scanKeys.map(function(k){return scanMap[k];}),backgroundColor:'rgba(34,211,238,.7)',borderWidth:0,borderRadius:4}]},options:{...cardCfg,indexAxis:'y',scales:{x:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},y:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false}}}});
    }

    // Noise reduction pipeline
    var noiseEl=$('c-noise');
    if(noiseEl){
      new Chart(noiseEl,{type:'bar',data:{labels:['Raw findings','After dedup','After filtering','Active'],datasets:[{label:'Findings',data:[S.raw_findings,S.unique_findings,S.unique_findings-S.quarantined,S.final_findings],backgroundColor:['rgba(96,165,250,.7)','rgba(34,211,238,.7)','rgba(250,204,21,.7)','rgba(74,222,128,.7)'],borderWidth:0,borderRadius:6}]},options:{...cardCfg,scales:{y:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},x:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false},tooltip:{callbacks:{label:function(ctx){return ctx.raw.toLocaleString()+' findings';}}}}}});
    }

    // Risk over time
    var histEl=$('c-history');
    if(histEl){
      var colors=['#60a5fa','#22d3ee','#818cf8','#4ade80','#fb923c'];
      var products=Object.keys(H);
      var histDatasets=[];
      products.forEach(function(prod,idx){
        var runs=H[prod];
        if(!runs||runs.length<1)return;
        histDatasets.push({label:prod,data:runs.map(function(r){return {x:r.run_date,y:r.avg_score};}),borderColor:colors[idx%colors.length],backgroundColor:'transparent',tension:.4,pointRadius:4,pointHoverRadius:6,borderWidth:2});
      });
      if(histDatasets.length){
        new Chart(histEl,{type:'line',data:{datasets:histDatasets},options:{...cardCfg,scales:{x:{type:'category',grid:{color:gridColor},ticks:{color:'#94a3b8',maxRotation:30}},y:{grid:{color:gridColor},ticks:{color:'#94a3b8'},title:{display:true,text:'Avg score',color:'#64748b'}}},plugins:{legend:{display:products.length>1,position:'bottom',labels:{color:'#94a3b8'}}}}});
      }else{
        histEl.parentElement.innerHTML='<div class="empty-state">'+svgIcon('icon-trend-up',32)+'<p class="empty-state-title">No History Data</p><p class="empty-state-desc">Need 2+ pipeline runs to show trend.</p></div>';
      }
    }

    // EPSS scatter
    var epssEl=$('c-epss');
    if(epssEl){
      var epssData=F.filter(function(f){return f.epss_score>0&&f.score>0;}).map(function(f){return {x:parseFloat((f.epss_score*100).toFixed(2)),y:f.score,label:f.title,kev:f.kev,sev:f.severity};});
      new Chart(epssEl,{type:'scatter',data:{datasets:[{label:'Findings',data:epssData,backgroundColor:epssData.map(function(p){return p.kev?'rgba(248,113,113,.75)':p.sev==='critical'?'rgba(248,113,113,.5)':p.sev==='high'?'rgba(251,146,60,.5)':p.sev==='medium'?'rgba(250,204,21,.5)':'rgba(74,222,128,.35)';}),pointRadius:5,pointHoverRadius:8}]},options:{...cardCfg,scales:{x:{title:{display:true,text:'EPSS score (%)',color:'#64748b'},grid:{color:gridColor},ticks:{color:'#94a3b8'}},y:{title:{display:true,text:'Risk score',color:'#64748b'},grid:{color:gridColor},ticks:{color:'#94a3b8'},min:0,max:100}},plugins:{legend:{display:false},tooltip:{callbacks:{label:function(ctx){var d=ctx.raw;return [d.label.substring(0,40),'EPSS: '+d.x+'%  Score: '+d.y,d.kev?'In CISA KEV':''];}}}}}});
    }

    // Threat intel coverage
    var threatEl=$('c-threat');
    if(threatEl){
      var kevCount=F.filter(function(f){return f.kev;}).length;
      var exploitCount=F.filter(function(f){return f.exploit_available&&!f.kev;}).length;
      var epssHighCount=F.filter(function(f){return f.epss_score>.3&&!f.kev&&!f.exploit_available;}).length;
      var noIntelCount=F.length-kevCount-exploitCount-epssHighCount;
      new Chart(threatEl,{type:'doughnut',data:{labels:['CISA KEV (confirmed exploit)','Exploit-DB match','EPSS > 30%','No active intel'],datasets:[{data:[kevCount,exploitCount,epssHighCount,noIntelCount],backgroundColor:['rgba(248,113,113,.85)','rgba(251,146,60,.8)','rgba(250,204,21,.7)','rgba(100,116,139,.4)'],borderWidth:0,hoverOffset:6,borderRadius:4}]},options:{...cardCfg,cutout:'60%',plugins:{legend:{display:true,position:'bottom',labels:{color:'#94a3b8',boxWidth:10,boxHeight:10,padding:10}}}}});
    }
  }catch(e){console.error('initCharts:',e);}
}

function waitForCharts(){
  if(typeof Chart!=='undefined'){initCharts();return;}
  var attempts=0;
  var check=setInterval(function(){
    attempts++;
    if(typeof Chart!=='undefined'){clearInterval(check);initCharts();}
    if(attempts>100){clearInterval(check);console.warn('Chart.js did not load');}
  },200);
}
if(document.readyState==='loading'){
  document.addEventListener('DOMContentLoaded',function(){waitForCharts();initTable();});
}else{
  waitForCharts();initTable();
}

/* ─── Findings Table ─── */
function initTable(){
  try{
    var F=DASH.findings;
    var priorities=[...new Set(F.map(function(f){return f.priority;}))].sort();
    var severities=[...new Set(F.map(function(f){return f.severity;}))].sort();
    var scanners=[...new Set(F.map(function(f){return f.scanner;}))].sort();
    [['f-priority',priorities],['f-severity',severities],['f-scanner',scanners]].forEach(function(arr){
      var sel=$(arr[0]);if(!sel)return;
      arr[1].forEach(function(v){
        var o=document.createElement('option');o.value=v;o.textContent=v;sel.appendChild(o);
      });
    });
    var COLS=[
      {k:'rank',label:'#',w:'40px',sortable:true},
      {k:'score',label:'Score',w:'110px',sortable:true},
      {k:'priority',label:'Priority',w:'80px',sortable:true},
      {k:'sla_hours',label:'SLA',w:'60px',sortable:true},
      {k:'product',label:'Product',w:'100px',sortable:true},
      {k:'scanner',label:'Scanner',w:'80px',sortable:true},
      {k:'severity',label:'Severity',w:'80px',sortable:true},
      {k:'title',label:'Title',w:'',sortable:false},
      {k:'cve',label:'CVE',w:'140px',sortable:false},
      {k:'kev',label:'KEV',w:'60px',sortable:true},
      {k:'epss_score',label:'EPSS',w:'70px',sortable:true},
      {k:'cwe',label:'CWE',w:'90px',sortable:false}
    ];
    var thead=$('tbl-head');if(!thead)return;
    thead.innerHTML='<tr>'+COLS.map(function(c){
      return '<th style="'+(c.w?'width:'+c.w:'')+'" '+(c.sortable?'data-col="'+c.k+'"':'')+'>'+c.label+(c.sortable?'<span class="sort-arrow">&#x2195;</span>':'')+'</th>';
    }).join('')+'</tr>';
    var sortCol='score',sortDir=-1,search='',fPri='',fSev='',fScan='',fKev='';
    function getFiltered(){
      var q=search.toLowerCase();
      return F.filter(function(f){
        if(fPri&&f.priority!==fPri)return false;
        if(fSev&&f.severity!==fSev)return false;
        if(fScan&&f.scanner!==fScan)return false;
        if(fKev==='kev'&&!f.kev)return false;
        if(fKev==='exploit'&&!f.exploit_available)return false;
        if(q)return(f.title+f.cve+f.cwe+f.endpoint+f.product).toLowerCase().includes(q);
        return true;
      }).sort(function(a,b){
        var av=a[sortCol],bv=b[sortCol];
        if(typeof av==='number')return(av-bv)*sortDir;
        return String(av).localeCompare(String(bv))*sortDir;
      });
    }
    function renderRow(f){
      var sc=scoreColor(f.score);
      var epssStr=f.epss_score>0?(f.epss_score*100).toFixed(1)+'%':'-';
      return '<tr class="data-row" data-rank="'+f.rank+'" onclick="toggleDetail(this)"><td class="no-wrap mono dimmed">'+f.rank+'</td><td class="no-wrap"><div class="score-cell"><span class="score-num" style="color:'+sc+'">'+f.score+'</span><div class="score-track"><div class="score-fill" style="width:'+f.score+'%;background:'+sc+'"></div></div></div></td><td class="no-wrap"><span class="badge '+priClass(f.priority)+'">'+esc(f.priority)+'</span></td><td class="no-wrap dimmed mono" style="font-size:11px">'+f.sla_hours+'h</td><td class="truncate primary" style="max-width:100px">'+esc(f.product)+'</td><td class="no-wrap dimmed" style="font-size:11.5px">'+esc(f.scanner)+'</td><td class="no-wrap"><span class="badge '+sevClass(f.severity)+'">'+esc(f.severity)+'</span></td><td style="max-width:300px"><span class="truncate primary" style="display:block">'+esc(f.title)+'</span></td><td class="no-wrap">'+(f.cve?'<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/'+esc(f.cve)+'" target="_blank" onclick="event.stopPropagation()">'+esc(f.cve)+'</a>':'-')+'</td><td class="no-wrap">'+(f.kev?'<span class="badge b-kev">KEV</span>':f.exploit_available?'<span class="badge b-exploit">Exploit</span>':'')+'</td><td class="no-wrap mono" style="font-size:11px"><span class="badge b-epss">'+epssStr+'</span></td><td class="no-wrap mono dimmed" style="font-size:11px">'+esc(f.cwe||'-')+'</td></tr><tr class="detail-row" id="detail-'+f.rank+'"><td colspan="12">'+renderDetail(f)+'</td></tr>';
    }
    function renderDetail(f){
      var sb=f.score_components||{};
      var comps=Object.entries(sb).map(function(kv){return '<span style="margin-right:10px"><span class="dimmed">'+kv[0]+':</span> <b>'+kv[1]+'</b></span>';}).join('');
      var drivers=(f.score_drivers||[]).map(function(d){return '<span style="margin-right:8px;color:var(--yellow)">'+svgIcon('icon-zap',12)+' '+esc(d)+'</span>';}).join('');
      var rems=(f.remediation||[]).map(function(r){return '<li><span class="rem-kind">'+esc(r.kind)+'</span> '+esc(r.text)+'</li>';}).join('');
      var aiRem=f.ai_remediation?'<div class="ai-box"><div class="ai-header">'+svgIcon('icon-bot')+'<span class="ai-label">AI-Generated Remediation</span></div><div class="ai-content">'+esc(f.ai_remediation)+'</div></div>':'';
      return '<div class="detail-panel"><div class="detail-section"><div class="detail-section-title">'+svgIcon('icon-list',12)+' Finding Details</div><div class="detail-row-item"><span class="detail-key">Endpoint</span><span class="detail-val">'+esc(f.endpoint||'-')+(f.parameter?' (param: '+esc(f.parameter)+')':'')+'</span></div><div class="detail-row-item"><span class="detail-key">EPSS score</span><span class="detail-val">'+pct(f.epss_score)+' (pct '+pct(f.epss_percentile)+', trend '+(f.epss_trend>0?'+':'')+f.epss_trend+')</span></div><div class="detail-row-item"><span class="detail-key">KEV status</span><span class="detail-val">'+(f.kev?'In CISA KEV ('+esc(f.kev_date)+')':'Not in KEV')+'</span></div><div class="detail-row-item"><span class="detail-key">Exploit</span><span class="detail-val">'+(f.exploit_available?'Yes - '+esc(f.exploit_source):'Not found')+'</span></div><div class="detail-row-item"><span class="detail-key">Escalation potential</span><span class="detail-val">'+f.escalation_potential+'</span></div><div class="detail-row-item"><span class="detail-key">Owner</span><span class="detail-val">'+esc(f.owner||'-')+' \u00b7 SLA '+f.sla_hours+'h</span></div><div style="margin-top:12px;color:var(--text-secondary);font-size:12px;line-height:1.6">'+esc(f.description)+'</div></div><div class="detail-section"><div class="detail-section-title">'+svgIcon('icon-bar-chart',12)+' Score Breakdown</div><div style="font-size:12px;margin-bottom:10px;line-height:2">'+(comps||'<span class="dimmed">no breakdown</span>')+'</div><div style="margin-bottom:12px">'+drivers+'</div><div class="detail-section-title">'+svgIcon('icon-rocket',12)+' Remediation Steps</div><ul class="rem-list">'+(rems||'<li class="dimmed">No remediation data</li>')+'</ul></div>'+aiRem+'</div>';
    }
    function render(){
      var rows=getFiltered();
      var rb=$('result-badge');if(rb)rb.textContent=rows.length+' of '+F.length+' findings';
      var tb=$('tbl-body');if(tb)tb.innerHTML=rows.map(renderRow).join('');
    }
    document.querySelectorAll('#tbl-head th[data-col]').forEach(function(th){
      th.addEventListener('click',function(){
        if(sortCol===th.dataset.col){sortDir*=-1;}else{sortCol=th.dataset.col;sortDir=-1;}
        document.querySelectorAll('#tbl-head th').forEach(function(t){t.classList.remove('sorted');var a=t.querySelector('.sort-arrow');if(a)a.textContent='\u2195';});
        th.classList.add('sorted');
        var arrow=th.querySelector('.sort-arrow');if(arrow)arrow.textContent=sortDir===-1?'\u2193':'\u2191';
        render();
      });
    });
    var searchTimer;
    var sb=$('tbl-search');if(sb)sb.addEventListener('input',function(e){clearTimeout(searchTimer);searchTimer=setTimeout(function(){search=e.target.value;render();},300);});
    var fp=$('f-priority');if(fp)fp.addEventListener('change',function(e){fPri=e.target.value;render();});
    var fs=$('f-severity');if(fs)fs.addEventListener('change',function(e){fSev=e.target.value;render();});
    var fsc=$('f-scanner');if(fsc)fsc.addEventListener('change',function(e){fScan=e.target.value;render();});
    var fk=$('f-kev');if(fk)fk.addEventListener('change',function(e){fKev=e.target.value;render();});

    // Store render function globally for CSV export
    window._tblRender=render;
    window._tblGetFiltered=getFiltered;
    window._tblData=F;

    render();
  }catch(e){console.error('initTable:',e);}
}

/* ─── CSV Export ─── */
function exportCSV(){
  var rows=window._tblGetFiltered?window._tblGetFiltered():[];
  if(!rows.length){showToast('No findings to export','info');return;}
  var headers=['Rank','Score','Priority','SLA Hours','Product','Scanner','Severity','Title','CVE','CWE','KEV','EPSS Score','Endpoint','Owner'];
  var csvRows=[headers.join(',')];
  rows.forEach(function(f){
    csvRows.push([f.rank,f.score,f.priority,f.sla_hours,'"'+(f.product||'').replace(/"/g,'""')+'"',f.scanner,f.severity,'"'+(f.title||'').replace(/"/g,'""')+'"',f.cve||'',f.cwe||'',f.kev?'YES':'NO',(f.epss_score*100).toFixed(1),'"'+(f.endpoint||'').replace(/"/g,'""')+'"',f.owner||''].join(','));
  });
  var blob=new Blob([csvRows.join('\n')],{type:'text/csv'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='findings_export.csv';a.click();
  showToast('Exported '+rows.length+' findings to CSV','success');
}

function toggleDetail(tr){
  var rank=tr.dataset.rank;var detail=$('detail-'+rank);if(!detail)return;
  var isOpen=detail.classList.contains('open');
  document.querySelectorAll('.detail-row.open').forEach(function(r){r.classList.remove('open');});
  document.querySelectorAll('.data-row.expanded').forEach(function(r){r.classList.remove('expanded');});
  if(!isOpen){detail.classList.add('open');tr.classList.add('expanded');}
}

/* ─── Quarantine ─── */
(function buildQuarantine(){
  try{
    var Q=DASH.quarantine;var qb=$('q-body');if(!qb)return;
    qb.innerHTML=Q.length?Q.map(function(q){return '<tr><td>'+esc(q.product)+'</td><td>'+esc(q.scanner)+'</td><td><span class="badge '+sevClass(q.severity)+'">'+esc(q.severity)+'</span></td><td>'+esc(q.title)+'</td><td>'+(q.cve?'<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/'+esc(q.cve)+'" target="_blank">'+esc(q.cve)+'</a>':'-')+'</td><td class="dimmed" style="font-size:12px">'+esc(q.reason)+'</td></tr>';}).join(''):'<tr><td colspan="6"><div class="empty-state">'+svgIcon('icon-shield-check',32)+'<p class="empty-state-title">No Quarantined Findings</p><p class="empty-state-desc">No findings quarantined this run.</p></div></td></tr>';
  }catch(e){console.error('buildQuarantine:',e);}
})();

/* ─── Products ─── */
(function buildProducts(){
  try{
    var P=DASH.products||{};var keys=Object.keys(P);
    var tp=$('tc-products');if(tp)tp.textContent=keys.length;
    if(!keys.length){var ptw=$('products-table-wrap');if(ptw)ptw.innerHTML='<div class="empty-state">'+svgIcon('icon-package',32)+'<p class="empty-state-title">No Products Configured</p><p class="empty-state-desc">Add one using the form below.</p></div>';return;}
    var rows=keys.map(function(k){
      var p=P[k];var findings=DASH.findings.filter(function(f){return f.product===k;});
      var p1c=findings.filter(function(f){return f.priority==='P1';}).length;
      var p2c=findings.filter(function(f){return f.priority==='P2';}).length;
      var repo=p.github_repo||'<span class="dimmed">not set</span>';
      return '<tr><td><b>'+esc(p.display_name||k)+'</b><br><span class="dimmed" style="font-size:11px">'+esc(k)+'</span></td><td class="mono" style="font-size:12px">'+esc(p.url||'-')+'</td><td style="font-size:12px">'+repo+'</td><td class="dimmed" style="font-size:12px">'+esc(p.owner||'-')+'</td><td class="mono" style="font-size:12px">'+(p.asset_criticality||5)+'/10</td><td class="mono" style="font-size:12px">'+findings.length+' findings</td><td>'+(p1c>0?'<span class="badge b-p1">'+p1c+' P1</span>':'')+(p2c>0?'<span class="badge b-p2">'+p2c+' P2</span>':'')+'</td><td><button class="btn btn-secondary" style="padding:5px 12px;font-size:11px" onclick="scanProduct(\''+esc(k)+'\')">'+svgIcon('icon-search',14)+' Scan</button></td></tr>';
    }).join('');
    var ptw=$('products-table-wrap');if(ptw)ptw.innerHTML='<table class="data-table"><thead><tr><th>Product</th><th>URL</th><th>GitHub Repo</th><th>Owner</th><th>Criticality</th><th>Findings</th><th>P1/P2</th><th>Actions</th></tr></thead><tbody>'+rows+'</tbody></table>';
  }catch(e){console.error('buildProducts:',e);}
})();

function addProduct(){
  var id=$('ap-id').value.trim();var name=$('ap-name').value.trim()||id;var url=$('ap-url').value.trim();
  var repo=$('ap-repo').value.trim();var owner=$('ap-owner').value.trim();
  var crit=parseInt($('ap-crit').value)||5;var sens=parseInt($('ap-sens').value)||5;
  var trivy=$('ap-trivy').value.trim();
  if(!id||!url){var m=$('ap-msg');if(m){m.textContent='Product ID and URL are required';m.style.color='#f87171';}return;}
  var scanners={nuclei:url,zap:url,wapiti:url};if(trivy)scanners.trivy=trivy;
  var product={display_name:name,owner:owner||'unassigned',asset_criticality:crit,business_impact:crit,exposure:8,control_effectiveness:3,data_sensitivity:sens,url:url,github_repo:repo,scanners:scanners};
  apiFetch('/api/products',{method:'POST',body:JSON.stringify({product_id:id,display_name:name,url:url,github_repo:repo,owner:owner||'unassigned',asset_criticality:crit,data_sensitivity:sens})}).then(function(data){
    var m2=$('ap-msg');if(m2){m2.textContent=data.status==='created'?'Product saved to server!':'Product updated';m2.style.color='#4ade80';}
  }).catch(function(e){
    DASH.products=DASH.products||{};DASH.products[id]=product;
    var m3=$('ap-msg');if(m3){m3.textContent='Saved locally (server unavailable)';m3.style.color='#facc15';}
  });
  var tp2=$('tc-products');if(tp2)tp2.textContent=Object.keys(DASH.products||{}).length;
  ['ap-id','ap-name','ap-url','ap-repo','ap-owner','ap-trivy'].forEach(function(fid){var el=$(fid);if(el)el.value='';});
  buildProducts();
}

function scanProduct(id){
  showToast('Starting scan for '+id+'...','info');
  apiFetch('/api/scans/start',{method:'POST',body:JSON.stringify({product:id})}).then(function(data){
    showToast('Scan started for '+id+'. '+((data.jobs||[]).length)+' scanner(s) queued.','success');
  }).catch(function(e){showToast('Scan failed: '+e.message,'error');});
}

/* ─── Control Center ─── */
function loadAppStatus(){
  apiFetch('/api/products').then(function(data){
    var el=$('app-status-list');if(!el)return;
    var products=data.products||{};var statuses=data.app_statuses||{};var keys=Object.keys(products);
    if(!keys.length){el.innerHTML='<div class="empty-state" style="padding:20px">'+svgIcon('icon-activity',24)+'<p class="empty-state-desc">No products configured.</p></div>';return;}
    el.innerHTML=keys.map(function(k){
      var p=products[k];var s=statuses[k]||{};var isUp=s.status==='up';
      var dotColor=isUp?'var(--green)':'var(--red)';
      return '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px"><span style="width:8px;height:8px;border-radius:50%;background:'+dotColor+';flex-shrink:0"></span><span style="flex:1"><b>'+esc(p.display_name||k)+'</b> <span class="dimmed">'+esc(p.url||'')+'</span></span><span class="dimmed">'+(isUp?'UP ('+s.response_time_ms+'ms)':'DOWN')+'</span></div>';
    }).join('');
  }).catch(function(){});
}

var ws=null;
function connectWebSocket(){
  if(typeof WebSocket==='undefined')return;
  var proto=location.protocol==='https:'?'wss:':'ws:';
  try{
    ws=new WebSocket(proto+'//'+location.host+'/ws/live');
    ws.onmessage=function(e){try{var msg=JSON.parse(e.data);if(msg.type==='scan_update')handleScanUpdate(msg.data);}catch(x){}};
    ws.onclose=function(){setTimeout(connectWebSocket,5000);};
    ws.onerror=function(){};
  }catch(x){}
}

function handleScanUpdate(job){
  var el=$('scanner-progress');if(!el)return;
  var existing=el.querySelector('[data-job="'+job.job_id+'"]');
  if(!existing){el.innerHTML='';existing=document.createElement('div');existing.setAttribute('data-job',job.job_id);el.appendChild(existing);}
  var statusColors={pending:'var(--text-muted)',running:'var(--blue)',completed:'var(--green)',failed:'var(--red)'};
  var sc=statusColors[job.status]||'var(--text-muted)';
  var elapsed=job.started_at?(job.finished_at||Date.now()/1000)-job.started_at:0;
  existing.innerHTML='<div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border)"><span style="width:10px;height:10px;border-radius:50%;background:'+sc+';flex-shrink:0"></span><div style="flex:1"><div style="font-size:13px;font-weight:500;color:var(--text-primary)">'+esc(job.product)+' / '+esc(job.scanner)+'</div><div class="dimmed" style="font-size:11px">'+esc(job.target_url)+'</div></div><div style="text-align:right"><span class="badge" style="background:rgba(148,163,184,0.08);color:'+sc+'">'+job.status+'</span><div class="dimmed" style="font-size:10px;margin-top:2px">'+elapsed.toFixed(1)+'s</div></div></div>';
}

function triggerScanAll(){
  showToast('Starting scan for all products...','info');
  apiFetch('/api/products').then(function(data){
    var products=data.products||{};var promises=Object.keys(products).map(function(pid){
      return apiFetch('/api/scans/start',{method:'POST',body:JSON.stringify({product:pid})}).catch(function(){});
    });
    Promise.all(promises).then(function(){
      showToast('Scans started for all products. Watch Scanner Progress below.','success');
      loadScannerJobs();
    });
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
}

function loadScannerJobs(){
  apiFetch('/api/scans/jobs').then(function(data){
    if(data.jobs&&data.jobs.length){
      var el=$('scanner-progress');if(!el)return;
      el.innerHTML=data.jobs.map(function(job){
        var statusColors={pending:'var(--text-muted)',running:'var(--blue)',completed:'var(--green)',failed:'var(--red)'};
        var sc=statusColors[job.status]||'var(--text-muted)';
        var elapsed=job.started_at?(job.finished_at||Date.now()/1000)-job.started_at:0;
        return '<div data-job="'+job.job_id+'" style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border)"><span style="width:10px;height:10px;border-radius:50%;background:'+sc+';flex-shrink:0"></span><div style="flex:1"><div style="font-size:13px;font-weight:500;color:var(--text-primary)">'+esc(job.product)+' / '+esc(job.scanner)+'</div><div class="dimmed" style="font-size:11px">'+esc(job.target_url)+'</div></div><div style="text-align:right"><span class="badge" style="background:rgba(148,163,184,0.08);color:'+sc+'">'+job.status+'</span><div class="dimmed" style="font-size:10px;margin-top:2px">'+elapsed.toFixed(1)+'s</div></div></div>';
      }).join('');
    }
  }).catch(function(){});
}

function runPipeline(){
  showToast('Running 8-stage pipeline...','info');
  apiFetch('/api/pipeline/run',{method:'POST',body:JSON.stringify({skip_enrich:true,skip_ai:true})}).then(function(){
    showToast('Pipeline started in background. Check status periodically.','success');
    pollPipelineStatus();
  }).catch(function(e){showToast('Pipeline failed: '+e.message,'error');});
}

function pollPipelineStatus(){
  var check=function(){
    apiFetch('/api/pipeline/status').then(function(data){
      if(data.running){showToast('Pipeline is running...','info');setTimeout(check,3000);}
      else{showToast('Pipeline complete! Refresh to see updated results.','success');}
    }).catch(function(){});
  };check();
}

function createTickets(){
  showToast('Creating GitHub Issues for findings above threshold...','info');
  apiFetch('/api/tickets/create?threshold=60',{method:'POST'}).then(function(data){
    var results=data.results||{};var total=0;Object.values(results).forEach(function(r){total+=(r.created||0);});
    showToast('Created '+total+' GitHub Issues across '+Object.keys(results).length+' products.','success');
  }).catch(function(e){showToast('Ticket creation failed: '+e.message,'error');});
}

function checkDocker(){
  showToast('Checking Docker...','info');
  apiFetch('/api/scanners/status').then(function(data){
    if(data.docker_available){showToast('Docker is running. Active jobs: '+data.active_jobs,'success');}
    else{showToast('Docker is not available. Install Docker Desktop.','error');}
  }).catch(function(e){showToast('Cannot connect to server: '+e.message,'error');});
}

/* ─── Attack Paths (D3) ─── */
var HIGH_IMPACT=['CWE-89','CWE-79','CWE-78','CWE-22','CWE-434','CWE-918','CWE-502','CWE-611','CWE-287','CWE-306'];
var apZoom,apSvgRoot;

function initD3(){
  if(typeof d3==='undefined'){var ap=$('ap-container');if(ap)ap.innerHTML='<div class="ap-no-data">'+svgIcon('icon-network',32)+'<br>D3.js not loaded. Check internet connection.</div>';return;}
  var AP=DASH.attack_paths;var products=Object.keys(AP);
  if(!products.length){$('ap-container').innerHTML='<div class="empty-state">'+svgIcon('icon-network',32)+'<p class="empty-state-title">No Attack Paths</p><p class="empty-state-desc">No attack paths found in this run.</p></div>';return;}
  var sel=$('ap-product');if(!sel)return;
  sel.innerHTML=products.map(function(p){return '<option value="'+esc(p)+'">'+esc(p)+'</option>';}).join('');
  var tp=$('tc-paths');if(tp)tp.textContent=Object.values(AP).reduce(function(a,v){return a+v.length;},0);
  sel.addEventListener('change',function(){renderD3(sel.value);});
  renderD3(products[0]);
}

function renderD3(product){
  var paths=DASH.attack_paths[product]||[];
  var svgEl=$('ap-svg');var tooltip=$('ap-tooltip');var container=$('ap-container');
  if(!svgEl)return;
  svgEl.innerHTML='';
  if(!paths.length){svgEl.innerHTML='<text x="50%" y="50%" text-anchor="middle" fill="#64748b" dy=".3em">No paths for this product</text>';return;}
  var nodeSet=new Map();
  paths.forEach(function(p){
    if(!nodeSet.has(p.from_cwe))nodeSet.set(p.from_cwe,{id:p.from_cwe,group:HIGH_IMPACT.includes(p.from_cwe)?1:0});
    if(!nodeSet.has(p.to_cwe))nodeSet.set(p.to_cwe,{id:p.to_cwe,group:HIGH_IMPACT.includes(p.to_cwe)?2:0});
  });
  var nodes=[...nodeSet.values()];
  var links=paths.map(function(p){return {source:p.from_cwe,target:p.to_cwe,prob:p.probability,desc:p.description||''};});
  var W=svgEl.parentElement.clientWidth||900,H=540;
  svgEl.setAttribute('viewBox','0 0 '+W+' '+H);
  var svg=d3.select('#ap-svg');var g=svg.append('g');
  apZoom=d3.zoom().scaleExtent([.3,3]).on('zoom',function(e){g.attr('transform',e.transform);});
  svg.call(apZoom);apSvgRoot=svg;
  var defs=svg.append('defs');
  ['low','med','high'].forEach(function(t,i){
    defs.append('marker').attr('id','arr-'+t).attr('viewBox','0 -4 8 8').attr('refX',26).attr('refY',0).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto').append('path').attr('d','M0,-4L8,0L0,4').attr('fill',['rgba(74,222,128,.7)','rgba(250,204,21,.8)','rgba(248,113,113,.8)'][i]);
  });
  var probClass=function(p){return p>.6?'high':p>.3?'med':'low';};
  var probColor=function(p){return p>.6?'rgba(248,113,113,.7)':p>.3?'rgba(250,204,21,.7)':'rgba(74,222,128,.6)';};
  var link=g.append('g').selectAll('line').data(links).join('line').attr('stroke',function(d){return probColor(d.prob);}).attr('stroke-width',function(d){return 1+d.prob*3;}).attr('stroke-opacity',.7).attr('marker-end',function(d){return 'url(#arr-'+probClass(d.prob)+')';});
  var linkLabel=g.append('g').selectAll('text').data(links).join('text').text(function(d){return 'p='+d.prob;}).attr('font-size',9).attr('fill','#64748b').attr('text-anchor','middle');
  var nodeG=g.append('g').selectAll('g').data(nodes).join('g').call(d3.drag().on('start',function(e,d){if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;}).on('drag',function(e,d){d.fx=e.x;d.fy=e.y;}).on('end',function(e,d){if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}));
  var filter=defs.append('filter').attr('id','glow');
  filter.append('feGaussianBlur').attr('stdDeviation','4').attr('result','blur');
  var feMerge=filter.append('feMerge');feMerge.append('feMergeNode').attr('in','blur');feMerge.append('feMergeNode').attr('in','SourceGraphic');
  nodeG.append('circle').attr('r',function(d){return d.group===2?32:d.group===1?28:22;}).attr('fill',function(d){return d.group===2?'rgba(248,113,113,.15)':d.group===1?'rgba(251,146,60,.12)':'rgba(96,165,250,.12)';}).attr('stroke',function(d){return d.group===2?'#f87171':d.group===1?'#fb923c':'#60a5fa';}).attr('stroke-width',2).attr('filter','url(#glow)');
  nodeG.append('text').text(function(d){return d.id.replace('CWE-','');}).attr('text-anchor','middle').attr('dy','-.2em').attr('font-size',10).attr('font-weight',700).attr('fill','#f1f5f9');
  nodeG.append('text').text('CWE').attr('text-anchor','middle').attr('dy','1em').attr('font-size',8).attr('fill','#64748b');
  nodeG.on('mouseover',function(e,d){if(tooltip){tooltip.style.display='block';tooltip.innerHTML='<b>'+d.id+'</b><br>'+(d.group===2?'High-impact exploitation target':d.group===1?'Attack entry point':'Intermediate escalation node');}}).on('mousemove',function(e){if(!container||!tooltip)return;var r=container.getBoundingClientRect();tooltip.style.left=(e.clientX-r.left+12)+'px';tooltip.style.top=(e.clientY-r.top-30)+'px';}).on('mouseout',function(){if(tooltip)tooltip.style.display='none';});
  link.on('mouseover',function(e,d){if(tooltip){tooltip.style.display='block';tooltip.innerHTML='<b>'+d.source.id+' to '+d.target.id+'</b><br>Probability: '+d.prob+'<br>'+esc(d.desc).substring(0,100);}}).on('mousemove',function(e){if(!container||!tooltip)return;var r=container.getBoundingClientRect();tooltip.style.left=(e.clientX-r.left+12)+'px';tooltip.style.top=(e.clientY-r.top-30)+'px';}).on('mouseout',function(){if(tooltip)tooltip.style.display='none';});
  var sim=d3.forceSimulation(nodes).force('link',d3.forceLink(links).id(function(d){return d.id;}).distance(function(d){return 100+d.prob*80;})).force('charge',d3.forceManyBody().strength(-420)).force('center',d3.forceCenter(W/2,H/2)).force('collision',d3.forceCollide(45));
  sim.on('tick',function(){
    link.attr('x1',function(d){return d.source.x;}).attr('y1',function(d){return d.source.y;}).attr('x2',function(d){return d.target.x;}).attr('y2',function(d){return d.target.y;});
    linkLabel.attr('x',function(d){return(d.source.x+d.target.x)/2;}).attr('y',function(d){return(d.source.y+d.target.y)/2-6;});
    nodeG.attr('transform',function(d){return 'translate('+d.x+','+d.y+')';});
  });
}

function apReset(){if(apSvgRoot)apSvgRoot.transition().duration(500).call(apZoom.transform,d3.zoomIdentity);}

/* ─── Lifecycle Tab ─── */
(function initLifecycle(){
  try{
    var LC=DASH.lifecycle||{};
    var tracked=LC.findings||[];
    var statusCounts=LC.status_counts||{};
    var overdueCount=LC.overdue_count||0;
    var statusColors={open:'#fb923c',in_progress:'#60a5fa',fixed:'#4ade80',verified:'#22d3ee',accepted:'#64748b',false_positive:'#f87171',risk_accepted:'#64748b'};
    var openCount=statusCounts.open||0;
    var inProgCount=statusCounts.in_progress||0;
    var fixedCount=(statusCounts.fixed||0)+(statusCounts.verified||0);
    var lckg=$('lc-kpi-grid');
    if(lckg)lckg.innerHTML=[
      {v:tracked.length,l:'Total Tracked',cls:'',icon:'icon-search'},
      {v:openCount,l:'Open',cls:'warn',icon:'icon-unlock'},
      {v:inProgCount,l:'In Progress',cls:'',icon:'icon-clock'},
      {v:fixedCount,l:'Fixed / Verified',cls:'success',icon:'icon-check'},
      {v:overdueCount,l:'SLA Breached',cls:'danger',icon:'icon-alert'},
    ].map(function(c,i){return '<div class="kpi-card '+c.cls+'"><div class="kpi-header"><div class="kpi-icon">'+svgIcon(c.icon)+'</div></div><div class="kpi-value">'+c.v+'</div><div class="kpi-label">'+c.l+'</div></div>';}).join('');
    var tcl=$('tc-lifecycle');if(tcl)tcl.textContent=tracked.length;
    if(tracked.length>0){
      var rows=tracked.slice(0,100).map(function(f){
        var sc2=statusColors[f.status]||'#64748b';
        var isBreach=f.sla_deadline&&new Date(f.sla_deadline)<new Date()&&(f.status==='open'||f.status==='in_progress');
        return '<tr><td>'+esc(f.product)+'</td><td><span class="badge '+sevClass(f.severity)+'">'+esc(f.severity)+'</span></td><td style="max-width:200px" class="truncate primary">'+esc(f.title)+'</td><td class="no-wrap">'+(f.cve?esc(f.cve):'-')+'</td><td class="no-wrap"><span class="badge" style="background:'+sc2+'22;color:'+sc2+';border:1px solid '+sc2+'44">'+f.status.replace('_',' ')+'</span></td><td class="no-wrap '+(isBreach?'':'dimmed')+'" style="font-size:11px;'+(isBreach?'color:var(--red);font-weight:600':'')+'">'+(isBreach?'BREACHED':'OK')+'</td><td class="no-wrap" style="font-size:11px">'+esc(f.owner||'-')+'</td><td class="no-wrap" style="font-size:11px">'+esc(f.sla_hours||0)+'h</td></tr>';
      }).join('');
      var lctw=$('lc-table-wrap');if(lctw)lctw.innerHTML='<table class="data-table"><thead><tr><th>Product</th><th>Severity</th><th>Title</th><th>CVE</th><th>Status</th><th>SLA</th><th>Owner</th><th>SLA Hours</th></tr></thead><tbody>'+rows+'</tbody></table>';
    }else{
      var lctw2=$('lc-table-wrap');if(lctw2)lctw2.innerHTML='<div class="empty-state">'+svgIcon('icon-refresh',32)+'<p class="empty-state-title">No Lifecycle Data</p><p class="empty-state-desc">No findings tracked yet. Run the pipeline to start lifecycle tracking.</p></div>';
    }
    var overdue=LC.overdue_findings||[];
    var lcbl=$('lc-breached-list');
    if(lcbl)lcbl.innerHTML=overdue.length?overdue.slice(0,20).map(function(f){
      return '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px"><span style="color:var(--red);font-weight:700">'+svgIcon('icon-alert',16)+'</span><span style="flex:1"><b style="color:var(--text-primary)">'+esc((f.title||'').substring(0,60))+'</b> <span class="dimmed">'+esc(f.product)+'</span></span><span class="badge b-p1">SLA BREACHED</span></div>';
    }).join(''):'<div class="empty-state" style="padding:20px">'+svgIcon('icon-check',24)+'<p class="empty-state-desc">No SLA breaches detected.</p></div>';
  }catch(e){console.error('initLifecycle:',e);}
})();

/* ─── Dedup Analytics Tab ─── */
(function initDedup(){
  try{
    var S=DASH.summary;
    var DA=DASH.dedup_analytics||{};
    var noiseRm=S.raw_findings>0?((S.raw_findings-S.final_findings)/S.raw_findings*100).toFixed(1):0;
    var dkg=$('dedup-kpi-grid');
    if(dkg)dkg.innerHTML=[
      {v:S.raw_findings,l:'Raw Findings',cls:'',icon:'icon-search'},
      {v:S.unique_findings,l:'After Dedup',cls:'',icon:'icon-shuffle'},
      {v:S.dedup_pct+'%',l:'Dedup Rate',cls:'success',icon:'icon-trend-down'},
      {v:noiseRm+'%',l:'Total Noise Removed',cls:'',icon:'icon-target'},
      {v:(DA.per_scanner_counts?Object.keys(DA.per_scanner_counts).length:0)+' scanners',l:'Scanner Sources',cls:'',icon:'icon-search'},
      {v:(DA.cross_scanner_redundancy||[]).length,l:'Cross-Scanner Overlaps',cls:'warn',icon:'icon-link'},
    ].map(function(c,i){return '<div class="kpi-card '+c.cls+'"><div class="kpi-header"><div class="kpi-icon">'+svgIcon(c.icon)+'</div></div><div class="kpi-value">'+c.v+'</div><div class="kpi-label">'+c.l+'</div></div>';}).join('');
    var scannerCounts=DA.per_scanner_counts||{};
    if(Object.keys(scannerCounts).length===0){
      var F=DASH.findings;var scanMap={};F.forEach(function(f){scanMap[f.scanner]=(scanMap[f.scanner]||0)+1;});
      scannerCounts=scanMap;
    }
    var scanKeys=Object.keys(scannerCounts).sort(function(a,b){return scannerCounts[b]-scannerCounts[a];});
    if(HAS_CHART&&$('c-dedup-scanner')){
      new Chart($('c-dedup-scanner'),{type:'bar',data:{labels:scanKeys,datasets:[{label:'Pre-dedup findings',data:scanKeys.map(function(k){return scannerCounts[k];}),backgroundColor:['rgba(96,165,250,.7)','rgba(34,211,238,.7)','rgba(250,204,21,.7)','rgba(248,113,113,.7)','rgba(129,140,248,.7)'],borderWidth:0,borderRadius:6}]},options:{...cardCfg,scales:{y:{grid:{color:gridColor},ticks:{color:'#94a3b8'}},x:{grid:{display:false},ticks:{color:'#94a3b8'}}},plugins:{legend:{display:false}}}});
    }
    var overlaps=DA.cross_scanner_redundancy||[];
    if(HAS_CHART&&$('c-dedup-overlap')&&overlaps.length>0){
      var topOverlaps=overlaps.slice(0,10);
      new Chart($('c-dedup-overlap'),{type:'bar',data:{labels:topOverlaps.map(function(o){return(o.cve||o.vulnerability||'').substring(0,25);}),datasets:[{label:'Scanners detecting',data:topOverlaps.map(function(o){return(o.scanners_found_it||[]).length;}),backgroundColor:'rgba(251,146,60,.7)',borderWidth:0,borderRadius:6}]},options:{...cardCfg,indexAxis:'y',scales:{x:{grid:{color:gridColor},ticks:{color:'#94a3b8'},title:{display:true,text:'# scanners',color:'#64748b'}},y:{grid:{display:false},ticks:{color:'#94a3b8',font:{size:10}}}},plugins:{legend:{display:false}}}});
    }else if($('c-dedup-overlap')){
      var cel=$('c-dedup-overlap');if(cel&&cel.parentElement)cel.parentElement.innerHTML='<div class="chart-header">'+svgIcon('icon-link')+'<span class="chart-title">Cross-Scanner Redundancy</span></div><div class="empty-state" style="height:200px">'+svgIcon('icon-link',32)+'<p class="empty-state-desc">No cross-scanner overlaps detected in this run.</p></div>';
    }
    var overlapRows=overlaps.map(function(o){
      var scanners=(o.scanners_found_it||[]).map(function(s){return '<span class="badge" style="background:var(--cyan-dim);color:var(--cyan);margin-right:4px">'+esc(s)+'</span>';}).join('');
      return '<tr><td class="no-wrap">'+(o.cve?'<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/'+esc(o.cve)+'" target="_blank">'+esc(o.cve)+'</a>':'<span class="dimmed">-</span>')+'</td><td>'+scanners+'</td><td style="max-width:200px" class="truncate">'+esc(o.vulnerability||'-')+'</td><td class="no-wrap">'+esc(o.product||'-')+'</td><td class="no-wrap dimmed">'+esc(o.canonical_source||'-')+'</td></tr>';
    }).join('');
    var dot=$('dedup-overlap-table');
    if(dot)dot.innerHTML=overlapRows?'<table class="data-table"><thead><tr><th>CVE</th><th>Detecting Scanners</th><th>Vulnerability</th><th>Product</th><th>Canonical</th></tr></thead><tbody>'+overlapRows+'</tbody></table>':'<div class="empty-state" style="padding:20px">'+svgIcon('icon-shuffle',24)+'<p class="empty-state-desc">No cross-scanner overlaps detected. Each vulnerability was found by only one scanner.</p></div>';
  }catch(e){console.error('initDedup:',e);}
})();

/* ─── Integrations Tab ─── */
async function testJira(){
  var el=$('jira-status');if(!el)return;
  el.innerHTML='<span class="dimmed">Testing connection...</span>';
  try{var data=await apiFetch('/api/jira/test');el.innerHTML=data.connected?'<span style="color:var(--green)">Connected to '+esc(data.url||'Jira')+'</span>':'<span style="color:var(--red)">'+esc(data.error||'Not configured')+'</span>';}catch(e){el.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>';}
}
async function createJiraIssues(){
  var el=$('jira-status');if(!el)return;
  el.innerHTML='<span class="dimmed">Creating issues...</span>';
  try{var data=await apiFetch('/api/jira/create?threshold=60',{method:'POST'});el.innerHTML='<span style="color:var(--green)">Created '+(data.created||0)+' issues</span>';}catch(e){el.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>';}
}
async function testDefectDojo(){
  var el=$('dd-status');if(!el)return;
  el.innerHTML='<span class="dimmed">Testing connection...</span>';
  try{var data=await apiFetch('/api/defectdojo/test');el.innerHTML=data.connected?'<span style="color:var(--green)">Connected to '+esc(data.url||'DefectDojo')+'</span>':'<span style="color:var(--red)">'+esc(data.error||'Not configured')+'</span>';}catch(e){el.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>';}
}
async function importDefectDojo(){
  var el=$('dd-status');if(!el)return;
  el.innerHTML='<span class="dimmed">Importing findings...</span>';
  try{var data=await apiFetch('/api/defectdojo/import?product_name=all',{method:'POST'});el.innerHTML='<span style="color:var(--green)">'+esc(data.message||'Imported')+'</span>';}catch(e){el.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>';}
}
async function saveApiKeys(){
  var el=$('apikey-status');if(!el)return;
  el.innerHTML='<span class="dimmed">Saving API keys...</span>';
  var keys={};
  var groq=$('ak-groq');if(groq&&groq.value.trim())keys.groq_api_key=groq.value.trim();
  var nvd=$('ak-nvd');if(nvd&&nvd.value.trim())keys.nvd_api_key=nvd.value.trim();
  var gh=$('ak-github');if(gh&&gh.value.trim())keys.github_token=gh.value.trim();
  var jurl=$('ak-jira-url');if(jurl&&jurl.value.trim())keys.jira_url=jurl.value.trim();
  var juser=$('ak-jira-user');if(juser&&juser.value.trim())keys.jira_user=juser.value.trim();
  var jtoken=$('ak-jira-token');if(jtoken&&jtoken.value.trim())keys.jira_token=jtoken.value.trim();
  var jproj=$('ak-jira-project');if(jproj&&jproj.value.trim())keys.jira_project=jproj.value.trim();
  var ddurl=$('ak-dd-url');if(ddurl&&ddurl.value.trim())keys.defectdojo_url=ddurl.value.trim();
  var ddkey=$('ak-dd-key');if(ddkey&&ddkey.value.trim())keys.defectdojo_api_key=ddkey.value.trim();
  try{await apiFetch('/api/config/keys',{method:'POST',body:JSON.stringify(keys)});el.innerHTML='<span style="color:var(--green)">API keys saved! Restart server to apply.</span>';}catch(e){el.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>';}
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
    # Prevent XSS: escape sequences that could break out of the <script> block
    json_str = json_str.replace("</script>", r"<\/script>")
    json_str = json_str.replace("</SCRIPT>", r"<\/SCRIPT>")
    json_str = json_str.replace("<!--", r"<\!--")
    json_str = json_str.replace("-->", r"--\>")
    html = _HTML_TEMPLATE.replace("__DASH_JSON__", json_str)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
