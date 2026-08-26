"""Output writers — ranking, CSV/JSON/Markdown export, analytics."""

from __future__ import annotations
import json
import os
from typing import Any, Dict, List
from .models import Finding, RunSummary

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    import csv

CSV_COLUMNS = [
    "rank", "score", "priority", "sla_hours", "owner", "product", "scanner",
    "title", "severity", "cve", "cwe", "endpoint", "parameter",
    "epss_score", "epss_percentile", "epss_trend", "kev", "kev_date",
    "exploit_available", "exploit_source", "escalation_potential",
    "ai_fp_probability", "ai_fp_reason", "package", "fixed_version",
    "description", "remediation_summary",
]


def rank_findings(findings: List[Finding], config) -> List[Finding]:
    """Sort active findings by score desc, then KEV, then EPSS percentile."""
    active = [f for f in findings if f.status == "active"]
    active.sort(key=lambda f: (f.score if f.score is not None else 0,
        1 if f.kev else 0, f.epss_percentile if f.epss_percentile is not None else 0), reverse=True)
    for i, f in enumerate(active, start=1):
        band = config.sla_for(f.score or 0, f.severity)
        f.priority = band["priority"]
        f.sla_hours = band["sla_hours"]
        f.owner = config.product(f.product).get("owner", "appsec-team")
        f.score_breakdown["rank"] = i
    return active


def top_action_list(ranked: List[Finding], top_n: int = 25) -> List[Finding]:
    return ranked[:top_n]


def _to_records(ranked: List[Finding]) -> List[Dict]:
    records = []
    for f in ranked:
        row = f.to_row()
        row["rank"] = f.score_breakdown.get("rank", "")
        row["ai_fp_probability"] = f.score_breakdown.get("ai_fp_probability", "")
        row["ai_fp_reason"] = f.score_breakdown.get("ai_fp_reason", "")
        records.append({c: row.get(c, "") for c in CSV_COLUMNS})
    return records


def write_ranked_csv(path: str, ranked: List[Finding]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    records = _to_records(ranked)
    if HAS_PANDAS:
        pd.DataFrame(records, columns=CSV_COLUMNS).to_csv(path, index=False, encoding="utf-8")
    else:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)


def write_analytics_csv(path: str, ranked: List[Finding]) -> None:
    if not HAS_PANDAS:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    records = _to_records(ranked)
    if not records:
        return
    df = pd.DataFrame(records)
    df["score"] = pd.to_numeric(df["score"], errors="coerce")
    df["epss_percentile"] = pd.to_numeric(df["epss_percentile"], errors="coerce")
    df["epss_score"] = pd.to_numeric(df["epss_score"], errors="coerce")
    df["kev"] = df["kev"].astype(str).str.lower().isin(("true", "yes", "1"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("=== Severity distribution ===\n" + df["severity"].value_counts().to_csv())
        fh.write("\n=== Priority distribution ===\n" + df["priority"].value_counts().to_csv())
        fh.write("\n=== Score percentiles ===\n" + df["score"].describe(percentiles=[0.25, 0.5, 0.75, 0.90, 0.95]).to_csv())
        fh.write("\n=== Scanner coverage ===\n" + df["scanner"].value_counts().to_csv())
        fh.write(f"\n=== KEV findings ===\nTotal in CISA KEV: {int(df['kev'].sum())}\n")
        top_epss = df[df["cve"].astype(str).str.startswith("CVE-")].nlargest(10, "epss_score")[["cve", "epss_score", "epss_percentile", "score", "priority"]]
        fh.write("\n=== Top 10 CVEs by EPSS ===\n" + top_epss.to_csv(index=False))


def write_ranked_json(path: str, ranked: List[Finding]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in ranked], fh, indent=2)


def write_metrics_json(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def write_top_actions_md(path: str, ranked: List[Finding], summary: RunSummary) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    lines = [
        "# Top Action List", "",
        f"Run: {summary.run_date}  ·  Products: {', '.join(summary.products)}", "",
        f"Raw: **{summary.raw_findings}** → unique: **{summary.unique_findings}** → active: **{summary.final_findings}** (dedup **{summary.dedup_pct}**)", "",
        "| Rank | Score | Pri | SLA | Owner | Product | Title | CVE | CWE | Endpoint |",
        "|-----:|------:|-----|----:|-------|---------|-------|-----|-----|----------|",
    ]
    for f in ranked:
        lines.append(f"| {f.score_breakdown.get('rank', '')} | {f.score} | {f.priority} | {f.sla_hours}h | {f.owner} | {f.product} | {f.title[:60]} | {f.cve or ''} | {f.cwe or ''} | {f.endpoint or ''} |")
    lines += ["", "## Score breakdown (top 10)", ""]
    for f in ranked[:10]:
        sb = f.score_breakdown.get("components", {})
        lines.append(f"**#{f.score_breakdown.get('rank')} · {f.score} — {f.title[:70]}**")
        lines.append(f"- {', '.join(f'{k}={v}' for k, v in sb.items())}")
        lines.append(f"- Drivers: {', '.join(f.score_breakdown.get('drivers', [])) or 'none'}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def write_tickets_md(path: str, ranked: List[Finding], threshold: float) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tickets = [f for f in ranked if (f.score or 0) >= threshold]
    lines = ["# Tickets Ready", "", f"{len(tickets)} findings above threshold (score ≥ {threshold}).", ""]
    for i, f in enumerate(tickets, start=1):
        scanners = f.raw.get("scanners") if isinstance(f.raw, dict) else None
        scanner_line = f"{', '.join(sorted(scanners))} ({len(scanners)} scanners)" if scanners and len(scanners) > 1 else f.scanner
        ai_rem = f.score_breakdown.get("ai_remediation", "")
        lines += [
            f"## Ticket {i}: [{f.priority}] {f.title}", "",
            f"- **Score:** {f.score} / 100  ·  **Owner:** {f.owner}  ·  **SLA:** {f.sla_hours}h",
            f"- **Product:** {f.product}  ·  **Confirmed by:** {scanner_line}",
            f"- **CVE:** {f.cve or '-'}  ·  **CWE:** {f.cwe or '-'}",
            f"- **Endpoint:** {f.endpoint or '-'}{'  (param: ' + f.parameter + ')' if f.parameter else ''}",
            f"- **Severity:** {f.severity}  ·  **EPSS:** {f.epss_score or '-'} (pct {f.epss_percentile or '-'})  ·  **KEV:** {'yes ' + str(f.kev_date) if f.kev else 'no'}",
            f"- **Escalation potential:** {f.escalation_potential or 0.0}",
            f"- **AI FP probability:** {f.score_breakdown.get('ai_fp_probability', 'n/a')} — {f.score_breakdown.get('ai_fp_reason', '')}",
            "", "**Score breakdown:** " + ", ".join(f"{k}={v}" for k, v in f.score_breakdown.get("components", {}).items()), "",
        ]
        if ai_rem:
            lines += ["**AI-generated remediation:**", "", ai_rem, ""]
        lines.append("**Remediation steps:**")
        for s in f.remediation_suggestions:
            lines.append(f"- *{s['kind']}* [{s.get('source', '')}]: {s['text']}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
