"""Output writers — ranking, pandas-powered ranked dataset, noise-reduction
metrics, ticket-ready markdown, analytics summary, and executive summary.

Merges the old rank.py and output.py into a single Stage 8 module.

Uses pandas when available (satisfies the Python/pandas tech-stack requirement);
falls back to stdlib csv so the pipeline still runs in minimal environments.
"""
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
    import csv  # stdlib fallback

CSV_COLUMNS = [
    "rank", "score", "priority", "sla_hours", "owner", "product", "scanner",
    "title", "severity", "cve", "cwe", "endpoint", "parameter",
    "epss_score", "epss_percentile", "epss_trend", "kev", "kev_date",
    "exploit_available", "exploit_source", "escalation_potential",
    "ai_fp_probability", "ai_fp_reason",
    "package", "fixed_version", "description", "remediation_summary",
]


# ─────────────────────────── ranking ─────────────────────────────────────────

def rank_findings(findings: List[Finding], config) -> List[Finding]:
    """Sort active findings into a ticket-ready action list.

    Order: score desc, then KEV, then EPSS percentile (explainable tie-breaks).
    Each ranked finding gets priority (P1..P4), SLA hours, and an owner from
    the product config.
    """
    active = [f for f in findings if f.status == "active"]
    active.sort(key=lambda f: (
        f.score if f.score is not None else 0,
        1 if f.kev else 0,
        f.epss_percentile if f.epss_percentile is not None else 0,
    ), reverse=True)

    for i, f in enumerate(active, start=1):
        band = config.sla_for(f.score or 0)
        f.priority = band["priority"]
        f.sla_hours = band["sla_hours"]
        f.owner = config.product(f.product).get("owner", "appsec-team")
        f.score_breakdown["rank"] = i
    return active


def top_action_list(ranked: List[Finding], top_n: int = 25) -> List[Finding]:
    return ranked[:top_n]


# ─────────────────────────── data serialisation ──────────────────────────────

def _to_records(ranked: List[Finding]) -> List[Dict]:
    records = []
    for f in ranked:
        row = f.to_row()
        row["rank"]             = f.score_breakdown.get("rank", "")
        row["ai_fp_probability"] = f.score_breakdown.get("ai_fp_probability", "")
        row["ai_fp_reason"]      = f.score_breakdown.get("ai_fp_reason", "")
        records.append({c: row.get(c, "") for c in CSV_COLUMNS})
    return records


# ─────────────────────────── ranked CSV ──────────────────────────────────────

def write_ranked_csv(path: str, ranked: List[Finding]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    records = _to_records(ranked)
    if HAS_PANDAS:
        df = pd.DataFrame(records, columns=CSV_COLUMNS)
        df.to_csv(path, index=False, encoding="utf-8")
    else:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS,
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)


# ─────────────────────────── analytics CSV (pandas) ──────────────────────────

def write_analytics_csv(path: str, ranked: List[Finding]) -> None:
    """Pandas-powered analytics: severity dist, scanner coverage, score stats,
    top CVEs by EPSS, KEV count.  Skipped gracefully without pandas."""
    if not HAS_PANDAS:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    records = _to_records(ranked)
    if not records:
        return
    df = pd.DataFrame(records)
    df["score"]           = pd.to_numeric(df["score"],           errors="coerce")
    df["epss_percentile"] = pd.to_numeric(df["epss_percentile"], errors="coerce")
    df["epss_score"]      = pd.to_numeric(df["epss_score"],      errors="coerce")
    df["kev"]             = df["kev"].astype(str).str.lower().isin(
        ("true", "yes", "1"))

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("=== Severity distribution ===\n")
        fh.write(df["severity"].value_counts().to_csv())

        fh.write("\n=== Priority distribution ===\n")
        fh.write(df["priority"].value_counts().to_csv())

        fh.write("\n=== Score percentiles (all active findings) ===\n")
        fh.write(df["score"].describe(
            percentiles=[.25, .5, .75, .90, .95]).to_csv())

        fh.write("\n=== Scanner coverage ===\n")
        fh.write(df["scanner"].value_counts().to_csv())

        fh.write("\n=== KEV findings ===\n")
        fh.write(f"Total in CISA KEV: {int(df['kev'].sum())}\n")

        fh.write("\n=== Top 10 CVEs by EPSS score ===\n")
        top_epss = (
            df[df["cve"].astype(str).str.startswith("CVE-")]
            .nlargest(10, "epss_score")[
                ["cve", "epss_score", "epss_percentile", "score", "priority"]]
        )
        fh.write(top_epss.to_csv(index=False))

        fh.write("\n=== Score distribution by severity ===\n")
        fh.write(df.groupby("severity")["score"]
                   .describe()[["mean", "min", "50%", "max"]]
                   .to_csv())


# ─────────────────────────── ranked JSON ─────────────────────────────────────

def write_ranked_json(path: str, ranked: List[Finding]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in ranked], fh, indent=2)


def write_metrics_json(path: str, metrics: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)


# ─────────────────────────── top actions markdown ────────────────────────────

def write_top_actions_md(path: str, ranked: List[Finding],
                         summary: RunSummary) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    lines = [
        "# Top Action List — Risk Prioritized Findings",
        "",
        f"Run: {summary.run_date}  ·  Products: {', '.join(summary.products)}",
        "",
        (f"Raw findings: **{summary.raw_findings}** → "
         f"unique: **{summary.unique_findings}** → "
         f"after filtering: **{summary.final_findings}** "
         f"(dedup **{summary.dedup_pct}**)"),
        "",
        "| Rank | Score | Pri | SLA | Owner | Product | "
        "Title | CVE | CWE | Endpoint |",
        "|-----:|------:|-----|----:|-------|---------|"
        "-------|-----|-----|----------|",
    ]
    for f in ranked:
        lines.append(
            f"| {f.score_breakdown.get('rank', '')} "
            f"| {f.score} | {f.priority} | {f.sla_hours}h "
            f"| {f.owner} | {f.product} | {f.title[:60]} "
            f"| {f.cve or ''} | {f.cwe or ''} | {f.endpoint or ''} |"
        )
    lines += ["", "## Score breakdown (top 10)", ""]
    for f in ranked[:10]:
        sb = f.score_breakdown.get("components", {})
        ai_rem = f.score_breakdown.get("ai_remediation", "")
        ai_fp  = f.score_breakdown.get("ai_fp_probability", "")
        lines.append(
            f"**#{f.score_breakdown.get('rank')} · "
            f"{f.score} — {f.title[:70]}**"
        )
        lines.append(
            f"- {', '.join(f'{k}={v}' for k, v in sb.items())}")
        lines.append(
            f"- Drivers: "
            f"{', '.join(f.score_breakdown.get('drivers', [])) or 'none'}")
        if ai_fp != "":
            lines.append(f"- AI FP probability: {ai_fp} "
                         f"({f.score_breakdown.get('ai_fp_reason', '')})")
        if ai_rem:
            lines.append(f"- AI remediation: {ai_rem}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ─────────────────────────── tickets markdown ─────────────────────────────────

def write_tickets_md(path: str, ranked: List[Finding],
                     threshold: float) -> None:
    """Ticket-ready markdown for findings above the auto-ticket threshold."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tickets = [f for f in ranked if (f.score or 0) >= threshold]
    lines = [
        "# Tickets Ready (auto-file candidates)",
        "",
        f"{len(tickets)} findings meet the auto-ticket threshold "
        f"(score ≥ {threshold}).",
        "",
    ]
    for i, f in enumerate(tickets, start=1):
        # Multi-scanner provenance
        scanners = f.raw.get("scanners") if isinstance(f.raw, dict) else None
        scanner_line = (
            f"{', '.join(sorted(scanners))} "
            f"({len(scanners)} scanners confirmed)"
            if scanners and len(scanners) > 1 else f.scanner
        )
        ai_rem = f.score_breakdown.get("ai_remediation", "")
        lines += [
            f"## Ticket {i}: [{f.priority}] {f.title}",
            "",
            f"- **Score:** {f.score} / 100  ·  "
            f"**Owner:** {f.owner}  ·  **SLA:** {f.sla_hours}h",
            f"- **Product:** {f.product}  ·  "
            f"**Confirmed by:** {scanner_line}",
            f"- **CVE:** {f.cve or '-'}  ·  **CWE:** {f.cwe or '-'}",
            f"- **Endpoint:** {f.endpoint or '-'}"
            f"{'  (param: ' + f.parameter + ')' if f.parameter else ''}",
            f"- **Severity:** {f.severity}  ·  "
            f"**EPSS:** {f.epss_score or '-'} "
            f"(pct {f.epss_percentile or '-'})  ·  "
            f"**KEV:** {'yes ' + str(f.kev_date) if f.kev else 'no'}",
            f"- **Escalation potential:** {f.escalation_potential or 0.0}",
            f"- **AI FP probability:** "
            f"{f.score_breakdown.get('ai_fp_probability', 'n/a')} — "
            f"{f.score_breakdown.get('ai_fp_reason', '')}",
            "",
            "**Score breakdown:** " + ", ".join(
                f"{k}={v}" for k, v in
                f.score_breakdown.get("components", {}).items()),
            "",
        ]
        if ai_rem:
            lines += ["**AI-generated remediation:**", "", ai_rem, ""]
        lines.append("**Remediation steps:**")
        for s in f.remediation_suggestions:
            lines.append(f"- *{s['kind']}* [{s.get('source','')}]: {s['text']}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
