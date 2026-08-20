"""Unified 8-stage pipeline runner.

Usage:
    python -m pipeline.run --reports scan_reports/ --config config.json --out outputs/
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Load .env file if present (harmless if missing)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from .config import Config
from .models import Finding, RunSummary

# Import all 8 stages
from . import (
    normalize,
    dedup,
    filter as filt,
    enrich,
    attackpath,
    score,
    remediation,
    output,
    history,
    dashboard,
)


def run_pipeline(
    reports_dir: str,
    config: Config,
    out_dir: str,
    products: Optional[List[str]] = None,
    skip_enrich: bool = False,
    skip_ai: bool = True,
    use_searchsploit: Optional[bool] = None,
    fetcher: Optional[enrich.Fetcher] = None,
    ollama_model: Optional[str] = None,
    groq_api_key: Optional[str] = None,
    groq_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute all 8 stages of the risk intelligence pipeline."""

    os.makedirs(out_dir, exist_ok=True)
    run_date = dt.datetime.now().isoformat(timespec="seconds")
    products = products or config.product_names()

    # ── Stage 1: Ingest & Normalize ─────────────────────────────────────
    print("=" * 60)
    print("STAGE 1/8: INGEST & NORMALIZE")
    print("=" * 60)
    findings = normalize.parse_reports_dir(reports_dir, products)
    scanners_found = sorted({f.scanner for f in findings})
    print(f"  [OK] Parsed {len(findings)} raw findings from {len(scanners_found)} scanners")
    print(f"  Scanners: {', '.join(scanners_found)}")

    # ── Stage 2: Deduplication ──────────────────────────────────────────
    print("\n" + "=" * 60)
    print("STAGE 2/8: DEDUPLICATION")
    print("=" * 60)
    dedup_result = dedup.deduplicate(findings, fuzzy=config.dedup_cfg.get("fuzzy_title", False))
    findings = dedup_result["findings"]
    metrics = dedup_result["metrics"]
    print(f"  Raw: {metrics['raw']} → Unique: {metrics['unique']} (dedup: {metrics['dedup_pct']}%)")

    # ── Stage 3: Filtering (Auditable) ────────────────────────────────────
    print("\n" + "=" * 60)
    print("STAGE 3/8: FILTERING (Auditable Quarantine)")
    print("=" * 60)
    uniques = [f for f in findings if not f.is_duplicate]
    filter_result = filt.filter_findings(uniques, config.filter_cfg, config.products)
    findings = filter_result["findings"]
    filter_metrics = filter_result["metrics"]
    print(f"  Active: {filter_metrics['active']} | Quarantined: {filter_metrics['quarantined']}")

    # ── Stage 4: Threat Enrichment ────────────────────────────────────────
    print("\n" + "=" * 60)
    print("STAGE 4/9: THREAT ENRICHMENT (KEV / EPSS / NVD / Exploit-DB)")
    print("=" * 60)
    enricher = enrich.Enricher(config.enrich_cfg, fetcher=fetcher)
    if not skip_enrich:
        enricher.enrich(findings, use_searchsploit=use_searchsploit)
        print(f"  [OK] Enriched: {enricher.counts_dict()}")
    else:
        print("  [SKIP] Skipped (offline mode)")

    # ── Stage 5: Attack Path Mapping ─────────────────────────────────────
    print("\n" + "=" * 60)
    print("STAGE 5/9: ATTACK PATH MAPPING")
    print("=" * 60)
    all_paths: Dict[str, List[Any]] = {}
    for product in products:
        if not any(f.product == product for f in findings):
            continue
        paths = attackpath.build_attack_paths(findings, product, config.product(product))
        all_paths[product] = [p.to_dict() for p in paths]
        attackpath.attach_escalation_potential(findings, paths)
    total_paths = sum(len(v) for v in all_paths.values())
    print(f"  [PATHS] {total_paths} attack paths across {len(all_paths)} products")

    # ── Stage 6: Risk Scoring ─────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("STAGE 6/9: RISK SCORING (8-Factor, Explainable)")
    print("=" * 60)
    active = [f for f in findings if f.status == "active"]
    for f in active:
        score.compute_score(f, config.product(f.product), config.weights)
    scores = [f.score or 0 for f in active]
    if scores:
        print(f"  [SCORE] Scored {len(active)} findings | Avg: {sum(scores)/len(scores):.1f} | Max: {max(scores):.1f}")
    else:
        print(f"  [SCORE] Scored {len(active)} findings")

    # ── Stage 7: AI Enrichment (FP classification + penalties + remediation)
    # Runs AFTER scoring so FP penalties actually modify scores.
    print("\n" + "=" * 60)
    print("STAGE 7/9: AI ENRICHMENT (FP classification + smart remediation)")
    print("=" * 60)
    from . import ai_enrich as ai_mod
    ai_summary_stats = {
        "raw_findings": metrics["raw"],
        "unique_findings": metrics["unique"],
        "final_findings": filter_metrics["active"],
        "p1": sum(1 for f in active if f.score is not None and f.score >= 90),
        "p2": sum(1 for f in active if f.score is not None and 70 <= f.score < 90),
        "p3": sum(1 for f in active if f.score is not None and 40 <= f.score < 70),
        "p4": sum(1 for f in active if f.score is not None and f.score < 40),
    }
    ai_result = ai_mod.ai_enrich(
        findings,
        summary_stats=ai_summary_stats,
        skip_remediation=skip_enrich,
        ollama_model="" if skip_ai else ollama_model,
        groq_api_key="" if skip_ai else groq_api_key,
        groq_model=groq_model,
    ) if not skip_ai else {"used": False, "counts": {}, "executive_brief": ""}

    # ── Stage 8: Remediation (static CWE guidance for findings without AI)
    print("\n" + "=" * 60)
    print("STAGE 8/9: REMEDIATION (First-Aid + Full Fix)")
    print("=" * 60)
    for f in active:
        if not f.remediation_suggestions:
            f.remediation_suggestions = remediation.suggest_remediation(f)
    print(f"  [REMEDIATE] Generated remediation for {len(active)} findings")

    # ── Stage 9: Ranking & Output ─────────────────────────────────────────
    print("\n" + "=" * 60)
    print("STAGE 9/9: RANKING & OUTPUT")
    print("=" * 60)
    ranked = output.rank_findings(findings, config)

    # Generate summary
    summary = RunSummary(
        run_date=run_date,
        products=[p for p in products if any(f.product == p for f in findings)],
        raw_findings=metrics["raw"],
        unique_findings=metrics["unique"],
        quarantined=filter_metrics["quarantined"],
        final_findings=filter_metrics["active"],
        dedup_pct=metrics["dedup_pct"],
        avg_score=round(sum(scores) / len(scores), 1) if scores else 0.0,
        top_score=max(scores) if scores else 0.0,
        p1=sum(1 for f in active if f.priority == "P1"),
        p2=sum(1 for f in active if f.priority == "P2"),
        p3=sum(1 for f in active if f.priority == "P3"),
        p4=sum(1 for f in active if f.priority == "P4"),
        enrich_counts={} if skip_enrich else enricher.counts_dict(),
        quarantine_by_rule=filter_metrics.get("quarantine_by_rule", {}),
        attack_paths=total_paths,
    )

    # Write all outputs
    output.write_ranked_csv(os.path.join(out_dir, "ranked_findings.csv"), ranked)
    output.write_ranked_json(os.path.join(out_dir, "ranked_findings.json"), ranked)
    output.write_analytics_csv(os.path.join(out_dir, "analytics.csv"), ranked)
    output.write_top_actions_md(os.path.join(out_dir, "top_actions.md"), ranked, summary)
    output.write_tickets_md(os.path.join(out_dir, "tickets_ready.md"), ranked,
                            config.reporting.get("ticket_threshold", 60))

    # Noise reduction metrics
    noise = {
        "run_date": run_date,
        "raw_findings": summary.raw_findings,
        "unique_findings": summary.unique_findings,
        "quarantined": summary.quarantined,
        "final_findings": summary.final_findings,
        "dedup_pct": summary.dedup_pct,
        "noise_removed_pct": round(
            (summary.raw_findings - summary.final_findings)
            / max(summary.raw_findings, 1) * 100, 2),
        "dedup_by_pass": metrics["by_pass"],
        "quarantine_by_rule": summary.quarantine_by_rule,
        "enrich_counts": summary.enrich_counts,
        "attack_paths": total_paths,
        "avg_score": summary.avg_score,
        "top_score": summary.top_score,
        "p1": summary.p1,
        "p2": summary.p2,
        "p3": summary.p3,
        "p4": summary.p4,
        "ai_used": ai_result["used"],
        "ai_fp_classified": ai_result["counts"].get("fp_classified", 0),
        "ai_remediation": ai_result["counts"].get("remediation", 0),
    }
    output.write_metrics_json(os.path.join(out_dir, "noise_reduction.json"), noise)

    # History tracking
    hist = history.History(os.path.join(out_dir, "history.db"))
    for product in summary.products:
        pf = [f for f in active if f.product == product]
        pscores = [f.score or 0 for f in pf]
        hist.add_run(run_date[:10], product, {
            "raw": summary.raw_findings,
            "unique": summary.unique_findings,
            "quarantined": summary.quarantined,
            "final": len(pf),
            "dedup_pct": summary.dedup_pct,
            "avg_score": round(sum(pscores) / len(pscores), 1) if pscores else 0.0,
            "top_score": max(pscores) if pscores else 0.0,
            "p1": sum(1 for f in pf if f.priority == "P1"),
            "p2": sum(1 for f in pf if f.priority == "P2"),
            "p3": sum(1 for f in pf if f.priority == "P3"),
            "p4": sum(1 for f in pf if f.priority == "P4"),
            "enrich_counts": summary.enrich_counts,
        })
    history_map = hist.all_history()
    hist.close()

    # Dashboard
    quarantine_list = [f for f in findings if f.status == "quarantined"]
    dashboard.build_dashboard(
        os.path.join(out_dir, "risk_dashboard.html"),
        findings, ranked, summary, all_paths, history_map, quarantine_list,
        executive_brief=ai_result.get("executive_brief", ""),
        products_config=config.products,
    )

    print(f"\n{'=' * 60}")
    print("[DONE] PIPELINE COMPLETE")
    print(f"{'=' * 60}")
    print(f"  Outputs in: {out_dir}")
    print(f"  - ranked_findings.csv/json")
    print(f"  - analytics.csv")
    print(f"  - top_actions.md")
    print(f"  - tickets_ready.md")
    print(f"  - noise_reduction.json")
    print(f"  - risk_dashboard.html")
    print(f"  - history.db")

    return {
        "findings": findings,
        "ranked": ranked,
        "summary": summary,
        "attack_paths": all_paths,
        "metrics": noise,
        "ai_result": ai_result,
    }


def main():
    parser = argparse.ArgumentParser(description="DevSecOps Risk Intelligence Pipeline")
    parser.add_argument("--reports", required=True, help="Directory with scanner reports")
    parser.add_argument("--config", default="config.json", help="Config file path")
    parser.add_argument("--out", default="outputs", help="Output directory")
    parser.add_argument("--products", default=None, help="Comma-separated product filter")
    parser.add_argument("--skip-enrich", action="store_true", help="Skip threat intel lookups")
    parser.add_argument("--skip-ai", action="store_true", help="Skip AI enrichment")
    parser.add_argument("--searchsploit", action="store_true", help="Use Exploit-DB CSV")
    parser.add_argument(
        "--ollama-model", default=None,
        help="Ollama model name (e.g. qwen2:1.5b). Use '' to disable Ollama."
    )
    parser.add_argument(
        "--groq-api-key", default=None,
        help="Groq API key (free at console.groq.com). Use '' to disable Groq."
    )
    parser.add_argument(
        "--groq-model", default=None,
        help="Groq model name (default: llama3-70b-8192)"
    )
    args = parser.parse_args()

    config = Config.load(args.config)
    products = args.products.split(",") if args.products else None

    result = run_pipeline(
        args.reports,
        config,
        args.out,
        products=products,
        skip_enrich=args.skip_enrich,
        skip_ai=args.skip_ai,
        use_searchsploit=True if args.searchsploit else None,
        ollama_model=args.ollama_model,
        groq_api_key=args.groq_api_key or os.environ.get("GROQ_API_KEY"),
        groq_model=args.groq_model,
    )

    # Exit with error if P1 findings exist (CI/CD gate)
    if result["summary"].p1 > 0:
        print(f"\n[WARN] {result['summary'].p1} P1 finding(s) detected!")
        sys.exit(1)


if __name__ == "__main__":
    main()
