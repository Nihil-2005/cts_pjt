"""Unified 9-stage pipeline runner.

Usage: python -m pipeline.run --reports scan_reports/ --config config.json --out outputs/
"""

from __future__ import annotations
import argparse
import datetime as dt
import json
import os
import sys
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from .config import Config
from .models import RunSummary, Finding
from . import normalize, dedup, filter as filt, enrich, attackpath, score, remediation, output, history, dashboard
import threading


# ── Background GitHub push (runs after pipeline, non-blocking) ─────────────
_GH_PUSH_LOG = "outputs/github_push.log"


def _push_github_worker(findings: list, threshold: float, lifecycle_path: str) -> None:
    """Background worker: push findings to GitHub Issues with rate-limit handling."""
    import time as _time
    from .github_tickets import GitHubTickets, GitHubError
    log_path = os.path.join(os.path.dirname(lifecycle_path) or "outputs", "github_push.log")

    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPO") or os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repo:
        with open(log_path, "w") as lf:
            lf.write("[SKIP] GITHUB_TOKEN or GITHUB_REPO not set\n")
        return

    active = [f for f in findings if f.status == "active" and (f.score or 0) >= threshold]
    if not active:
        with open(log_path, "w") as lf:
            lf.write("[SKIP] No findings above threshold\n")
        return

    gh = GitHubTickets(repo, token, dry_run=False)
    existing_titles = gh._open_issue_titles()

    new_findings = []
    for f in active:
        title = f"[{f.priority}] {f.title[:100]} ({f.product})"
        if title not in existing_titles:
            new_findings.append(f)

    lifecycle = None
    if lifecycle_path and os.path.exists(lifecycle_path):
        try:
            from .lifecycle import LifecycleManager
            lifecycle = LifecycleManager(lifecycle_path)
        except Exception:
            pass

    total = len(new_findings)
    created = 0
    errors_list = []

    with open(log_path, "w") as lf:
        lf.write(f"[START] Pushing {total} issues to GitHub (repo: {repo})\n")
        lf.flush()

    for idx, f in enumerate(new_findings):
        try:
            stats = gh.create_tickets([f], threshold=0, labels=["security", "auto-generated"], lifecycle=lifecycle)
            c = stats.get("created", 0)
            errs = stats.get("errors", [])
            created += c
            errors_list.extend(errs)
            if idx > 0 and idx % 50 == 0:
                with open(log_path, "a") as lf:
                    lf.write(f"[PROGRESS] {idx}/{total} (created: {created}, errors: {len(errors_list)})\n")
            _time.sleep(0.5)
        except Exception as exc:
            errors_list.append(str(exc))
            if "rate limit" in str(exc).lower():
                with open(log_path, "a") as lf:
                    lf.write(f"[RATE_LIMIT] Pausing 300s at {idx}/{total}\n")
                _time.sleep(300)

    if lifecycle:
        lifecycle.close()

    with open(log_path, "a") as lf:
        lf.write(f"[DONE] Created {created}/{total} issues. Errors: {len(errors_list)}\n")
        if errors_list:
            for e in errors_list[:20]:
                lf.write(f"  ! {e}\n")


def _launch_github_push(findings: list, lifecycle_manager_path: str = "", blocking: bool = False) -> Optional[threading.Thread]:
    """Start background GitHub push as a daemon thread.
    If blocking=True, waits for completion (used by CLI). Returns the thread.
    """
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPO") or os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repo:
        print("  [GITHUB] Skipped — GITHUB_TOKEN or GITHUB_REPO not set")
        return None
    active = [f for f in findings if f.status == "active" and (f.score or 0) >= 0]
    if not active:
        print("  [GITHUB] Skipped — no active findings")
        return None
    log_path = os.path.join(os.path.dirname(lifecycle_manager_path) or "outputs", "github_push.log")
    t = threading.Thread(target=_push_github_worker, args=(active, 0.0, lifecycle_manager_path), daemon=True)
    t.start()
    print(f"  [GITHUB] Background push started ({len(active)} findings, log: {log_path})")
    if blocking:
        t.join(timeout=1800)
    return t


def run_pipeline(
    reports_dir: str, config: Config, out_dir: str,
    products: Optional[List[str]] = None,
    skip_ai: bool = True, use_searchsploit: Optional[bool] = None,
    fetcher: Optional[enrich.Fetcher] = None,
    ollama_model: Optional[str] = None, groq_api_key: Optional[str] = None,
    groq_model: Optional[str] = None,
    stage_callback: Optional[Any] = None,
) -> Dict[str, Any]:
    def _notify_stage(stage_num: int, name: str, detail: str = ""):
        if stage_callback:
            try:
                stage_callback(stage_num, name, detail)
            except Exception:
                pass

    os.makedirs(out_dir, exist_ok=True)
    run_date = dt.datetime.now().isoformat(timespec="seconds")
    products = products or config.product_names()

    # Stage 1: Ingest & Normalize
    _notify_stage(1, "Ingest & Normalize", "Parsing scanner reports")
    print("=" * 60)
    print("STAGE 1/9: INGEST & NORMALIZE")
    print("=" * 60)
    findings = normalize.parse_reports_dir(reports_dir, products)
    # Set found_at timestamp on all findings
    for f in findings:
        if not f.found_at:
            f.found_at = run_date
    scanners_found = sorted({f.scanner for f in findings})
    print(f"  [OK] Parsed {len(findings)} raw findings from {len(scanners_found)} scanners")
    print(f"  Scanners: {', '.join(scanners_found)}")

    # Stage 2: Deduplication
    _notify_stage(2, "Deduplication", f"Deduplicating {len(findings)} findings")
    print("\n" + "=" * 60)
    print("STAGE 2/9: DEDUPLICATION")
    print("=" * 60)
    dedup_result = dedup.deduplicate(findings, fuzzy=config.dedup_cfg.get("fuzzy_title", False))
    findings = dedup_result["findings"]
    metrics = dedup_result["metrics"]
    removed_findings = [
        {"product": f.product or "", "scanner": f.scanner or "", "title": (f.title or "")[:120],
         "severity": f.severity or "", "cve": f.cve or "", "cwe": f.cwe or "",
         "endpoint": (f.endpoint or "")[:100], "duplicate_of": f.duplicate_of or "", "pass": ""}
        for f in findings if f.is_duplicate
    ]
    for rf in removed_findings:
        rf["pass"] = metrics.get("_pass_for_id", {}).get(rf["duplicate_of"], "cve")
    print(f"  Raw: {metrics['raw']} -> Unique: {metrics['unique']} (dedup: {metrics['dedup_pct']}%) | Removed: {len(removed_findings)}")

    # Stage 3: Filtering
    _notify_stage(3, "Filtering & Quarantine", "Applying quarantine and suppression rules")
    print("\n" + "=" * 60)
    print("STAGE 3/9: FILTERING")
    print("=" * 60)
    uniques = [f for f in findings if not f.is_duplicate]
    filter_result = filt.filter_findings(uniques, config.filter_cfg, config.products)
    findings = filter_result["findings"]
    filter_metrics = filter_result["metrics"]
    print(f"  Active: {filter_metrics['active']} | Quarantined: {filter_metrics['quarantined']}")

    # Stage 4: Threat Enrichment
    _notify_stage(4, "Threat Intelligence", "Enriching with CISA KEV, EPSS, Exploit-DB, and NVD")
    print("\n" + "=" * 60)
    print("STAGE 4/9: THREAT ENRICHMENT")
    print("=" * 60)
    enricher = enrich.Enricher(config.enrich_cfg, fetcher=fetcher)
    enricher.enrich(findings, use_searchsploit=use_searchsploit)
    print(f"  [OK] Enriched: {enricher.counts_dict()}")

    # Stage 5: Attack Path Mapping
    _notify_stage(5, "Attack Path Mapping", "Building attack chains and transition graphs")
    print("\n" + "=" * 60)
    print("STAGE 5/9: ATTACK PATH MAPPING")
    print("=" * 60)
    all_paths: Dict[str, List[Any]] = {}
    for product in products:
        if not any(f.product == product for f in findings):
            continue
        paths = attackpath.build_attack_paths(findings, product, config.product(product))
        all_paths[product] = [p.to_dict() for p in paths]
        attackpath.attach_escalation_potential(findings, paths, product=product)
    total_paths = sum(len(v) for v in all_paths.values())
    print(f"  [PATHS] {total_paths} attack paths across {len(all_paths)} products")

    # Stage 6: Risk Scoring
    _notify_stage(6, "Risk Scoring", "Calculating 8-factor composite risk scores")
    print("\n" + "=" * 60)
    print("STAGE 6/9: RISK SCORING")
    print("=" * 60)
    active = [f for f in findings if f.status == "active"]
    for f in active:
        score.compute_score(f, config.product(f.product), config.weights)
    scores = [f.score or 0 for f in active]
    if scores:
        print(f"  [SCORE] Scored {len(active)} findings | Avg: {sum(scores) / len(scores):.1f} | Max: {max(scores):.1f}")
    else:
        print(f"  [SCORE] Scored {len(active)} findings")

    # Stage 7: AI Enrichment
    _notify_stage(7, "AI Enrichment", "Generating executive brief and remediation notes")
    print("\n" + "=" * 60)
    print("STAGE 7/9: AI ENRICHMENT")
    print("=" * 60)
    from . import ai_enrich as ai_mod
    ai_summary_stats = {
        "raw_findings": metrics["raw"], "unique_findings": metrics["unique"],
        "final_findings": filter_metrics["active"],
        "p1": sum(1 for f in active if f.score is not None and f.score >= 90),
        "p2": sum(1 for f in active if f.score is not None and 70 <= f.score < 90),
        "p3": sum(1 for f in active if f.score is not None and 40 <= f.score < 70),
        "p4": sum(1 for f in active if f.score is not None and f.score < 40),
    }
    ai_result = (ai_mod.ai_enrich(findings, summary_stats=ai_summary_stats,
                  skip_remediation=False, ollama_model="" if skip_ai else ollama_model,
                  groq_api_key="" if skip_ai else groq_api_key, groq_model=groq_model)
                 if not skip_ai else {"used": False, "counts": {}, "executive_brief": ""})
    if not ai_result.get("executive_brief") and ai_summary_stats:
        ai_result["executive_brief"] = ai_mod._executive_brief(active, ai_summary_stats)

    # Stage 8: Remediation
    _notify_stage(8, "Remediation Engineering", "Generating contextual remediation guidance")
    print("\n" + "=" * 60)
    print("STAGE 8/9: REMEDIATION")
    print("=" * 60)
    for f in active:
        if not f.remediation_suggestions:
            f.remediation_suggestions = remediation.suggest_remediation(f)
    print(f"  [REMEDIATE] Generated remediation for {len(active)} findings")

    # Stage 9: Ranking & Output
    _notify_stage(9, "Ranking & Output", "Generating reports, history DB, and dashboard")
    print("\n" + "=" * 60)
    print("STAGE 9/9: RANKING & OUTPUT")
    print("=" * 60)
    ranked = output.rank_findings(findings, config)

    summary = RunSummary(
        run_date=run_date,
        products=[p for p in products if any(f.product == p for f in findings)],
        raw_findings=metrics["raw"], unique_findings=metrics["unique"],
        quarantined=filter_metrics["quarantined"], final_findings=filter_metrics["active"],
        dedup_pct=metrics["dedup_pct"],
        avg_score=round(sum(scores) / len(scores), 1) if scores else 0.0,
        top_score=max(scores) if scores else 0.0,
        p1=sum(1 for f in active if f.priority == "Critical"),
        p2=sum(1 for f in active if f.priority == "High"),
        p3=sum(1 for f in active if f.priority == "Medium"),
        p4=sum(1 for f in active if f.priority == "Low"),
        enrich_counts=enricher.counts_dict(),
        quarantine_by_rule=filter_metrics.get("quarantine_by_rule", {}),
        attack_paths=total_paths,
    )

    output.write_ranked_csv(os.path.join(out_dir, "ranked_findings.csv"), ranked)
    output.write_ranked_json(os.path.join(out_dir, "ranked_findings.json"), ranked)
    output.write_analytics_csv(os.path.join(out_dir, "analytics.csv"), ranked)
    output.write_top_actions_md(os.path.join(out_dir, "top_actions.md"), ranked, summary)
    output.write_tickets_md(os.path.join(out_dir, "tickets_ready.md"), ranked, config.reporting.get("ticket_threshold", 60))

    noise = {
        "run_date": run_date, "raw_findings": summary.raw_findings,
        "unique_findings": summary.unique_findings, "quarantined": summary.quarantined,
        "final_findings": summary.final_findings, "dedup_pct": summary.dedup_pct,
        "noise_removed_pct": round((summary.raw_findings - summary.final_findings) / max(summary.raw_findings, 1) * 100, 2),
        "dedup_by_pass": metrics["by_pass"],
        "per_scanner_counts": metrics.get("per_scanner_counts", {}),
        "cross_scanner_redundancy": metrics.get("cross_scanner_redundancy", []),
        "quarantine_by_rule": summary.quarantine_by_rule, "enrich_counts": summary.enrich_counts,
        "attack_paths": total_paths, "avg_score": summary.avg_score, "top_score": summary.top_score,
        "p1": summary.p1, "p2": summary.p2, "p3": summary.p3, "p4": summary.p4,
        "ai_used": ai_result["used"],
        "ai_fp_classified": ai_result["counts"].get("fp_classified", 0),
        "ai_remediation": ai_result["counts"].get("remediation", 0),
        "removed_findings": removed_findings,
    }
    output.write_metrics_json(os.path.join(out_dir, "noise_reduction.json"), noise)

    hist = history.History(os.path.join(out_dir, "history.db"))
    for product in summary.products:
        pf = [f for f in active if f.product == product]
        pscores = [f.score or 0 for f in pf]
        hist.add_run(run_date[:10], product, {
            "raw": summary.raw_findings, "unique": summary.unique_findings,
            "quarantined": summary.quarantined, "final": len(pf),
            "dedup_pct": summary.dedup_pct,
            "avg_score": round(sum(pscores) / len(pscores), 1) if pscores else 0.0,
            "top_score": max(pscores) if pscores else 0.0,
            "p1": sum(1 for f in pf if f.priority == "Critical"),
            "p2": sum(1 for f in pf if f.priority == "High"),
            "p3": sum(1 for f in pf if f.priority == "Medium"),
            "p4": sum(1 for f in pf if f.priority == "Low"),
            "enrich_counts": summary.enrich_counts,
        })
    history_map = hist.all_history()
    hist.close()

    from . import lifecycle
    lc = lifecycle.LifecycleManager(os.path.join(out_dir, "lifecycle.db"))
    # Sync external ticket status changes back into lifecycle
    try:
        from .jira_client import JiraClient
        jc = JiraClient()
        if jc.configured:
            sync_result = jc.sync_from_jira(lc)
            if sync_result.get("synced", 0) > 0:
                print(f"  [JIRA] Synced {sync_result['synced']} findings from Jira")
    except Exception:
        pass
    try:
        from . import github_tickets as _gh
        gh_token = os.environ.get("GITHUB_TOKEN", "")
        gh_repo = os.environ.get("GITHUB_REPO") or os.environ.get("GITHUB_REPOSITORY", "")
        if gh_token and gh_repo:
            gh_client = _gh.GitHubTickets(gh_repo, gh_token)
            sync_result = gh_client.sync_from_github(lc)
            if sync_result.get("synced", 0) > 0:
                print(f"  [GITHUB] Synced {sync_result['synced']} findings from GitHub")
    except Exception:
        pass
    for product in summary.products:
        pf = [f for f in active if f.product == product]
        pscores = [f.score or 0 for f in pf]
        lc.record_engagement(run_date=run_date, product=product, current_findings=pf,
            summary_stats={"avg_score": round(sum(pscores) / len(pscores), 1) if pscores else 0.0})
        for f in pf:
            lc.upsert_finding(f, run_date=run_date)
    lc.close()

    quarantine_list = [f for f in findings if f.status == "quarantined"]
    # Save quarantine findings for dashboard regeneration
    if quarantine_list:
        quarantine_path = os.path.join(out_dir, "quarantine_findings.json")
        with open(quarantine_path, "w", encoding="utf-8") as qf:
            json.dump([f.to_dict() for f in quarantine_list], qf, indent=2)
    dashboard.build_dashboard(
        os.path.join(out_dir, "risk_dashboard.html"), findings, ranked, summary,
        all_paths, history_map, quarantine_list,
        executive_brief=ai_result.get("executive_brief", ""),
        products_config=config.products, removed_findings=removed_findings,
    )

    from . import sarif_export
    sarif_export.write_sarif(os.path.join(out_dir, "results.sarif"), ranked)
    sarif_export.write_cyclonedx(os.path.join(out_dir, "bom.json"), ranked)
    sarif_export.write_defectdojo(os.path.join(out_dir, "defectdojo_import.json"), ranked)

    # Auto-push findings to GitHub Issues in background thread
    gh_thread = _launch_github_push(active, lifecycle_manager_path=os.path.join(out_dir, "lifecycle.db"))

    print(f"\n{'=' * 60}")
    print("[DONE] PIPELINE COMPLETE")
    print(f"{'=' * 60}")
    print(f"  Outputs in: {out_dir}")

    return {"findings": findings, "ranked": ranked, "summary": summary,
            "attack_paths": all_paths, "metrics": noise, "ai_result": ai_result,
            "github_push_thread": gh_thread}


def main():
    parser = argparse.ArgumentParser(description="DevSecOps Risk Intelligence Pipeline")
    parser.add_argument("--reports", required=True, help="Directory with scanner reports")
    parser.add_argument("--config", default="config.json", help="Config file path")
    parser.add_argument("--out", default="outputs", help="Output directory")
    parser.add_argument("--products", default=None, help="Comma-separated product filter")

    parser.add_argument("--skip-ai", action="store_true", help="Skip AI enrichment")
    parser.add_argument("--searchsploit", action="store_true", help="Use Exploit-DB CSV")
    parser.add_argument("--ollama-model", default=None, help="Ollama model name")
    parser.add_argument("--groq-api-key", default=None, help="Groq API key")
    parser.add_argument("--groq-model", default=None, help="Groq model name")
    args = parser.parse_args()

    config = Config.load(args.config)
    products = args.products.split(",") if args.products else None
    result = run_pipeline(args.reports, config, args.out, products=products,
        skip_ai=args.skip_ai,
        use_searchsploit=True if args.searchsploit else None,
        ollama_model=args.ollama_model,
        groq_api_key=args.groq_api_key if args.groq_api_key is not None else os.environ.get("GROQ_API_KEY"),
        groq_model=args.groq_model)

    if result["summary"].p1 > 0:
        print(f"\n[INFO] {result['summary'].p1} Critical finding(s) detected — review in dashboard.")

    # Wait for background GitHub push if running from CLI
    gh_thread = result.get("github_push_thread")
    if gh_thread and gh_thread.is_alive():
        print("\n[GITHUB] Waiting for issue push to complete...")
        gh_thread.join(timeout=1800)
        print("[GITHUB] Push finished.")


if __name__ == "__main__":
    main()
