"""Product manager for multi-product security scanning.

Handles adding, removing, listing, and scanning products.
Each product has its own URL, GitHub repo, scanners, and risk profile.

Usage:
    python -m pipeline.product_manager list
    python -m pipeline.product_manager add --name myapp --url https://myapp.com --repo myorg/myapp
    python -m pipeline.product_manager remove --name myapp
    python -m pipeline.product_manager scan --name myapp
    python -m pipeline.product_manager scan --all
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config.json")
SCAN_DIR = os.path.join(os.path.dirname(__file__), "..", "scan_reports")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")


def _load_config() -> Dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _save_config(config: Dict) -> None:
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def list_products() -> List[Dict]:
    """List all configured products with their metadata."""
    config = _load_config()
    products = []
    for key, prod in config.get("products", {}).items():
        products.append({
            "id": key,
            "display_name": prod.get("display_name", key),
            "url": prod.get("url", ""),
            "owner": prod.get("owner", ""),
            "github_repo": prod.get("github_repo", ""),
            "asset_criticality": prod.get("asset_criticality", 5),
            "data_sensitivity": prod.get("data_sensitivity", 5),
            "scanners": list(prod.get("scanners", {}).keys()),
        })
    return products


def add_product(
    name: str,
    display_name: str,
    url: str,
    github_repo: str = "",
    owner: str = "",
    asset_criticality: int = 5,
    business_impact: int = 5,
    exposure: int = 5,
    control_effectiveness: int = 5,
    data_sensitivity: int = 5,
    scanners: Optional[Dict[str, str]] = None,
) -> Dict:
    """Add a new product to config.json."""
    config = _load_config()

    # Slug-ify the name for config key
    product_id = name.lower().replace(" ", "_").replace("-", "_")

    if product_id in config.get("products", {}):
        raise ValueError(f"Product '{product_id}' already exists in config")

    # Auto-generate scanner targets from URL
    if scanners is None:
        scanners = {}
        if url:
            scanners["nuclei"] = url
            scanners["zap"] = url
            scanners["wapiti"] = url
            # Trivy needs a Docker image name, not URL
            # User must provide this separately if they want Trivy

    product = {
        "display_name": display_name or product_id,
        "owner": owner or "unassigned",
        "asset_criticality": asset_criticality,
        "business_impact": business_impact,
        "exposure": exposure,
        "control_effectiveness": control_effectiveness,
        "data_sensitivity": data_sensitivity,
        "url": url,
        "github_repo": github_repo,
        "scanners": scanners,
    }

    config.setdefault("products", {})[product_id] = product
    _save_config(config)

    return {"id": product_id, "product": product}


def remove_product(product_id: str) -> bool:
    """Remove a product from config.json."""
    config = _load_config()
    products = config.get("products", {})

    if product_id not in products:
        raise ValueError(f"Product '{product_id}' not found in config")

    del products[product_id]
    _save_config(config)
    return True


def update_product(product_id: str, **kwargs) -> Dict:
    """Update fields on an existing product."""
    config = _load_config()
    products = config.get("products", {})

    if product_id not in products:
        raise ValueError(f"Product '{product_id}' not found in config")

    for key, value in kwargs.items():
        if value is not None:
            products[product_id][key] = value

    _save_config(config)
    return products[product_id]


def get_product_github_repo(product_id: str) -> str:
    """Get the GitHub repo for a product (for ticket creation)."""
    config = _load_config()
    prod = config.get("products", {}).get(product_id, {})
    return prod.get("github_repo", "")


def scan_product(product_id: str, skip_enrich: bool = False, skip_ai: bool = False) -> Dict:
    """Run scanners against a single product and process through pipeline."""
    config = _load_config()
    prod = config.get("products", {}).get(product_id)

    if not prod:
        raise ValueError(f"Product '{product_id}' not found in config")

    url = prod.get("url", "")
    scanners_config = prod.get("scanners", {})
    scan_dir = os.path.abspath(SCAN_DIR)
    output_dir = os.path.abspath(OUTPUT_DIR)

    os.makedirs(scan_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n{'=' * 60}")
    print(f"  SCANNING: {prod.get('display_name', product_id)}")
    print(f"  URL: {url}")
    print(f"  Scanners: {', '.join(scanners_config.keys())}")
    print(f"{'=' * 60}\n")

    scan_results = {}

    # Run Nuclei
    if "nuclei" in scanners_config:
        target = scanners_config["nuclei"]
        output = os.path.join(scan_dir, f"{product_id}_nuclei.json")
        print(f"  [SCAN] Nuclei -> {target}")
        try:
            subprocess.run(
                ["docker", "run", "--rm", "--network=host",
                 "projectdiscovery/nuclei:latest",
                 "-u", target, "-json", "-o", output],
                timeout=300, capture_output=True,
            )
            scan_results["nuclei"] = os.path.exists(output)
            print(f"  [OK] Nuclei complete")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  [WARN] Nuclei failed: {e}")
            scan_results["nuclei"] = False

    # Run ZAP
    if "zap" in scanners_config:
        target = scanners_config["zap"]
        output = os.path.join(scan_dir, f"{product_id}_zap.json")
        print(f"  [SCAN] ZAP -> {target}")
        try:
            subprocess.run(
                ["docker", "run", "--rm", "--network=host",
                 "-v", f"{scan_dir}:/zap/wrk",
                 "ghcr.io/zaproxy/zaproxy:stable",
                 "zap-baseline.py", "-t", target,
                 "-J", f"/zap/wrk/{product_id}_zap.json"],
                timeout=600, capture_output=True,
            )
            scan_results["zap"] = os.path.exists(output)
            print(f"  [OK] ZAP complete")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  [WARN] ZAP failed: {e}")
            scan_results["zap"] = False

    # Run Trivy
    if "trivy" in scanners_config:
        image = scanners_config["trivy"]
        output = os.path.join(scan_dir, f"{product_id}_trivy.json")
        print(f"  [SCAN] Trivy -> {image}")
        try:
            subprocess.run(
                ["docker", "run", "--rm",
                 "-v", f"{scan_dir}:/out",
                 "aquasec/trivy:latest",
                 "image", "--format", "json",
                 "-o", f"/out/{product_id}_trivy.json", image],
                timeout=300, capture_output=True,
            )
            scan_results["trivy"] = os.path.exists(output)
            print(f"  [OK] Trivy complete")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  [WARN] Trivy failed: {e}")
            scan_results["trivy"] = False

    # Run Wapiti
    if "wapiti" in scanners_config:
        target = scanners_config["wapiti"]
        output = os.path.join(scan_dir, f"{product_id}_wapiti.json")
        print(f"  [SCAN] Wapiti -> {target}")
        try:
            subprocess.run(
                ["wapiti", "-u", target, "-f", "json",
                 "-o", output, "--flush-attacks", "--flush-session"],
                timeout=300, capture_output=True,
            )
            scan_results["wapiti"] = os.path.exists(output)
            print(f"  [OK] Wapiti complete")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  [WARN] Wapiti failed: {e}")
            scan_results["wapiti"] = False

    # Run pipeline on the scanned reports
    print(f"\n  [PIPELINE] Processing {product_id} findings...")
    from . import run as pipeline_run

    # Build pipeline args
    sys.argv = [
        "pipeline.run",
        "--reports", scan_dir,
        "--config", os.path.abspath(CONFIG_PATH),
        "--out", output_dir,
        "--products", product_id,
    ]
    if skip_enrich:
        sys.argv.append("--skip-enrich")
    if skip_ai:
        sys.argv.append("--skip-ai")

    try:
        result = pipeline_run.run_pipeline(
            scan_dir,
            pipeline_run.Config.load(os.path.abspath(CONFIG_PATH)),
            output_dir,
            products=[product_id],
            skip_enrich=skip_enrich,
            skip_ai=skip_ai,
        )
        print(f"  [OK] Pipeline complete for {product_id}")

        # Auto-create GitHub issues if repo is configured
        github_repo = prod.get("github_repo", "")
        if github_repo:
            _create_github_issues(product_id, github_repo, output_dir)

        return {
            "product": product_id,
            "scans": scan_results,
            "pipeline": result,
        }

    except Exception as e:
        print(f"  [ERROR] Pipeline failed: {e}")
        return {"product": product_id, "scans": scan_results, "error": str(e)}


def _create_github_issues(product_id: str, github_repo: str, output_dir: str) -> None:
    """Auto-create GitHub Issues for a product's findings."""
    from . import github_tickets

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print(f"  [SKIP] No GITHUB_TOKEN — skipping issue creation for {product_id}")
        return

    findings_path = os.path.join(output_dir, "ranked_findings.json")
    if not os.path.exists(findings_path):
        print(f"  [SKIP] No ranked_findings.json found")
        return

    with open(findings_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    # Filter findings to this product only
    from .models import Finding
    findings = []
    for item in data:
        if item.get("product") == product_id:
            f = Finding(**{k: v for k, v in item.items() if k != "raw"})
            f.score_breakdown = item.get("score_breakdown", {})
            f.remediation_suggestions = item.get("remediation_suggestions", [])
            findings.append(f)

    if not findings:
        print(f"  [SKIP] No findings for {product_id}")
        return

    gh = github_tickets.GitHubTickets(github_repo, token)
    config = _load_config()
    threshold = config.get("reporting", {}).get("ticket_threshold", 60)
    labels = config.get("reporting", {}).get("github_labels", ["security", "auto-generated"])

    stats = gh.create_tickets(findings, threshold=threshold, labels=labels)
    print(f"  [ISSUES] Created {stats['created']} issues in {github_repo}")
    if stats.get("errors"):
        for err in stats["errors"][:3]:
            print(f"    ! {err}")


def scan_all(skip_enrich: bool = False, skip_ai: bool = False) -> List[Dict]:
    """Scan all configured products."""
    products = list_products()
    results = []
    for prod in products:
        result = scan_product(prod["id"], skip_enrich=skip_enrich, skip_ai=skip_ai)
        results.append(result)
    return results


# ─────────────────────── CLI ────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Multi-product security manager")
    sub = parser.add_subparsers(dest="command")

    # list
    sub.add_parser("list", help="List all products")

    # add
    add_p = sub.add_parser("add", help="Add a new product")
    add_p.add_argument("--name", required=True, help="Product identifier (slug)")
    add_p.add_argument("--display-name", default="", help="Human-readable name")
    add_p.add_argument("--url", required=True, help="Target URL to scan")
    add_p.add_argument("--repo", default="", help="GitHub repo (org/name) for issues")
    add_p.add_argument("--owner", default="", help="Team responsible for this product")
    add_p.add_argument("--criticality", type=int, default=5, help="Asset criticality 1-10")
    add_p.add_argument("--data-sensitivity", type=int, default=5, help="Data sensitivity 1-10")

    # remove
    rm_p = sub.add_parser("remove", help="Remove a product")
    rm_p.add_argument("--name", required=True, help="Product identifier to remove")

    # update
    upd_p = sub.add_parser("update", help="Update a product")
    upd_p.add_argument("--name", required=True, help="Product identifier to update")
    upd_p.add_argument("--url", default=None, help="New target URL")
    upd_p.add_argument("--repo", default=None, help="New GitHub repo")
    upd_p.add_argument("--owner", default=None, help="New team owner")
    upd_p.add_argument("--criticality", type=int, default=None, help="New criticality 1-10")

    # scan
    scan_p = sub.add_parser("scan", help="Scan a product")
    scan_p.add_argument("--name", default=None, help="Product to scan (omit for all)")
    scan_p.add_argument("--all", action="store_true", help="Scan all products")
    scan_p.add_argument("--skip-enrich", action="store_true", help="Skip threat intel")
    scan_p.add_argument("--skip-ai", action="store_true", help="Skip AI enrichment")

    args = parser.parse_args()

    if args.command == "list":
        products = list_products()
        if not products:
            print("No products configured. Add one with: python -m pipeline.product_manager add ...")
            return
        print(f"\n{'ID':<20} {'Name':<25} {'URL':<30} {'GitHub Repo':<30} {'Scanners'}")
        print("-" * 130)
        for p in products:
            scanners = ", ".join(p["scanners"]) if p["scanners"] else "none"
            repo = p["github_repo"] or "(not set)"
            print(f"{p['id']:<20} {p['display_name']:<25} {p['url']:<30} {repo:<30} {scanners}")
        print()

    elif args.command == "add":
        result = add_product(
            name=args.name,
            display_name=args.display_name or args.name,
            url=args.url,
            github_repo=args.repo,
            owner=args.owner,
            asset_criticality=args.criticality,
            data_sensitivity=args.data_sensitivity,
        )
        print(f"Product '{result['id']}' added to config.json")
        print(f"  URL: {result['product']['url']}")
        print(f"  GitHub: {result['product']['github_repo'] or '(not set)'}")
        print(f"  Scanners: {', '.join(result['product']['scanners'].keys())}")

    elif args.command == "remove":
        remove_product(args.name)
        print(f"Product '{args.name}' removed from config.json")

    elif args.command == "update":
        kwargs = {}
        if args.url is not None:
            kwargs["url"] = args.url
            # Auto-update scanner targets too
            scanners = {}
            scanners["nuclei"] = args.url
            scanners["zap"] = args.url
            scanners["wapiti"] = args.url
            kwargs["scanners"] = scanners
        if args.repo is not None:
            kwargs["github_repo"] = args.repo
        if args.owner is not None:
            kwargs["owner"] = args.owner
        if args.criticality is not None:
            kwargs["asset_criticality"] = args.criticality

        result = update_product(args.name, **kwargs)
        print(f"Product '{args.name}' updated")

    elif args.command == "scan":
        if args.all or args.name is None:
            scan_all(skip_enrich=args.skip_enrich, skip_ai=args.skip_ai)
        else:
            scan_product(args.name, skip_enrich=args.skip_enrich, skip_ai=args.skip_ai)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
