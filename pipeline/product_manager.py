"""Product manager for multi-product security scanning.

Usage:
    python -m pipeline.product_manager list
    python -m pipeline.product_manager add --name myapp --url https://myapp.com
    python -m pipeline.product_manager remove --name myapp
    python -m pipeline.product_manager scan --name myapp
"""

from __future__ import annotations
import argparse
import json
import os
import subprocess
from typing import Dict, List, Optional

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config.json")
SCAN_DIR = os.path.join(os.path.dirname(__file__), "..", "scan_reports")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")


def _load_config() -> Dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _save_config(config: Dict) -> None:
    import tempfile
    dir_name = os.path.dirname(CONFIG_PATH) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp_path, CONFIG_PATH)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def list_products() -> List[Dict]:
    config = _load_config()
    products = []
    for key, prod in config.get("products", {}).items():
        products.append({
            "id": key, "display_name": prod.get("display_name", key),
            "url": prod.get("url", ""), "owner": prod.get("owner", ""),
            "github_repo": prod.get("github_repo", ""),
            "asset_criticality": prod.get("asset_criticality", 5),
            "data_sensitivity": prod.get("data_sensitivity", 5),
            "scanners": list(prod.get("scanners", {}).keys()),
        })
    return products


def add_product(name: str, display_name: str, url: str, github_repo: str = "",
                owner: str = "", asset_criticality: int = 5, business_impact: int = 5,
                exposure: int = 5, control_effectiveness: int = 5, data_sensitivity: int = 5,
                scanners: Optional[Dict[str, str]] = None) -> Dict:
    config = _load_config()
    product_id = name.lower().replace(" ", "_").replace("-", "_")
    if product_id in config.get("products", {}):
        raise ValueError(f"Product '{product_id}' already exists")
    if scanners is None:
        scanners = {}
        if url:
            scanners.update({"nuclei": url, "zap": url, "wapiti": url})
    product = {
        "display_name": display_name or product_id, "owner": owner or "unassigned",
        "asset_criticality": asset_criticality, "business_impact": business_impact,
        "exposure": exposure, "control_effectiveness": control_effectiveness,
        "data_sensitivity": data_sensitivity, "url": url, "github_repo": github_repo,
        "scanners": scanners,
    }
    config.setdefault("products", {})[product_id] = product
    _save_config(config)
    return {"id": product_id, "product": product}


def remove_product(product_id: str) -> bool:
    config = _load_config()
    if product_id not in config.get("products", {}):
        raise ValueError(f"Product '{product_id}' not found")
    del config["products"][product_id]
    _save_config(config)
    return True


def update_product(product_id: str, **kwargs) -> Dict:
    config = _load_config()
    if product_id not in config.get("products", {}):
        raise ValueError(f"Product '{product_id}' not found")
    for key, value in kwargs.items():
        if value is not None:
            config["products"][product_id][key] = value
    _save_config(config)
    return config["products"][product_id]


def get_product_github_repo(product_id: str) -> str:
    return _load_config().get("products", {}).get(product_id, {}).get("github_repo", "")


def scan_product(product_id: str, skip_enrich: bool = False, skip_ai: bool = False) -> Dict:
    config = _load_config()
    prod = config.get("products", {}).get(product_id)
    if not prod:
        raise ValueError(f"Product '{product_id}' not found")

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

    for scanner_name in ["nuclei", "zap", "trivy", "wapiti"]:
        if scanner_name not in scanners_config:
            continue
        target = scanners_config[scanner_name]
        output_name = f"{product_id}_{scanner_name}.json"
        output = os.path.join(scan_dir, output_name)
        print(f"  [SCAN] {scanner_name.title()} -> {target}")

        cmd_map = {
            "nuclei": ["docker", "run", "--rm", "--network=host", "--add-host", "host.docker.internal:host-gateway",
                       "-v", f"{scan_dir}:/out", "projectdiscovery/nuclei:latest",
                       "-u", target, "-jsonl", "-o", f"/out/{output_name}"],
            "zap": ["docker", "run", "--rm", "--network=host", "--add-host", "host.docker.internal:host-gateway",
                    "--memory=1g", "--cpus=1", "-v", f"{scan_dir}:/zap/wrk",
                    "ghcr.io/zaproxy/zaproxy:stable", "zap-baseline.py", "-t", target,
                    "-J", f"/zap/wrk/{output_name}"],
            "wapiti": ["docker", "run", "--rm", "--network=host", "--add-host", "host.docker.internal:host-gateway",
                       "-v", f"{scan_dir}:/out", "vulnlab/wapiti:latest", "wapiti",
                       "-u", target, "-f", "json", "-o", f"/out/{output_name}",
                       "--flush-attacks", "--flush-session"],
        }

        if scanner_name == "trivy":
            image = target
            if ":" not in target and "/" not in target:
                try:
                    result = subprocess.run(
                        ["docker", "inspect", "--format", "{{.Config.Image}}", target],
                        capture_output=True, text=True, timeout=10,
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        image = result.stdout.strip()
                except Exception:
                    pass
            cmd = ["docker", "run", "--rm", "-v", f"{scan_dir}:/out",
                   "aquasec/trivy:latest", "image", "--format", "json",
                   "-o", f"/out/{output_name}", image]
        else:
            cmd = cmd_map[scanner_name]

        timeout = 300 if scanner_name == "trivy" else 600
        try:
            subprocess.run(cmd, timeout=timeout, capture_output=True)
            scan_results[scanner_name] = os.path.exists(output)
            print(f"  [OK] {scanner_name.title()} complete")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  [WARN] {scanner_name.title()} failed: {e}")
            scan_results[scanner_name] = False

    print(f"\n  [PIPELINE] Processing {product_id} findings...")
    from . import run as pipeline_run
    try:
        result = pipeline_run.run_pipeline(scan_dir, pipeline_run.Config.load(os.path.abspath(CONFIG_PATH)),
            output_dir, products=[product_id], skip_enrich=skip_enrich, skip_ai=skip_ai)
        github_repo = prod.get("github_repo", "")
        if github_repo:
            _create_github_issues(product_id, github_repo, output_dir)
        return {"product": product_id, "scans": scan_results, "pipeline": result}
    except Exception as e:
        print(f"  [ERROR] Pipeline failed: {e}")
        return {"product": product_id, "scans": scan_results, "error": str(e)}


def _create_github_issues(product_id: str, github_repo: str, output_dir: str) -> None:
    from . import github_tickets
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print(f"  [SKIP] No GITHUB_TOKEN for {product_id}")
        return
    findings_path = os.path.join(output_dir, "ranked_findings.json")
    if not os.path.exists(findings_path):
        return
    with open(findings_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    from .models import Finding
    findings = [Finding(**{k: v for k, v in item.items() if k != "raw"}) | {"score_breakdown": item.get("score_breakdown", {}), "remediation_suggestions": item.get("remediation_suggestions", [])}
                for item in data if item.get("product") == product_id]
    if not findings:
        return
    gh = github_tickets.GitHubTickets(github_repo, token)
    config = _load_config()
    stats = gh.create_tickets(findings, threshold=config.get("reporting", {}).get("ticket_threshold", 60),
                              labels=config.get("reporting", {}).get("github_labels", ["security", "auto-generated"]))
    print(f"  [ISSUES] Created {stats['created']} issues in {github_repo}")


def scan_all(skip_enrich: bool = False, skip_ai: bool = False) -> List[Dict]:
    return [scan_product(p["id"], skip_enrich=skip_enrich, skip_ai=skip_ai) for p in list_products()]


def main():
    parser = argparse.ArgumentParser(description="Multi-product security manager")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="List all products")
    add_p = sub.add_parser("add", help="Add a new product")
    add_p.add_argument("--name", required=True)
    add_p.add_argument("--display-name", default="")
    add_p.add_argument("--url", required=True)
    add_p.add_argument("--repo", default="")
    add_p.add_argument("--owner", default="")
    add_p.add_argument("--criticality", type=int, default=5)
    add_p.add_argument("--data-sensitivity", type=int, default=5)
    rm_p = sub.add_parser("remove", help="Remove a product")
    rm_p.add_argument("--name", required=True)
    upd_p = sub.add_parser("update", help="Update a product")
    upd_p.add_argument("--name", required=True)
    upd_p.add_argument("--url", default=None)
    upd_p.add_argument("--repo", default=None)
    upd_p.add_argument("--owner", default=None)
    upd_p.add_argument("--criticality", type=int, default=None)
    scan_p = sub.add_parser("scan", help="Scan a product")
    scan_p.add_argument("--name", default=None)
    scan_p.add_argument("--all", action="store_true")
    scan_p.add_argument("--skip-enrich", action="store_true")
    scan_p.add_argument("--skip-ai", action="store_true")

    args = parser.parse_args()
    if args.command == "list":
        products = list_products()
        if not products:
            print("No products configured.")
            return
        print(f"\n{'ID':<20} {'Name':<25} {'URL':<30} {'GitHub Repo':<30} {'Scanners'}")
        print("-" * 130)
        for p in products:
            print(f"{p['id']:<20} {p['display_name']:<25} {p['url']:<30} {p['github_repo'] or '(not set)':<30} {', '.join(p['scanners']) or 'none'}")
    elif args.command == "add":
        result = add_product(name=args.name, display_name=args.display_name or args.name, url=args.url,
                             github_repo=args.repo, owner=args.owner, asset_criticality=args.criticality,
                             data_sensitivity=args.data_sensitivity)
        print(f"Product '{result['id']}' added")
    elif args.command == "remove":
        remove_product(args.name)
        print(f"Product '{args.name}' removed")
    elif args.command == "update":
        kwargs = {}
        if args.url is not None:
            kwargs["url"] = args.url
            config = _load_config()
            current_scanners = config.get("products", {}).get(args.name, {}).get("scanners", {})
            current_scanners.update({"nuclei": args.url, "zap": args.url, "wapiti": args.url})
            kwargs["scanners"] = current_scanners
        if args.repo is not None:
            kwargs["github_repo"] = args.repo
        if args.owner is not None:
            kwargs["owner"] = args.owner
        if args.criticality is not None:
            kwargs["asset_criticality"] = args.criticality
        update_product(args.name, **kwargs)
        print(f"Product '{args.name}' updated")
    elif args.command == "scan":
        if args.all or args.name is None:
            scan_all(skip_enrich=args.skip_enrich, skip_ai=args.skip_ai)
        else:
            scan_product(args.name, skip_enrich=args.skip_enrich, skip_ai=args.skip_ai)


if __name__ == "__main__":
    main()
