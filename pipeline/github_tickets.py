"""Auto-ticketing via GitHub Issues with dedup guard and smart labeling.

Files one issue per P1/P2 finding (configurable threshold), with an
explainable body: score breakdown, threat intel, attack-path context,
remediation (first-aid + full), SLA + owner labels.

De-dup guard: if an open issue with the same ``[P1]``-prefixed title already
exists, we skip instead of spamming.  Uses ``urllib`` (stdlib) so the Docker
image needs no extra packages.
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

from .models import Finding

API = "https://api.github.com"


class GitHubError(RuntimeError):
    pass


class GitHubTickets:
    def __init__(self, repo: str, token: str, dry_run: bool = False):
        self.repo = repo  # "owner/name"
        self.token = token
        self.dry_run = dry_run

    # ------------------------------------------------------------------ http
    def _request(self, method: str, path: str, body: Optional[Dict] = None) -> Any:
        url = f"{API}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("User-Agent", "devsecops-pipeline/2.0")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raise GitHubError(f"GitHub {method} {path} -> HTTP {exc.code}: "
                              f"{exc.read().decode()[:300]}")

    def _open_issue_titles(self) -> set:
        titles = set()
        page = 1
        while True:
            data = self._request("GET", f"/repos/{self.repo}/issues?state=open&per_page=100&page={page}")
            if not data:
                break
            titles.update(i.get("title", "") for i in data)
            if len(data) < 100:
                break
            page += 1
        return titles

    # ---------------------------------------------------------------- filing
    def create_tickets(self, findings: List[Finding], threshold: float = 60.0,
                       labels: List[str] = None) -> Dict[str, Any]:
        """File one issue per active finding with score >= threshold."""
        stats = {"created": 0, "skipped_duplicate": 0, "below_threshold": 0,
                 "errors": []}
        labels = labels or ["security", "auto-generated"]

        existing = self._open_issue_titles() if not self.dry_run and self.token else set()

        if not self.token and not self.dry_run:
            stats["errors"].append("No GitHub token configured")
            return stats

        for f in findings:
            if f.status != "active":
                continue
            score = f.score or 0
            if score < threshold:
                stats["below_threshold"] += 1
                continue
            title = f"[{f.priority}] {f.title} ({f.product})"
            if title in existing:
                stats["skipped_duplicate"] += 1
                continue
            body = _issue_body(f)
            if self.dry_run:
                print(f"  [DRY-RUN] Would create: {title}")
                stats["created"] += 1
                continue
            try:
                self._request("POST", f"/repos/{self.repo}/issues", {
                    "title": title,
                    "body": body,
                    "labels": labels + [f"priority:{f.priority}", f"scanner:{f.scanner}"],
                })
                stats["created"] += 1
                existing.add(title)
            except GitHubError as exc:
                stats["errors"].append(str(exc))

        return stats


def create_tickets_per_product(
    findings: List[Finding],
    products_config: Dict[str, Any],
    token: str,
    threshold: float = 60.0,
    labels: List[str] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Auto-route GitHub Issues to each product's configured repo.

    For each product that has a github_repo set, creates Issues in that repo.
    Products without a github_repo are skipped.
    """
    labels = labels or ["security", "auto-generated"]
    total_stats = {"created": 0, "skipped_duplicate": 0, "below_threshold": 0,
                   "errors": [], "per_product": {}}

    # Group findings by product
    by_product: Dict[str, List[Finding]] = {}
    for f in findings:
        if f.status != "active":
            continue
        by_product.setdefault(f.product or "unknown", []).append(f)

    # Process each product
    for product_id, product_findings in by_product.items():
        prod_cfg = products_config.get(product_id, {})
        github_repo = prod_cfg.get("github_repo", "")

        if not github_repo:
            total_stats["per_product"][product_id] = {
                "skipped": True,
                "reason": "no github_repo configured",
            }
            continue

        gh = GitHubTickets(github_repo, token, dry_run=dry_run)
        stats = gh.create_tickets(product_findings, threshold=threshold, labels=labels)

        total_stats["created"] += stats["created"]
        total_stats["skipped_duplicate"] += stats["skipped_duplicate"]
        total_stats["below_threshold"] += stats["below_threshold"]
        total_stats["errors"].extend(stats["errors"])
        total_stats["per_product"][product_id] = {
            "repo": github_repo,
            "created": stats["created"],
            "skipped": False,
        }

    return total_stats


def _issue_body(f: Finding) -> str:
    """Generate rich, explainable issue body."""
    comps = (f.score_breakdown or {}).get("components", {})
    comp_table = "\n".join(f"| {k} | {v} |" for k, v in sorted(comps.items()))
    remediation = "\n".join(
        f"- **{s.get('kind')}:** {s.get('text', '')}"
        for s in (f.remediation_suggestions or [])
    )

    return f"""## 🚨 Risk Score: {f.score:.1f}/100 — {f.priority} (SLA: {f.sla_hours}h)

| Field | Value |
|-------|-------|
| **Owner** | {f.owner} |
| **Product** | {f.product} |
| **Scanner** | {f.scanner} |
| **CVE** | {f.cve or '-'} |
| **CWE** | {f.cwe or '-'} |
| **Endpoint** | {f.endpoint or '-'} |
| **Parameter** | {f.parameter or '-'} |

### 📊 Score Breakdown
| Factor | Points |
|--------|--------|
{comp_table}

### 🎯 Threat Intelligence
- **EPSS:** {f.epss_score or 0:.4f} (percentile {f.epss_percentile or 0:.3f}, trend {f.epss_trend or 0:+.4f}/7d)
- **CISA KEV:** {'✅ YES (' + (f.kev_date or '') + ')' if f.kev else '❌ No'}
- **Public Exploit:** {'✅ ' + (f.exploit_source or '?') if f.exploit_available else '❌ No'}
- **Escalation Potential:** {f.escalation_potential or 0.0:.2f}

### 📝 Description
{f.description or 'No description available.'}

### 💡 Remediation
{remediation or 'No remediation guidance provided.'}

---
_Auto-generated by DevSecOps Risk Intelligence Pipeline v2.0_
"""


def main():
    parser = argparse.ArgumentParser(description="Auto-create GitHub Issues from pipeline findings")
    parser.add_argument("--findings", required=True, help="Path to ranked_findings.json")
    parser.add_argument("--threshold", type=float, default=60.0, help="Score threshold for ticketing")
    parser.add_argument("--repo", default=None, help="GitHub repo owner/name")
    parser.add_argument("--token", default=None, help="GitHub token")
    parser.add_argument("--dry-run", action="store_true", help="Don't actually create issues")
    args = parser.parse_args()

    repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "")
    token = args.token or os.environ.get("GITHUB_TOKEN", "")

    with open(args.findings) as fh:
        data = json.load(fh)

    # Reconstruct Finding objects
    findings = []
    for item in data:
        f = Finding(**{k: v for k, v in item.items() if k != "raw"})
        f.score_breakdown = item.get("score_breakdown", {})
        f.remediation_suggestions = item.get("remediation_suggestions", [])
        findings.append(f)

    gh = GitHubTickets(repo, token, dry_run=args.dry_run)
    stats = gh.create_tickets(findings, threshold=args.threshold)

    print(f"Tickets: {stats['created']} created, {stats['skipped_duplicate']} skipped (dup), "
          f"{stats['below_threshold']} below threshold")
    if stats["errors"]:
        print(f"Errors: {len(stats['errors'])}")
        for err in stats["errors"][:5]:
            print(f"  ! {err}")


if __name__ == "__main__":
    main()
