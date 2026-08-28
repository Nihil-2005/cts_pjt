"""Auto-ticketing via GitHub Issues with lifecycle-aware dedup."""

from __future__ import annotations
import argparse
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from .models import Finding

API = "https://api.github.com"


class GitHubError(RuntimeError):
    pass


class GitHubTickets:
    def __init__(self, repo: str, token: str, dry_run: bool = False):
        self.repo = repo
        self.token = token
        self.dry_run = dry_run

    def _request(self, method: str, path: str, body: Optional[Dict] = None) -> Any:
        url = f"{API}{path}"
        data = json.dumps(body).encode() if body is not None else None
        last_err: Optional[Exception] = None
        for attempt in range(5):
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
                err_body = exc.read().decode()[:500]
                if exc.code == 403 and "rate limit" in err_body.lower():
                    retry_after = int(exc.headers.get("Retry-After", 60)) if hasattr(exc, 'headers') else 60
                    wait = max(retry_after, 2 ** (attempt + 2))
                    last_err = GitHubError(f"Rate limited, waiting {wait}s")
                    time.sleep(wait)
                    continue
                if exc.code == 422 and "secondary rate limit" in err_body.lower():
                    retry_after = int(exc.headers.get("Retry-After", 300)) if hasattr(exc, 'headers') else 300
                    wait = max(retry_after, 2 ** (attempt + 3))
                    last_err = GitHubError(f"Secondary rate limit, waiting {wait}s")
                    time.sleep(wait)
                    continue
                if exc.code == 429 or exc.code >= 500:
                    retry_after = int(exc.headers.get("Retry-After", 0)) if hasattr(exc, 'headers') else 0
                    wait = max(retry_after, 2 ** (attempt + 2))
                    last_err = GitHubError(f"GitHub {method} {path} -> HTTP {exc.code}")
                    time.sleep(wait)
                    continue
                raise GitHubError(f"GitHub {method} {path} -> HTTP {exc.code}: {err_body}")
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_err = exc
                time.sleep(2 ** (attempt + 1))
        raise GitHubError(f"GitHub {method} {path} failed after retries: {last_err}")

    def _comment_on_issue(self, tracked, f: Finding) -> None:
        num = _issue_number_from_url(tracked.issue_url or "")
        if not num:
            raise GitHubError(f"cannot parse issue number from {tracked.issue_url!r}")
        self._request("POST", f"/repos/{self.repo}/issues/{num}/comments",
            {"body": f"🔄 **Reintroduced** — reappeared in latest scan at score **{f.score}** ({f.severity})"})

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

    def get_issue_status(self, issue_number: int) -> Dict[str, Any]:
        """Get GitHub issue state (open/closed)."""
        try:
            data = self._request("GET", f"/repos/{self.repo}/issues/{issue_number}")
            state = data.get("state", "")
            return {"number": issue_number, "state": state,
                    "lifecycle_status": "fixed" if state == "closed" else "open",
                    "title": data.get("title", "")}
        except Exception as e:
            return {"number": issue_number, "error": str(e)}

    def sync_from_github(self, lifecycle_manager) -> Dict[str, Any]:
        """Pull GitHub issue state changes into the lifecycle tracker."""
        if not self.token or self.dry_run:
            return {"synced": 0, "error": "GitHub not configured"}
        updated = 0
        rows = lifecycle_manager.conn.execute(
            "SELECT finding_id, issue_url, status FROM tracked_findings WHERE issue_url IS NOT NULL"
        ).fetchall()
        for row in rows:
            finding_id = row["finding_id"]
            issue_url = row["issue_url"] or ""
            current_status = row["status"]
            # Skip business triage overrides, but allow open <-> fixed syncing with GitHub
            if current_status in ("false_positive", "risk_accepted"):
                continue
            issue_num = _issue_number_from_url(issue_url)
            if not issue_num:
                continue
            gh_status = self.get_issue_status(issue_num)
            if "error" in gh_status:
                continue
            new_status = gh_status.get("lifecycle_status", "")
            if new_status and new_status != current_status:
                lifecycle_manager.transition_status(
                    finding_id, new_status, f"synced from GitHub #{issue_num} ({gh_status.get('state', '')})")
                updated += 1
        return {"synced": updated, "total_checked": len(rows)}

    def create_tickets(self, findings: List[Finding], threshold: float = 60.0,
                       labels: List[str] = None, lifecycle=None,
                       min_priority: Optional[str] = None) -> Dict[str, Any]:
        stats = {"created": 0, "skipped_duplicate": 0, "skipped_ticketed": 0,
                 "skipped_status": 0, "commented_reopened": 0, "below_threshold": 0, "errors": []}
        labels = labels or ["security", "auto-generated"]
        existing = self._open_issue_titles() if not self.dry_run and self.token else set()

        if not self.token and not self.dry_run:
            stats["errors"].append("No GitHub token configured")
            return stats

        pri_filter = [p.strip().lower() for p in min_priority.split(",")] if min_priority else None

        for f in findings:
            if f.status != "active":
                continue
            score = f.score or 0
            if pri_filter:
                if (f.priority or "").lower() not in pri_filter and score < threshold:
                    stats["below_threshold"] += 1
                    continue
            elif score < threshold:
                stats["below_threshold"] += 1
                continue
            title = f"[{f.priority}] {f.title} ({f.product})"

            tracked = None
            if lifecycle is not None:
                fid = lifecycle.id_for(f)
                tracked = lifecycle.get_tracked(fid)
                if tracked is None and f.dedup_key and f.dedup_key != fid:
                    tracked = lifecycle.get_tracked(f.dedup_key)
                if tracked is None:
                    tracked, _ = lifecycle.upsert_finding(f)
                if tracked.status != "open":
                    stats["skipped_status"] += 1
                    continue
                if tracked.issue_url:
                    if _was_reintroduced(tracked):
                        if self.dry_run:
                            print(f"  [DRY-RUN] Would comment (reintroduced): {title}")
                        else:
                            try:
                                self._comment_on_issue(tracked, f)
                                stats["commented_reopened"] += 1
                            except GitHubError as exc:
                                stats["errors"].append(f"{title}: {exc}")
                    else:
                        stats["skipped_ticketed"] += 1
                    continue

            if title in existing:
                stats["skipped_duplicate"] += 1
                continue

            body = _issue_body(f)
            if self.dry_run:
                print(f"  [DRY-RUN] Would create: {title}")
                continue
            try:
                resp = self._request("POST", f"/repos/{self.repo}/issues", {
                    "title": title, "body": body,
                    "labels": labels + [f"priority:{f.priority}", f"scanner:{f.scanner}"],
                })
                stats["created"] += 1
                existing.add(title)
                if lifecycle is not None and tracked is not None:
                    url = resp.get("html_url") or f"https://github.com/{self.repo}/issues/{resp.get('number')}"
                    lifecycle.set_issue_url(tracked.finding_id, url)
            except (GitHubError, urllib.error.URLError, TimeoutError, OSError) as exc:
                stats["errors"].append(f"{title}: {exc}")

        return stats


def _was_reintroduced(tracked) -> bool:
    for t in (tracked.transitions or [])[-6:]:
        if t.get("to") == "open" and "reintroduced" in str(t.get("reason", "")):
            return True
    return False


def _issue_number_from_url(url: str) -> Optional[int]:
    try:
        return int(str(url).rstrip("/").rsplit("/", 1)[-1])
    except (ValueError, TypeError):
        return None


def create_tickets_per_product(findings: List[Finding], products_config: Dict[str, Any],
                               token: str, threshold: float = 60.0, labels: List[str] = None,
                               dry_run: bool = False, lifecycle=None,
                               min_priority: Optional[str] = None) -> Dict[str, Any]:
    labels = labels or ["security", "auto-generated"]
    total_stats = {"created": 0, "skipped_duplicate": 0, "skipped_ticketed": 0,
                   "skipped_status": 0, "commented_reopened": 0, "below_threshold": 0,
                   "errors": [], "per_product": {}}

    by_product: Dict[str, List[Finding]] = {}
    for f in findings:
        if f.status != "active":
            continue
        by_product.setdefault(f.product or "unknown", []).append(f)

    for product_id, product_findings in by_product.items():
        prod_cfg = products_config.get(product_id, {})
        github_repo = prod_cfg.get("github_repo", "")
        if not github_repo:
            total_stats["per_product"][product_id] = {"skipped": True, "reason": "no github_repo"}
            continue
        gh = GitHubTickets(github_repo, token, dry_run=dry_run)
        stats = gh.create_tickets(product_findings, threshold=threshold, labels=labels, lifecycle=lifecycle, min_priority=min_priority)
        for key in ("created", "skipped_duplicate", "skipped_ticketed", "skipped_status", "commented_reopened", "below_threshold"):
            total_stats[key] += stats.get(key, 0)
        total_stats["errors"].extend(stats["errors"])
        total_stats["per_product"][product_id] = {"repo": github_repo, "created": stats["created"], "skipped": False}

    return total_stats


def _issue_body(f: Finding) -> str:
    comps = (f.score_breakdown or {}).get("components", {})
    comp_table = "\n".join(f"| {k} | {v} |" for k, v in sorted(comps.items()))
    remediation = "\n".join(f"- **{s.get('kind')}:** {s.get('text', '')}" for s in (f.remediation_suggestions or []))
    return f"""## 🚨 Risk Score: {(f.score or 0.0):.1f}/100 — {f.priority or 'N/A'} (SLA: {f.sla_hours or 0}h)

| Field | Value |
|-------|-------|
| **Owner** | {f.owner} |
| **Product** | {f.product} |
| **Scanner** | {f.scanner} |
| **CVE** | {f.cve or "-"} |
| **CWE** | {f.cwe or "-"} |
| **Endpoint** | {f.endpoint or "-"} |
| **Parameter** | {f.parameter or "-"} |

### Score Breakdown
| Factor | Points |
|--------|--------|
{comp_table}

### Threat Intelligence
- **EPSS:** {f.epss_score or 0:.4f} (percentile {f.epss_percentile or 0:.3f}, trend {f.epss_trend or 0:+.4f}/7d)
- **CISA KEV:** {"✅ YES (" + (f.kev_date or "") + ")" if f.kev else "❌ No"}
- **Public Exploit:** {"✅ " + (f.exploit_source or "?") if f.exploit_available else "❌ No"}

### Description
{f.description or "No description available."}

### Remediation
{remediation or "No remediation guidance provided."}

---
_Auto-generated by DevSecOps Risk Intelligence Pipeline v2.0_
"""


def main():
    parser = argparse.ArgumentParser(description="Auto-create GitHub Issues from pipeline findings")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--threshold", type=float, default=60.0)
    parser.add_argument("--repo", default=None)
    parser.add_argument("--token", default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "")
    token = args.token or os.environ.get("GITHUB_TOKEN", "")
    with open(args.findings) as fh:
        data = json.load(fh)
    findings = []
    for item in data:
        f = Finding(**{k: v for k, v in item.items() if k != "raw"})
        f.score_breakdown = item.get("score_breakdown", {})
        f.remediation_suggestions = item.get("remediation_suggestions", [])
        findings.append(f)
    gh = GitHubTickets(repo, token, dry_run=args.dry_run)
    stats = gh.create_tickets(findings, threshold=args.threshold)
    print(f"Tickets: {stats['created']} created, {stats['skipped_duplicate']} skipped")
    if stats["errors"]:
        for err in stats["errors"][:5]:
            print(f"  ! {err}")


if __name__ == "__main__":
    main()
