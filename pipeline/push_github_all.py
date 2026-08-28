#!/usr/bin/env python3
"""Push ALL findings to GitHub Issues with rate-limit handling.

Usage:
    python -m pipeline.push_github_all [--threshold 0] [--dry-run]
"""
import argparse
import json
import os
import sys
import time
from typing import List

from dotenv import load_dotenv
load_dotenv()

from .models import Finding
from .github_tickets import GitHubTickets


def main():
    parser = argparse.ArgumentParser(description="Push all findings to GitHub Issues")
    parser.add_argument("--findings", default="outputs/ranked_findings.json")
    parser.add_argument("--threshold", type=float, default=0.0,
                        help="Minimum score to create issue (default: 0 = all)")
    parser.add_argument("--batch-size", type=int, default=50,
                        help="Issues per batch before pausing")
    parser.add_argument("--batch-delay", type=float, default=60.0,
                        help="Seconds to wait between batches (rate limit)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPO", "")

    if not token:
        print("ERROR: GITHUB_TOKEN not set in .env")
        sys.exit(1)
    if not repo:
        print("ERROR: GITHUB_REPO not set in .env")
        sys.exit(1)

    print(f"Repo: {repo}")
    print(f"Token: {token[:20]}...")
    print(f"Threshold: {args.threshold}")

    # Load findings
    with open(args.findings) as fh:
        data = json.load(fh)

    findings: List[Finding] = []
    for item in data:
        f = Finding(**{k: v for k, v in item.items() if k not in ("raw", "score_breakdown", "remediation_suggestions")})
        f.score_breakdown = item.get("score_breakdown", {})
        f.remediation_suggestions = item.get("remediation_suggestions", [])
        findings.append(f)

    # Filter by threshold
    eligible = [f for f in findings if f.status == "active" and (f.score or 0) >= args.threshold]
    print(f"\nTotal findings: {len(findings)}")
    print(f"Eligible (score >= {args.threshold}): {len(eligible)}")

    if not eligible:
        print("No findings to push.")
        return

    # Check existing issues
    gh = GitHubTickets(repo, token, dry_run=args.dry_run)
    existing_titles = gh._open_issue_titles()
    print(f"Existing open issues: {len(existing_titles)}")

    # Filter out already-existing
    new_findings = []
    skipped = 0
    for f in eligible:
        title = f"[{f.priority}] {f.title[:100]} ({f.product})"
        if title in existing_titles:
            skipped += 1
            continue
        new_findings.append(f)

    print(f"New issues to create: {len(new_findings)}")
    print(f"Skipped (already exist): {skipped}")

    if not new_findings:
        print("Nothing new to create.")
        return

    # Create in batches — one issue at a time for rate limit safety
    total_created = 0
    total_errors = 0
    rate_limited = False

    for idx, f in enumerate(new_findings):
        if rate_limited:
            break

        # Rate limit: wait if we've been blocked
        if total_errors > 0 and total_errors % 20 == 0:
            wait = min(300, 60 * (total_errors // 20))
            print(f"\n  Rate limited — waiting {wait}s before continuing...")
            time.sleep(wait)

        try:
            stats = gh.create_tickets([f], threshold=0, labels=["security", "auto-generated"])
            created = stats.get("created", 0)
            errors = stats.get("errors", [])
            total_created += created
            total_errors += len(errors)

            if errors and "secondary rate limit" in str(errors[0]).lower():
                print(f"\n  Hit secondary rate limit at issue {idx + 1}/{len(new_findings)}")
                print(f"  Created so far: {total_created}")
                print(f"  Remaining: {len(new_findings) - idx - 1}")
                print(f"  Waiting 10 minutes for rate limit reset...")
                time.sleep(600)  # Wait 10 minutes
                rate_limited = True
            elif idx % 50 == 0:
                print(f"  Progress: {idx + 1}/{len(new_findings)} (created: {total_created}, errors: {total_errors})")

            # Small delay between requests
            if not args.dry_run:
                time.sleep(0.5)

        except Exception as e:
            total_errors += 1
            if "secondary rate limit" in str(e).lower():
                rate_limited = True
                print(f"\n  Rate limited at issue {idx + 1}")

    print(f"\n=== DONE ===")
    print(f"Created: {total_created}")
    print(f"Errors: {total_errors}")
    print(f"Skipped: {skipped}")


if __name__ == "__main__":
    main()
