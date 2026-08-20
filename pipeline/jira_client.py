"""Jira integration for creating and syncing issues from findings.

Supports:
- Create Jira Issues from pipeline findings
- Sync status between Jira and Finding lifecycle
- Map pipeline priorities to Jira priorities
- Bulk import findings as Jira Issues

Requires:
    JIRA_URL=https://yourorg.atlassian.net
    JIRA_USER=you@company.com
    JIRA_TOKEN=your-api-token

Get a token at: https://id.atlassian.com/manage-profile/security/api-tokens
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from .models import Finding


# ─── Priority mapping ────────────────────────────────────────────────────────

PRIORITY_MAP = {
    "P1": {"jira": "Highest", "name": "Critical"},
    "P2": {"jira": "High", "name": "High"},
    "P3": {"jira": "Medium", "name": "Medium"},
    "P4": {"jira": "Low", "name": "Low"},
}

# Jira status mapping (Jira workflow → our lifecycle)
JIRA_STATUS_MAP = {
    "to do": "open",
    "open": "open",
    "in progress": "in_progress",
    "in review": "in_progress",
    "done": "fixed",
    "closed": "verified",
    "won't fix": "risk_accepted",
    "duplicate": "false_positive",
}

# Reverse mapping (our lifecycle → Jira transition name)
LIFECYCLE_TO_JIRA_TRANSITION = {
    "in_progress": "In Progress",
    "fixed": "Done",
    "verified": "Closed",
    "accepted": "Won't Fix",
    "false_positive": "Duplicate",
    "risk_accepted": "Won't Fix",
}


class JiraClient:
    """Client for Jira REST API v2."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        user: Optional[str] = None,
        token: Optional[str] = None,
        project_key: Optional[str] = None,
    ):
        self.base_url = (base_url or os.environ.get("JIRA_URL", "")).rstrip("/")
        self.user = user or os.environ.get("JIRA_USER", "")
        self.token = token or os.environ.get("JIRA_TOKEN", "")
        self.project_key = project_key or os.environ.get("JIRA_PROJECT", "")
        self._auth = (self.user, self.token) if self.user and self.token else None

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self._auth and self.project_key)

    def _api(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}/rest/api/2/{path.lstrip('/')}"
        return requests.request(method, url, auth=self._auth, json=kwargs.get("json"),
                                params=kwargs.get("params"), timeout=30)

    # ─── Create issue ────────────────────────────────────────────────────

    def create_issue(self, finding: Finding, labels: Optional[List[str]] = None) -> Dict[str, Any]:
        """Create a Jira Issue from a finding. Returns Jira response."""
        if not self.configured:
            return {"error": "Jira not configured", "configured": False}

        pri = PRIORITY_MAP.get(finding.priority or "P4", PRIORITY_MAP["P4"])
        issue_labels = labels or ["security", "auto-generated", f"scanner:{finding.scanner}"]

        # Build description
        desc_parts = [
            f"*Risk Score:* {finding.score}/100 — {finding.priority}",
            f"*Product:* {finding.product}",
            f"*Endpoint:* {finding.endpoint or 'N/A'}",
            f"*CVE:* [{finding.cve}|https://nvd.nist.gov/vuln/detail/{finding.cve}]" if finding.cve else "*CVE:* N/A",
            f"*CWE:* {finding.cwe or 'N/A'}",
            "",
        ]

        if finding.epss_score:
            desc_parts.append(f"*EPSS:* {finding.epss_score:.2%} (percentile: {finding.epss_percentile:.1%})")
        if finding.kev:
            desc_parts.append(f"*CISA KEV:* Yes ({finding.kev_date or 'date unknown'})")
        if finding.exploit_available:
            desc_parts.append(f"*Exploit Available:* Yes ({finding.exploit_source or 'unknown'})")

        desc_parts.extend([
            "",
            "h3. Score Breakdown",
        ])
        for k, v in (finding.score_breakdown.get("components", {}) or {}).items():
            desc_parts.append(f"* {k}: {v}")

        if finding.remediation_suggestions:
            desc_parts.extend(["", "h3. Remediation"])
            for s in finding.remediation_suggestions[:5]:
                desc_parts.append(f"* [{s.get('kind', '')}] {s.get('text', '')[:200]}")

        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[{finding.priority}] {finding.title[:140]} ({finding.product})",
                "description": "\n".join(desc_parts),
                "issuetype": {"name": "Bug"},
                "priority": {"name": pri["jira"]},
                "labels": issue_labels,
            }
        }

        resp = self._api("POST", "issue", json=payload)
        if resp.status_code in (200, 201):
            data = resp.json()
            return {
                "configured": True,
                "created": True,
                "key": data.get("key"),
                "id": data.get("id"),
                "self": data.get("self"),
            }
        return {
            "configured": True,
            "created": False,
            "error": resp.text[:500],
            "status_code": resp.status_code,
        }

    def create_issues_bulk(self, findings: List[Finding], labels: Optional[List[str]] = None) -> Dict[str, Any]:
        """Create multiple Jira Issues. Returns summary."""
        created = []
        failed = []

        for f in findings:
            if f.status != "active" or (f.score or 0) < 40:
                continue
            result = self.create_issue(f, labels)
            if result.get("created"):
                created.append({"key": result["key"], "title": f.title[:60]})
            else:
                failed.append({"title": f.title[:60], "error": result.get("error", "unknown")})
            time.sleep(0.1)  # rate limit

        return {
            "total": len(findings),
            "created": len(created),
            "failed": len(failed),
            "issues": created,
            "errors": failed,
        }

    # ─── Sync status ─────────────────────────────────────────────────────

    def get_issue_status(self, issue_key: str) -> Dict[str, Any]:
        """Get current status of a Jira Issue."""
        if not self.configured:
            return {"error": "Jira not configured"}

        resp = self._api("GET", f"issue/{issue_key}", params={"fields": "status,priority,labels"})
        if resp.status_code == 200:
            data = resp.json()
            fields = data.get("fields", {})
            status_name = fields.get("status", {}).get("name", "").lower()
            return {
                "key": issue_key,
                "status": status_name,
                "lifecycle_status": JIRA_STATUS_MAP.get(status_name, "open"),
                "priority": fields.get("priority", {}).get("name", ""),
                "labels": fields.get("labels", []),
            }
        return {"key": issue_key, "error": resp.text[:200]}

    def sync_status_to_jira(self, issue_key: str, lifecycle_status: str) -> bool:
        """Transition a Jira Issue to match our lifecycle status."""
        if not self.configured:
            return False

        transition_name = LIFECYCLE_TO_JIRA_TRANSITION.get(lifecycle_status)
        if not transition_name:
            return False

        # Get available transitions
        resp = self._api("GET", f"issue/{issue_key}/transitions")
        if resp.status_code != 200:
            return False

        transitions = resp.json().get("transitions", [])
        target = None
        for t in transitions:
            if t.get("name", "").lower() == transition_name.lower():
                target = t
                break

        if not target:
            return False

        # Execute transition
        resp = self._api("POST", f"issue/{issue_key}/transitions",
                         json={"transition": {"id": target["id"]}})
        return resp.status_code in (200, 204)

    def sync_status_from_jira(self, issue_key: str) -> Optional[str]:
        """Read Jira status and return our lifecycle equivalent."""
        info = self.get_issue_status(issue_key)
        return info.get("lifecycle_status")

    # ─── Search ──────────────────────────────────────────────────────────

    def search_issues(self, jql: str, max_results: int = 50) -> List[Dict]:
        """Search Jira issues using JQL."""
        if not self.configured:
            return []

        resp = self._api("GET", "search", params={
            "jql": jql,
            "maxResults": max_results,
            "fields": "status,priority,summary,labels",
        })
        if resp.status_code == 200:
            return resp.json().get("issues", [])
        return []

    def get_open_security_issues(self) -> List[Dict]:
        """Get all open security issues in the project."""
        jql = f'project = {self.project_key} AND labels = "security" AND status NOT IN (Done, Closed)'
        return self.search_issues(jql)

    # ─── Connection test ─────────────────────────────────────────────────

    def test_connection(self) -> Dict[str, Any]:
        """Test Jira connection and authentication."""
        if not self.configured:
            return {
                "configured": False,
                "error": "Missing JIRA_URL, JIRA_USER, JIRA_TOKEN, or JIRA_PROJECT",
            }

        resp = self._api("GET", "myself")
        if resp.status_code == 200:
            user = resp.json()
            return {
                "configured": True,
                "connected": True,
                "user": user.get("displayName", ""),
                "email": user.get("emailAddress", ""),
                "project": self.project_key,
            }
        return {
            "configured": True,
            "connected": False,
            "error": resp.text[:200],
        }
