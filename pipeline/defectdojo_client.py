"""DefectDojo API client for importing findings.

Supports:
- Import findings via DefectDojo REST API v2
- Create engagements for each pipeline run
- Auto-map products to DefectDojo products
- Status sync between DefectDojo and our lifecycle

Requires:
    DEFECTDOJO_URL=http://localhost:8080
    DEFECTDOJO_API_KEY=your-api-key

API docs: https://defectdojo.github.io/django-DefectDojo/
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import requests

from .models import Finding


class DefectDojoClient:
    """Client for DefectDojo REST API v2."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.base_url = (base_url or os.environ.get("DEFECTDOJO_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("DEFECTDOJO_API_KEY", "")
        self._headers = {
            "Authorization": f"Token {self.api_key}",
            "Content-Type": "application/json",
        } if self.api_key else {}

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    def _api(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}/api/v2/{path.lstrip('/')}"
        return requests.request(method, url, headers=self._headers,
                                json=kwargs.get("json"),
                                data=kwargs.get("data"),
                                files=kwargs.get("files"),
                                timeout=60)

    # ─── Products ────────────────────────────────────────────────────────

    def list_products(self) -> List[Dict]:
        """List all DefectDojo products."""
        if not self.configured:
            return []
        resp = self._api("GET", "products/", params={"limit": 200})
        if resp.status_code == 200:
            return resp.json().get("results", [])
        return []

    def get_or_create_product(self, name: str, description: str = "") -> Optional[int]:
        """Get product ID by name, or create it. Returns product ID."""
        if not self.configured:
            return None

        # Search existing
        resp = self._api("GET", "products/", params={"name": name, "limit": 10})
        if resp.status_code == 200:
            results = resp.json().get("results", [])
            for p in results:
                if p.get("name", "").lower() == name.lower():
                    return p["id"]

        # Create new
        resp = self._api("POST", "products/", json={
            "name": name,
            "description": description or f"Auto-created by DevSecOps Pipeline",
            "prod_type": 1,  # default product type
        })
        if resp.status_code in (200, 201):
            return resp.json().get("id")
        return None

    # ─── Engagements ─────────────────────────────────────────────────────

    def create_engagement(
        self,
        name: str,
        product_id: int,
        target_start: str = "",
        target_end: str = "",
    ) -> Optional[int]:
        """Create an engagement (scan session). Returns engagement ID."""
        if not self.configured:
            return None

        now = target_start or datetime.utcnow().strftime("%Y-%m-%d")
        end = target_end or now

        resp = self._api("POST", "engagements/", json={
            "name": name,
            "product": product_id,
            "target_start": now,
            "target_end": end,
            "status": "Completed",
            "engagement_type": "Technical",
        })
        if resp.status_code in (200, 201):
            return resp.json().get("id")
        return None

    # ─── Import findings ─────────────────────────────────────────────────

    def import_findings(
        self,
        findings: List[Finding],
        engagement_id: int,
        scan_type: str = "DevSecOps Pipeline",
    ) -> Dict[str, Any]:
        """Import findings into DefectDojo via JSON import.

        Returns import summary.
        """
        if not self.configured:
            return {"configured": False, "error": "Not configured"}

        # Build the JSON import payload
        import_data = {
            "scan_type": scan_type,
            "engagement": engagement_id,
            "close_old_findings": False,
            "skip_duplicates": True,
            "file_format": "json",
        }

        # Convert findings to DefectDojo format
        findings_data = []
        for f in findings:
            if f.status != "active":
                continue

            finding_dict = {
                "title": f.title,
                "description": f.description or f.title,
                "severity": f.severity.upper() if f.severity else "INFO",
                "cwe": self._parse_cwe(f.cwe),
                "cve": f.cve,
                "cvss": f.nvd_cvss,
                "url": f.endpoint,
                "steps_to_reproduce": f.evidence or "",
                "mitigation": f.remediation or "",
                "impact": f.description[:200] if f.description else "",
                "false_p": False,
                "active": True,
                "verified": False,
                "duplicate": False,
                "out_of_scope": False,
                "risk_accepted": False,
                "component_name": f.package,
                "component_version": f.installed_version,
            }
            findings_data.append(finding_dict)

        if not findings_data:
            return {"configured": True, "imported": 0, "message": "No active findings to import"}

        # Use the JSON import endpoint
        json_payload = json.dumps(findings_data)
        resp = self._api("POST", "import-scan/", data={
            "engagement": engagement_id,
            "scan_type": "JSON Import",
            "close_old_findings": "false",
            "skip_duplicates": "true",
        }, files={
            ("file", ("findings.json", json_payload, "application/json")),
        })

        if resp.status_code in (200, 201):
            data = resp.json()
            return {
                "configured": True,
                "imported": data.get("test", {}).get("finding_count", len(findings_data)),
                "test_id": data.get("test", {}).get("id"),
                "engagement_id": engagement_id,
                "message": "Findings imported successfully",
            }

        return {
            "configured": True,
            "imported": 0,
            "error": resp.text[:500],
            "status_code": resp.status_code,
        }

    # ─── Status sync ─────────────────────────────────────────────────────

    def get_findings(self, engagement_id: Optional[int] = None) -> List[Dict]:
        """Get findings from DefectDojo, optionally filtered by engagement."""
        if not self.configured:
            return []

        params = {"limit": 500}
        if engagement_id:
            params["test__engagement"] = engagement_id

        resp = self._api("GET", "findings/", params=params)
        if resp.status_code == 200:
            return resp.json().get("results", [])
        return []

    def update_finding_status(self, finding_id: int, status: str) -> bool:
        """Update a finding's status in DefectDojo."""
        if not self.configured:
            return False

        status_map = {
            "open": {"active": True, "verified": False},
            "in_progress": {"active": True, "verified": False},
            "fixed": {"active": False, "verified": True},
            "verified": {"active": False, "verified": True},
            "false_positive": {"active": False, "false_p": True},
            "risk_accepted": {"active": True, "risk_accepted": True},
        }

        update = status_map.get(status, {})
        if not update:
            return False

        resp = self._api("PATCH", f"findings/{finding_id}/", json=update)
        return resp.status_code in (200, 204)

    # ─── Connection test ─────────────────────────────────────────────────

    def test_connection(self) -> Dict[str, Any]:
        """Test DefectDojo connection."""
        if not self.configured:
            return {
                "configured": False,
                "error": "Missing DEFECTDOJO_URL or DEFECTDOJO_API_KEY",
            }

        resp = self._api("GET", "users/me/")
        if resp.status_code == 200:
            user = resp.json()
            return {
                "configured": True,
                "connected": True,
                "user": user.get("username", ""),
                "url": self.base_url,
            }

        # Try the root API endpoint
        resp = self._api("GET", "")
        if resp.status_code == 200:
            return {
                "configured": True,
                "connected": True,
                "user": "unknown",
                "url": self.base_url,
            }

        return {
            "configured": True,
            "connected": False,
            "error": resp.text[:200],
        }

    # ─── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _parse_cwe(cwe: Optional[str]) -> Optional[int]:
        """Extract CWE number from string like 'CWE-89'."""
        if not cwe:
            return None
        try:
            return int(cwe.replace("CWE-", "").replace("cwe-", "").strip())
        except (ValueError, TypeError):
            return None


# ─── Convenience function ───────────────────────────────────────────────────

def import_to_defectdojo(
    findings: List[Finding],
    product_name: str,
    engagement_name: str = "",
) -> Dict[str, Any]:
    """One-shot import: create product, engagement, and import findings."""
    client = DefectDojoClient()

    if not client.configured:
        return {"configured": False, "error": "Set DEFECTDOJO_URL and DEFECTDOJO_API_KEY"}

    # Get or create product
    product_id = client.get_or_create_product(product_name)
    if not product_id:
        return {"configured": True, "error": "Failed to create/get product"}

    # Create engagement
    eng_name = engagement_name or f"Pipeline Run {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
    engagement_id = client.create_engagement(eng_name, product_id)
    if not engagement_id:
        return {"configured": True, "error": "Failed to create engagement"}

    # Import findings
    result = client.import_findings(findings, engagement_id)
    result["product_id"] = product_id
    result["engagement_id"] = engagement_id
    return result
