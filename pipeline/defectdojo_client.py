"""DefectDojo API client for importing findings.

Requires: DEFECTDOJO_URL, DEFECTDOJO_API_KEY env vars.
"""

from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import requests
from .models import Finding


class DefectDojoClient:
    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = (base_url or os.environ.get("DEFECTDOJO_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("DEFECTDOJO_API_KEY", "")
        self._headers = ({"Authorization": f"Token {self.api_key}", "Content-Type": "application/json"}
                         if self.api_key else {})

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    def _api(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}/api/v2/{path.lstrip('/')}"
        from .netutil import requests_with_retry
        return requests_with_retry(method, url, headers=self._headers, json=kwargs.get("json"),
                                   data=kwargs.get("data"), files=kwargs.get("files"), timeout=60)

    def list_products(self) -> List[Dict]:
        if not self.configured:
            return []
        resp = self._api("GET", "products/", params={"limit": 200})
        return resp.json().get("results", []) if resp.status_code == 200 else []

    def get_or_create_product(self, name: str, description: str = "") -> Optional[int]:
        if not self.configured:
            return None
        resp = self._api("GET", "products/", params={"name": name, "limit": 10})
        if resp.status_code == 200:
            for p in resp.json().get("results", []):
                if p.get("name", "").lower() == name.lower():
                    return p["id"]
        resp = self._api("POST", "products/", json={"name": name,
            "description": description or "Auto-created by DevSecOps Pipeline", "prod_type": 1})
        return resp.json().get("id") if resp.status_code in (200, 201) else None

    def create_engagement(self, name: str, product_id: int, target_start: str = "",
                          target_end: str = "") -> Optional[int]:
        if not self.configured:
            return None
        now = target_start or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        resp = self._api("POST", "engagements/", json={
            "name": name, "product": product_id, "target_start": now,
            "target_end": target_end or now, "status": "Completed", "engagement_type": "Technical",
        })
        return resp.json().get("id") if resp.status_code in (200, 201) else None

    def import_findings(self, findings: List[Finding], engagement_id: int,
                        scan_type: str = "DevSecOps Pipeline") -> Dict[str, Any]:
        if not self.configured:
            return {"configured": False, "error": "Not configured"}
        findings_data = []
        for f in findings:
            if f.status != "active":
                continue
            findings_data.append({
                "title": f.title, "description": f.description or f.title,
                "severity": f.severity.upper() if f.severity else "INFO",
                "cwe": self._parse_cwe(f.cwe), "cve": f.cve, "cvss": f.nvd_cvss,
                "url": f.endpoint, "steps_to_reproduce": f.evidence or "",
                "mitigation": f.remediation or "", "impact": f.description[:200] if f.description else "",
                "false_p": False, "active": True, "verified": False,
                "component_name": f.package, "component_version": f.installed_version,
            })
        if not findings_data:
            return {"configured": True, "imported": 0, "message": "No active findings"}
        json_payload = json.dumps(findings_data)
        resp = self._api("POST", "import-scan/", data={
            "engagement": engagement_id, "scan_type": "JSON Import",
            "close_old_findings": "false", "skip_duplicates": "true",
        }, files={("file", ("findings.json", json_payload, "application/json"))})
        if resp.status_code in (200, 201):
            data = resp.json()
            return {"configured": True, "imported": data.get("test", {}).get("finding_count", len(findings_data)),
                    "engagement_id": engagement_id}
        return {"configured": True, "imported": 0, "error": resp.text[:500]}

    def get_findings(self, engagement_id: Optional[int] = None) -> List[Dict]:
        if not self.configured:
            return []
        params = {"limit": 500}
        if engagement_id:
            params["test__engagement"] = engagement_id
        resp = self._api("GET", "findings/", params=params)
        return resp.json().get("results", []) if resp.status_code == 200 else []

    def update_finding_status(self, finding_id: int, status: str) -> bool:
        if not self.configured:
            return False
        status_map = {"open": {"active": True, "verified": False},
                      "fixed": {"active": False, "verified": True},
                      "verified": {"active": False, "verified": True},
                      "false_positive": {"active": False, "false_p": True},
                      "risk_accepted": {"active": True, "risk_accepted": True}}
        update = status_map.get(status, {})
        if not update:
            return False
        resp = self._api("PATCH", f"findings/{finding_id}/", json=update)
        return resp.status_code in (200, 204)

    def test_connection(self) -> Dict[str, Any]:
        if not self.configured:
            return {"configured": False, "error": "Missing DEFECTDOJO_URL or DEFECTDOJO_API_KEY"}
        resp = self._api("GET", "users/me/")
        if resp.status_code == 200:
            return {"configured": True, "connected": True, "user": resp.json().get("username", ""), "url": self.base_url}
        resp = self._api("GET", "")
        if resp.status_code == 200:
            return {"configured": True, "connected": True, "user": "unknown", "url": self.base_url}
        return {"configured": True, "connected": False, "error": resp.text[:200]}

    @staticmethod
    def _parse_cwe(cwe: Optional[str]) -> Optional[int]:
        if not cwe:
            return None
        try:
            return int(cwe.replace("CWE-", "").replace("cwe-", "").strip())
        except (ValueError, TypeError):
            return None


def import_to_defectdojo(findings: List[Finding], product_name: str,
                         engagement_name: str = "") -> Dict[str, Any]:
    client = DefectDojoClient()
    if not client.configured:
        return {"configured": False, "error": "Set DEFECTDOJO_URL and DEFECTDOJO_API_KEY"}
    product_id = client.get_or_create_product(product_name)
    if not product_id:
        return {"configured": True, "error": "Failed to create/get product"}
    eng_name = engagement_name or f"Pipeline Run {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}"
    engagement_id = client.create_engagement(eng_name, product_id)
    if not engagement_id:
        return {"configured": True, "error": "Failed to create engagement"}
    result = client.import_findings(findings, engagement_id)
    result["product_id"] = product_id
    result["engagement_id"] = engagement_id
    return result
