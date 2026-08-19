"""Thin DefectDojo API v2 client (optional integration).

Responsible for:
  - upserting a Product (per pipeline product/target),
  - creating/attaching an Engagement + Test,
  - pushing each *deduplicated, enriched* finding as a DefectDojo Finding.

Uses only ``requests`` (no extra deps beyond what's in requirements.txt).
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

DEFAULT_BASE_URL = os.environ.get("DD_BASE_URL", "http://localhost:8080")
DEFAULT_TOKEN = os.environ.get("DD_API_TOKEN", "")


class DefectDojoError(RuntimeError):
    pass


class DefectDojoClient:
    def __init__(self, base_url: Optional[str] = None, api_token: Optional[str] = None,
                 verify_ssl: bool = True, timeout: int = 30):
        if requests is None:
            raise DefectDojoError("requests library not installed: pip install requests")
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.api_token = api_token if api_token is not None else DEFAULT_TOKEN
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {self.api_token}",
            "Accept": "application/json",
        })

    # ------------------------------------------------------------------ core
    def _request(self, method: str, path: str, params: Optional[Dict] = None,
                 json_body: Optional[Dict] = None) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/{path.lstrip('/')}"
        resp = self.session.request(method, url, params=params, json=json_body,
                                    verify=self.verify_ssl, timeout=self.timeout)
        if resp.status_code >= 400:
            raise DefectDojoError(
                f"DefectDojo {method} {path} -> HTTP {resp.status_code}: {resp.text[:300]}")
        try:
            return resp.json()
        except ValueError:
            return {}

    def get(self, path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        return self._request("GET", path, params=params)

    def post(self, path: str, body: Dict) -> Dict[str, Any]:
        return self._request("POST", path, json_body=body)

    def patch(self, path: str, body: Dict) -> Dict[str, Any]:
        return self._request("PATCH", path, json_body=body)

    # ------------------------------------------------------------- resources
    def upsert_product(self, name: str, description: str = "",
                       prod_type: str = "Research & Development") -> Dict[str, Any]:
        data = self.get("products/", params={"name": name, "limit": 1}).get("results", [])
        if data:
            return data[0]
        pt_id = self._product_type_id(prod_type)
        return self.post("products/", {
            "name": name,
            "description": description or f"Risk-pipeline product for {name}",
            "prod_type": pt_id,
        })

    def _product_type_id(self, name: str) -> int:
        data = self.get("product_types/", params={"name": name, "limit": 1}).get("results", [])
        if data:
            return data[0]["id"]
        return self.post("product_types/", {"name": name})["id"]

    def upsert_engagement(self, product_id: int, name: str,
                          description: str = "") -> Dict[str, Any]:
        data = self.get("engagements/", params={"product": product_id, "limit": 5}).get("results", [])
        for eng in data:
            if eng.get("name") == name and eng.get("status") in ("In Progress", "Active"):
                return eng
        return self.post("engagements/", {
            "name": name,
            "product": product_id,
            "target_start": _today(),
            "target_end": _today(),
            "status": "In Progress",
            "description": description or "Auto-created by the risk pipeline.",
        })

    def upsert_test(self, engagement_id: int, test_type: str = "Manual Finding") -> Dict[str, Any]:
        data = self.get("tests/", params={"engagement": engagement_id, "limit": 20}).get("results", [])
        for t in data:
            if t.get("test_type_name") == test_type:
                return t
        tt_id = self._test_type_id(test_type)
        return self.post("tests/", {
            "engagement": engagement_id,
            "test_type": tt_id,
            "title": f"Risk pipeline — {test_type}",
            "target_start": _today(),
            "target_end": _today(),
            "description": "Deduplicated + enriched findings pushed by the risk pipeline.",
        })

    def _test_type_id(self, name: str) -> int:
        data = self.get("test_types/", params={"name": name, "limit": 1}).get("results", [])
        if data:
            return data[0]["id"]
        return self.post("test_types/", {"name": name})["id"]

    def push_finding(self, test_id: int, payload: Dict, product_id: Optional[int] = None) -> Dict[str, Any]:
        sev = str(payload["severity"]).capitalize()
        body = {
            "test": test_id,
            "found_by": [test_id],
            "title": payload["title"],
            "severity": sev,
            "description": payload["description"],
            "mitigation": payload.get("mitigation", ""),
            "references": payload.get("references", ""),
            "cwe": payload.get("cwe"),
            "cve": payload.get("cve"),
            "cvssv3": _cvss_vector(payload.get("cvssv3")),
            "cvssv3_score": payload.get("cvssv3"),
            "epss_score": payload.get("epss_score"),
            "epss_percentile": payload.get("epss_percentile"),
            "known_exploited": payload.get("known_exploited"),
            "kev_date": payload.get("kev_date"),
            "active": payload.get("active", True),
            "verified": payload.get("verified", True),
            "numerical_severity": _numerical_severity(sev),
            "deduplication_on_engagement": True,
            "impact": payload.get("impact", ""),
        }
        return self.post("findings/", body)


def _today() -> str:
    import datetime as dt
    return dt.date.today().isoformat()


def _numerical_severity(sev: str) -> str:
    return {"Critical": "S0", "High": "S1", "Medium": "S2", "Low": "S3", "Info": "S4"}.get(sev, "S4")


def _cvss_vector(score: Optional[float]) -> Optional[str]:
    """Best-effort CVSS v3 vector string from a bare score."""
    if score is None:
        return None
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if not 0 <= s <= 10:
        return None
    if s >= 9.0:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if s >= 7.0:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"
    if s >= 4.0:
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"
    return "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"
