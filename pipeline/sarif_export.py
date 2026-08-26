"""SARIF + CycloneDX + DefectDojo export."""

from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from .models import Finding

SEVERITY_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
CONFIDENCE_MAP = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "none"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_cwe(cwe: Optional[str]) -> Optional[int]:
    if not cwe or not cwe.startswith("CWE-"):
        return None
    try:
        return int(cwe.split("-", 1)[1])
    except (ValueError, IndexError):
        return None


def finding_to_sarif_result(finding: Finding) -> Dict[str, Any]:
    level = SEVERITY_LEVEL.get(finding.severity, "warning")
    result = {
        "ruleId": finding.cwe or finding.cve or "UNCATEGORIZED",
        "level": level,
        "message": {"text": finding.description[:500] if finding.description else finding.title},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": finding.endpoint or "/", "uriBaseId": "%SRCROOT%"},
        }}],
        "properties": {
            "severity": finding.severity, "confidence": CONFIDENCE_MAP.get(finding.severity, "medium"),
            "score": finding.score or 0, "priority": finding.priority or "P4",
            "product": finding.product, "scanner": finding.scanner,
            "cwe": finding.cwe or "", "epss_score": finding.epss_score or 0, "kev": finding.kev,
        },
    }
    if finding.cve:
        result["properties"]["cve"] = finding.cve
    if finding.endpoint:
        result["locations"][0]["physicalLocation"]["region"] = {"startLine": 1}
    return result


def findings_to_sarif(findings: List[Finding], tool_name: str = "devsecops-pipeline",
                      tool_version: str = "2.0.0", run_uri: str = "") -> Dict[str, Any]:
    active_findings = [f for f in findings if f.status == "active"]
    rules = {}
    for f in active_findings:
        rule_id = f.cwe or f.cve or "UNCATEGORIZED"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id, "name": rule_id,
                "shortDescription": {"text": f.title[:120]},
                "defaultConfiguration": {"level": SEVERITY_LEVEL.get(f.severity, "warning")},
                "properties": {"tags": [f"security/{f.severity}"]},
            }
            if f.cwe and f.cwe.startswith("CWE-"):
                rules[rule_id]["helpUri"] = f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html"

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool_name, "version": tool_version,
                  "informationUri": "https://github.com/your-org/devsecops-pipeline",
                  "rules": list(rules.values())}},
                  "results": [finding_to_sarif_result(f) for f in active_findings],
                  "invocations": [{"executionSuccessful": True, "startTimeUtc": _now_iso()}]}],
    }
    if run_uri:
        sarif["runs"][0]["originalUriBaseIds"] = {"%SRCROOT%": {"uri": run_uri}}
    return sarif


def write_sarif(path: str, findings: List[Finding], **kwargs) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(findings_to_sarif(findings, **kwargs), fh, indent=2)
    return path


def findings_to_cyclonedx(findings: List[Finding]) -> Dict[str, Any]:
    components, vulnerabilities = [], []
    seen_components, seen_vulns = set(), set()
    for f in findings:
        if f.status != "active" or not f.package:
            continue
        key = f"{f.package}:{f.installed_version or 'unknown'}"
        if key not in seen_components:
            seen_components.add(key)
            comp = {"type": "library", "name": f.package, "version": f.installed_version or "unknown"}
            if f.fixed_version:
                comp["properties"] = [{"name": "fixed_version", "value": f.fixed_version}]
            components.append(comp)
        if f.cve and f.cve not in seen_vulns:
            seen_vulns.add(f.cve)
            vulnerabilities.append({"id": f.cve, "severity": f.severity,
                "description": f.description[:200] if f.description else "",
                "affects": [{"ref": f"pkg:generic/{f.package}@{f.installed_version or 'unknown'}"}]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"timestamp": _now_iso(),
                         "tools": [{"vendor": "devsecops-pipeline", "name": "pipeline", "version": "2.0.0"}]},
            "components": components, "vulnerabilities": vulnerabilities}


def write_cyclonedx(path: str, findings: List[Finding]) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(findings_to_cyclonedx(findings), fh, indent=2)
    return path


def finding_to_defectdojo(finding: Finding) -> Dict[str, Any]:
    return {
        "title": finding.title, "description": finding.description or "",
        "severity": finding.severity.upper(), "cwe": _parse_cwe(finding.cwe),
        "cve": finding.cve, "cvss": finding.nvd_cvss, "url": finding.endpoint,
        "steps_to_reproduce": finding.evidence or "", "mitigation": finding.remediation or "",
        "component_name": finding.package, "component_version": finding.installed_version,
        "fixed_version": finding.fixed_version,
        "false_p": finding.status == "quarantined", "risk_accepted": False,
        "active": finding.status == "active", "verified": False,
        "scanner": {"name": finding.scanner},
        "endpoints": [{"endpoint": finding.endpoint or "", "param": finding.parameter or ""}] if finding.endpoint else [],
    }


def findings_to_defectdojo(findings: List[Finding], engagement_name: str = "") -> Dict[str, Any]:
    return {
        "engagement": {"name": engagement_name or f"Pipeline Run {_now_iso()[:10]}"},
        "findings": [finding_to_defectdojo(f) for f in findings if f.status == "active"],
    }


def write_defectdojo(path: str, findings: List[Finding], **kwargs) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(findings_to_defectdojo(findings, **kwargs), fh, indent=2)
    return path
