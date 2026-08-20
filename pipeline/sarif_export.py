"""SARIF (Static Analysis Results Interchange Format) export.

Generates SARIF 2.1.0 files that can be uploaded to:
- GitHub Security tab (via codeql-action/upload-sarif)
- Azure DevOps Code Scanning
- Any SARIF-compatible viewer

SARIF is the industry standard for static analysis result exchange.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import Finding


# ─── SARIF severity mapping ─────────────────────────────────────────────────

SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}

CONFIDENCE_MAP = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "none",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def finding_to_sarif_result(finding: Finding) -> Dict[str, Any]:
    """Convert a Finding to a SARIF result object."""
    level = SEVERITY_LEVEL.get(finding.severity, "warning")
    confidence = CONFIDENCE_MAP.get(finding.severity, "medium")

    result = {
        "ruleId": finding.cwe or finding.cve or "UNCATEGORIZED",
        "level": level,
        "message": {
            "text": finding.description[:500] if finding.description else finding.title,
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.endpoint or "/",
                    "uriBaseId": "%SRCROOT%",
                },
            },
        }],
        "properties": {
            "severity": finding.severity,
            "confidence": confidence,
            "score": finding.score or 0,
            "priority": finding.priority or "P4",
            "product": finding.product,
            "scanner": finding.scanner,
            "cwe": finding.cwe or "",
            "epss_score": finding.epss_score or 0,
            "kev": finding.kev,
        },
    }

    if finding.cve:
        result["properties"]["cve"] = finding.cve
        result["ruleId"] = finding.cve  # Use CVE as ruleId when available

    if finding.endpoint:
        result["locations"][0]["physicalLocation"]["region"] = {
            "startLine": 1,
        }

    return result


def findings_to_sarif(
    findings: List[Finding],
    tool_name: str = "devsecops-pipeline",
    tool_version: str = "2.0.0",
    run_uri: str = "",
) -> Dict[str, Any]:
    """Convert a list of Findings to a complete SARIF 2.1.0 document."""
    active_findings = [f for f in findings if f.status == "active"]

    # Group rules by CWE/CVE
    rules = {}
    for f in active_findings:
        rule_id = f.cwe or f.cve or "UNCATEGORIZED"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {
                    "text": f.title[:120],
                },
                "defaultConfiguration": {
                    "level": SEVERITY_LEVEL.get(f.severity, "warning"),
                },
                "properties": {
                    "tags": [f"security/{f.severity}"],
                },
            }
            if f.cwe and f.cwe.startswith("CWE-"):
                rules[rule_id]["helpUri"] = f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html"

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/your-org/devsecops-pipeline",
                    "rules": list(rules.values()),
                },
            },
            "results": [finding_to_sarif_result(f) for f in active_findings],
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": _now_iso(),
                "toolExecutionNotifications": [],
            }],
        }],
    }

    if run_uri:
        sarif["runs"][0]["originalUriBaseIds"] = {
            "%SRCROOT%": {"uri": run_uri}
        }

    return sarif


def write_sarif(path: str, findings: List[Finding], **kwargs) -> str:
    """Write SARIF file and return the path."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    sarif = findings_to_sarif(findings, **kwargs)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
    return path


# ─── CycloneDX SBOM export ──────────────────────────────────────────────────

def findings_to_cyclonedx(findings: List[Finding]) -> Dict[str, Any]:
    """Convert package-related findings to CycloneDX 1.5 BOM format."""
    components = []
    seen = set()

    for f in findings:
        if f.status != "active" or not f.package:
            continue
        key = f"{f.package}:{f.fixed_version or f.installed_version or 'unknown'}"
        if key in seen:
            continue
        seen.add(key)

        component = {
            "type": "library",
            "name": f.package,
            "version": f.installed_version or "unknown",
        }
        if f.fixed_version:
            component["properties"] = [{"name": "fixed_version", "value": f.fixed_version}]
        if f.cve:
            component["licenses"] = []  # placeholder
            component["vulnerabilities"] = [{
                "id": f.cve,
                "severity": f.severity,
                "description": f.description[:200] if f.description else "",
            }]
        components.append(component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": [{"vendor": "devsecops-pipeline", "name": "pipeline", "version": "2.0.0"}],
        },
        "components": components,
    }


def write_cyclonedx(path: str, findings: List[Finding]) -> str:
    """Write CycloneDX SBOM file."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    bom = findings_to_cyclonedx(findings)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
    return path


# ─── DefectDojo JSON export ─────────────────────────────────────────────────

def finding_to_defectdojo(finding: Finding) -> Dict[str, Any]:
    """Convert a Finding to DefectDojo import format."""
    return {
        "title": finding.title,
        "description": finding.description or "",
        "severity": finding.severity.upper(),
        "cwe": int(finding.cwe.split("-")[1]) if finding.cwe and finding.cwe.startswith("CWE-") else None,
        "cve": finding.cve,
        "cvss": finding.nvd_cvss,
        "url": finding.endpoint,
        "steps_to_reproduce": finding.evidence or "",
        "mitigation": finding.remediation or "",
        "component_name": finding.package,
        "component_version": finding.installed_version,
        "fixed_version": finding.fixed_version,
        "false_p": finding.status == "quarantined",
        "risk_accepted": False,
        "active": finding.status == "active",
        "verified": False,
        "scanner": {"name": finding.scanner},
        "endpoints": [{
            "endpoint": finding.endpoint or "",
            "param": finding.parameter or "",
        }] if finding.endpoint else [],
    }


def findings_to_defectdojo(findings: List[Finding], engagement_name: str = "") -> Dict[str, Any]:
    """Convert findings to DefectDojo bulk import format."""
    return {
        "engagement": {
            "name": engagement_name or f"Pipeline Run {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
        },
        "findings": [finding_to_defectdojo(f) for f in findings if f.status == "active"],
    }


def write_defectdojo(path: str, findings: List[Finding], **kwargs) -> str:
    """Write DefectDojo import JSON."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    data = findings_to_defectdojo(findings, **kwargs)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path
