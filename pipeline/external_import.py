"""Import external findings from JSON, XML, CSV, SARIF, and other formats.

Supports:
- JSON (array of finding objects or DefectDojo format)
- XML (SARIF, CycloneDX, generic vulnerability XML)
- CSV (columns: title, severity, cve, cwe, endpoint, description)
- SARIF (standard static analysis format)
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from typing import Any, Dict, List, Optional

from .models import Finding, normalize_severity


def import_file(path: str, source_name: str = "") -> List[Finding]:
    """Import findings from a file. Detects format by extension."""
    ext = os.path.splitext(path)[1].lower()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    if ext in (".json", ".sarif"):
        return _import_json(content, source_name)
    elif ext == ".xml":
        return _import_xml(content, source_name)
    elif ext == ".csv":
        return _import_csv(content, source_name)
    else:
        trimmed = content.strip()
        if trimmed.startswith("{") or trimmed.startswith("["):
            return _import_json(content, source_name)
        elif trimmed.startswith("<"):
            return _import_xml(content, source_name)
        raise ValueError(f"Unsupported format: {ext}")


def import_data(data: Any, source_name: str = "") -> List[Finding]:
    """Import findings from parsed data (dict or list)."""
    if isinstance(data, list):
        return _parse_finding_list(data, source_name)
    elif isinstance(data, dict):
        return _parse_finding_dict(data, source_name)
    return []


def _import_json(content: str, source_name: str) -> List[Finding]:
    """Import from JSON — supports multiple formats."""
    data = json.loads(content)

    # DefectDojo import format (array of finding dicts)
    if isinstance(data, list):
        return _parse_finding_list(data, source_name)

    # Single finding dict
    if isinstance(data, dict):
        # Check for SARIF wrapper
        if "runs" in data:
            return _import_sarif(data, source_name)
        # Check for CycloneDX wrapper
        if data.get("bomFormat") == "CycloneDX":
            return _import_cyclonedx(data, source_name)
        # Check for wrapper with findings key
        if "findings" in data:
            return _parse_finding_list(data["findings"], source_name)
        if "vulnerabilities" in data:
            return _parse_finding_list(data["vulnerabilities"], source_name)
        return _parse_finding_dict(data, source_name)

    return []


def _import_xml(content: str, source_name: str) -> List[Finding]:
    """Import from XML — supports SARIF and generic vulnerability XML."""
    import xml.etree.ElementTree as ET

    root = ET.fromstring(content)

    # SARIF format
    if root.tag == "{http://json-schema.org/sarif#/schema/2.1.0}sarif" or root.tag == "sarif":
        return _import_sarif_etree(root, source_name)

    # Generic vulnerability XML (e.g., from Nessus, OpenVAS)
    findings = []
    for vuln in root.iter():
        if "vuln" in vuln.tag.lower() or "finding" in vuln.tag.lower():
            f = _parse_xml_vuln(vuln, source_name)
            if f:
                findings.append(f)

    return findings


def _import_csv(content: str, source_name: str) -> List[Finding]:
    """Import from CSV."""
    reader = csv.DictReader(io.StringIO(content))
    findings = []
    for row in reader:
        title = row.get("title") or row.get("Title") or row.get("name", "")
        if not title:
            continue
        severity = normalize_severity(
            row.get("severity") or row.get("Severity") or row.get("risk", "info")
        )
        f = Finding(
            scanner=source_name or "external_import",
            product=row.get("product") or row.get("Product", "unknown"),
            title=title,
            severity=severity,
            cve=row.get("cve") or row.get("CVE") or row.get("cve_id"),
            cwe=row.get("cwe") or row.get("CWE"),
            endpoint=row.get("endpoint") or row.get("url") or row.get("host"),
            description=row.get("description") or row.get("Description", ""),
        )
        findings.append(f)
    return findings


def _import_sarif(data: Dict, source_name: str) -> List[Finding]:
    """Import from SARIF JSON."""
    findings = []
    for run in data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", source_name)
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            level = result.get("level", "warning")
            locations = result.get("locations", [])
            endpoint = ""
            if locations:
                physical = locations[0].get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                endpoint = artifact.get("uri", "")

            f = Finding(
                scanner=tool_name or source_name,
                product="unknown",
                title=f"{rule_id}: {message[:80]}",
                severity=normalize_severity(level),
                cwe=rule_id if rule_id.startswith("CWE-") else None,
                endpoint=endpoint,
                description=message,
            )
            findings.append(f)
    return findings


def _import_sarif_etree(root, source_name: str) -> List[Finding]:
    """Import from SARIF XML."""
    findings = []
    for result in root.iter():
        if "result" in result.tag.lower():
            rule_id = ""
            message = ""
            for child in result:
                if "ruleid" in child.tag.lower():
                    rule_id = child.text or ""
                if "message" in child.tag.lower():
                    message = child.text or ""
            if rule_id or message:
                f = Finding(
                    scanner=source_name,
                    product="unknown",
                    title=f"{rule_id}: {message[:80]}" if rule_id else message[:80],
                    severity="medium",
                    cwe=rule_id if rule_id.startswith("CWE-") else None,
                    description=message,
                )
                findings.append(f)
    return findings


def _import_cyclonedx(data: Dict, source_name: str) -> List[Finding]:
    """Import from CycloneDX SBOM."""
    findings = []
    for vuln in data.get("vulnerabilities", []):
        f = Finding(
            scanner=source_name,
            product="unknown",
            title=f"{vuln.get('id', 'unknown')}: {vuln.get('description', '')[:80]}",
            severity=normalize_severity(vuln.get("severity", "info")),
            cve=vuln.get("id"),
            description=vuln.get("description", ""),
        )
        findings.append(f)
    return findings


def _parse_finding_list(items: List[Dict], source_name: str) -> List[Finding]:
    """Parse a list of finding dicts into Finding objects."""
    findings = []
    for item in items:
        f = _parse_finding_dict(item, source_name)
        if f:
            findings.append(f)
    return findings


def _parse_finding_dict(item: Dict, source_name: str) -> Optional[Finding]:
    """Parse a single finding dict into a Finding object."""
    title = item.get("title") or item.get("name") or item.get("vulnerability", "")
    if not title:
        return None

    severity = normalize_severity(
        item.get("severity") or item.get("risk") or item.get("level", "info")
    )

    f = Finding(
        scanner=item.get("scanner") or source_name or "external_import",
        product=item.get("product") or item.get("project", "unknown"),
        title=str(title)[:200],
        severity=severity,
        cve=item.get("cve") or item.get("cve_id") or item.get("id"),
        cwe=item.get("cwe") or item.get("cwe_id"),
        endpoint=item.get("endpoint") or item.get("url") or item.get("host"),
        description=item.get("description") or item.get("desc", ""),
        evidence=item.get("evidence") or item.get("proof", ""),
        remediation=item.get("remediation") or item.get("solution", ""),
        package=item.get("package") or item.get("component"),
        installed_version=item.get("installed_version") or item.get("version"),
        fixed_version=item.get("fixed_version"),
    )

    # Parse CVSS if present
    cvss = item.get("cvss") or item.get("cvss_score") or item.get("score")
    if cvss is not None:
        try:
            f.nvd_cvss = float(cvss)
        except (ValueError, TypeError):
            pass

    # Parse EPSS if present
    epss = item.get("epss_score") or item.get("epss")
    if epss is not None:
        try:
            f.epss_score = float(epss)
        except (ValueError, TypeError):
            pass

    # Parse boolean flags
    f.kev = bool(item.get("kev") or item.get("known_exploited"))
    f.exploit_available = bool(item.get("exploit_available") or item.get("exploit"))

    return f


def _parse_xml_vuln(elem, source_name: str) -> Optional[Finding]:
    """Parse an XML vulnerability element."""
    props = {}
    for child in elem:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        props[tag.lower()] = child.text or ""

    title = props.get("title") or props.get("name") or props.get("id", "")
    if not title:
        return None

    return Finding(
        scanner=source_name,
        product="unknown",
        title=str(title)[:200],
        severity=normalize_severity(props.get("severity", "info")),
        cve=props.get("cve"),
        cwe=props.get("cwe"),
        endpoint=props.get("host") or props.get("url"),
        description=props.get("description", ""),
    )
