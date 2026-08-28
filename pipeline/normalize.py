"""Normalization: parse raw scanner reports into the unified ``Finding`` schema.

Supported scanners:
  - OWASP ZAP      (JSON: site[].alerts[])
  - Nuclei         (JSON: list of findings with info.classification)
  - Wapiti         (JSON: vulnerabilities dict + classifications)
  - Trivy          (JSON: Results[].Vulnerabilities[])
  - Nmap           (XML: open ports -> exposure findings)
  - OpenVAS        (XML: report results)

Each parser maps to a normalized Finding so downstream stages never need to
know which scanner produced a row.
"""

from __future__ import annotations

import json
import os
import re
from defusedxml import ElementTree as ET
from typing import Any, Dict, List, Optional

from .models import Finding, normalize_severity

import hashlib
from pathlib import Path

SCANNER_ALIASES = {
    "zap": "zap",
    "owasp zap": "zap",
    "zaproxy": "zap",
    "nuclei": "nuclei",
    "wapiti": "wapiti",
    "trivy": "trivy",
    "nmap": "nmap",
    "openvas": "openvas",
    "gvm": "openvas",
}


def _first(*values: Any) -> Any:
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return None


def _listify(v: Any) -> List[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _clean(s: Any) -> str:
    if s is None:
        return ""
    return str(s).strip()


# --------------------------------------------------------------------------
# ZAP
# --------------------------------------------------------------------------
def parse_zap(data: Dict[str, Any], product: str) -> List[Finding]:
    out: List[Finding] = []
    for site in data.get("site", []) or []:
        site_name = site.get("@name", "") or site.get("name", "")
        for alert in site.get("alerts", []) or []:
            # riskdesc/risk only — confidence is NOT a severity and must not
            # be misclassified as one when the risk fields are absent.
            risk = alert.get("riskdesc") or alert.get("risk") or ""
            sev = normalize_severity(str(risk).split(" ")[0])
            cweid = alert.get("cweid")
            cwe = f"CWE-{cweid}" if str(cweid).isdigit() else None
            refs = alert.get("reference", "")
            cve = None
            if "CVE-" in str(refs):
                for token in str(refs).replace(",", " ").split():
                    if token.startswith("CVE-") and len(token) > 6:
                        cve = token.strip(".")
                        break
            out.append(
                Finding(
                    scanner="zap",
                    product=product,
                    title=_clean(alert.get("name") or alert.get("alert")),
                    severity=sev,
                    cve=cve,
                    cwe=cwe,
                    endpoint=_first(alert.get("url"), site_name),
                    parameter=_clean(alert.get("param")),
                    description=_clean(alert.get("desc")),
                    remediation=_clean(alert.get("solution")),
                    evidence=_clean(alert.get("evidence")),
                    raw=alert,
                )
            )
    return out


# --------------------------------------------------------------------------
# Nuclei
# --------------------------------------------------------------------------
def parse_nuclei(data: Any, product: str) -> List[Finding]:
    out: List[Finding] = []
    for item in data or []:
        if not isinstance(item, dict):
            continue
        info = item.get("info") or {}
        classification = info.get("classification") or {}
        cve = _first(classification.get("cve-id"), classification.get("cve"))
        cve = cve[0] if isinstance(cve, list) else cve
        cwes = classification.get("cwe-id") or []
        cwe = cwes[0] if isinstance(cwes, list) and cwes else cwes
        # Ensure CWE IDs are uppercase for cross-scanner dedup
        cwe_str = str(cwe).strip().upper() if cwe else None
        if cwe_str and not cwe_str.startswith("CWE-"):
            cwe_str = f"CWE-{cwe_str}" if cwe_str.isdigit() else cwe_str
        out.append(
            Finding(
                scanner="nuclei",
                product=product,
                title=_clean(info.get("name") or item.get("template-id")),
                severity=normalize_severity(info.get("severity")),
                cve=_clean(cve) or None,
                cwe=cwe_str,
                endpoint=_first(item.get("matched-at"), item.get("url")),
                description=_clean(info.get("description")),
                remediation=_clean(" ".join(_listify(info.get("reference")))),
                evidence=_clean(item.get("matched-at")),
                raw=item,
            )
        )
    return out


# --------------------------------------------------------------------------
# Wapiti
# --------------------------------------------------------------------------
def parse_wapiti(data: Dict[str, Any], product: str) -> List[Finding]:
    out: List[Finding] = []
    classifications = data.get("classifications") or {}
    for category, findings in (data.get("vulnerabilities") or {}).items():
        cls = classifications.get(category) or {}
        for f in findings or []:
            level = f.get("level", 0)
            sev = {3: "high", 2: "medium", 1: "low", 0: "info"}.get(level, "info")
            cwe = None
            refs = cls.get("ref") or {}
            for key in refs:
                if str(key).upper().startswith("CWE-"):
                    cwe = str(key).split(":")[0].strip().upper()
                    break
            cve = f.get("cve") or None
            out.append(
                Finding(
                    scanner="wapiti",
                    product=product,
                    title=f"{category}: {_clean(f.get('info'))[:120]}"
                    if f.get("info")
                    else category,
                    severity=sev,
                    cve=cve,
                    cwe=cwe,
                    endpoint=_clean(f.get("path")),
                    parameter=_clean(f.get("parameter")),
                    description=_clean(cls.get("desc") or f.get("info")),
                    remediation=_clean(cls.get("sol")),
                    evidence=_clean(f.get("path")),
                    raw=f,
                )
            )
    return out


# --------------------------------------------------------------------------
# Trivy
# --------------------------------------------------------------------------
def parse_trivy(data: Dict[str, Any], product: str) -> List[Finding]:
    out: List[Finding] = []
    for result in data.get("Results") or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            cvss = None
            cvss_map = v.get("CVSS") or {}
            for source in ("nvd", "redhat", "ghsa", "vendor"):
                entry = cvss_map.get(source) or {}
                for key, val in entry.items():
                    if isinstance(val, dict) and val.get("V3Score"):
                        cvss = val["V3Score"]
                        break
                    if isinstance(val, (int, float)) and val:
                        cvss = float(val)
                        break
                if cvss:
                    break
            cwe = None
            cwe_ids = v.get("CweIDs") or []
            if cwe_ids:
                cwe = str(cwe_ids[0]).strip().upper()
            else:
                for ref in v.get("References") or []:
                    if "cwe.mitre.org" in str(ref) and "CWE-" in str(ref):
                        idx = str(ref).find("CWE-")
                        cwe = str(ref)[idx : idx + 9].strip()
                        break
            fixed = v.get("FixedVersion") or ""
            out.append(
                Finding(
                    scanner="trivy",
                    product=product,
                    title=_clean(v.get("Title") or v.get("VulnerabilityID")),
                    severity=normalize_severity(v.get("Severity")),
                    cve=v.get("VulnerabilityID") or None,
                    cwe=cwe,
                    endpoint=target,
                    description=_clean(v.get("Description")),
                    remediation=(
                        f"Upgrade {v.get('PkgName')} from {v.get('InstalledVersion')} "
                        f"to {fixed}"
                        if fixed
                        else _clean(v.get("Title"))
                    ),
                    evidence=f"{target}: {v.get('PkgName')} {v.get('InstalledVersion')}",
                    raw={"cvss_score": cvss, **v},
                    package=v.get("PkgName"),
                    installed_version=v.get("InstalledVersion"),
                    fixed_version=fixed or None,
                )
            )
    return out


# --------------------------------------------------------------------------
# Nmap (light: open ports -> exposure findings)
# --------------------------------------------------------------------------
_NMAP_RISKY_SERVICES: Dict[str, tuple] = {
    "ftp": ("CWE-319", "low"),  # cleartext auth
    "telnet": ("CWE-319", "low"),  # cleartext
    "http": ("CWE-200", "low"),  # plain HTTP = exposure
    "snmp": ("CWE-200", "low"),  # information disclosure
    "rdp": ("CWE-284", "low"),  # direct admin access
    "vnc": ("CWE-284", "low"),
    "ms-sql-s": ("CWE-284", "medium"),
    "mysql": ("CWE-284", "medium"),
    "postgresql": ("CWE-284", "medium"),
    "mongodb": ("CWE-284", "medium"),
    "redis": ("CWE-284", "medium"),
    "elasticsearch": ("CWE-284", "medium"),
    "memcached": ("CWE-284", "medium"),
}


def parse_nmap_xml(text: str, product: str) -> List[Finding]:
    out: List[Finding] = []
    root = ET.fromstring(text)
    for host in root.iter("host"):
        addr = ""
        for a in host.iter("address"):
            if a.get("addrtype") in ("ipv4", "ipv6", None):
                addr = a.get("addr", "")
                break
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            svc_name = (svc.get("name", "") if svc is not None else "").lower()
            portid = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            cwe, severity = _NMAP_RISKY_SERVICES.get(svc_name, (None, "info"))
            desc = (
                f"Port {portid}/{proto} ({svc_name or 'unknown'}) is open on {addr}. "
            )
            if cwe:
                desc += (
                    f"Service '{svc_name}' presents attack surface — "
                    f"see {cwe} ({severity} risk)."
                )
            else:
                desc += "Adds to external attack surface."
            out.append(
                Finding(
                    scanner="nmap",
                    product=product,
                    title=f"Open {proto}/{portid} ({svc_name or 'unknown service'})",
                    severity=severity,
                    cwe=cwe,
                    endpoint=f"{addr}:{portid}",
                    description=desc,
                    evidence=f"{addr}:{portid}/{proto} {svc_name}",
                    raw={
                        "port": portid,
                        "protocol": proto,
                        "service": svc_name,
                        "host": addr,
                    },
                )
            )
            # Parse NSE vuln scripts attached to this port
            for script in port.findall("script"):
                sid = script.get("id", "")
                sout = script.get("output", "")
                # Skip informational scripts
                if sid in ("fingerprint-strings", "http-server-header",
                           "http-enum", "http-methods"):
                    continue
                # vulners script has nested <table> elements with CVE data
                if sid == "vulners":
                    for table in script.iter("table"):
                        cve_el = table.find("elem[@key='id']")
                        cvss_el = table.find("elem[@key='cvss']")
                        cve_text = cve_el.text if cve_el is not None else ""
                        cvss_text = cvss_el.text if cvss_el is not None else "0"
                        if not cve_text or not cve_text.startswith("CVE-"):
                            continue
                        try:
                            cvss_val = float(cvss_text)
                        except (ValueError, TypeError):
                            cvss_val = 0.0
                        v_sev = (
                            "critical" if cvss_val >= 9.0
                            else "high" if cvss_val >= 7.0
                            else "medium" if cvss_val >= 4.0
                            else "low" if cvss_val > 0.0
                            else "info"
                        )
                        out.append(Finding(
                            scanner="nmap",
                            product=product,
                            title=f"{cve_text} ({svc_name})",
                            severity=v_sev,
                            cve=cve_text,
                            cwe=None,
                            endpoint=f"{addr}:{portid}",
                            description=f"Nmap vulners detected {cve_text} (CVSS {cvss_val}) on {svc_name} port {portid}.",
                            evidence=sout[:500],
                            raw={"nse_script": sid, "port": portid, "host": addr, "cvss_score": cvss_val, "service": svc_name},
                        ))
                # http-slowloris-check, http-csrf, http-dombased-xss, etc.
                elif sid.startswith("http-") and "VULNERABLE" in sout.upper():
                    # Extract CVE if present
                    cve_match = None
                    import re as _re
                    for tok in sout.split():
                        if tok.startswith("CVE-"):
                            cve_match = tok.rstrip(",")
                            break
                    v_sev = "high" if "CRITICAL" in sout.upper() else "medium"
                    out.append(Finding(
                        scanner="nmap",
                        product=product,
                        title=f"NSE: {sid} on {svc_name}:{portid}",
                        severity=v_sev,
                        cve=cve_match,
                        endpoint=f"{addr}:{portid}",
                        description=sout[:300],
                        evidence=sout[:500],
                        raw={"nse_script": sid, "port": portid, "host": addr},
                    ))
                # http-csrf (no VULNERABLE flag but has findings)
                elif sid == "http-csrf" and "Path:" in sout:
                    out.append(Finding(
                        scanner="nmap",
                        product=product,
                        title=f"Potential CSRF on {svc_name}:{portid}",
                        severity="medium",
                        cwe="CWE-352",
                        endpoint=f"{addr}:{portid}",
                        description=sout[:300],
                        evidence=sout[:500],
                        raw={"nse_script": sid, "port": portid, "host": addr},
                    ))
                # http-dombased-xss
                elif sid == "http-dombased-xss" and "Source:" in sout:
                    out.append(Finding(
                        scanner="nmap",
                        product=product,
                        title=f"DOM-based XSS on {svc_name}:{portid}",
                        severity="medium",
                        cwe="CWE-79",
                        endpoint=f"{addr}:{portid}",
                        description=sout[:300],
                        evidence=sout[:500],
                        raw={"nse_script": sid, "port": portid, "host": addr},
                    ))
                # http-cookie-flags (httponly not set)
                elif sid == "http-cookie-flags" and "httponly flag not set" in sout.lower():
                    out.append(Finding(
                        scanner="nmap",
                        product=product,
                        title=f"Cookie without HttpOnly flag on {svc_name}:{portid}",
                        severity="low",
                        cwe="CWE-614",
                        endpoint=f"{addr}:{portid}",
                        description=sout[:300],
                        evidence=sout[:500],
                        raw={"nse_script": sid, "port": portid, "host": addr},
                    ))
    return out


# --------------------------------------------------------------------------
# OpenVAS (light: report results -> generic findings)
# --------------------------------------------------------------------------
def parse_openvas_xml(text: str, product: str) -> List[Finding]:
    out: List[Finding] = []
    root = ET.fromstring(text)
    for result in root.iter("result"):
        name = result.findtext("name") or ""
        if not name:
            continue
        severity_raw = result.findtext("severity") or "0"
        try:
            severity_score = float(severity_raw)
        except (ValueError, TypeError):
            severity_score = 0.0
        if severity_score >= 9.0:
            sev = "critical"
        elif severity_score >= 7.0:
            sev = "high"
        elif severity_score >= 4.0:
            sev = "medium"
        elif severity_score > 0.0:
            sev = "low"
        else:
            sev = "info"
        cve = None
        nvt = result.find("nvt")
        if nvt is not None:
            for ref in nvt.iter("ref"):
                if ref.get("type") == "cve":
                    cve = ref.get("id")
                    break
        cwe = None
        for ref in result.iter("ref"):
            if ref.get("type") == "cwe":
                cwe = ref.get("id")
                break
        host = result.findtext("host") or ""
        out.append(
            Finding(
                scanner="openvas",
                product=product,
                title=name,
                severity=normalize_severity(sev),
                cve=cve,
                cwe=cwe,
                endpoint=host,
                description=result.findtext("description") or "",
                remediation=result.findtext("solution") or "",
                evidence=f"{host} severity={severity_raw}",
                raw={"severity": severity_raw, "host": host},
            )
        )
    return out


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------
PARSERS = {
    "zap": lambda d, p: parse_zap(d, p),
    "nuclei": lambda d, p: parse_nuclei(d, p),
    "wapiti": lambda d, p: parse_wapiti(d, p),
    "trivy": lambda d, p: parse_trivy(d, p),
}


def _load_json(path: str) -> Any:
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    text = text.strip()
    if not text:
        return []
    # Try standard JSON first (array or object)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Handle JSONL (one JSON object per line) — e.g. nuclei -jsonl output
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def parse_report_file(
    path: str, product: str, scanner: Optional[str] = None
) -> List[Finding]:
    """Parse a single report file into Findings.

    Scanner is inferred from the filename when not provided:
    ``<product>_<scanner>.json`` or ``<product>_<scanner>.xml``.
    """
    base = os.path.basename(path)
    if scanner is None:
        stem = base.rsplit(".", 1)[0]
        # Match scanner tokens bounded by underscores/end and take the LAST
        # match: "<product>_<scanner>.json" works, products containing a
        # scanner name ("my_zap_app_nuclei") route to their real scanner,
        # and suffixed files ("app_nuclei_extra") still resolve.
        matches = re.findall(
            r"(?:^|_)(zap|nuclei|wapiti|trivy|nmap|openvas)(?=$|[^a-z0-9])",
            stem.lower(),
        )
        if matches:
            scanner = matches[-1]
        if scanner is None:
            raise ValueError(f"Cannot infer scanner from filename: {base}")
    scanner = SCANNER_ALIASES.get(scanner.lower(), scanner.lower())

    if scanner in ("nmap",):
        with open(path, encoding="utf-8") as fh:
            return parse_nmap_xml(fh.read(), product)
    if scanner in ("openvas",):
        with open(path, encoding="utf-8") as fh:
            return parse_openvas_xml(fh.read(), product)
    data = _load_json(path)
    if scanner not in PARSERS:
        raise ValueError(f"Unsupported scanner: {scanner}")
    return PARSERS[scanner](data, product)


def _product_from_filename(
    fname: str, product_names: Optional[List[str]] = None
) -> str:
    """Extract the product from ``<product>_<scanner>.json``.

    Product names may themselves contain underscores (e.g. ``juice_shop``),
    so we match against the longest known product prefix first.
    Also handles the scan-script convention of using container names
    (``juiceshop``) instead of config product names (``juice_shop``).
    """
    stem = fname.rsplit(".", 1)[0]
    candidates = sorted(product_names or [], key=len, reverse=True)
    for product in candidates:
        if stem == product or stem.startswith(product + "_"):
            return product
    # Fuzzy match: strip underscores and check prefix
    # Handles e.g. "juiceshop_nuclei" matching config product "juice_shop"
    stem_clean = stem.replace("_", "")
    for product in candidates:
        product_clean = product.replace("_", "")
        if stem_clean.startswith(product_clean):
            return product
    return stem.split("_")[0] or "unknown"


def parse_reports_dir(
    reports_dir: str, product_names: Optional[List[str]] = None
) -> List[Finding]:
    """Parse every report file under ``reports_dir`` (recursive).

    Files are expected as ``<product>_<scanner>.json``.  If ``product_names``
    is given, only those products are parsed (product names may contain
    underscores; the longest prefix match wins).
    """
    findings: List[Finding] = []
    reports_path = Path(reports_dir)
    # Recursive glob to handle nested artifact directories; a single pass
    # over all files with extension-based dispatch.
    for report_file in sorted(reports_path.rglob("*")):
        if not report_file.is_file():
            continue
        if "archive" in report_file.parts or any(p.startswith(".") for p in report_file.parts):
            continue
        if report_file.suffix.lower() not in (".json", ".xml"):
            continue
        fname = report_file.name
        product = _product_from_filename(fname, product_names)
        if product_names and product not in product_names:
            continue
        try:
            findings.extend(parse_report_file(str(report_file), product))
        except Exception as exc:
            print(f"  ! skipping {fname}: {exc}")
    # Populate dedup_key for stable cross-run identity. Tiered to mirror
    # LifecycleManager._finding_id so scanner title-drift between versions
    # does not create phantom "new"/"fixed" findings.
    for f in findings:
        if f.cve:
            raw = f"{f.product}|cve|{f.cve.upper()}"
        elif f.cwe and f.endpoint:
            ep = re.sub(r"^https?://", "", str(f.endpoint).strip().lower())
            raw = f"{f.product}|cwe|{str(f.cwe).upper()}|{ep}"
        else:
            norm_title = re.sub(r"[^a-z0-9]+", " ", (f.title or "").lower()).strip()
            raw = f"{f.product}|title|{norm_title[:80]}"
        f.dedup_key = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return findings
