"""Attack-path & escalation model.

This is a lightweight, *explainable* model (no exploit simulation).  It is
inspired by CAPEC attack patterns, which declare prerequisites (CWEs that must
exist) and consequences (CWEs they enable) — that gives us a defensible
CWE -> CWE transition graph instead of an invented one.

For every product we:

  1. collect the set of CWEs present in the *active* findings,
  2. keep every known chain (from_cwe -> to_cwe) where both CWEs exist,
  3. compute an escalation probability per path:

        P(path) = chainability
                  x exploit_available_boost   (1.3 if an exploit/KEV exists
                                               on either end of the path)
                  x exposure_boost            (1 + 0.2 * exposure/10)
                  x trend_boost               (1.15 if EPSS 7-day trend is rising)

     capped at 0.95,

  4. attach ``escalation_potential`` to each finding = the highest-probability
     path originating at its CWE (paths ending at high-impact CWEs such as
     RCE / auth-bypass / data-exfil count as escalation targets).
"""
from __future__ import annotations

from typing import Dict, List, Optional

from .models import AttackPath, Finding

# Curated from CAPEC attack-pattern prerequisites/consequences.
# (from_cwe, to_cwe, chainability 0-1, description, capec reference)
CHAINS: List[tuple] = [
    ("CWE-200", "CWE-287", 0.45, "Exposed sensitive data reveals credentials/tokens enabling authentication bypass.", "CAPEC-115 Authentication Bypass"),
    ("CWE-522", "CWE-287", 0.60, "Exposed credentials enable authentication bypass.", "CAPEC-115 Authentication Bypass"),
    ("CWE-798", "CWE-287", 0.65, "Hardcoded credentials enable authentication bypass.", "CAPEC-115 Authentication Bypass"),
    ("CWE-319", "CWE-522", 0.60, "Cleartext transmission allows credential interception.", "CAPEC-102 Session Sidejacking"),
    ("CWE-287", "CWE-284", 0.70, "Authentication bypass grants unauthorized access.", "CAPEC-115 Authentication Bypass"),
    ("CWE-284", "CWE-94", 0.30, "Unauthorized privileged access exposes injection surface.", "CAPEC-233 Privilege Escalation"),
    ("CWE-287", "CWE-94", 0.30, "Authentication bypass reaches injection-capable functionality.", "CAPEC-233 Privilege Escalation"),
    ("CWE-287", "CWE-434", 0.40, "Authentication bypass reaches administrative file upload.", "CAPEC-650 Upload a Web Shell"),
    ("CWE-89", "CWE-94", 0.50, "SQL injection enables stacked queries / file writes toward code execution.", "CAPEC-66 SQL Injection"),
    ("CWE-89", "CWE-200", 0.80, "SQL injection exfiltrates sensitive data.", "CAPEC-66 SQL Injection"),
    ("CWE-79", "CWE-287", 0.40, "XSS steals session tokens enabling account takeover.", "CAPEC-86 XSS"),
    ("CWE-79", "CWE-352", 0.55, "XSS can be used to drive CSRF state-changing requests.", "CAPEC-86 XSS"),
    ("CWE-352", "CWE-284", 0.50, "CSRF performs unauthorized state-changing actions.", "CAPEC-62 Cross-Site Request Forgery"),
    ("CWE-352", "CWE-434", 0.30, "CSRF can trigger file upload on admin functions.", "CAPEC-62 Cross-Site Request Forgery"),
    ("CWE-434", "CWE-94", 0.75, "Uploaded web shell provides direct code execution.", "CAPEC-650 Upload a Web Shell"),
    ("CWE-502", "CWE-94", 0.80, "Insecure deserialization leads to arbitrary code execution.", "CAPEC-586 Object Injection"),
    ("CWE-918", "CWE-284", 0.60, "SSRF reaches internal services bypassing network ACLs.", "CAPEC-664 Server-Side Request Forgery"),
    ("CWE-918", "CWE-200", 0.65, "SSRF reads cloud metadata / internal sensitive data.", "CAPEC-664 Server-Side Request Forgery"),
    ("CWE-918", "CWE-94", 0.40, "SSRF to metadata endpoints yields credentials enabling code execution.", "CAPEC-664 Server-Side Request Forgery"),
    ("CWE-22", "CWE-200", 0.70, "Path traversal reads sensitive files.", "CAPEC-126 Path Traversal"),
    ("CWE-22", "CWE-434", 0.30, "Path traversal can write arbitrary files.", "CAPEC-126 Path Traversal"),
    ("CWE-611", "CWE-200", 0.70, "XXE reads local files / internal resources.", "CAPEC-652 XML External Entities"),
    ("CWE-611", "CWE-918", 0.50, "XXE can be leveraged for server-side request forgery.", "CAPEC-652 XML External Entities"),
    ("CWE-269", "CWE-284", 0.60, "Improper privilege management escalates to unauthorized access.", "CAPEC-233 Privilege Escalation"),
    ("CWE-601", "CWE-522", 0.20, "Open redirect enables phishing for credentials.", "CAPEC-154 Resource Location Spoofing"),
    ("CWE-78", "CWE-94", 0.90, "OS command injection is direct code execution.", "CAPEC-88 OS Command Injection"),
]

# High-impact CWEs: paths ending here are the "escalation targets".
IMPACT_CWES = {"CWE-94", "CWE-78", "CWE-434", "CWE-502", "CWE-89",
               "CWE-918", "CWE-287", "CWE-284", "CWE-522", "CWE-200"}


def _findings_for_cwe(findings: List[Finding], cwe: str) -> List[Finding]:
    return [f for f in findings if f.status == "active" and (f.cwe or "").upper() == cwe]


def _any_exploit(findings: List[Finding]) -> bool:
    return any(f.exploit_available for f in findings)


def _any_rising_trend(findings: List[Finding]) -> bool:
    return any((f.epss_trend or 0) > 0.001 for f in findings)


def build_attack_paths(findings: List[Finding], product: str,
                       product_cfg: Dict) -> List[AttackPath]:
    """Build explainable attack paths for one product."""
    active = [f for f in findings if f.status == "active" and f.product == product]
    if not active:
        return []
    cwes = {f.cwe.upper() for f in active if f.cwe}

    exposure = float(product_cfg.get("exposure", 5)) / 10.0
    paths: List[AttackPath] = []
    for from_cwe, to_cwe, chainability, desc, ref in CHAINS:
        if from_cwe not in cwes or to_cwe not in cwes:
            continue
        factors = [f"chainability={chainability}"]
        prob = chainability
        f_from = _findings_for_cwe(active, from_cwe)
        f_to = _findings_for_cwe(active, to_cwe)
        if _any_exploit(f_from + f_to):
            prob *= 1.3
            factors.append("exploit-available +30%")
        if exposure > 0:
            boost = 1 + 0.2 * exposure
            prob *= boost
            factors.append(f"exposure {product_cfg.get('exposure', 5)}/10 +{round((boost-1)*100)}%")
        if _any_rising_trend(f_from):
            prob *= 1.15
            factors.append("EPSS rising +15%")
        prob = min(0.95, round(prob, 3))
        paths.append(AttackPath(
            product=product, from_cwe=from_cwe, to_cwe=to_cwe,
            chainability=chainability, probability=prob,
            factors=factors, capec_ref=ref, description=desc,
        ))
    return paths


def attach_escalation_potential(findings: List[Finding], paths: List[AttackPath]) -> None:
    """Per-finding escalation_potential = best path originating at its CWE
    (prefer paths that terminate at a high-impact CWE)."""
    by_from: Dict[str, List[AttackPath]] = {}
    for p in paths:
        by_from.setdefault(p.from_cwe, []).append(p)

    def best(cwe: str) -> float:
        candidates = by_from.get(cwe, [])
        if not candidates:
            return 0.0
        impact = [p for p in candidates if p.to_cwe in IMPACT_CWES]
        pool = impact or candidates
        return max(p.probability for p in pool)

    for f in findings:
        if f.cwe:
            f.escalation_potential = best(f.cwe.upper())
