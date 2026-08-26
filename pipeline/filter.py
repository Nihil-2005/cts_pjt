"""Noise filtering with auditable quarantine bucket.

Rules (configurable in config.json):
  - severity floor: findings at/below a severity are dropped
  - FP patterns: regex matched against title + description
  - risk_accept: explicit (product, cwe, reason) allow-list
"""

from __future__ import annotations
import re
from typing import Dict, List, Optional
from .models import Finding, SEVERITY_LEVELS


def _matches_any(text: str, patterns: List[str]) -> Optional[str]:
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return pat
    return None


def filter_findings(findings: List[Finding], filter_cfg: Dict, product_cfg: Dict[str, Dict]) -> Dict[str, object]:
    """Applies filtering to the unique findings set. Returns {findings, metrics}."""
    drop_severity = filter_cfg.get("drop_severity", [])
    floor = max((SEVERITY_LEVELS.get(s, -1) for s in drop_severity), default=-1)
    fp_patterns = filter_cfg.get("fp_patterns", [])
    risk_accept = filter_cfg.get("risk_accept", [])
    accept_keys = {(str(r.get("product")), str(r.get("cwe", "")).upper()) for r in risk_accept}

    quarantine_by_rule: Dict[str, int] = {}
    active = 0

    for f in findings:
        if f.status == "quarantined":
            continue
        rule = None
        key = (f.product, (f.cwe or "").upper())

        if key in accept_keys:
            rule = "risk_accept"
        elif f.severity_num <= floor:
            rule = f"severity in ({','.join(drop_severity)})" if drop_severity else "severity: below configured floor"
        elif _matches_any(f"{f.title} {f.description}", fp_patterns):
            rule = f"fp_pattern:{_matches_any(f'{f.title} {f.description}', fp_patterns)}"

        if rule:
            f.status = "quarantined"
            f.quarantine_reason = rule
            quarantine_by_rule[rule] = quarantine_by_rule.get(rule, 0) + 1
        else:
            active += 1

    total = len(findings)
    return {
        "findings": findings,
        "metrics": {
            "after_dedup": total,
            "active": active,
            "quarantined": total - active,
            "quarantine_by_rule": quarantine_by_rule,
        },
    }
