"""Core data models: Finding, AttackPath, RunSummary."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SEVERITY_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_CVSS_APPROX = {
    "critical": 9.5, "high": 8.0, "medium": 6.0, "low": 3.5, "info": 1.0,
}


def normalize_severity(value: Any) -> str:
    """Map any scanner severity string to critical|high|medium|low|info."""
    if value is None:
        return "info"
    v = str(value).strip().lower()
    if v.startswith("crit"):
        return "critical"
    if v.startswith("high"):
        return "high"
    if v.startswith("med") or v.startswith("mod") or v.startswith("important"):
        return "medium"
    if v.startswith("low"):
        return "low"
    if v in ("informational", "info", "none", "unknown", ""):
        return "info"
    return "info"


@dataclass
class Finding:
    scanner: str
    product: str
    title: str
    severity: str
    cve: Optional[str] = None
    cwe: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    description: str = ""
    remediation: Optional[str] = None
    evidence: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    dedup_key: Optional[str] = None
    group_id: Optional[str] = None
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    status: str = "active"
    quarantine_reason: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_trend: Optional[float] = None
    kev: bool = False
    kev_date: Optional[str] = None
    exploit_available: bool = False
    exploit_source: Optional[str] = None
    nvd_cvss: Optional[float] = None
    score: Optional[float] = None
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    priority: Optional[str] = None
    sla_hours: Optional[int] = None
    owner: Optional[str] = None
    remediation_suggestions: List[Dict[str, Any]] = field(default_factory=list)
    escalation_potential: Optional[float] = None
    found_at: Optional[str] = None

    @property
    def severity_num(self) -> float:
        return SEVERITY_LEVELS.get(self.severity, 0)

    @property
    def effective_cvss(self) -> Optional[float]:
        if self.nvd_cvss is not None:
            return self.nvd_cvss
        cv = self.raw.get("cvss_score") if isinstance(self.raw, dict) else None
        if isinstance(cv, (int, float)) and 0 <= cv <= 10:
            return float(cv)
        return SEVERITY_CVSS_APPROX.get(self.severity)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("raw", None)
        return d

    def to_row(self) -> Dict[str, Any]:
        row = self.to_dict()
        for k, v in self.score_breakdown.items():
            row[f"sb_{k}"] = v if not isinstance(v, dict) else json.dumps(v)
        row["remediation_summary"] = " | ".join(
            f"[{s.get('kind')}] {s.get('text', '')[:120]}"
            for s in self.remediation_suggestions
        )
        return row

    def __repr__(self) -> str:
        return f"<Finding {self.scanner}/{self.product} {self.severity} {self.title[:40]}>"


@dataclass
class AttackPath:
    product: str
    from_cwe: str
    to_cwe: str
    chainability: float
    probability: float
    factors: List[str] = field(default_factory=list)
    capec_ref: Optional[str] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RunSummary:
    run_date: str
    products: List[str]
    raw_findings: int = 0
    unique_findings: int = 0
    quarantined: int = 0
    final_findings: int = 0
    dedup_pct: float = 0.0
    avg_score: float = 0.0
    top_score: float = 0.0
    p1: int = 0
    p2: int = 0
    p3: int = 0
    p4: int = 0
    enrich_counts: Dict[str, int] = field(default_factory=dict)
    quarantine_by_rule: Dict[str, int] = field(default_factory=dict)
    attack_paths: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
