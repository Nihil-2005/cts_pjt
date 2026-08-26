"""Contextual risk scoring (0-100, explainable).

Eight factors: cvss, epss, kev, exploit, asset, exposure, data, patch.
Each has a configurable weight summing to 100.
"""

from __future__ import annotations
from typing import Any, Dict
from .models import Finding


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))


def compute_score(f: Finding, product_cfg: Dict, weights: Dict[str, Any]) -> Dict[str, Any]:
    """Returns updated score_breakdown; also sets f.score."""
    cvss = f.effective_cvss or 1.0
    epss_prob = f.epss_score if f.epss_score is not None else 0.0
    asset = float(product_cfg.get("asset_criticality", 5))
    exposure = float(product_cfg.get("exposure", 5))
    data_sensitivity = float(product_cfg.get("data_sensitivity", 5))

    w = {k: float(weights.get(k, 0)) for k in ("cvss", "epss", "kev", "exploit", "asset", "exposure", "data", "patch")}

    has_patch = 1.0 if f.fixed_version else 0.0

    components = {
        "cvss": round(_clamp(cvss / 10.0) * w["cvss"], 1),
        "epss": round(_clamp(epss_prob) * w["epss"], 1),
        "kev": w["kev"] if f.kev else 0.0,
        "exploit": w["exploit"] if f.exploit_available else 0.0,
        "asset": round(_clamp(asset / 10.0) * w["asset"], 1),
        "exposure": round(_clamp(exposure / 10.0) * w["exposure"], 1),
        "data": round(_clamp(data_sensitivity / 10.0) * w["data"], 1),
        "patch": -round(_clamp(has_patch) * w["patch"], 1),
    }
    total = round(_clamp(sum(components.values())), 1)

    reasons = []
    if f.kev:
        reasons.append("in CISA KEV (known exploited)")
    if f.epss_score is not None and f.epss_score > 0:
        reasons.append(f"EPSS probability {f.epss_score:.3f} ({f.epss_score*100:.1f}% in 30d)")
    if f.epss_percentile is not None:
        reasons.append(f"EPSS percentile {f.epss_percentile:.3f}")
    if f.exploit_available:
        reasons.append(f"public exploit ({f.exploit_source})")
    if f.epss_trend is not None and f.epss_trend > 0.001:
        reasons.append(f"EPSS rising +{f.epss_trend:.3f}/7d")
    if f.fixed_version:
        reasons.append(f"patch available ({f.fixed_version})")

    breakdown = {"total": total, "components": components, "drivers": reasons}
    f.score = total
    f.score_breakdown = breakdown
    return breakdown
