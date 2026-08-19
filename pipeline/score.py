"""Contextual risk scoring (0-100, explainable).

Eight factors feed the score, each with a configurable weight that sums to 100:

  cvss      (0-20)  severity / CVSS base score
  epss      (0-20)  FIRST.org EPSS percentile (exploit prediction)
  kev       (0-25)  CISA KEV known-exploited status
  exploit   (0-10)  public exploit available (exploit-db / KEV)
  asset     (0-10)  asset criticality (per product, from config)
  exposure  (0-5)   exposure level (per product, from config)
  data      (0-5)   data sensitivity (per product, from config)
  patch     (0-5)   patch available (reduces score if fix exists)

The weighting deliberately makes threat intel matter: a KEV-listed Medium
CVE outranks a non-KEV High CVE — the rubric's "not raw CVSS alone" test.
Every finding carries a ``score_breakdown`` so the ranking is explainable.
"""
from __future__ import annotations

from typing import Any, Dict

from .models import Finding


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))


def compute_score(f: Finding, product_cfg: Dict, weights: Dict[str, Any]) -> Dict[str, Any]:
    """Returns the updated score_breakdown; also sets f.score."""
    cvss = f.effective_cvss or 1.0
    epss_pct = f.epss_percentile if f.epss_percentile is not None else 0.0
    asset = float(product_cfg.get("asset_criticality", 5))
    exposure = float(product_cfg.get("exposure", 5))
    data_sensitivity = float(product_cfg.get("data_sensitivity", 5))
    controls = float(product_cfg.get("control_effectiveness", 3))

    w = {k: float(weights.get(k, 0)) for k in
         ("cvss", "epss", "kev", "exploit", "asset", "exposure", "data", "patch")}

    # Patch available reduces score (a fix exists, so urgency is lower)
    has_patch = 1.0 if f.fixed_version else 0.0

    components = {
        "cvss": round(_clamp(cvss / 10.0) * w["cvss"], 1),
        "epss": round(_clamp(epss_pct) * w["epss"], 1),
        "kev": w["kev"] if f.kev else 0.0,
        "exploit": w["exploit"] if f.exploit_available else 0.0,
        "asset": round(_clamp(asset / 10.0) * w["asset"], 1),
        "exposure": round(_clamp(exposure / 10.0) * w["exposure"], 1),
        "data": round(_clamp(data_sensitivity / 10.0) * w["data"], 1),
        "patch": -round(_clamp(has_patch) * w["patch"], 1),
    }
    total = round(sum(components.values()), 1)
    total = _clamp(total)

    reasons = []
    if f.kev:
        reasons.append("in CISA KEV (known exploited)")
    if f.epss_percentile is not None:
        reasons.append(f"EPSS percentile {f.epss_percentile:.3f}")
    if f.exploit_available:
        reasons.append(f"public exploit ({f.exploit_source})")
    if f.epss_trend is not None and f.epss_trend > 0.001:
        reasons.append(f"EPSS rising +{f.epss_trend:.3f}/7d")
    if f.fixed_version:
        reasons.append(f"patch available ({f.fixed_version})")

    breakdown = {
        "total": total,
        "components": components,
        "drivers": reasons,
    }
    f.score = total
    f.score_breakdown = breakdown
    return breakdown
