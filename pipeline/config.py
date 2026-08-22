"""Configuration loader.

The pipeline is driven by a single JSON config.  Every value has a sane default
so the pipeline runs with a minimal config file.
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, Optional

DEFAULT_CONFIG: Dict[str, Any] = {
    "products": {},
    "scoring": {
        "weights": {
            "cvss": 20, "epss": 20, "kev": 25, "exploit": 10,
            "asset": 10, "exposure": 5, "data": 5, "patch": 5,
        },
        "sla_bands": [
            {"min": 90, "priority": "P1", "sla_hours": 24},
            {"min": 70, "priority": "P2", "sla_hours": 72},
            {"min": 40, "priority": "P3", "sla_hours": 168},
            {"min": 0,  "priority": "P4", "sla_hours": 720},
        ],
    },
    "filter": {
        "drop_severity": ["info"],
        "fp_patterns": [
            "swagger", "backup file", "server header", "user agent",
            "cookie without httponly", "cookie without secure",
            "x-content-type-options", "x-frame-options", "x-xss-protection",
            "hsts", "content security policy", "cross-domain",
        ],
        "risk_accept": [],
    },
    "dedup": {
        "fuzzy_title": True,
    },
    "enrich": {
        "cache_dir": "intel",
        "use_nvd": True,
        "use_searchsploit": True,
        "kev_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "epss_url": "https://api.first.org/data/v1/epss",
        "nvd_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "cache_ttl_days": 1,
    },
    "reporting": {
        "top_n": 25,
        "ticket_threshold": 60,
        "auto_ticket": True,
        "github_labels": ["security", "auto-generated"],
    },
}

DEFAULT_PRODUCT: Dict[str, Any] = {
    "display_name": "",
    "owner": "appsec-team",
    "asset_criticality": 5,      # 0-10
    "business_impact": 5,        # 0-10
    "exposure": 5,               # 0-10 (10 = internet-facing)
    "control_effectiveness": 3,  # 0-10 (10 = strong controls, reduces score)
    "data_sensitivity": 5,       # 0-10
    "url": "",
}


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, data: Dict[str, Any]):
        self.data = deep_merge(DEFAULT_CONFIG, data or {})

    # ------------------------------------------------------------- accessors
    @property
    def products(self) -> Dict[str, Any]:
        return self.data["products"]

    @property
    def scoring(self) -> Dict[str, Any]:
        return self.data["scoring"]

    @property
    def weights(self) -> Dict[str, Any]:
        return self.scoring["weights"]

    @property
    def sla_bands(self) -> list:
        return self.scoring["sla_bands"]

    @property
    def filter_cfg(self) -> Dict[str, Any]:
        return self.data["filter"]

    @property
    def enrich_cfg(self) -> Dict[str, Any]:
        return self.data["enrich"]

    @property
    def reporting(self) -> Dict[str, Any]:
        return self.data["reporting"]

    @property
    def dedup_cfg(self) -> Dict[str, Any]:
        return self.data["dedup"]

    # ------------------------------------------------------------- helpers
    def product(self, name: str) -> Dict[str, Any]:
        p = dict(DEFAULT_PRODUCT)
        p.update(self.products.get(name, {}))
        if not p.get("display_name"):
            p["display_name"] = name.replace("_", " ").title()
        return p

    def sla_for(self, score: float) -> Dict[str, Any]:
        for band in sorted(self.sla_bands, key=lambda b: -b["min"]):
            if score >= band["min"]:
                return band
        return self.sla_bands[-1]

    def product_names(self) -> list:
        return list(self.products.keys())

    # ------------------------------------------------------------- io
    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                return cls(json.load(fh))
        return cls({})

    def save(self, path: str) -> None:
        """Atomic write: write to temp file then rename for crash safety."""
        dir_name = os.path.dirname(path) or "."
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2)
            os.replace(tmp_path, path)  # Atomic on POSIX; near-atomic on Windows
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
