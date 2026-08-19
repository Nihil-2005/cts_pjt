"""Unit tests for auditable noise filtering."""
import unittest

from pipeline.models import Finding
from pipeline.filter import filter_findings

FILTER_CFG = {
    "drop_severity": ["info"],
    "fp_patterns": ["server header", "swagger"],
    "risk_accept": [],
}
PRODUCT_CFG = {"app": {"asset_criticality": 5}}


class TestFilter(unittest.TestCase):
    def test_info_findings_quarantined(self):
        """Info-severity findings should be quarantined."""
        f1 = Finding(scanner="zap", product="app", title="XSS",
                     severity="medium", cwe="CWE-79")
        f2 = Finding(scanner="zap", product="app", title="Server header",
                     severity="info", cwe="CWE-200")
        result = filter_findings([f1, f2], FILTER_CFG, PRODUCT_CFG)
        self.assertEqual(result["metrics"]["active"], 1)
        self.assertEqual(result["metrics"]["quarantined"], 1)

    def test_fp_pattern_quarantined(self):
        """Findings matching FP patterns should be quarantined."""
        f1 = Finding(scanner="zap", product="app", title="Server Header Missing",
                     severity="low", cwe="CWE-200",
                     description="Server header not set")
        result = filter_findings([f1], FILTER_CFG, PRODUCT_CFG)
        self.assertEqual(result["metrics"]["quarantined"], 1)
        self.assertIn("fp_pattern", f1.quarantine_reason)

    def test_active_findings_preserved(self):
        """Non-matching findings should remain active."""
        f1 = Finding(scanner="zap", product="app", title="SQL Injection",
                     severity="high", cwe="CWE-89")
        result = filter_findings([f1], FILTER_CFG, PRODUCT_CFG)
        self.assertEqual(result["metrics"]["active"], 1)
        self.assertEqual(result["metrics"]["quarantined"], 0)

    def test_quarantine_by_rule_breakdown(self):
        """Quarantine should track which rule caused each drop."""
        f1 = Finding(scanner="zap", product="app", title="Info finding",
                     severity="info")
        f2 = Finding(scanner="zap", product="app", title="Swagger endpoint",
                     severity="low")
        result = filter_findings([f1, f2], FILTER_CFG, PRODUCT_CFG)
        rules = result["metrics"]["quarantine_by_rule"]
        self.assertEqual(sum(rules.values()), 2)


if __name__ == "__main__":
    unittest.main()
