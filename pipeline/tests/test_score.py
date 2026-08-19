"""Unit tests for the 8-factor risk scoring module."""
import unittest

from pipeline.models import Finding
from pipeline.score import compute_score

WEIGHTS = {"cvss": 20, "epss": 20, "kev": 25, "exploit": 10, "asset": 10,
           "exposure": 5, "data": 5, "patch": 5}
PRODUCT = {"asset_criticality": 5, "business_impact": 5, "exposure": 5,
           "control_effectiveness": 3, "data_sensitivity": 5}


def mk(severity="high", cve=None, epss_pct=None, kev=False, exploit=False):
    f = Finding(scanner="trivy", product="app", title="t", severity=severity, cve=cve)
    f.epss_percentile = epss_pct
    f.kev = kev
    f.exploit_available = exploit
    return f


class TestScore(unittest.TestCase):
    def test_kev_medium_outranks_nonkev_high(self):
        """The rubric's 'not raw CVSS alone' test."""
        kev_medium = mk(severity="medium", epss_pct=0.9, kev=True, exploit=True)
        plain_high = mk(severity="high", epss_pct=0.05)
        compute_score(kev_medium, PRODUCT, WEIGHTS)
        compute_score(plain_high, PRODUCT, WEIGHTS)
        self.assertGreater(kev_medium.score, plain_high.score)

    def test_score_in_range_and_explainable(self):
        f = mk(severity="critical", epss_pct=1.0, kev=True, exploit=True)
        bd = compute_score(f, PRODUCT, WEIGHTS)
        self.assertLessEqual(f.score, 100)
        self.assertGreaterEqual(f.score, 0)
        comps = bd["components"]
        self.assertEqual(sum(comps.values()), f.score)
        self.assertIn("CISA KEV", " ".join(bd["drivers"]))

    def test_data_sensitivity_affects_score(self):
        """Higher data sensitivity should increase the score."""
        f1 = mk(severity="high")
        f2 = mk(severity="high")
        low_data = dict(PRODUCT, data_sensitivity=0)
        high_data = dict(PRODUCT, data_sensitivity=10)
        compute_score(f1, low_data, WEIGHTS)
        compute_score(f2, high_data, WEIGHTS)
        self.assertGreater(f2.score, f1.score)

    def test_maximum_components(self):
        f = mk(severity="critical", epss_pct=1.0, kev=True, exploit=True)
        bd = compute_score(f, {k: 10 for k in
                              ("asset_criticality", "business_impact", "exposure",
                               "control_effectiveness", "data_sensitivity")}, WEIGHTS)
        self.assertEqual(bd["components"]["kev"], 25)
        self.assertEqual(bd["components"]["exploit"], 10)

    def test_patch_reduces_score(self):
        """Having a fix available reduces the score."""
        f1 = mk(severity="high", cve="CVE-2024-0001")
        f1.fixed_version = None
        f2 = mk(severity="high", cve="CVE-2024-0002")
        f2.fixed_version = "1.2.3"
        compute_score(f1, PRODUCT, WEIGHTS)
        compute_score(f2, PRODUCT, WEIGHTS)
        self.assertGreater(f1.score, f2.score)



if __name__ == "__main__":
    unittest.main()
