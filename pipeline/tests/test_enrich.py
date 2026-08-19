"""Unit tests for threat intelligence enrichment."""
import os
import tempfile
import unittest

from pipeline.models import Finding
from pipeline.enrich import Enricher, Fetcher


class FakeFetcher(Fetcher):
    def get_json(self, url, headers=None, timeout=20):
        if "known_exploited" in url or "kev" in url:
            return {"vulnerabilities": [
                {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}
        if "epss" in url and "date=" in url:
            return {"data": [{"cve": "CVE-2021-44228", "epss": "0.500000000"}]}
        if "epss" in url:
            return {"data": [{"cve": "CVE-2021-44228", "epss": "0.999990000",
                              "percentile": "1.000000000"}]}
        if "nvd" in url:
            return {"vulnerabilities": [{"cve": {"metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]}}}]}
        return {}


class TestEnrich(unittest.TestCase):
    def test_kev_enrichment(self):
        """KEV-listed CVE should be marked as exploited."""
        f = Finding(scanner="nuclei", product="app", title="Log4Shell",
                    severity="critical", cve="CVE-2021-44228")
        with tempfile.TemporaryDirectory() as td:
            enricher = Enricher({"cache_dir": td, "use_nvd": True,
                                 "use_searchsploit": False,
                                 "kev_url": "http://fake/kev",
                                 "epss_url": "http://fake/epss",
                                 "nvd_url": "http://fake/nvd",
                                 "cache_ttl_days": 1},
                                fetcher=FakeFetcher())
            enricher.enrich([f], use_searchsploit=False)
        self.assertTrue(f.kev)
        self.assertTrue(f.exploit_available)

    def test_epss_enrichment(self):
        """EPSS data should be populated for known CVEs."""
        f = Finding(scanner="trivy", product="app", title="Log4j",
                    severity="critical", cve="CVE-2021-44228")
        with tempfile.TemporaryDirectory() as td:
            enricher = Enricher({"cache_dir": td, "use_nvd": True,
                                 "use_searchsploit": False,
                                 "kev_url": "http://fake/kev",
                                 "epss_url": "http://fake/epss",
                                 "nvd_url": "http://fake/nvd",
                                 "cache_ttl_days": 1},
                                fetcher=FakeFetcher())
            enricher.enrich([f], use_searchsploit=False)
        self.assertIsNotNone(f.epss_score)
        self.assertGreater(f.epss_score, 0)

    def test_counts_dict(self):
        """counts_dict should return enrichment statistics."""
        with tempfile.TemporaryDirectory() as td:
            enricher = Enricher({"cache_dir": td, "use_nvd": False,
                                 "use_searchsploit": False,
                                 "kev_url": "http://fake/kev",
                                 "epss_url": "http://fake/epss",
                                 "cache_ttl_days": 1},
                                fetcher=FakeFetcher())
            counts = enricher.counts_dict()
        self.assertIn("kev", counts)
        self.assertIn("epss", counts)


if __name__ == "__main__":
    unittest.main()
