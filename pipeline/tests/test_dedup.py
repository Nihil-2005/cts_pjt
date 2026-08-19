"""Unit tests for cross-scanner deduplication."""
import unittest

from pipeline.models import Finding
from pipeline.dedup import deduplicate


class TestDedup(unittest.TestCase):
    def test_cve_dedup(self):
        """Same CVE from two scanners should be deduplicated."""
        f1 = Finding(scanner="nuclei", product="app", title="Log4Shell",
                     severity="critical", cve="CVE-2021-44228")
        f2 = Finding(scanner="trivy", product="app", title="Log4j RCE",
                     severity="critical", cve="CVE-2021-44228")
        result = deduplicate([f1, f2])
        self.assertEqual(result["metrics"]["unique"], 1)
        self.assertEqual(result["metrics"]["by_pass"]["cve"], 1)

    def test_endpoint_cwe_dedup(self):
        """Same endpoint+CWE from two scanners should be deduplicated."""
        f1 = Finding(scanner="zap", product="app", title="XSS",
                     severity="medium", cwe="CWE-79",
                     endpoint="http://app:3000/search")
        f2 = Finding(scanner="wapiti", product="app", title="XSS in search",
                     severity="medium", cwe="CWE-79",
                     endpoint="http://app:3000/search")
        result = deduplicate([f1, f2])
        self.assertEqual(result["metrics"]["unique"], 1)
        self.assertEqual(result["metrics"]["by_pass"]["endpoint"], 1)

    def test_different_findings_not_deduped(self):
        """Different findings should not be deduplicated."""
        f1 = Finding(scanner="zap", product="app", title="XSS",
                     severity="medium", cwe="CWE-79",
                     endpoint="http://app:3000/search")
        f2 = Finding(scanner="nuclei", product="app", title="SQLi",
                     severity="high", cwe="CWE-89",
                     endpoint="http://app:3000/api")
        result = deduplicate([f1, f2])
        self.assertEqual(result["metrics"]["unique"], 2)
        self.assertEqual(result["metrics"]["dedup_pct"], 0.0)

    def test_canonical_picks_most_severe(self):
        """The canonical finding should be the most severe one."""
        f1 = Finding(scanner="nuclei", product="app", title="Low",
                     severity="low", cve="CVE-2024-0001")
        f2 = Finding(scanner="trivy", product="app", title="Critical",
                     severity="critical", cve="CVE-2024-0001")
        result = deduplicate([f1, f2])
        unique = [f for f in result["findings"] if not f.is_duplicate]
        self.assertEqual(unique[0].severity, "critical")

    def test_fuzzy_title_dedup(self):
        """Fuzzy title matching should collapse similar scanner titles."""
        f1 = Finding(scanner="zap", product="app",
                     title="Information Disclosure - Backup File Found",
                     severity="medium", cwe="CWE-200",
                     endpoint="http://app:3000/backup")
        f2 = Finding(scanner="nuclei", product="app",
                     title="Backup File Found (Information Disclosure)",
                     severity="medium", cwe="CWE-200",
                     endpoint="http://app:3000/backup")
        result = deduplicate([f1, f2], fuzzy=True)
        self.assertEqual(result["metrics"]["unique"], 1)

    def test_empty_findings(self):
        """Empty input should return empty output."""
        result = deduplicate([])
        self.assertEqual(result["metrics"]["raw"], 0)
        self.assertEqual(result["metrics"]["unique"], 0)


if __name__ == "__main__":
    unittest.main()
