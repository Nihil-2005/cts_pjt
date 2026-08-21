"""Tests for cross-scanner deduplication redundancy tracking."""
from __future__ import annotations

import unittest
from pipeline.models import Finding
from pipeline.dedup import deduplicate


class TestCrossScannerRedundancy(unittest.TestCase):
    """Verify that deduplicate() tracks which scanners found the same vulnerability."""

    def _make(self, scanner: str, product: str = "app", cve: str = None,
              title: str = "XSS", endpoint: str = "/api", cwe: str = "CWE-79") -> Finding:
        return Finding(
            scanner=scanner, product=product, title=title,
            severity="high", cve=cve, cwe=cwe,
            endpoint=endpoint, description="test",
        )

    def test_cross_scanner_redundancy_tracked(self):
        """Same CVE found by Nuclei, ZAP, and Trivy should be logged."""
        findings = [
            self._make("nuclei", cve="CVE-2024-1234", endpoint="/api"),
            self._make("zap", cve="CVE-2024-1234", endpoint="/api"),
            self._make("trivy", cve="CVE-2024-1234", endpoint="/api"),
        ]
        result = deduplicate(findings, fuzzy=False)
        metrics = result["metrics"]

        # Should be 1 unique finding (all 3 collapsed into 1)
        self.assertEqual(metrics["unique"], 1)
        self.assertGreater(metrics["dedup_pct"], 50)

        # Cross-scanner redundancy should be populated
        cross = metrics["cross_scanner_redundancy"]
        self.assertEqual(len(cross), 1)
        entry = cross[0]
        self.assertIn("nuclei", entry["scanners_found_it"])
        self.assertIn("zap", entry["scanners_found_it"])
        self.assertIn("trivy", entry["scanners_found_it"])
        self.assertEqual(entry["total_duplicates"], 2)

    def test_per_scanner_counts(self):
        """Pre-dedup counts per scanner should be tracked."""
        findings = [
            self._make("nuclei", cve="CVE-2024-1"),
            self._make("nuclei", cve="CVE-2024-2"),
            self._make("zap", cve="CVE-2024-1"),
            self._make("trivy", cve="CVE-2024-3"),
        ]
        result = deduplicate(findings, fuzzy=False)
        counts = result["metrics"]["per_scanner_counts"]
        self.assertEqual(counts["nuclei"], 2)
        self.assertEqual(counts["zap"], 1)
        self.assertEqual(counts["trivy"], 1)

    def test_no_cross_scanner_for_single_scanner(self):
        """Findings from only one scanner should not create cross-scanner entries."""
        findings = [
            self._make("nuclei", cve="CVE-2024-1"),
            self._make("nuclei", cve="CVE-2024-1"),  # dup from same scanner
        ]
        result = deduplicate(findings, fuzzy=False)
        cross = result["metrics"]["cross_scanner_redundancy"]
        # Same scanner dup = no cross-scanner entry
        self.assertEqual(len(cross), 0)

    def test_empty_findings(self):
        """Empty input should return zero metrics."""
        result = deduplicate([], fuzzy=False)
        self.assertEqual(result["metrics"]["raw"], 0)
        self.assertEqual(result["metrics"]["unique"], 0)
        self.assertEqual(result["metrics"]["cross_scanner_redundancy"], [])


if __name__ == "__main__":
    unittest.main()
