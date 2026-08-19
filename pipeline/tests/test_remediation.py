"""Unit tests for remediation suggestions."""
import unittest

from pipeline.models import Finding
from pipeline.remediation import suggest_remediation


class TestRemediation(unittest.TestCase):
    def test_cwe_guidance(self):
        """Known CWE should return specific guidance."""
        f = Finding(scanner="zap", product="app", title="SQLi",
                    severity="high", cwe="CWE-89")
        suggestions = suggest_remediation(f)
        self.assertGreaterEqual(len(suggestions), 2)
        self.assertEqual(suggestions[0]["kind"], "first_aid")
        self.assertEqual(suggestions[1]["kind"], "full_remediation")
        self.assertIn("parameterized", suggestions[1]["text"].lower())

    def test_trivy_package_specific(self):
        """Trivy findings with fixed_version should get package-specific advice."""
        f = Finding(scanner="trivy", product="app", title="Log4j",
                    severity="critical", cve="CVE-2021-44228",
                    package="log4j-core", installed_version="2.14.0",
                    fixed_version="2.17.1")
        suggestions = suggest_remediation(f)
        self.assertTrue(any("log4j-core" in s["text"] for s in suggestions))

    def test_unknown_cwe_generic(self):
        """Unknown CWE should fall back to generic guidance."""
        f = Finding(scanner="zap", product="app", title="Weird vuln",
                    severity="medium", cwe="CWE-9999")
        suggestions = suggest_remediation(f)
        self.assertGreaterEqual(len(suggestions), 2)

    def test_scanner_guidance_included(self):
        """If scanner provides remediation text, it should be included."""
        f = Finding(scanner="zap", product="app", title="XSS",
                    severity="medium", cwe="CWE-79",
                    remediation="Use output encoding")
        suggestions = suggest_remediation(f)
        kinds = [s["kind"] for s in suggestions]
        self.assertIn("scanner_guidance", kinds)


if __name__ == "__main__":
    unittest.main()
