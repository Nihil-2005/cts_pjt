"""Unit tests for scanner report normalization."""
import unittest

from pipeline.normalize import parse_zap, parse_nuclei, parse_wapiti, parse_trivy


class TestNormalize(unittest.TestCase):
    def test_parse_zap(self):
        data = {"site": [{"@name": "http://app:3000", "alerts": [
            {"name": "XSS", "riskdesc": "High", "cweid": 79,
             "url": "http://app:3000/search", "param": "q",
             "desc": "XSS found", "solution": "Encode output"}
        ]}]}
        findings = parse_zap(data, "app")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].cwe, "CWE-79")
        self.assertEqual(findings[0].scanner, "zap")

    def test_parse_nuclei(self):
        data = [{"template-id": "log4shell", "info": {
            "name": "Log4Shell", "severity": "critical",
            "classification": {"cve-id": ["CVE-2021-44228"],
                               "cwe-id": ["CWE-502"]}},
            "matched-at": "http://app:3000/"}]
        findings = parse_nuclei(data, "app")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cve, "CVE-2021-44228")
        self.assertEqual(findings[0].severity, "critical")

    def test_parse_trivy(self):
        data = {"Results": [{"Target": "app:latest", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-0001", "Severity": "HIGH",
             "PkgName": "libfoo", "InstalledVersion": "1.0",
             "FixedVersion": "1.1", "Title": "Foo vuln"}
        ]}]}
        findings = parse_trivy(data, "app")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].package, "libfoo")
        self.assertEqual(findings[0].fixed_version, "1.1")

    def test_parse_wapiti(self):
        data = {
            "vulnerabilities": {"XSS": [
                {"level": 2, "path": "/search", "parameter": "q",
                 "info": "Reflected XSS"}]},
            "classifications": {"XSS": {
                "desc": "XSS", "sol": "Encode",
                "ref": {"CWE-79": "https://cwe.mitre.org/79"}}}}
        findings = parse_wapiti(data, "app")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-79")


if __name__ == "__main__":
    unittest.main()
