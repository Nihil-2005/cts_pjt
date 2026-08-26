"""Unit tests for attack path mapping."""
import unittest

from pipeline.models import Finding
from pipeline.attackpath import build_attack_paths, attach_escalation_potential


class TestAttackPath(unittest.TestCase):
    def test_single_chain(self):
        """CWE-502 + CWE-94 should produce the deserialization->RCE chain."""
        findings = [
            Finding(scanner="nuclei", product="app", title="Deser",
                    severity="critical", cwe="CWE-502"),
            Finding(scanner="nuclei", product="app", title="RCE",
                    severity="high", cwe="CWE-94"),
        ]
        paths = build_attack_paths(findings, "app", {"exposure": 8})
        self.assertTrue(len(paths) >= 1)
        chain = [p for p in paths if p.from_cwe == "CWE-502" and p.to_cwe == "CWE-94"]
        self.assertEqual(len(chain), 1)
        self.assertGreater(chain[0].probability, 0)

    def test_no_paths_when_missing_cwe(self):
        """No paths if only one end of a chain exists."""
        findings = [
            Finding(scanner="zap", product="app", title="XSS",
                    severity="medium", cwe="CWE-79"),
        ]
        paths = build_attack_paths(findings, "app", {"exposure": 5})
        self.assertEqual(len(paths), 0)

    def test_escalation_potential(self):
        """Findings at the start of a chain should have escalation_potential > 0."""
        findings = [
            Finding(scanner="nuclei", product="app", title="Deser",
                    severity="critical", cwe="CWE-502"),
            Finding(scanner="nuclei", product="app", title="RCE",
                    severity="high", cwe="CWE-94"),
        ]
        paths = build_attack_paths(findings, "app", {"exposure": 8})
        attach_escalation_potential(findings, paths)
        deser = [f for f in findings if f.cwe == "CWE-502"][0]
        self.assertGreater(deser.escalation_potential, 0)

    def test_empty_findings(self):
        """No findings should produce no paths."""
        paths = build_attack_paths([], "app", {"exposure": 5})
        self.assertEqual(len(paths), 0)


if __name__ == "__main__":
    unittest.main()
