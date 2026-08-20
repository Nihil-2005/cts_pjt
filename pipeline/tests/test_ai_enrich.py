"""Tests for the 3-tier hybrid AI enrichment: Groq → Ollama → Rule-based."""
import json
import unittest
from unittest.mock import patch, MagicMock

from pipeline.models import Finding
from pipeline.ai_enrich import (
    ai_enrich, _classify_fp, _ai_remediation, _executive_brief,
    GroqClient, OllamaClient, _safe_json_array,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Rule-based heuristics
# ═══════════════════════════════════════════════════════════════════════════════

class TestFPClassification(unittest.TestCase):
    def test_known_fp_pattern_high_probability(self):
        f = Finding(scanner="zap", product="app", title="Server Header Missing",
                    severity="low", cwe="CWE-200")
        prob, reason = _classify_fp(f)
        self.assertGreater(prob, 0.5)
        self.assertIn("server header", reason.lower())

    def test_sqli_is_not_fp(self):
        f = Finding(scanner="nuclei", product="app", title="SQL Injection",
                    severity="high", cwe="CWE-89",
                    endpoint="http://app:3000/api", evidence="UNION SELECT")
        prob, _ = _classify_fp(f)
        self.assertLess(prob, 0.5)

    def test_kev_reduces_fp(self):
        f = Finding(scanner="nuclei", product="app", title="Vuln",
                    severity="high", cwe="CWE-89", cve="CVE-2024-0001")
        f.kev = True
        prob_kev, _ = _classify_fp(f)

        f2 = Finding(scanner="nuclei", product="app", title="Vuln",
                     severity="high", cwe="CWE-89", cve="CVE-2024-0001")
        prob_no_kev, _ = _classify_fp(f2)
        self.assertLess(prob_kev, prob_no_kev)

    def test_score_in_valid_range(self):
        f = Finding(scanner="zap", product="app", title="Test",
                    severity="medium", cwe="CWE-79")
        prob, _ = _classify_fp(f)
        self.assertGreaterEqual(prob, 0.0)
        self.assertLessEqual(prob, 1.0)


class TestAIRemediation(unittest.TestCase):
    def test_known_cwe(self):
        f = Finding(scanner="zap", product="app", title="SQLi",
                    severity="high", cwe="CWE-89")
        rem = _ai_remediation(f)
        self.assertIn("parameterized", rem.lower())

    def test_trivy_package(self):
        f = Finding(scanner="trivy", product="app", title="Log4j",
                    severity="critical", cve="CVE-2021-44228",
                    package="log4j-core", fixed_version="2.17.1")
        rem = _ai_remediation(f)
        self.assertIn("log4j-core", rem)

    def test_kev_mentioned(self):
        f = Finding(scanner="nuclei", product="app", title="X",
                    severity="critical", cve="CVE-2021-44228", cwe="CWE-502")
        f.kev = True
        self.assertIn("CISA", _ai_remediation(f))


class TestExecutiveBrief(unittest.TestCase):
    def test_basic_brief(self):
        f = Finding(scanner="nuclei", product="app", title="Critical",
                    severity="critical", score=95)
        f.kev = True
        stats = {"raw_findings": 100, "unique_findings": 60,
                 "final_findings": 40, "p1": 3, "p2": 5}
        brief = _executive_brief([f], stats)
        self.assertIn("100", brief)
        self.assertIn("P1", brief)


# ═══════════════════════════════════════════════════════════════════════════════
# Groq client
# ═══════════════════════════════════════════════════════════════════════════════

class TestGroqClient(unittest.TestCase):
    @patch("pipeline.ai_enrich.urllib.request.urlopen")
    def test_is_available_true(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "choices": [{"message": {"content": "ok"}}]
        }).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = GroqClient(api_key="test-key")
        self.assertTrue(client.is_available())

    @patch("pipeline.ai_enrich.urllib.request.urlopen")
    def test_is_available_no_key(self, mock_urlopen):
        client = GroqClient(api_key="")
        self.assertFalse(client.is_available())

    @patch("pipeline.ai_enrich.urllib.request.urlopen")
    def test_chat(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "choices": [{"message": {"content": "test response"}}]
        }).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = GroqClient(api_key="test-key")
        result = client.chat("system", "user")
        self.assertEqual(result, "test response")


# ═══════════════════════════════════════════════════════════════════════════════
# Ollama client
# ═══════════════════════════════════════════════════════════════════════════════

class TestOllamaClient(unittest.TestCase):
    @patch("pipeline.ai_enrich.urllib.request.urlopen")
    def test_is_available_true(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "models": [{"name": "qwen2:1.5b"}]
        }).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        self.assertTrue(OllamaClient(model="qwen2:1.5b").is_available())

    @patch("pipeline.ai_enrich.urllib.request.urlopen")
    def test_is_available_false(self, mock_urlopen):
        mock_urlopen.side_effect = ConnectionRefusedError()
        self.assertFalse(OllamaClient(model="qwen2:1.5b").is_available())


# ═══════════════════════════════════════════════════════════════════════════════
# JSON helper
# ═══════════════════════════════════════════════════════════════════════════════

class TestSafeJsonArray(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(len(_safe_json_array('[{"a":1}]', 1)), 1)
    def test_fenced(self):
        self.assertEqual(len(_safe_json_array('```json\n[]\n```', 2)), 2)
    def test_short_padded(self):
        self.assertEqual(len(_safe_json_array('[{}]', 3)), 3)
    def test_invalid(self):
        self.assertEqual(len(_safe_json_array('garbage', 2)), 2)


# ═══════════════════════════════════════════════════════════════════════════════
# Full ai_enrich — rule-based only (no AI)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAIEnrichRuleOnly(unittest.TestCase):
    def test_basic(self):
        findings = [
            Finding(scanner="nuclei", product="app", title="SQL Injection",
                    severity="high", cwe="CWE-89"),
            Finding(scanner="zap", product="app", title="Server Header",
                    severity="low", cwe="CWE-200"),
        ]
        result = ai_enrich(findings, ollama_model="", groq_api_key="")
        self.assertTrue(result["used"])
        self.assertFalse(result["llm_used"])
        self.assertEqual(result["llm_tier"], "rule-based")
        self.assertEqual(result["counts"]["fp_classified"], 2)

    def test_quarantined_excluded(self):
        f = Finding(scanner="zap", product="app", title="X", severity="info")
        f.status = "quarantined"
        result = ai_enrich([f], ollama_model="", groq_api_key="")
        self.assertEqual(result["counts"]["fp_classified"], 0)

    def test_empty(self):
        result = ai_enrich([], ollama_model="", groq_api_key="")
        self.assertTrue(result["used"])

    def test_executive_brief(self):
        f = Finding(scanner="nuclei", product="app", title="X",
                    severity="high", cwe="CWE-89", score=75)
        stats = {"raw_findings": 50, "unique_findings": 30,
                 "final_findings": 20, "p1": 1, "p2": 3}
        result = ai_enrich([f], summary_stats=stats,
                           ollama_model="", groq_api_key="")
        self.assertGreater(len(result["executive_brief"]), 0)

    def test_skip_remediation(self):
        f = Finding(scanner="nuclei", product="app", title="X",
                    severity="high", cwe="CWE-89")
        result = ai_enrich([f], skip_remediation=True,
                           ollama_model="", groq_api_key="")
        self.assertEqual(result["counts"]["remediation"], 0)


# ═══════════════════════════════════════════════════════════════════════════════
# Full ai_enrich — Groq enhanced
# ═══════════════════════════════════════════════════════════════════════════════

class TestAIEnrichGroq(unittest.TestCase):
    @patch("pipeline.ai_enrich.GroqClient")
    def test_groq_enhances(self, MockGroq):
        mock = MockGroq.return_value
        mock.is_available.return_value = True
        mock.model = "llama3-70b-8192"
        mock.chat.side_effect = [
            json.dumps([{"fp_probability": 0.1, "fp_reason": "Real SQLi"}]),
            json.dumps(["Block endpoint. Use parameterized queries."]),
            "Critical risk. Fix immediately.",
        ]
        findings = [Finding(scanner="nuclei", product="app", title="SQLi",
                            severity="high", cwe="CWE-89")]
        findings[0].score = 75.0
        stats = {"raw_findings": 10, "unique_findings": 8,
                 "final_findings": 5, "p1": 1, "p2": 0}
        result = ai_enrich(findings, summary_stats=stats,
                           ollama_model="", groq_api_key="test-key")
        self.assertTrue(result["llm_used"])
        self.assertEqual(result["llm_tier"], "groq")
        self.assertIn("groq", findings[0].score_breakdown.get("ai_fp_source", ""))


# ═══════════════════════════════════════════════════════════════════════════════
# Full ai_enrich — Ollama enhanced
# ═══════════════════════════════════════════════════════════════════════════════

class TestAIEnrichOllama(unittest.TestCase):
    @patch("pipeline.ai_enrich.OllamaClient")
    def test_ollama_enhances(self, MockOllama):
        mock = MockOllama.return_value
        mock.is_available.return_value = True
        mock.model = "qwen2:1.5b"
        mock.chat.side_effect = [
            json.dumps([{"fp_probability": 0.15, "fp_reason": "Real vuln"}]),
            json.dumps(["Block endpoint. Patch the component."]),
            "Moderate risk. Fix within SLA.",
        ]
        findings = [Finding(scanner="nuclei", product="app", title="XSS",
                            severity="medium", cwe="CWE-79")]
        findings[0].score = 50.0
        stats = {"raw_findings": 5, "unique_findings": 4,
                 "final_findings": 3, "p1": 0, "p2": 1}
        result = ai_enrich(findings, summary_stats=stats,
                           ollama_model="qwen2:1.5b", groq_api_key="")
        self.assertTrue(result["llm_used"])
        self.assertEqual(result["llm_tier"], "ollama")


# ═══════════════════════════════════════════════════════════════════════════════
# Cascade: Groq fails → falls back to Ollama
# ═══════════════════════════════════════════════════════════════════════════════

class TestCascade(unittest.TestCase):
    @patch("pipeline.ai_enrich.GroqClient")
    @patch("pipeline.ai_enrich.OllamaClient")
    def test_groq_fails_ollama_works(self, MockOllama, MockGroq):
        MockGroq.return_value.is_available.return_value = False
        mock = MockOllama.return_value
        mock.is_available.return_value = True
        mock.model = "qwen2:1.5b"
        mock.chat.side_effect = [
            json.dumps([{"fp_probability": 0.2, "fp_reason": "Real"}]),
            json.dumps(["Fix it."]),
            "Risk.",
        ]
        findings = [Finding(scanner="nuclei", product="app", title="V",
                            severity="high", cwe="CWE-89")]
        findings[0].score = 70.0
        result = ai_enrich(findings, summary_stats={"raw_findings": 1},
                           ollama_model="qwen2:1.5b", groq_api_key="test-key")
        self.assertTrue(result["llm_used"])
        self.assertEqual(result["llm_tier"], "ollama")

    @patch("pipeline.ai_enrich.GroqClient")
    @patch("pipeline.ai_enrich.OllamaClient")
    def test_both_fail_rule_based(self, MockOllama, MockGroq):
        MockGroq.return_value.is_available.return_value = False
        MockOllama.return_value.is_available.return_value = False
        findings = [Finding(scanner="nuclei", product="app", title="V",
                            severity="high", cwe="CWE-89")]
        result = ai_enrich(findings, ollama_model="x", groq_api_key="x")
        self.assertFalse(result["llm_used"])
        self.assertEqual(result["llm_tier"], "rule-based")


if __name__ == "__main__":
    unittest.main()
