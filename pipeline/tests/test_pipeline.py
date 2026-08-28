"""End-to-end pipeline integration test."""
import json
import os
import tempfile
import unittest

from pipeline.config import Config
from pipeline.enrich import Fetcher
from pipeline.run import run_pipeline


class FakeFetcher(Fetcher):
    """Fake fetcher that returns mock threat-intel data."""
    def get_json(self, url, headers=None, timeout=20):
        if "known_exploited" in url or "kev" in url:
            return {"vulnerabilities": [
                {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10",
                 "vendorProject": "Apache", "product": "Log4j"}]}
        if "epss" in url and "date=" in url:
            return {"data": [{"cve": "CVE-2021-44228", "epss": "0.500000000"}]}
        if "epss" in url:
            return {"data": [{"cve": "CVE-2021-44228", "epss": "0.999990000",
                              "percentile": "1.000000000"}]}
        if "nvd" in url:
            return {"vulnerabilities": [{"cve": {"metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]}}}]}
        return {}


def write_report(td, name, data):
    with open(os.path.join(td, name), "w") as fh:
        json.dump(data, fh)


class TestPipeline(unittest.TestCase):
    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as out:
            # zap + wapiti find the same XSS (dedup pair), nuclei+trivy same CVE
            write_report(td, "app_zap.json", {"site": [{"@name": "http://app:3000", "alerts": [
                {"name": "Reflected XSS", "riskdesc": "Medium", "cweid": 79,
                 "url": "http://app:3000/search", "param": "q", "desc": "xss"},
                {"name": "Info noise", "riskdesc": "Informational", "cweid": 200,
                 "url": "http://app:3000/", "desc": "server header"},
            ]}]})
            write_report(td, "app_wapiti.json", {
                "vulnerabilities": {"Cross Site Scripting": [
                    {"level": 2, "path": "http://app:3000/search", "parameter": "q",
                     "info": "XSS"}]},
                "classifications": {"Cross Site Scripting": {
                    "desc": "xss", "sol": "encode output",
                    "ref": {"CWE-79: XSS": "https://cwe.mitre.org/79"}}}})
            write_report(td, "app_nuclei.json", [{
                "template-id": "log4shell", "info": {
                    "name": "Log4Shell", "severity": "critical",
                    "classification": {"cve-id": ["CVE-2021-44228"],
                                       "cwe-id": ["CWE-502"]}},
                "matched-at": "http://app:3000/"}])
            write_report(td, "app_trivy.json", {"Results": [{
                "Target": "app:latest", "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2021-44228", "Severity": "CRITICAL",
                    "PkgName": "log4j-core", "InstalledVersion": "2.14.0",
                    "FixedVersion": "2.17.1", "Title": "Log4Shell",
                    "Description": "JNDI RCE"}]}]})
            # second nuclei finding carries CWE-94 (RCE) so the CWE-502 ->
            # CWE-94 deserialization->RCE chain has an active target
            write_report(td, "app_nuclei_extra.json", [{
                "template-id": "rce-check", "info": {
                    "name": "Code Execution", "severity": "high",
                    "classification": {"cwe-id": ["CWE-94"]}},
                "matched-at": "http://app:3000/admin"}])

            config = Config({"products": {"app": {"asset_criticality": 8,
                                                  "business_impact": 8, "exposure": 9,
                                                  "control_effectiveness": 2}},
                             "enrich": {"cache_dir": os.path.join(td, "cache")}})
            result = run_pipeline(td, config, out, products=["app"],
                                  skip_ai=True,
                                  use_searchsploit=False,
                                  fetcher=FakeFetcher())

            s = result["summary"]
            # raw = 2 zap + 1 wapiti + 1 nuclei + 1 trivy + 1 nuclei_extra = 6
            self.assertEqual(s.raw_findings, 6)
            # dedup: wapiti XSS dup of zap XSS (1), nuclei+trivy CVE dup (1) -> 4 unique
            self.assertEqual(s.unique_findings, 4)
            # filter drops the info-severity zap alert -> 3 final
            self.assertEqual(s.final_findings, 3)
            self.assertGreater(s.dedup_pct, 0)

            ranked = result["ranked"]
            self.assertEqual(len(ranked), 3)
            self.assertEqual(ranked[0].cve, "CVE-2021-44228")
            self.assertTrue(ranked[0].kev)
            self.assertGreater(ranked[0].score, 60)
            self.assertGreaterEqual(len(ranked[0].remediation_suggestions), 2)

            # attack paths: CWE-502 (Log4Shell) + CWE-94 (RCE) active -> the
            # deserialization->RCE chain from the CAPEC table must appear
            paths = result["attack_paths"]["app"]
            self.assertTrue(any(p["from_cwe"] == "CWE-502" and p["to_cwe"] == "CWE-94"
                                for p in paths))

            # outputs exist
            for fname in ("ranked_findings.csv", "ranked_findings.json",
                          "top_actions.md", "tickets_ready.md",
                          "noise_reduction.json", "risk_dashboard.html", "history.db"):
                self.assertTrue(os.path.exists(os.path.join(out, fname)), fname)

            with open(os.path.join(out, "noise_reduction.json")) as fh:
                metrics = json.load(fh)
            self.assertIn("dedup_pct", metrics)
            self.assertIn("quarantine_by_rule", metrics)
            self.assertGreaterEqual(metrics["noise_removed_pct"], 0)


if __name__ == "__main__":
    unittest.main()
