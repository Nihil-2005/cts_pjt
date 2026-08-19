"""Unit tests for ranking and output module."""
import unittest

from pipeline.models import Finding
from pipeline.output import rank_findings
from pipeline.config import Config


class TestRank(unittest.TestCase):
    def test_ranking_order(self):
        """Higher scores should rank first."""
        f1 = Finding(scanner="nuclei", product="app", title="Critical",
                     severity="critical", cve="CVE-2024-0001")
        f1.score = 95.0
        f2 = Finding(scanner="zap", product="app", title="Low",
                     severity="low")
        f2.score = 20.0
        config = Config({"products": {"app": {}}})
        ranked = rank_findings([f1, f2], config)
        self.assertEqual(ranked[0].score, 95.0)
        self.assertEqual(ranked[1].score, 20.0)

    def test_priority_assignment(self):
        """Findings should get correct priority based on score."""
        f = Finding(scanner="trivy", product="app", title="Critical",
                    severity="critical")
        f.score = 95.0
        config = Config({"products": {"app": {}}})
        ranked = rank_findings([f], config)
        self.assertEqual(ranked[0].priority, "P1")
        self.assertEqual(ranked[0].sla_hours, 24)

    def test_kev_tiebreak(self):
        """KEV findings should rank higher than non-KEV at same score."""
        f1 = Finding(scanner="nuclei", product="app", title="KEV",
                     severity="high")
        f1.score = 70.0
        f1.kev = True
        f2 = Finding(scanner="zap", product="app", title="Non-KEV",
                     severity="high")
        f2.score = 70.0
        f2.kev = False
        config = Config({"products": {"app": {}}})
        ranked = rank_findings([f2, f1], config)
        self.assertEqual(ranked[0].title, "KEV")

    def test_quarantined_excluded(self):
        """Quarantined findings should not appear in ranking."""
        f = Finding(scanner="zap", product="app", title="Quarantined",
                    severity="info")
        f.status = "quarantined"
        f.score = 50.0
        config = Config({"products": {"app": {}}})
        ranked = rank_findings([f], config)
        self.assertEqual(len(ranked), 0)


if __name__ == "__main__":
    unittest.main()
