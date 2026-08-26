"""Regression tests pinning reviewed bug fixes.

Each test here corresponds to a defect found in the senior-engineer code
review; together they ensure the fixes cannot silently regress.
"""

import os
import tempfile
import unittest

from pipeline.models import Finding, normalize_severity
from pipeline.dedup import deduplicate
from pipeline.filter import filter_findings
from pipeline import attackpath
from pipeline import lifecycle as lifecycle_mod


def _f(
    scanner="zap",
    product="app",
    title="XSS",
    severity="medium",
    cwe=None,
    cve=None,
    endpoint=None,
    parameter=None,
):
    return Finding(
        scanner=scanner,
        product=product,
        title=title,
        severity=severity,
        cwe=cwe,
        cve=cve,
        endpoint=endpoint,
        parameter=parameter,
    )


class TestSeverityNormalization(unittest.TestCase):
    def test_moderate_maps_to_medium(self):
        """GitHub/GHSA 'Moderate' must not fall through to info (dropped)."""
        self.assertEqual(normalize_severity("Moderate"), "medium")
        self.assertEqual(normalize_severity("moderate"), "medium")

    def test_important_maps_to_medium(self):
        """Debian/Red Hat advisory 'important' must not become info."""
        self.assertEqual(normalize_severity("Important"), "medium")
        self.assertEqual(normalize_severity("important"), "medium")


class TestDedupRegressions(unittest.TestCase):
    def test_unknown_scanner_loses_canonical_tiebreak(self):
        """With equal severity + CVE presence, a known scanner must win over
        an unknown one (pre-fix reverse=True made rank 9 the best)."""
        known = Finding(
            scanner="trivy",
            product="app",
            title="Known scanner view",
            severity="high",
            cve="CVE-2024-0001",
        )
        unknown = Finding(
            scanner="mystery_scanner",
            product="app",
            title="Unknown scanner view",
            severity="high",
            cve="CVE-2024-0001",
        )
        result = deduplicate([unknown, known])
        unique = [f for f in result["findings"] if not f.is_duplicate]
        self.assertEqual(len(unique), 1)
        self.assertEqual(unique[0].scanner, "trivy")

    def test_parameter_not_part_of_endpoint_key(self):
        """nuclei (no parameter) and ZAP (parameter=q) reporting the same
        endpoint+CWE must collapse into one finding."""
        zap = _f(
            scanner="zap",
            cwe="CWE-79",
            endpoint="http://app:3000/search",
            parameter="q",
        )
        nuclei = _f(
            scanner="nuclei",
            cwe="CWE-79",
            endpoint="http://app:3000/search",
            parameter="",
        )
        result = deduplicate([zap, nuclei])
        self.assertEqual(result["metrics"]["unique"], 1)
        self.assertEqual(result["metrics"]["by_pass"]["endpoint"], 1)

    def test_provenance_includes_canonical_scanner(self):
        """The multi-scanner provenance list must include the canonical's
        own scanner, not just duplicates'."""
        f1 = _f(scanner="zap", cwe="CWE-79", endpoint="http://a/")
        f2 = _f(scanner="nuclei", cwe="CWE-79", endpoint="http://a/")
        result = deduplicate([f1, f2])
        canon = next(f for f in result["findings"] if not f.is_duplicate)
        scanners = set(canon.raw.get("scanners", []))
        self.assertEqual(scanners, {"zap", "nuclei"})


class TestFilterFloor(unittest.TestCase):
    CFG_BASE = {"fp_patterns": [], "risk_accept": []}

    def test_multi_value_drop_severity_drops_each_level(self):
        cfg = {"drop_severity": ["info", "low"], "fp_patterns": [], "risk_accept": []}
        findings = [
            _f(title="i", severity="info"),
            _f(title="l", severity="low"),
            _f(title="m", severity="medium"),
        ]
        result = filter_findings(findings, cfg, {})
        active = [f for f in result["findings"] if f.status == "active"]
        self.assertEqual({f.severity for f in active}, {"medium"})

    def test_empty_drop_severity_quarantines_nothing(self):
        cfg = {"drop_severity": [], "fp_patterns": [], "risk_accept": []}
        findings = [_f(title="i", severity="info"), _f(title="h", severity="high")]
        result = filter_findings(findings, cfg, {})
        quarantined = [f for f in result["findings"] if f.status == "quarantined"]
        self.assertEqual(len(quarantined), 0)


class TestAttackPathScoping(unittest.TestCase):
    def test_no_cross_product_contamination(self):
        """Paths built for product A must not annotate product B findings,
        even when both products' findings are passed in the same list."""
        f_a = _f(
            product="app", cwe="CWE-502", endpoint="http://a/", severity="critical"
        )
        f_a2 = _f(
            scanner="nuclei",
            product="app",
            title="RCE",
            cwe="CWE-94",
            endpoint="http://a/admin",
            severity="critical",
        )
        f_b = _f(
            scanner="zap",
            product="other",
            cwe="CWE-502",
            endpoint="http://b/",
            severity="critical",
        )
        paths = attackpath.build_attack_paths([f_a, f_a2], "app", {"exposure": 9})
        self.assertTrue(paths, "expected CWE-502 -> CWE-94 chain")
        attackpath.attach_escalation_potential([f_a, f_a2, f_b], paths, product="app")
        # Product filter means f_b was never annotated
        self.assertIsNone(f_b.escalation_potential)
        self.assertIsNotNone(f_a.escalation_potential)
        self.assertIsNotNone(f_a2.escalation_potential)

    def test_quarantined_findings_not_annotated(self):
        f_q = _f(product="app", cwe="CWE-89", endpoint="http://a/")
        f_q.status = "quarantined"
        paths = attackpath.build_attack_paths(
            [_f(product="app", cwe="CWE-89", endpoint="http://a/")],
            "app",
            {"exposure": 9},
        )
        attackpath.attach_escalation_potential([f_q], paths, product="app")
        self.assertIsNone(f_q.escalation_potential)


class TestLifecycleScoping(unittest.TestCase):
    def _make_lc(self):
        ctx = tempfile.TemporaryDirectory()
        self.addCleanup(ctx.cleanup)
        return lifecycle_mod.LifecycleManager(os.path.join(ctx.name, "lc.db"))

    def test_engagement_for_one_product_cannot_fix_another(self):
        lc = self._make_lc()
        try:
            f_a = _f(
                product="app_a", title="SQLi app A", cwe="CWE-89", endpoint="http://a/"
            )
            f_b = _f(
                product="app_b", title="SQLi app B", cwe="CWE-89", endpoint="http://b/"
            )
            lc.upsert_finding(f_a, run_date="2026-01-01T00:00:00")
            lc.upsert_finding(f_b, run_date="2026-01-01T00:00:00")

            # Engagement for app_a with only app_a's current findings:
            # app_b's open finding must NOT be marked fixed.
            fixed = lc.get_fixed_findings([f_a], product="app_a")
            self.assertEqual(fixed, [])
            tracked_b = lc.get_tracked(lc._finding_id(f_b))
            self.assertEqual(tracked_b.status, "open")

            # Without scoping, app_b's finding WOULD have been fixed — pin
            # that the scoped query returns it when its own product runs.
            fixed_b = lc.get_fixed_findings([], product="app_b")
            self.assertEqual(len(fixed_b), 1)
            self.assertEqual(fixed_b[0].product, "app_b")
        finally:
            lc.close()

    def test_breached_sla_scope(self):
        lc = self._make_lc()
        try:
            f_a = _f(product="app_a", title="Old A", cwe="CWE-89", endpoint="http://a/")
            f_a.score = 95  # P1 -> tiny SLA
            lc.upsert_finding(f_a, run_date="2020-01-01T00:00:00")
            self.assertEqual(len(lc.get_breached_findings(product="app_a")), 1)
            self.assertEqual(len(lc.get_breached_findings(product="app_b")), 0)
        finally:
            lc.close()

    def test_reappearing_fixed_finding_is_reopened(self):
        """A finding auto-marked fixed that reappears in a later scan must
        be reopened — otherwise it is live but invisible to SLA monitoring."""
        lc = self._make_lc()
        try:
            f1 = _f(
                product="app",
                title="SQLi",
                cwe="CWE-89",
                endpoint="http://a/",
                cve="CVE-2024-0001",
            )
            lc.upsert_finding(f1, run_date="2026-01-01T00:00:00")
            fid = lc._finding_id(f1)

            # Disappears -> auto-fixed by get_fixed_findings
            fixed = lc.get_fixed_findings([], product="app")
            self.assertEqual(len(fixed), 1)

            # Reappears in the next scan -> must reopen
            tracked, is_new = lc.upsert_finding(f1, run_date="2026-02-01T00:00:00")
            self.assertFalse(is_new)
            self.assertEqual(tracked.status, "open")

            # Human dispositions are NOT auto-reopened
            lc.transition_status(fid, "in_progress", "analyst")
            lc.transition_status(fid, "false_positive", "analyst review")
            tracked2, _ = lc.upsert_finding(f1, run_date="2026-03-01T00:00:00")
            self.assertEqual(tracked2.status, "false_positive")
        finally:
            lc.close()

    def test_sightings_accumulate_across_runs(self):
        """Every scan that sees a finding appends a sighting with a score
        snapshot — 'found again' never overwrites the earlier timestamp."""
        lc = self._make_lc()
        try:
            f1 = _f(
                product="app",
                title="SQLi",
                cwe="CWE-89",
                endpoint="http://a/",
                cve="CVE-2024-0001",
            )
            f1.score = 80.0
            lc.upsert_finding(f1, run_date="2026-01-01T00:00:00")
            f1.score = 85.0  # intel changed between runs, not recurrence
            lc.upsert_finding(f1, run_date="2026-02-01T00:00:00")
            f1.score = 82.5
            lc.upsert_finding(f1, run_date="2026-03-01T00:00:00")

            fid = lc._finding_id(f1)
            sightings = lc.get_sightings(fid)
            self.assertEqual(len(sightings), 3)
            self.assertEqual([s["score"] for s in sightings], [80.0, 85.0, 82.5])

            persistent = lc.get_persistent_findings(min_count=2)
            match = [p for p in persistent if p["finding_id"] == fid]
            self.assertEqual(len(match), 1)
            self.assertEqual(match[0]["times_seen"], 3)
            self.assertEqual(match[0]["max_score"], 85.0)
        finally:
            lc.close()

    def test_issue_url_roundtrip(self):
        lc = self._make_lc()
        try:
            f1 = _f(product="app", title="SQLi", cwe="CWE-89", endpoint="http://a/")
            tracked, _ = lc.upsert_finding(f1, run_date="2026-01-01T00:00:00")
            fid = tracked.finding_id
            self.assertIsNone(lc.get_tracked(fid).issue_url)
            self.assertTrue(lc.set_issue_url(fid, "https://github.com/o/r/issues/7"))
            self.assertEqual(
                lc.get_tracked(fid).issue_url, "https://github.com/o/r/issues/7"
            )
        finally:
            lc.close()


class TestScoreInvariance(unittest.TestCase):
    """Rule: recurrence never changes a score. Scores are computed fresh
    from threat intel each run — sighting count must not feed the scorer."""

    def _score(self) -> float:
        from pipeline.score import compute_score

        f = _f(
            product="app",
            title="SQLi",
            cwe="CWE-89",
            endpoint="http://a/",
            cve="CVE-2024-0001",
            severity="critical",
        )
        f.nvd_cvss = 9.8
        f.epss_percentile = 0.9
        f.kev = True
        f.exploit_available = True
        weights = {
            "cvss": 20,
            "epss": 20,
            "kev": 25,
            "exploit": 10,
            "asset": 10,
            "exposure": 5,
            "data": 5,
            "patch": 5,
        }
        pcfg = {"asset_criticality": 8, "exposure": 9, "data_sensitivity": 8}
        compute_score(f, pcfg, weights)
        return round(f.score or 0.0, 2)

    def test_score_identical_regardless_of_history(self):
        first = self._score()
        # Simulate three rescans — same inputs must yield the same score
        for _ in range(3):
            again = self._score()
            self.assertEqual(again, first)


if __name__ == "__main__":
    unittest.main()
