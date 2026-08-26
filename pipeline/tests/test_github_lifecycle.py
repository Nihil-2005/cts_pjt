"""Lifecycle-gated auto-ticketing tests (GitHub transport fully mocked)."""

import tempfile
import unittest

from pipeline import github_tickets as gt
from pipeline.lifecycle import LifecycleManager
from pipeline.models import Finding


def _f(product="app", title="SQLi", score=90.0, priority="P1", dedup_key=None):
    f = Finding(
        scanner="nuclei",
        product=product,
        title=title,
        severity="critical",
        cve="CVE-2024-0001",
        cwe="CWE-89",
        endpoint="http://a/",
    )
    f.score = score
    f.priority = priority
    f.sla_hours = 24
    f.dedup_key = dedup_key
    return f


class FakeGH(gt.GitHubTickets):
    """Records requests instead of hitting GitHub."""

    def __init__(self, existing_titles=None):
        super().__init__("org/repo", token="t", dry_run=False)
        self.calls = []
        self.existing_titles = existing_titles or set()

    def _request(self, method, path, body=None):
        self.calls.append((method, path))
        if method == "GET":  # _open_issue_titles
            return [{"title": t} for t in self.existing_titles]
        if method == "POST" and path.endswith("/issues"):
            return {"number": 1, "html_url": "https://github.com/org/repo/issues/1"}
        return {}  # comments etc.


class TestLifecycleGating(unittest.TestCase):
    def setUp(self):
        ctx = tempfile.TemporaryDirectory()
        self.addCleanup(ctx.cleanup)
        self.lc = LifecycleManager(f"{ctx.name}/lc.db")

    def tearDown(self):
        self.lc.close()

    def _track(self, f, run_date="2026-01-01T00:00:00"):
        tracked, _ = self.lc.upsert_finding(f, run_date=run_date)
        return tracked

    def test_new_open_finding_creates_and_remembers_url(self):
        f = _f(dedup_key="k1")
        self._track(f)
        gh = FakeGH()
        stats = gh.create_tickets([f], lifecycle=self.lc)
        self.assertEqual(stats["created"], 1)
        self.assertEqual(
            self.lc.get_tracked("k1").issue_url, "https://github.com/org/repo/issues/1"
        )

    def test_second_run_with_ticket_is_silent(self):
        f = _f(dedup_key="k1")
        self._track(f)
        gh1 = FakeGH()
        gh1.create_tickets([f], lifecycle=self.lc)

        # Rescan: same finding seen again
        self.lc.upsert_finding(f, run_date="2026-02-01T00:00:00")
        gh2 = FakeGH()
        stats = gh2.create_tickets([f], lifecycle=self.lc)
        self.assertEqual(stats["created"], 0)
        self.assertEqual(stats["skipped_ticketed"], 1)

    def test_fixed_finding_never_touched(self):
        f = _f(dedup_key="k1")
        tracked = self._track(f)
        self.lc.transition_status(tracked.finding_id, "fixed", "gone")
        gh = FakeGH()
        stats = gh.create_tickets([f], lifecycle=self.lc)
        self.assertEqual(stats["created"], 0)
        self.assertEqual(stats["skipped_status"], 1)

    def test_reopened_finding_comments_instead_of_creating(self):
        f = _f(dedup_key="k1")
        tracked = self._track(f)
        gh1 = FakeGH()
        gh1.create_tickets([f], lifecycle=self.lc)  # creates issue #1
        self.lc.set_issue_url(
            tracked.finding_id, "https://github.com/org/repo/issues/1"
        )
        self.lc.transition_status(tracked.finding_id, "fixed", "gone")

        # Reintroduced in a later scan -> FSM reopens with that reason
        self.lc.upsert_finding(f, run_date="2026-02-01T00:00:00")
        gh2 = FakeGH(existing_titles={"[P1] SQLi (app)"})
        stats = gh2.create_tickets([f], lifecycle=self.lc)
        self.assertEqual(stats["created"], 0)
        self.assertEqual(stats["commented_reopened"], 1)
        self.assertTrue(any("/issues/1/comments" in p for _, p in gh2.calls))

    def test_below_threshold_untouched_even_when_new(self):
        f = _f(score=30.0, priority="P4", dedup_key="k1")
        self._track(f)
        gh = FakeGH()
        stats = gh.create_tickets([f], threshold=60.0, lifecycle=self.lc)
        self.assertEqual(stats["below_threshold"], 1)
        self.assertEqual(stats["created"], 0)

    def test_no_lifecycle_legacy_title_guard(self):
        f = _f()
        gh = FakeGH(existing_titles={"[P1] SQLi (app)"})
        stats = gh.create_tickets([f], lifecycle=None)
        self.assertEqual(stats["skipped_duplicate"], 1)
        self.assertEqual(stats["created"], 0)


if __name__ == "__main__":
    unittest.main()
