"""Tests for lifecycle tracking, SLA, cross-run dedup, and engagement model."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from pipeline.lifecycle import (
    LifecycleManager,
    calculate_sla_deadline,
    is_sla_breached,
    sla_remaining_hours,
)
from pipeline.models import Finding


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        scanner="nuclei",
        product="test_app",
        title="SQL Injection in /login",
        severity="high",
        cve="CVE-2024-0001",
        cwe="CWE-89",
        endpoint="/login",
        score=85.0,
        sla_hours=24,
        dedup_key="test-finding-001",
    )
    defaults.update(overrides)
    return Finding(**defaults)


@pytest.fixture
def tmp_db():
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "test_lifecycle.db")
        mgr = LifecycleManager(db_path)
        yield mgr
        mgr.close()


class TestSLACalculation:
    def test_calculate_sla_deadline(self):
        run_date = "2026-08-21T10:00:00"
        deadline = calculate_sla_deadline(85.0, 24, run_date)
        assert "2026-08-22" in deadline

    def test_sla_not_breached(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=10)).isoformat()
        assert not is_sla_breached(future)

    def test_sla_breached(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat()
        assert is_sla_breached(past)

    def test_sla_remaining_positive(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=10)).isoformat()
        remaining = sla_remaining_hours(future)
        assert remaining is not None
        assert 9 < remaining < 11

    def test_sla_remaining_negative(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
        remaining = sla_remaining_hours(past)
        assert remaining is not None
        assert remaining < 0

    def test_empty_deadline(self):
        assert not is_sla_breached("")
        assert sla_remaining_hours("") is None


class TestFindingLifecycle:
    def test_new_finding_is_open(self, tmp_db):
        f = _make_finding()
        tracked, is_new = tmp_db.upsert_finding(f)
        assert is_new is True
        assert tracked.status == "open"
        assert tracked.first_seen == tracked.last_seen

    def test_existing_finding_updates_last_seen(self, tmp_db):
        f = _make_finding()
        tmp_db.upsert_finding(f, run_date="2026-08-21T10:00:00")
        tracked2, is_new = tmp_db.upsert_finding(f, run_date="2026-08-22T10:00:00")
        assert is_new is False
        assert tracked2.last_seen == "2026-08-22T10:00:00"
        assert tracked2.first_seen == "2026-08-21T10:00:00"

    def test_valid_transitions(self, tmp_db):
        f = _make_finding()
        tracked, _ = tmp_db.upsert_finding(f)

        assert tmp_db.transition_status(tracked.finding_id, "in_progress")
        assert tmp_db.transition_status(tracked.finding_id, "fixed")
        assert tmp_db.transition_status(tracked.finding_id, "verified")
        assert tmp_db.transition_status(tracked.finding_id, "accepted")

        updated = tmp_db.get_tracked(tracked.finding_id)
        assert updated.status == "accepted"
        assert (
            len(updated.transitions) == 5
        )  # open → in_progress → fixed → verified → accepted

    def test_invalid_transition_rejected(self, tmp_db):
        f = _make_finding()
        tracked, _ = tmp_db.upsert_finding(f)

        # Can't go directly from open to verified
        assert not tmp_db.transition_status(tracked.finding_id, "verified")
        assert tmp_db.get_tracked(tracked.finding_id).status == "open"

    def test_mark_fixed(self, tmp_db):
        f = _make_finding()
        tracked, _ = tmp_db.upsert_finding(f)
        tmp_db.transition_status(tracked.finding_id, "in_progress")
        assert tmp_db.mark_fixed(tracked.finding_id)
        assert tmp_db.get_tracked(tracked.finding_id).status == "fixed"

    def test_mark_false_positive(self, tmp_db):
        f = _make_finding()
        tracked, _ = tmp_db.upsert_finding(f)
        assert tmp_db.mark_false_positive(tracked.finding_id)
        assert tmp_db.get_tracked(tracked.finding_id).status == "false_positive"

    def test_mark_risk_accepted(self, tmp_db):
        f = _make_finding()
        tracked, _ = tmp_db.upsert_finding(f)
        assert tmp_db.mark_risk_accepted(tracked.finding_id)
        assert tmp_db.get_tracked(tracked.finding_id).status == "risk_accepted"

    def test_transition_to_invalid_status(self, tmp_db):
        f = _make_finding()
        tracked, _ = tmp_db.upsert_finding(f)
        assert not tmp_db.transition_status(tracked.finding_id, "bogus_status")

    def test_transition_nonexistent_finding(self, tmp_db):
        assert not tmp_db.transition_status("nonexistent-id", "fixed")


class TestCrossRunDedup:
    def test_known_finding(self, tmp_db):
        f = _make_finding()
        tmp_db.upsert_finding(f)
        assert tmp_db.is_known_finding(f)

    def test_unknown_finding(self, tmp_db):
        f = _make_finding(dedup_key="brand-new-finding")
        assert not tmp_db.is_known_finding(f)

    def test_get_unseen_findings(self, tmp_db):
        f1 = _make_finding(dedup_key="known-1", title="Known finding")
        f2 = _make_finding(dedup_key="unknown-1", title="New finding")
        tmp_db.upsert_finding(f1)

        unseen = tmp_db.get_unseen_findings([f1, f2])
        assert len(unseen) == 1
        assert unseen[0].dedup_key == "unknown-1"

    def test_get_new_vs_existing(self, tmp_db):
        f1 = _make_finding(dedup_key="existing-1", title="Existing")
        f2 = _make_finding(dedup_key="new-1", title="Brand new")
        tmp_db.upsert_finding(f1)

        new, existing = tmp_db.get_new_vs_existing([f1, f2])
        assert len(new) == 1
        assert len(existing) == 1
        assert new[0].dedup_key == "new-1"
        assert existing[0].dedup_key == "existing-1"

    def test_get_fixed_findings(self, tmp_db):
        f1 = _make_finding(dedup_key="still-here", title="Still present")
        f2 = _make_finding(dedup_key="disappeared", title="Gone finding")
        tmp_db.upsert_finding(f1)
        tmp_db.upsert_finding(f2)

        # Only f1 is in current scan — f2 should be marked fixed
        fixed = tmp_db.get_fixed_findings([f1])
        assert len(fixed) == 1
        assert fixed[0].finding_id == f2.dedup_key
        assert fixed[0].status == "fixed"


class TestSLATracking:
    def test_breached_findings(self, tmp_db):
        f = _make_finding(sla_hours=1)
        tracked, _ = tmp_db.upsert_finding(f, run_date="2026-01-01T00:00:00")

        breached = tmp_db.get_breached_findings()
        assert len(breached) == 1
        assert breached[0].finding_id == tracked.finding_id

    def test_not_breached_when_recent(self, tmp_db):
        f = _make_finding(sla_hours=9999)
        tmp_db.upsert_finding(f)

        breached = tmp_db.get_breached_findings()
        assert len(breached) == 0

    def test_sla_status(self, tmp_db):
        f = _make_finding(sla_hours=24)
        tracked, _ = tmp_db.upsert_finding(f)
        status = tmp_db.get_sla_status(tracked.finding_id)
        assert status["found"] is True
        assert status["sla_hours"] == 24
        assert status["breached"] is False or status["remaining_hours"] > 0

    def test_sla_status_nonexistent(self, tmp_db):
        status = tmp_db.get_sla_status("nonexistent")
        assert status["found"] is False


class TestEngagementModel:
    def test_record_engagement(self, tmp_db):
        # Create findings and upsert them FIRST (simulates first scan)
        findings = [_make_finding(dedup_key=f"finding-{i}") for i in range(5)]
        for f in findings:
            tmp_db.upsert_finding(f)

        # Now record engagement — findings are already known, so new=0
        engagement = tmp_db.record_engagement(
            run_date="2026-08-21T10:00:00",
            product="test_app",
            current_findings=findings,
            summary_stats={"avg_score": 75.0},
        )
        assert engagement["total_findings"] == 5
        assert engagement["new_findings"] == 0  # all already tracked
        assert engagement["fixed_findings"] == 0
        assert engagement["unchanged_findings"] == 5

    def test_second_run_shows_delta(self, tmp_db):
        # First run
        f1 = _make_finding(dedup_key="f1", title="Still here")
        f2 = _make_finding(dedup_key="f2", title="Will disappear")
        tmp_db.upsert_finding(f1)
        tmp_db.upsert_finding(f2)
        tmp_db.record_engagement("2026-08-21T10:00:00", "test_app", [f1, f2])

        # Second run — f2 is gone, f3 is new
        f3 = _make_finding(dedup_key="f3", title="New finding")
        engagement = tmp_db.record_engagement(
            "2026-08-22T10:00:00", "test_app", [f1, f3]
        )

        assert engagement["new_findings"] == 1  # f3
        assert engagement["unchanged_findings"] == 1  # f1
        assert engagement["fixed_findings"] == 1  # f2 disappeared

    def test_engagement_history(self, tmp_db):
        findings = [_make_finding(dedup_key="f1")]
        for f in findings:
            tmp_db.upsert_finding(f)

        tmp_db.record_engagement("2026-08-21", "app1", findings)
        tmp_db.record_engagement("2026-08-22", "app1", findings)
        tmp_db.record_engagement("2026-08-21", "app2", findings)

        all_hist = tmp_db.get_engagement_history()
        assert len(all_hist) == 3

        app1_hist = tmp_db.get_engagement_history(product="app1")
        assert len(app1_hist) == 2


class TestGitHubJiraIntegration:
    def test_set_github_issue(self, tmp_db):
        f = _make_finding()
        tracked, _ = tmp_db.upsert_finding(f)
        tmp_db.set_github_issue(tracked.finding_id, 42)
        updated = tmp_db.get_tracked(tracked.finding_id)
        assert updated.github_issue == 42

    def test_set_jira_key(self, tmp_db):
        f = _make_finding()
        tracked, _ = tmp_db.upsert_finding(f)
        tmp_db.set_jira_key(tracked.finding_id, "SEC-123")
        updated = tmp_db.get_tracked(tracked.finding_id)
        assert updated.jira_key == "SEC-123"


class TestDashboardData:
    def test_dashboard_data(self, tmp_db):
        f1 = _make_finding(dedup_key="d1", score=90)
        f2 = _make_finding(dedup_key="d2", score=50)
        tmp_db.upsert_finding(f1)
        tmp_db.upsert_finding(f2)
        tmp_db.mark_false_positive(f2.dedup_key)

        data = tmp_db.get_dashboard_data()
        assert data["total_tracked"] == 2
        assert data["status_counts"]["open"] == 1
        assert data["status_counts"]["false_positive"] == 1
