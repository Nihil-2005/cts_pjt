"""Finding lifecycle, SLA tracking, and cross-run deduplication.

Tracks findings across pipeline runs:
- Finding lifecycle: Open → In Progress → Fixed → Verified → Accepted
- SLA breach detection with overdue alerts
- Cross-run dedup: don't re-create issues for findings already tracked
- Engagement model: each pipeline run = one engagement/session

Persisted in SQLite for history across runs.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .models import Finding


# ─── Finding Status Lifecycle ────────────────────────────────────────────────

VALID_STATUSES = ("open", "in_progress", "fixed", "verified", "accepted", "false_positive", "risk_accepted")
STATUS_TRANSITIONS = {
    "open":         ("in_progress", "false_positive", "risk_accepted"),
    "in_progress":  ("fixed", "open", "false_positive"),
    "fixed":        ("verified", "open"),
    "verified":     ("accepted", "open"),
    "accepted":     ("open",),
    "false_positive": ("open",),
    "risk_accepted":  ("open",),
}


@dataclass
class TrackedFinding:
    """A finding tracked across multiple pipeline runs."""
    finding_id: str           # dedup_key or generated hash
    product: str
    title: str
    severity: str
    cve: Optional[str] = None
    cwe: Optional[str] = None
    endpoint: Optional[str] = None
    status: str = "open"      # open | in_progress | fixed | verified | accepted | false_positive | risk_accepted
    first_seen: str = ""      # ISO date of first pipeline run
    last_seen: str = ""       # ISO date of most recent pipeline run
    first_score: float = 0.0
    last_score: float = 0.0
    sla_deadline: str = ""    # ISO date when SLA breaches
    sla_hours: int = 0
    owner: str = ""
    github_issue: Optional[int] = None  # GitHub Issue number
    jira_key: Optional[str] = None      # Jira issue key
    notes: str = ""
    transitions: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── SLA Calculation ─────────────────────────────────────────────────────────

# SLA hours by priority band (configurable via config.json)
DEFAULT_SLA_BANDS = [
    (90, 24),    # Score >= 90 → 24 hours
    (70, 72),    # Score >= 70 → 72 hours (3 days)
    (40, 168),   # Score >= 40 → 168 hours (1 week)
    (0, 336),    # Score >= 0  → 336 hours (2 weeks)
]


def calculate_sla_deadline(score: float, sla_hours: int, run_date: str = "") -> str:
    """Calculate when SLA breaches for a finding."""
    if not run_date:
        run_date = datetime.utcnow().isoformat()
    try:
        base = datetime.fromisoformat(run_date.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        base = datetime.utcnow()
    deadline = base + timedelta(hours=sla_hours)
    return deadline.isoformat()


def is_sla_breached(sla_deadline: str) -> bool:
    """Check if a finding's SLA has been breached."""
    if not sla_deadline:
        return False
    try:
        deadline = datetime.fromisoformat(sla_deadline.replace("Z", "+00:00"))
        return datetime.utcnow() > deadline
    except (ValueError, TypeError):
        return False


def sla_remaining_hours(sla_deadline: str) -> Optional[float]:
    """Returns hours until SLA breach, or negative if breached."""
    if not sla_deadline:
        return None
    try:
        deadline = datetime.fromisoformat(sla_deadline.replace("Z", "+00:00"))
        delta = deadline - datetime.utcnow()
        return delta.total_seconds() / 3600
    except (ValueError, TypeError):
        return None


# ─── Database Schema ─────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tracked_findings (
    finding_id TEXT PRIMARY KEY,
    product TEXT NOT NULL,
    title TEXT,
    severity TEXT,
    cve TEXT,
    cwe TEXT,
    endpoint TEXT,
    status TEXT DEFAULT 'open',
    first_seen TEXT,
    last_seen TEXT,
    first_score REAL DEFAULT 0,
    last_score REAL DEFAULT 0,
    sla_deadline TEXT,
    sla_hours INTEGER DEFAULT 0,
    owner TEXT,
    github_issue INTEGER,
    jira_key TEXT,
    notes TEXT,
    transitions TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_date TEXT NOT NULL,
    product TEXT NOT NULL,
    total_findings INTEGER DEFAULT 0,
    new_findings INTEGER DEFAULT 0,
    fixed_findings INTEGER DEFAULT 0,
    unchanged_findings INTEGER DEFAULT 0,
    avg_score REAL DEFAULT 0,
    breached_sla INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sla_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    alerted_at TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    message TEXT,
    FOREIGN KEY (finding_id) REFERENCES tracked_findings(finding_id)
);
"""


# ─── Lifecycle Manager ──────────────────────────────────────────────────────

class LifecycleManager:
    """Tracks findings across pipeline runs with lifecycle, SLA, and dedup."""

    def __init__(self, db_path: str = "outputs/lifecycle.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ─── Finding tracking ────────────────────────────────────────────────

    def get_tracked(self, finding_id: str) -> Optional[TrackedFinding]:
        """Get a tracked finding by ID."""
        row = self.conn.execute(
            "SELECT * FROM tracked_findings WHERE finding_id=?", (finding_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_tracked(row)

    def upsert_finding(self, finding: Finding, run_date: str = "") -> Tuple[TrackedFinding, bool]:
        """Track a finding. Returns (tracked_finding, is_new).

        If the finding already exists, updates last_seen and score.
        If new, creates it with open status and SLA deadline.
        """
        fid = self._finding_id(finding)
        existing = self.get_tracked(fid)
        now = run_date or datetime.utcnow().isoformat()

        if existing:
            # Update existing finding
            existing.last_seen = now
            existing.last_score = finding.score or 0
            self.conn.execute(
                "UPDATE tracked_findings SET last_seen=?, last_score=? WHERE finding_id=?",
                (now, existing.last_score, fid)
            )
            self.conn.commit()
            return existing, False
        else:
            # New finding
            sla_hours = finding.sla_hours or self._default_sla(finding.score or 0)
            deadline = calculate_sla_deadline(finding.score or 0, sla_hours, now)

            tracked = TrackedFinding(
                finding_id=fid,
                product=finding.product,
                title=finding.title,
                severity=finding.severity,
                cve=finding.cve,
                cwe=finding.cwe,
                endpoint=finding.endpoint,
                status="open",
                first_seen=now,
                last_seen=now,
                first_score=finding.score or 0,
                last_score=finding.score or 0,
                sla_deadline=deadline,
                sla_hours=sla_hours,
                owner=finding.owner or "",
                transitions=[{"from": None, "to": "open", "at": now, "reason": "first seen"}],
            )

            self.conn.execute(
                """INSERT INTO tracked_findings
                   (finding_id, product, title, severity, cve, cwe, endpoint,
                    status, first_seen, last_seen, first_score, last_score,
                    sla_deadline, sla_hours, owner, transitions)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fid, tracked.product, tracked.title, tracked.severity,
                 tracked.cve, tracked.cwe, tracked.endpoint, tracked.status,
                 tracked.first_seen, tracked.last_seen, tracked.first_score,
                 tracked.last_score, tracked.sla_deadline, tracked.sla_hours,
                 tracked.owner, json.dumps(tracked.transitions))
            )
            self.conn.commit()
            return tracked, True

    def transition_status(self, finding_id: str, new_status: str, reason: str = "") -> bool:
        """Transition a finding to a new status. Returns True if valid."""
        tracked = self.get_tracked(finding_id)
        if not tracked:
            return False

        if new_status not in VALID_STATUSES:
            return False

        allowed = STATUS_TRANSITIONS.get(tracked.status, ())
        if new_status not in allowed:
            return False

        now = datetime.utcnow().isoformat()
        tracked.transitions.append({
            "from": tracked.status,
            "to": new_status,
            "at": now,
            "reason": reason,
        })

        self.conn.execute(
            "UPDATE tracked_findings SET status=?, transitions=? WHERE finding_id=?",
            (new_status, json.dumps(tracked.transitions), finding_id)
        )
        self.conn.commit()
        return True

    def mark_fixed(self, finding_id: str) -> bool:
        return self.transition_status(finding_id, "fixed", "remediation confirmed")

    def mark_verified(self, finding_id: str) -> bool:
        return self.transition_status(finding_id, "verified", "re-scan confirmed fix")

    def mark_false_positive(self, finding_id: str) -> bool:
        return self.transition_status(finding_id, "false_positive", "analyst review")

    def mark_risk_accepted(self, finding_id: str) -> bool:
        return self.transition_status(finding_id, "risk_accepted", "risk accepted by owner")

    def set_github_issue(self, finding_id: str, issue_number: int):
        self.conn.execute(
            "UPDATE tracked_findings SET github_issue=? WHERE finding_id=?",
            (issue_number, finding_id)
        )
        self.conn.commit()

    def set_jira_key(self, finding_id: str, jira_key: str):
        self.conn.execute(
            "UPDATE tracked_findings SET jira_key=? WHERE finding_id=?",
            (jira_key, finding_id)
        )
        self.conn.commit()

    # ─── Cross-run dedup ─────────────────────────────────────────────────

    def is_known_finding(self, finding: Finding) -> bool:
        """Check if this finding was seen in a previous pipeline run."""
        fid = self._finding_id(finding)
        row = self.conn.execute(
            "SELECT finding_id FROM tracked_findings WHERE finding_id=?", (fid,)
        ).fetchone()
        return row is not None

    def get_unseen_findings(self, findings: List[Finding]) -> List[Finding]:
        """Return only findings NOT seen in previous runs."""
        return [f for f in findings if not self.is_known_finding(f)]

    def get_new_vs_existing(self, findings: List[Finding]) -> Tuple[List[Finding], List[Finding]]:
        """Split findings into new (never seen) and existing (seen before)."""
        new = []
        existing = []
        for f in findings:
            if self.is_known_finding(f):
                existing.append(f)
            else:
                new.append(f)
        return new, existing

    def get_fixed_findings(self, current_findings: List[Finding]) -> List[TrackedFinding]:
        """Find findings that were open but are no longer in the current scan."""
        current_ids = {self._finding_id(f) for f in current_findings}
        rows = self.conn.execute(
            "SELECT * FROM tracked_findings WHERE status IN ('open', 'in_progress')"
        ).fetchall()
        fixed = []
        for row in rows:
            tracked = self._row_to_tracked(row)
            if tracked.finding_id not in current_ids:
                # This finding disappeared — mark as fixed
                self.transition_status(tracked.finding_id, "fixed", "not seen in latest scan")
                tracked.status = "fixed"
                fixed.append(tracked)
        return fixed

    # ─── SLA tracking ────────────────────────────────────────────────────

    def get_breached_findings(self) -> List[TrackedFinding]:
        """Find all findings where SLA has been breached."""
        rows = self.conn.execute(
            "SELECT * FROM tracked_findings WHERE status IN ('open', 'in_progress')"
        ).fetchall()
        breached = []
        for row in rows:
            tracked = self._row_to_tracked(row)
            if is_sla_breached(tracked.sla_deadline):
                breached.append(tracked)
        return breached

    def get_sla_status(self, finding_id: str) -> Dict[str, Any]:
        """Get SLA status for a specific finding."""
        tracked = self.get_tracked(finding_id)
        if not tracked:
            return {"found": False}

        remaining = sla_remaining_hours(tracked.sla_deadline)
        breached = is_sla_breached(tracked.sla_deadline)

        return {
            "found": True,
            "finding_id": finding_id,
            "status": tracked.status,
            "sla_hours": tracked.sla_hours,
            "sla_deadline": tracked.sla_deadline,
            "remaining_hours": round(remaining, 1) if remaining is not None else None,
            "breached": breached,
        }

    def get_overdue_summary(self) -> Dict[str, Any]:
        """Summary of all overdue findings."""
        breached = self.get_breached_findings()
        return {
            "total_overdue": len(breached),
            "by_product": {},
            "by_severity": {},
            "findings": [f.to_dict() for f in breached],
        }

    # ─── Engagement model ────────────────────────────────────────────────

    def record_engagement(self, run_date: str, product: str,
                          current_findings: List[Finding],
                          summary_stats: Dict[str, Any] = None) -> Dict[str, Any]:
        """Record a pipeline run as an engagement. Returns delta stats."""
        new, existing = self.get_new_vs_existing(current_findings)
        fixed = self.get_fixed_findings(current_findings)

        engagement = {
            "run_date": run_date,
            "product": product,
            "total_findings": len(current_findings),
            "new_findings": len(new),
            "fixed_findings": len(fixed),
            "unchanged_findings": len(existing),
            "avg_score": summary_stats.get("avg_score", 0) if summary_stats else 0,
            "breached_sla": len(self.get_breached_findings()),
        }

        self.conn.execute(
            """INSERT INTO engagements
               (run_date, product, total_findings, new_findings,
                fixed_findings, unchanged_findings, avg_score, breached_sla)
               VALUES (?,?,?,?,?,?,?,?)""",
            (run_date, product, engagement["total_findings"],
             engagement["new_findings"], engagement["fixed_findings"],
             engagement["unchanged_findings"], engagement["avg_score"],
             engagement["breached_sla"])
        )
        self.conn.commit()
        return engagement

    def get_engagement_history(self, product: Optional[str] = None) -> List[Dict]:
        """Get engagement history, optionally filtered by product."""
        if product:
            rows = self.conn.execute(
                "SELECT * FROM engagements WHERE product=? ORDER BY run_date DESC",
                (product,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM engagements ORDER BY run_date DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ─── Dashboard data ──────────────────────────────────────────────────

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get all lifecycle data for the dashboard."""
        all_findings = self.conn.execute(
            "SELECT * FROM tracked_findings ORDER BY last_score DESC"
        ).fetchall()

        status_counts = {}
        for row in all_findings:
            s = row["status"]
            status_counts[s] = status_counts.get(s, 0) + 1

        breached = self.get_breached_findings()
        engagements = self.get_engagement_history()

        return {
            "total_tracked": len(all_findings),
            "status_counts": status_counts,
            "overdue_count": len(breached),
            "overdue_findings": [f.to_dict() for f in breached[:20]],
            "recent_engagements": engagements[:10],
            "findings": [self._row_to_tracked(row).to_dict() for row in all_findings[:100]],
        }

    # ─── Internal helpers ────────────────────────────────────────────────

    def _finding_id(self, finding: Finding) -> str:
        """Generate a stable ID for a finding."""
        if finding.dedup_key:
            return finding.dedup_key
        parts = [
            finding.product or "",
            finding.cve or "",
            finding.cwe or "",
            finding.endpoint or "",
            finding.title[:80],
        ]
        import hashlib
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def _default_sla(self, score: float) -> int:
        """Get default SLA hours based on score."""
        for threshold, hours in DEFAULT_SLA_BANDS:
            if score >= threshold:
                return hours
        return 336  # 2 weeks default

    def _row_to_tracked(self, row) -> TrackedFinding:
        """Convert a database row to TrackedFinding."""
        transitions = json.loads(row["transitions"]) if row["transitions"] else []
        return TrackedFinding(
            finding_id=row["finding_id"],
            product=row["product"],
            title=row["title"] or "",
            severity=row["severity"] or "info",
            cve=row["cve"],
            cwe=row["cwe"],
            endpoint=row["endpoint"],
            status=row["status"] or "open",
            first_seen=row["first_seen"] or "",
            last_seen=row["last_seen"] or "",
            first_score=row["first_score"] or 0,
            last_score=row["last_score"] or 0,
            sla_deadline=row["sla_deadline"] or "",
            sla_hours=row["sla_hours"] or 0,
            owner=row["owner"] or "",
            github_issue=row["github_issue"],
            jira_key=row["jira_key"],
            notes=row["notes"] or "",
            transitions=transitions,
        )
