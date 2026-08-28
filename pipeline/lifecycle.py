"""Finding lifecycle, SLA tracking, and cross-run deduplication via SQLite."""

from __future__ import annotations
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from .models import Finding

VALID_STATUSES = ("open", "in_progress", "fixed", "verified", "accepted", "false_positive", "risk_accepted")
STATUS_TRANSITIONS = {
    "open": ("in_progress", "fixed", "false_positive", "risk_accepted"),
    "in_progress": ("fixed", "open", "false_positive"),
    "fixed": ("verified", "open"),
    "verified": ("accepted", "open"),
    "accepted": ("open",),
    "false_positive": ("open",),
    "risk_accepted": ("open",),
}


@dataclass
class TrackedFinding:
    finding_id: str
    product: str
    title: str
    severity: str
    cve: Optional[str] = None
    cwe: Optional[str] = None
    endpoint: Optional[str] = None
    status: str = "open"
    first_seen: str = ""
    last_seen: str = ""
    first_score: float = 0.0
    last_score: float = 0.0
    sla_deadline: str = ""
    sla_hours: int = 0
    owner: str = ""
    github_issue: Optional[int] = None
    issue_url: Optional[str] = None
    jira_key: Optional[str] = None
    description: str = ""
    notes: str = ""
    transitions: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


DEFAULT_SLA_BANDS = [(90, 10), (70, 15), (40, 20), (20, 24), (0, 30)]


def calculate_sla_deadline(score: float, sla_hours: int, run_date: str = "") -> str:
    if not run_date:
        run_date = datetime.now(timezone.utc).isoformat()
    try:
        base = datetime.fromisoformat(run_date.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        base = datetime.now(timezone.utc)
    return (base + timedelta(hours=sla_hours)).isoformat()


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def is_sla_breached(sla_deadline: str) -> bool:
    if not sla_deadline:
        return False
    try:
        deadline = datetime.fromisoformat(sla_deadline.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) > _ensure_utc(deadline)
    except (ValueError, TypeError):
        return False


def sla_remaining_hours(sla_deadline: str) -> Optional[float]:
    if not sla_deadline:
        return None
    try:
        deadline = datetime.fromisoformat(sla_deadline.replace("Z", "+00:00"))
        delta = _ensure_utc(deadline) - datetime.now(timezone.utc)
        return delta.total_seconds() / 3600
    except (ValueError, TypeError):
        return None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS tracked_findings (
    finding_id TEXT PRIMARY KEY, product TEXT NOT NULL, title TEXT, severity TEXT,
    cve TEXT, cwe TEXT, endpoint TEXT, status TEXT DEFAULT 'open',
    first_seen TEXT, last_seen TEXT, first_score REAL DEFAULT 0, last_score REAL DEFAULT 0,
    sla_deadline TEXT, sla_hours INTEGER DEFAULT 0, owner TEXT,
    github_issue INTEGER, issue_url TEXT, jira_key TEXT, notes TEXT,
    transitions TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS sightings (
    finding_id TEXT NOT NULL, seen_at TEXT NOT NULL, score REAL DEFAULT 0, severity TEXT,
    PRIMARY KEY (finding_id, seen_at),
    FOREIGN KEY (finding_id) REFERENCES tracked_findings(finding_id)
);
CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_date TEXT NOT NULL, product TEXT NOT NULL,
    total_findings INTEGER DEFAULT 0, new_findings INTEGER DEFAULT 0,
    fixed_findings INTEGER DEFAULT 0, unchanged_findings INTEGER DEFAULT 0,
    avg_score REAL DEFAULT 0, breached_sla INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sla_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL,
    alerted_at TEXT NOT NULL, alert_type TEXT NOT NULL, message TEXT,
    FOREIGN KEY (finding_id) REFERENCES tracked_findings(finding_id)
);
"""


class LifecycleManager:
    def __init__(self, db_path: str = "outputs/lifecycle.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(tracked_findings)")}
        if "issue_url" not in cols:
            self.conn.execute("ALTER TABLE tracked_findings ADD COLUMN issue_url TEXT")
        if "description" not in cols:
            self.conn.execute("ALTER TABLE tracked_findings ADD COLUMN description TEXT")

    def close(self):
        self.conn.close()

    def id_for(self, finding: Finding) -> str:
        return finding.dedup_key or self._finding_id(finding)

    def get_tracked(self, finding_id: str) -> Optional[TrackedFinding]:
        row = self.conn.execute("SELECT * FROM tracked_findings WHERE finding_id=?", (finding_id,)).fetchone()
        if not row:
            return None
        return self._row_to_tracked(row)

    def upsert_finding(self, finding: Finding, run_date: str = "") -> Tuple[TrackedFinding, bool]:
        fid = self._finding_id(finding)
        existing = self.get_tracked(fid)
        now = run_date or datetime.now(timezone.utc).isoformat()

        if existing:
            existing.last_seen = now
            existing.last_score = finding.score or 0
            desc = finding.description or existing.description or ""
            self.conn.execute(
                "UPDATE tracked_findings SET last_seen=?, last_score=?, description=COALESCE(NULLIF(?, ''), description) WHERE finding_id=?",
                (now, existing.last_score, desc, fid),
            )
            if existing.status in ("fixed", "verified"):
                if self.transition_status(fid, "open", "reintroduced in latest scan"):
                    existing.status = "open"
            self._record_sighting(fid, now, finding)
            self.conn.commit()
            return existing, False
        else:
            sla_hours = finding.sla_hours or self._default_sla(finding.score or 0, finding.severity)
            deadline = calculate_sla_deadline(finding.score or 0, sla_hours, now)
            tracked = TrackedFinding(
                finding_id=fid, product=finding.product, title=finding.title,
                severity=finding.severity, cve=finding.cve, cwe=finding.cwe,
                endpoint=finding.endpoint, status="open", first_seen=now, last_seen=now,
                first_score=finding.score or 0, last_score=finding.score or 0,
                sla_deadline=deadline, sla_hours=sla_hours, owner=finding.owner or "",
                description=finding.description or "",
                transitions=[{"from": None, "to": "open", "at": now, "reason": "first seen"}],
            )
            self.conn.execute(
                """INSERT INTO tracked_findings
                   (finding_id, product, title, severity, cve, cwe, endpoint,
                    status, first_seen, last_seen, first_score, last_score,
                    sla_deadline, sla_hours, owner, description, transitions)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fid, tracked.product, tracked.title, tracked.severity, tracked.cve,
                 tracked.cwe, tracked.endpoint, tracked.status, tracked.first_seen,
                 tracked.last_seen, tracked.first_score, tracked.last_score,
                 tracked.sla_deadline, tracked.sla_hours, tracked.owner,
                 tracked.description, json.dumps(tracked.transitions)),
            )
            self._record_sighting(fid, now, finding)
            self.conn.commit()
            return tracked, True

    def _record_sighting(self, finding_id: str, seen_at: str, finding: Finding) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO sightings (finding_id, seen_at, score, severity) VALUES (?,?,?,?)",
            (finding_id, seen_at, finding.score or 0, finding.severity),
        )

    def get_sightings(self, finding_id: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT seen_at, score, severity FROM sightings WHERE finding_id=? ORDER BY seen_at", (finding_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_persistent_findings(self, min_count: int = 2) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT s.finding_id, t.product, t.title, t.status,
                      COUNT(*) AS times_seen, MIN(s.seen_at) AS first_seen,
                      MAX(s.seen_at) AS last_seen, MIN(s.score) AS min_score,
                      MAX(s.score) AS max_score
               FROM sightings s JOIN tracked_findings t ON t.finding_id = s.finding_id
               GROUP BY s.finding_id HAVING COUNT(*) >= ? ORDER BY times_seen DESC""",
            (min_count,),
        ).fetchall()
        return [dict(r) for r in rows]

    def set_issue_url(self, finding_id: str, url: str) -> bool:
        cur = self.conn.execute("UPDATE tracked_findings SET issue_url=? WHERE finding_id=?", (url, finding_id))
        self.conn.commit()
        return cur.rowcount > 0

    def transition_status(self, finding_id: str, new_status: str, reason: str = "") -> bool:
        tracked = self.get_tracked(finding_id)
        if not tracked or new_status not in VALID_STATUSES:
            return False
        allowed = STATUS_TRANSITIONS.get(tracked.status, ())
        if new_status not in allowed:
            return False
        now = datetime.now(timezone.utc).isoformat()
        tracked.transitions.append({"from": tracked.status, "to": new_status, "at": now, "reason": reason})
        self.conn.execute("UPDATE tracked_findings SET status=?, transitions=? WHERE finding_id=?",
                          (new_status, json.dumps(tracked.transitions), finding_id))
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
        self.conn.execute("UPDATE tracked_findings SET github_issue=? WHERE finding_id=?", (issue_number, finding_id))
        self.conn.commit()

    def set_jira_key(self, finding_id: str, jira_key: str):
        self.conn.execute("UPDATE tracked_findings SET jira_key=? WHERE finding_id=?", (jira_key, finding_id))
        self.conn.commit()

    def is_known_finding(self, finding: Finding) -> bool:
        fid = self._finding_id(finding)
        return self.conn.execute("SELECT finding_id FROM tracked_findings WHERE finding_id=?", (fid,)).fetchone() is not None

    def get_unseen_findings(self, findings: List[Finding]) -> List[Finding]:
        return [f for f in findings if not self.is_known_finding(f)]

    def get_new_vs_existing(self, findings: List[Finding]) -> Tuple[List[Finding], List[Finding]]:
        new, existing = [], []
        for f in findings:
            (existing if self.is_known_finding(f) else new).append(f)
        return new, existing

    def get_fixed_findings(self, current_findings: List[Finding], product: Optional[str] = None) -> List[TrackedFinding]:
        current_ids = {self._finding_id(f) for f in current_findings}
        if product is not None:
            rows = self.conn.execute(
                "SELECT * FROM tracked_findings WHERE status IN ('open', 'in_progress') AND product=?", (product,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM tracked_findings WHERE status IN ('open', 'in_progress')"
            ).fetchall()
        fixed = []
        for row in rows:
            tracked = self._row_to_tracked(row)
            if tracked.finding_id not in current_ids:
                if self.transition_status(tracked.finding_id, "fixed", "not seen in latest scan"):
                    tracked.status = "fixed"
                    fixed.append(tracked)
        return fixed

    def get_breached_findings(self, product: Optional[str] = None) -> List[TrackedFinding]:
        if product is not None:
            rows = self.conn.execute(
                "SELECT * FROM tracked_findings WHERE status IN ('open', 'in_progress') AND product=?", (product,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM tracked_findings WHERE status IN ('open', 'in_progress')"
            ).fetchall()
        return [self._row_to_tracked(row) for row in rows if is_sla_breached(self._row_to_tracked(row).sla_deadline)]

    def get_sla_status(self, finding_id: str) -> Dict[str, Any]:
        tracked = self.get_tracked(finding_id)
        if not tracked:
            return {"found": False}
        remaining = sla_remaining_hours(tracked.sla_deadline)
        return {"found": True, "finding_id": finding_id, "status": tracked.status,
                "sla_hours": tracked.sla_hours, "sla_deadline": tracked.sla_deadline,
                "remaining_hours": round(remaining, 1) if remaining is not None else None,
                "breached": is_sla_breached(tracked.sla_deadline)}

    def get_overdue_summary(self) -> Dict[str, Any]:
        breached = self.get_breached_findings()
        return {"total_overdue": len(breached), "by_product": {}, "by_severity": {},
                "findings": [f.to_dict() for f in breached]}

    def record_engagement(self, run_date: str, product: str, current_findings: List[Finding],
                          summary_stats: Dict[str, Any] = None) -> Dict[str, Any]:
        product_findings = [f for f in current_findings if f.product == product]
        new, existing = self.get_new_vs_existing(product_findings)
        fixed = self.get_fixed_findings(product_findings, product=product)
        engagement = {
            "run_date": run_date, "product": product,
            "total_findings": len(product_findings), "new_findings": len(new),
            "fixed_findings": len(fixed), "unchanged_findings": len(existing),
            "avg_score": summary_stats.get("avg_score", 0) if summary_stats else 0,
            "breached_sla": len(self.get_breached_findings(product=product)),
        }
        self.conn.execute(
            """INSERT INTO engagements
               (run_date, product, total_findings, new_findings, fixed_findings,
                unchanged_findings, avg_score, breached_sla)
               VALUES (?,?,?,?,?,?,?,?)""",
            (run_date, product, engagement["total_findings"], engagement["new_findings"],
             engagement["fixed_findings"], engagement["unchanged_findings"],
             engagement["avg_score"], engagement["breached_sla"]),
        )
        self.conn.commit()
        return engagement

    def get_engagement_history(self, product: Optional[str] = None) -> List[Dict]:
        if product:
            rows = self.conn.execute("SELECT * FROM engagements WHERE product=? ORDER BY run_date DESC", (product,)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM engagements ORDER BY run_date DESC").fetchall()
        return [dict(r) for r in rows]

    def get_dashboard_data(self) -> Dict[str, Any]:
        all_findings = self.conn.execute("SELECT * FROM tracked_findings ORDER BY last_score DESC").fetchall()
        status_counts = {}
        for row in all_findings:
            s = row["status"]
            status_counts[s] = status_counts.get(s, 0) + 1
        breached = self.get_breached_findings()
        return {
            "total_tracked": len(all_findings), "status_counts": status_counts,
            "overdue_count": len(breached), "overdue_findings": [f.to_dict() for f in breached[:20]],
            "recent_engagements": self.get_engagement_history()[:10],
            "findings": [{**self._row_to_tracked(row).to_dict(),
                "advisory_type": ('cve' if (row['cve'] or '').startswith('CVE-') else 'ghsa' if (row['cve'] or '').startswith('GHSA-') else 'nswg' if (row['cve'] or '').startswith('NSWG-') else 'other' if row['cve'] else '')
            } for row in all_findings],
        }

    def _finding_id(self, finding: Finding) -> str:
        if finding.dedup_key:
            return finding.dedup_key
        import hashlib
        if finding.cve:
            raw = f"{finding.product}|cve|{finding.cve.upper()}"
        elif finding.cwe and finding.endpoint:
            ep = re.sub(r"^https?://", "", str(finding.endpoint).strip().lower())
            raw = f"{finding.product}|cwe|{str(finding.cwe).upper()}|{ep}"
        else:
            norm_title = re.sub(r"[^a-z0-9]+", " ", (finding.title or "").lower()).strip()
            raw = f"{finding.product}|title|{norm_title[:80]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _default_sla(self, score: float, severity: str = "") -> int:
        SEVERITY_SLA = {"critical": 10, "high": 15, "medium": 20, "low": 24, "info": 30}
        sev = (severity or "").lower().strip()
        if sev in SEVERITY_SLA:
            return SEVERITY_SLA[sev]
        for threshold, hours in DEFAULT_SLA_BANDS:
            if score >= threshold:
                return hours
        return 24

    def _row_to_tracked(self, row) -> TrackedFinding:
        transitions = json.loads(row["transitions"]) if row["transitions"] else []
        return TrackedFinding(
            finding_id=row["finding_id"], product=row["product"], title=row["title"] or "",
            severity=row["severity"] or "info", cve=row["cve"], cwe=row["cwe"],
            endpoint=row["endpoint"], status=row["status"] or "open",
            first_seen=row["first_seen"] or "", last_seen=row["last_seen"] or "",
            first_score=row["first_score"] or 0, last_score=row["last_score"] or 0,
            sla_deadline=row["sla_deadline"] or "", sla_hours=row["sla_hours"] or 0,
            owner=row["owner"] or "", github_issue=row["github_issue"],
            issue_url=(row["issue_url"] if "issue_url" in row.keys() else None),
            jira_key=row["jira_key"],
            description=(row["description"] or "") if "description" in row.keys() else "",
            notes=row["notes"] or "", transitions=transitions,
        )
