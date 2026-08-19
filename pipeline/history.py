"""Run history persisted in SQLite.

Every pipeline run appends one row per product (raw/unique/final counts, score
stats, P1..P4 counts, dedup %).  The dashboard reads this to plot
risk-reduction over time — the "before/after across runs" story.
"""
from __future__ import annotations

import json
import os
import sqlite3
from typing import Any, Dict, List

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_date TEXT NOT NULL,
    product TEXT NOT NULL,
    raw INTEGER, unique_findings INTEGER, quarantined INTEGER, final INTEGER,
    dedup_pct REAL, avg_score REAL, top_score REAL,
    p1 INTEGER, p2 INTEGER, p3 INTEGER, p4 INTEGER,
    enrich TEXT,
    UNIQUE(run_date, product)
);
"""


class History:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def add_run(self, run_date: str, product: str, summary: Dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO runs
               (run_date, product, raw, unique_findings, quarantined, final,
                dedup_pct, avg_score, top_score, p1, p2, p3, p4, enrich)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (run_date, product,
             summary.get("raw", 0), summary.get("unique", 0),
             summary.get("quarantined", 0), summary.get("final", 0),
             summary.get("dedup_pct", 0.0), summary.get("avg_score", 0.0),
             summary.get("top_score", 0.0),
             summary.get("p1", 0), summary.get("p2", 0),
             summary.get("p3", 0), summary.get("p4", 0),
             json.dumps(summary.get("enrich_counts", {}))))
        self.conn.commit()

    def history_for(self, product: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT run_date, raw, unique_findings, quarantined, final, dedup_pct, "
            "avg_score, top_score, p1, p2, p3, p4 FROM runs WHERE product=? "
            "ORDER BY run_date", (product,)).fetchall()
        cols = ["run_date", "raw", "unique_findings", "quarantined", "final",
                "dedup_pct", "avg_score", "top_score", "p1", "p2", "p3", "p4"]
        return [dict(zip(cols, r)) for r in rows]

    def all_history(self) -> Dict[str, List[Dict[str, Any]]]:
        products = [r[0] for r in self.conn.execute(
            "SELECT DISTINCT product FROM runs ORDER BY product").fetchall()]
        return {p: self.history_for(p) for p in products}

    def close(self) -> None:
        self.conn.close()
