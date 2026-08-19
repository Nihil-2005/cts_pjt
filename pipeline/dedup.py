"""Cross-scanner deduplication.

Multi-pass approach (each pass only considers findings still ungrouped):

  Pass 1 - CVE-centric   : same (product, CVE) from any scanner -> one bug.
                           This collapses e.g. Nuclei + Trivy + ZAP reports of
                           the same CVE into a single finding.
  Pass 2 - Endpoint+CWE  : same (product, CWE, endpoint[, parameter]) with no
                           CVE (web-scanner findings rarely carry CVEs).
  Pass 3 - Title fuzzy   : normalized-title match on remaining leftovers
                           (optional, enabled via config).

Every duplicate records ``duplicate_of`` (the canonical finding) and the
reason, so the pipeline can report a precise dedup %.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Dict, List, Optional

from .models import Finding


def _norm_endpoint(endpoint: Optional[str]) -> str:
    if not endpoint:
        return ""
    e = str(endpoint).strip().lower()
    e = re.sub(r"^https?://", "", e)
    e = re.sub(r"[:/]+$", "", e)
    return e


def _norm_title(title: Optional[str]) -> str:
    if not title:
        return ""
    t = re.sub(r"[^a-z0-9]+", " ", str(title).lower()).strip()
    return t


def _key(*parts: str) -> str:
    joined = "|".join(p or "" for p in parts)
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:16]


def _canonical_rank(f: Finding) -> tuple:
    """Pick the canonical member of a group: most severe, then most CVEs, then
    the scanner with richest evidence."""
    scanner_rank = {"trivy": 0, "zap": 1, "wapiti": 2, "nuclei": 3,
                    "openvas": 4, "nmap": 5}
    return (f.severity_num, 1 if f.cve else 0, scanner_rank.get(f.scanner, 9))


def deduplicate(findings: List[Finding], fuzzy: bool = False) -> Dict[str, object]:
    """Returns {findings, metrics}.  Metrics: raw, unique, dedup_pct, by_pass."""
    metrics: Dict[str, object] = {
        "raw": len(findings),
        "unique": 0,
        "dedup_pct": 0.0,
        "by_pass": {"cve": 0, "endpoint": 0, "title": 0},
    }
    if not findings:
        return {"findings": findings, "metrics": metrics}

    groups: Dict[str, List[Finding]] = defaultdict(list)
    reason: Dict[str, str] = {}
    assigned = set()

    # Pass 1: CVE-centric
    cve_groups = defaultdict(list)
    for f in findings:
        if f.cve:
            cve_groups[(f.product, f.cve.upper())].append(f)
    for key, members in cve_groups.items():
        members.sort(key=_canonical_rank, reverse=True)
        gid = _key("cve", *key)
        for m in members:
            groups[gid].append(m)
            reason[id(m)] = "cve"
            assigned.add(id(m))

    # Pass 2: endpoint + CWE
    ep_groups = defaultdict(list)
    for f in findings:
        if id(f) in assigned:
            continue
        if f.cwe and f.endpoint:
            ep_groups[(f.product, f.cwe, _norm_endpoint(f.endpoint), _norm_title(f.parameter))].append(f)
    for key, members in ep_groups.items():
        members.sort(key=_canonical_rank, reverse=True)
        gid = _key("ep", *key)
        for m in members:
            groups[gid].append(m)
            reason[id(m)] = "endpoint"
            assigned.add(id(m))

    # Pass 3: fuzzy title (same product + severity, token-set overlap)
    if fuzzy:
        leftovers = [f for f in findings if id(f) not in assigned]
        clustered: List[List[Finding]] = []
        for f in leftovers:
            placed = False
            for cluster in clustered:
                rep = cluster[0]
                if rep.product == f.product and rep.severity == f.severity \
                        and _title_similar(_norm_title(rep.title), _norm_title(f.title)):
                    cluster.append(f)
                    placed = True
                    break
            if not placed:
                clustered.append([f])
        for members in clustered:
            if len(members) < 2:
                continue
            members.sort(key=_canonical_rank, reverse=True)
            gid = _key("title", members[0].product, members[0].severity, _norm_title(members[0].title))
            for m in members:
                groups[gid].append(m)
                reason[id(m)] = "title"
                assigned.add(id(m))

    # Assign group ids + duplicate flags, merging best evidence from
    # duplicates into the canonical finding so no intel is lost.
    for gid, members in groups.items():
        members.sort(key=_canonical_rank, reverse=True)
        canon = members[0]
        canon.group_id = gid
        canon.is_duplicate = False
        for dup in members[1:]:
            dup.group_id = gid
            dup.is_duplicate = True
            dup.duplicate_of = _stable_id(canon)
            _merge_into(canon, dup)
            metrics["by_pass"][reason[id(dup)]] += 1  # type: ignore[index]

    unique = [f for f in findings if not f.is_duplicate]
    metrics["unique"] = len(unique)
    if metrics["raw"]:
        metrics["dedup_pct"] = round(
            (metrics["raw"] - metrics["unique"]) / metrics["raw"] * 100, 2)
    return {"findings": findings, "metrics": metrics}


_TITLE_STOPWORDS = {"the", "a", "an", "of", "in", "on", "found", "is", "are",
                    "and", "or", "via", "with", "by"}


def _title_similar(a: str, b: str, min_jaccard: float = 0.5) -> bool:
    """True when two normalized titles share enough tokens (Jaccard) —
    order-insensitive so reworded scanner titles still collapse."""
    ta = {t for t in a.split() if t and t not in _TITLE_STOPWORDS}
    tb = {t for t in b.split() if t and t not in _TITLE_STOPWORDS}
    if not ta or not tb:
        return False
    union = ta | tb
    inter = ta & tb
    return len(inter) / len(union) >= min_jaccard


def _merge_into(canon: Finding, dup: Finding) -> None:
    """Fill missing fields on the canonical finding from a duplicate."""
    for attr in ("cwe", "cve", "endpoint", "parameter", "description",
                 "remediation", "evidence", "package", "installed_version",
                 "fixed_version"):
        if not getattr(canon, attr) and getattr(dup, attr):
            setattr(canon, attr, getattr(dup, attr))
    if not canon.raw and dup.raw:
        canon.raw = dup.raw
    # keep a combined scanner provenance list for reporting
    seen = {s.strip() for s in (canon.raw.get("scanners") or [])} if isinstance(canon.raw, dict) else set()
    if dup.scanner not in seen:
        seen.add(dup.scanner)
        canon.raw = dict(canon.raw or {})
        canon.raw["scanners"] = sorted(seen)


def _stable_id(f: Finding) -> str:
    """Stable, content-based id so duplicates can reference canonicals across
    serialization round-trips."""
    return _key(f.product, f.scanner, _norm_title(f.title), _norm_endpoint(f.endpoint), f.cve or "")
