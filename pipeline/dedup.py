"""Cross-scanner deduplication.

Pass 1: same (product, CVE) from any scanner → one bug.
Pass 2: same (product, CWE, endpoint) with no CVE.
Pass 3: fuzzy title match (optional, config-driven).
"""

from __future__ import annotations
import hashlib
import re
from collections import defaultdict
from typing import Dict, List, Optional
from .models import Finding


def _norm_endpoint(endpoint: Optional[str]) -> str:
    """Normalize URL to path-only form for cross-scanner matching."""
    if not endpoint:
        return ""
    e = str(endpoint).strip().lower()
    e = re.sub(r"^https?://", "", e)
    e = re.sub(r"[?#].*$", "", e)
    m = re.match(r"^[^/]*:(\d+)/(.*)", e)
    if m:
        e = m.group(2)
    elif not e.startswith("/") and "/" not in e.split(":", 1)[0]:
        pass
    e = e.strip("/")
    return e


def _norm_title(title: Optional[str]) -> str:
    if not title:
        return ""
    return re.sub(r"[^a-z0-9]+", " ", str(title).lower()).strip()


def _key(*parts: str) -> str:
    joined = "|".join(p or "" for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _canonical_rank(f: Finding) -> tuple:
    """Sort key where HIGHER = better canonical candidate."""
    scanner_preference = {"trivy": 3, "zap": 3, "nuclei": 2, "wapiti": 2, "openvas": 1, "nmap": 1}
    return (
        f.severity_num,
        1 if f.cve else 0,
        scanner_preference.get(f.scanner, 0),
    )


def deduplicate(findings: List[Finding], fuzzy: bool = False) -> Dict[str, object]:
    """Returns {findings, metrics}."""
    per_scanner = {}
    for f in findings:
        per_scanner[f.scanner] = per_scanner.get(f.scanner, 0) + 1

    metrics: Dict[str, object] = {
        "raw": len(findings),
        "unique": 0,
        "dedup_pct": 0.0,
        "by_pass": {"cve": 0, "endpoint": 0, "title": 0},
        "per_scanner_counts": per_scanner,
        "cross_scanner_redundancy": [],
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
            ep_groups[(f.product, str(f.cwe).upper(), _norm_endpoint(f.endpoint))].append(f)
    for key, members in ep_groups.items():
        members.sort(key=_canonical_rank, reverse=True)
        gid = _key("ep", *key)
        for m in members:
            groups[gid].append(m)
            reason[id(m)] = "endpoint"
            assigned.add(id(m))

    # Pass 3: fuzzy title
    if fuzzy:
        leftovers = [f for f in findings if id(f) not in assigned]
        clustered: List[List[Finding]] = []
        for f in leftovers:
            placed = False
            for cluster in clustered:
                rep = cluster[0]
                if (rep.product == f.product and rep.severity == f.severity
                        and _title_similar(_norm_title(rep.title), _norm_title(f.title))):
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

    # Assign group IDs + merge duplicates into canonical
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
            metrics["by_pass"][reason[id(dup)]] += 1

    # Build cross-scanner redundancy log
    cross_redundancy = []
    for gid, members in groups.items():
        if len(members) < 2:
            continue
        scanners = sorted(set(m.scanner for m in members))
        if len(scanners) < 2:
            continue
        canonical = members[0]
        dupes = [m for m in members if m.is_duplicate]
        cross_redundancy.append({
            "vulnerability": canonical.title[:80],
            "product": canonical.product,
            "cve": canonical.cve,
            "cwe": canonical.cwe,
            "endpoint": canonical.endpoint,
            "scanners_found_it": scanners,
            "canonical_source": canonical.scanner,
            "duplicate_sources": [m.scanner for m in dupes],
            "total_duplicates": len(dupes),
        })
    metrics["cross_scanner_redundancy"] = cross_redundancy

    unique = [f for f in findings if not f.is_duplicate]
    metrics["unique"] = len(unique)
    if metrics["raw"]:
        metrics["dedup_pct"] = round((metrics["raw"] - metrics["unique"]) / metrics["raw"] * 100, 2)
    return {"findings": findings, "metrics": metrics}


_TITLE_STOPWORDS = {"the", "a", "an", "of", "in", "on", "found", "is", "are", "and", "or", "via", "with", "by"}


def _title_similar(a: str, b: str, min_jaccard: float = 0.35) -> bool:
    ta = {t for t in a.split() if t and t not in _TITLE_STOPWORDS}
    tb = {t for t in b.split() if t and t not in _TITLE_STOPWORDS}
    if not ta or not tb:
        return False
    union = ta | tb
    inter = ta & tb
    return len(inter) / len(union) >= min_jaccard


def _merge_into(canon: Finding, dup: Finding) -> None:
    """Fill missing fields on canonical from duplicate."""
    for attr in ("cwe", "cve", "endpoint", "parameter", "description", "remediation",
                 "evidence", "package", "installed_version", "fixed_version"):
        if not getattr(canon, attr) and getattr(dup, attr):
            setattr(canon, attr, getattr(dup, attr))
    if not canon.raw and dup.raw:
        canon.raw = dup.raw
    seen = {canon.scanner}
    if isinstance(canon.raw, dict):
        seen.update(s.strip() for s in (canon.raw.get("scanners") or []))
    if dup.scanner not in seen:
        seen.add(dup.scanner)
    canon.raw = dict(canon.raw or {})
    canon.raw["scanners"] = sorted(seen)


def _stable_id(f: Finding) -> str:
    """Stable content-based ID for dedup references."""
    return _key(f.product, f.scanner, _norm_title(f.title), _norm_endpoint(f.endpoint), f.cve or "")
