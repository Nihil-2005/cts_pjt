"""AI-powered enrichment stage using the Claude API.

Adds three AI signals to each finding (batch-processed to minimise API calls):
  - fp_probability  : 0.0 (definitely real) to 1.0 (likely false positive)
  - fp_reason       : one-sentence explanation of the FP call
  - ai_remediation  : context-aware fix advice beyond the static CWE table

Also generates an executive_brief string for the dashboard header.

All calls are gracefully guarded: if ANTHROPIC_API_KEY is unset or any call
fails, the pipeline continues unchanged — AI enrichment is additive, not
blocking.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from .models import Finding

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL   = "claude-sonnet-4-6"
MAX_TOKENS     = 1024
BATCH_SIZE     = 10     # findings per API call — keeps prompts ≤ ~4k tokens


# ─────────────────────────────── helpers ─────────────────────────────────────

def _api_key() -> Optional[str]:
    return os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")


def _call_claude(system: str, user: str, api_key: str,
                 retries: int = 2) -> str:
    """POST to Claude API with simple exponential-backoff retry."""
    payload = json.dumps({
        "model":      CLAUDE_MODEL,
        "max_tokens": MAX_TOKENS,
        "system":     system,
        "messages":   [{"role": "user", "content": user}],
    }).encode("utf-8")

    last_exc: Exception = RuntimeError("no attempt made")
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                CLAUDE_API_URL,
                data=payload,
                headers={
                    "Content-Type":      "application/json",
                    "x-api-key":         api_key,
                    "anthropic-version": "2023-06-01",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["content"][0]["text"]
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(2 ** attempt)
    raise last_exc


def _safe_json(raw: str) -> Any:
    """Strip markdown fences and parse JSON."""
    cleaned = raw.strip()
    for fence in ("```json", "```"):
        if cleaned.startswith(fence):
            cleaned = cleaned[len(fence):]
    cleaned = cleaned.rstrip("`").strip()
    return json.loads(cleaned)


# ──────────────────────────── FP classification ──────────────────────────────

def _batch_classify_fp(findings: List[Finding],
                       api_key: str) -> List[Dict[str, Any]]:
    """Ask Claude to rate FP likelihood for a batch of findings."""
    items = []
    for i, f in enumerate(findings):
        items.append(
            f"{i + 1}. title={f.title!r} scanner={f.scanner} "
            f"severity={f.severity} cwe={f.cwe or 'none'} "
            f"cve={f.cve or 'none'} endpoint={f.endpoint or 'none'} "
            f"evidence={str(f.evidence)[:120]!r}"
        )
    system = (
        "You are a senior application-security engineer reviewing vulnerability "
        "scanner findings. For each finding assess the false-positive (FP) "
        "likelihood based on the scanner type, CWE, title, endpoint, and "
        "evidence. Return ONLY a JSON array — one object per finding — each "
        "with exactly two keys: "
        "\"fp_probability\" (float 0.0 = definitely real, 1.0 = definitely FP) "
        "and \"fp_reason\" (one short sentence). "
        "No markdown, no preamble, no trailing text. Raw JSON only."
    )
    user = "Classify these findings:\n\n" + "\n".join(items)
    raw = _call_claude(system, user, api_key)
    result = _safe_json(raw)
    while len(result) < len(findings):
        result.append({"fp_probability": 0.5, "fp_reason": "classification unavailable"})
    return result[:len(findings)]


# ─────────────────────────── AI remediation ──────────────────────────────────

def _batch_remediation(findings: List[Finding], api_key: str) -> List[str]:
    """Generate context-aware 2-sentence remediation for a batch."""
    items = []
    for i, f in enumerate(findings):
        pkg = ""
        if f.package:
            pkg = (f" package={f.package}"
                   f" installed={f.installed_version or '?'}"
                   f" fixed={f.fixed_version or 'unknown'}")
        items.append(
            f"{i + 1}. title={f.title!r} cwe={f.cwe or 'none'} "
            f"cve={f.cve or 'none'} scanner={f.scanner} "
            f"severity={f.severity} endpoint={f.endpoint or 'none'}"
            f"{pkg} desc={f.description[:180]!r}"
        )
    system = (
        "You are an AppSec engineer writing ticket-ready remediation steps. "
        "For each finding give exactly 2 sentences: sentence 1 = immediate "
        "mitigation (can be done today, reduces risk right now); sentence 2 = "
        "permanent root-cause fix. Be concrete — reference the actual endpoint, "
        "package version, or CVE. Return ONLY a JSON array of strings, one "
        "string per finding. No markdown, no preamble, raw JSON only."
    )
    user = "Write remediation for:\n\n" + "\n".join(items)
    raw = _call_claude(system, user, api_key)
    result = _safe_json(raw)
    while len(result) < len(findings):
        result.append("Refer to the CWE guidance and patch the affected component.")
    return result[:len(findings)]


# ──────────────────────────── Executive brief ─────────────────────────────────

def _executive_brief(top_findings: List[Finding],
                     summary_stats: Dict,
                     api_key: str) -> str:
    """3-sentence CISO-ready brief summarising the scan run."""
    top_lines = []
    for f in top_findings[:5]:
        kev_tag = " [KEV]" if f.kev else ""
        top_lines.append(
            f"  #{f.score_breakdown.get('rank', '?')} score={f.score}"
            f"{kev_tag} {f.title[:60]} ({f.product})"
        )
    system = (
        "You are a CISO writing a concise executive security briefing for a "
        "non-technical audience. Write exactly 3 sentences: "
        "(1) overall risk posture from this scan run, "
        "(2) the single most critical finding requiring immediate action, "
        "(3) the top recommended action for the team. "
        "Use non-technical language. Be specific and direct."
    )
    user = (
        f"Scan summary: {summary_stats.get('raw_findings', 0)} raw findings → "
        f"{summary_stats.get('unique_findings', 0)} unique after deduplication → "
        f"{summary_stats.get('final_findings', 0)} active after filtering. "
        f"P1={summary_stats.get('p1', 0)} P2={summary_stats.get('p2', 0)} "
        f"P3={summary_stats.get('p3', 0)} P4={summary_stats.get('p4', 0)}.\n"
        f"Top findings:\n" + "\n".join(top_lines)
    )
    return _call_claude(system, user, api_key)


# ─────────────────────────────── main entry ──────────────────────────────────

def ai_enrich(
    findings: List[Finding],
    summary_stats: Optional[Dict] = None,
    api_key: Optional[str] = None,
    skip_remediation: bool = False,
) -> Dict[str, Any]:
    """Enrich *findings* in-place with AI signals.

    Returns a metadata dict:
        {
            "used": bool,
            "counts": {"fp_classified": int, "remediation": int},
            "executive_brief": str,
        }
    """
    api_key = api_key or _api_key()
    result: Dict[str, Any] = {
        "used": False,
        "counts": {"fp_classified": 0, "remediation": 0},
        "executive_brief": "",
    }

    if not api_key:
        print("  [ai-enrich] ANTHROPIC_API_KEY not set — skipping AI enrichment")
        return result

    active = [f for f in findings if f.status == "active"]
    if not active:
        return result

    # ── FP classification (all active findings, batched) ──────────────────
    print(f"  [ai-enrich] classifying {len(active)} findings for FP likelihood …")
    for i in range(0, len(active), BATCH_SIZE):
        batch = active[i: i + BATCH_SIZE]
        try:
            classifications = _batch_classify_fp(batch, api_key)
            for f, clf in zip(batch, classifications):
                fp_prob = float(clf.get("fp_probability", 0.5))
                f.score_breakdown["ai_fp_probability"] = round(fp_prob, 3)
                f.score_breakdown["ai_fp_reason"] = clf.get("fp_reason", "")

                # High FP probability reduces score by up to 10 pts
                if fp_prob > 0.6 and f.score is not None:
                    penalty = round((fp_prob - 0.6) * 25, 1)   # max -10 at fp=1.0
                    f.score = max(0, round(f.score - penalty, 1))
                    f.score_breakdown["ai_fp_penalty"] = -penalty

                result["counts"]["fp_classified"] += 1
        except Exception as exc:
            print(f"  [ai-enrich] FP batch {i // BATCH_SIZE + 1} failed: {exc}")

    # ── AI remediation (top 50 by score — focus effort where it matters) ──
    if not skip_remediation:
        top_50 = sorted(active, key=lambda f: f.score or 0, reverse=True)[:50]
        print(f"  [ai-enrich] generating AI remediation for top {len(top_50)} findings …")
        for i in range(0, len(top_50), BATCH_SIZE):
            batch = top_50[i: i + BATCH_SIZE]
            try:
                remediations = _batch_remediation(batch, api_key)
                for f, rem in zip(batch, remediations):
                    f.score_breakdown["ai_remediation"] = rem
                    f.remediation_suggestions.insert(0, {
                        "kind":   "ai_remediation",
                        "text":   rem,
                        "source": f"claude:{CLAUDE_MODEL}",
                    })
                result["counts"]["remediation"] += len(batch)
            except Exception as exc:
                print(f"  [ai-enrich] remediation batch "
                      f"{i // BATCH_SIZE + 1} failed: {exc}")

    # ── Executive brief ────────────────────────────────────────────────────
    if summary_stats:
        ranked = sorted(active, key=lambda f: f.score or 0, reverse=True)
        try:
            brief = _executive_brief(ranked, summary_stats, api_key)
            result["executive_brief"] = brief
            print(f"  [ai-enrich] executive brief generated ({len(brief)} chars)")
        except Exception as exc:
            print(f"  [ai-enrich] executive brief failed: {exc}")

    result["used"] = True
    print(f"  [ai-enrich] done — FP-classified: "
          f"{result['counts']['fp_classified']} · "
          f"AI remediation: {result['counts']['remediation']}")
    return result
