"""AI-powered enrichment — 3-tier hybrid: Groq → Ollama → Rule-based.

The pipeline enriches findings in-place with FP classification and remediation.
Three tiers of AI, all free, all using open-source models:

  Tier 1 — Groq API (free, fastest, smartest)
    Cloud API using custom LPU hardware. Llama 3 70B, Mixtral, Gemma.
    Responses in <1 second. Requires free signup at console.groq.com.
    Set GROQ_API_KEY env var.

  Tier 2 — Ollama (free, local, private)
    Runs open-source models on your machine. Qwen2 1.5B, Phi3, Llama 3.2.
    Fully offline, fully private. Requires Ollama installed.
    Auto-detected at localhost:11434.

  Tier 3 — Rule-based heuristics (always runs, instant)
    CWE patterns, scanner noise, EPSS, KEV, multi-scanner confirmation.
    Zero dependencies, zero network. Always provides a baseline result.

Cascade logic:
  - Rule-based heuristics ALWAYS run first (instant baseline).
  - Then the best available AI tier enhances the results.
  - If Groq is available → use it (best quality, fastest).
  - Else if Ollama is available → use it (local, private).
  - Else → keep rule-based results only.

Every call is gracefully guarded: failures in any tier fall through to the
next. The pipeline NEVER fails due to AI unavailability.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from .models import Finding

# ─────────────────────── Configuration ────────────────────────────────────────

OLLAMA_BASE = "http://localhost:11434"
OLLAMA_MODEL = "qwen2:1.5b"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama3-70b-8192"
GROQ_TIMEOUT = 30
OLLAMA_TIMEOUT = 30


# ═══════════════════════════════════════════════════════════════════════════════
# Tier 1: Groq (free cloud API, blazing fast)
# ═══════════════════════════════════════════════════════════════════════════════


class GroqClient:
    """Client for the Groq free API (OpenAI-compatible chat completions)."""

    def __init__(self, api_key: Optional[str] = None, model: str = GROQ_MODEL):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY") or ""
        self.model = model
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if Groq API key is set and the endpoint is reachable."""
        if self._available is not None:
            return self._available
        if not self.api_key:
            self._available = False
            return False
        try:
            # Lightweight check — send a minimal request
            payload = json.dumps(
                {
                    "model": self.model,
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 1,
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                GROQ_API_URL,
                data=payload,
                method="POST",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            self._available = bool(data.get("choices"))
            if self._available:
                print(f"  [groq] connected — using {self.model}")
            return self._available
        except Exception:
            self._available = False
            return False

    def chat(self, system: str, user: str, temperature: float = 0.3) -> str:
        """Send a chat completion request."""
        payload = json.dumps(
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": temperature,
                "max_tokens": 512,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            GROQ_API_URL,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=GROQ_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]


# ═══════════════════════════════════════════════════════════════════════════════
# Tier 2: Ollama (local, private, free)
# ═══════════════════════════════════════════════════════════════════════════════


class OllamaClient:
    """Client for the Ollama local HTTP API."""

    def __init__(self, base_url: str = OLLAMA_BASE, model: str = OLLAMA_MODEL):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if Ollama is running and the model is available."""
        if self._available is not None:
            return self._available
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name", "") for m in data.get("models", [])]
            self._available = any(
                self.model in m or m.startswith(self.model.split(":")[0])
                for m in models
            )
            if self._available:
                print(f"  [ollama] detected — using {self.model}")
            else:
                print(
                    f"  [ollama] running but model '{self.model}' not found "
                    f"(available: {', '.join(models[:5])})"
                )
            return self._available
        except Exception:
            self._available = False
            return False

    def chat(self, system: str, user: str, temperature: float = 0.3) -> str:
        """Send a chat message to Ollama."""
        payload = json.dumps(
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "options": {"temperature": temperature, "num_predict": 512},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("message", {}).get("content", "")


# ═══════════════════════════════════════════════════════════════════════════════
# LLM prompts (shared by Groq and Ollama)
# ═══════════════════════════════════════════════════════════════════════════════

_FP_SYSTEM_PROMPT = """You are a senior application-security engineer reviewing vulnerability scanner findings.

For EACH finding, assess the false-positive (FP) likelihood. Consider:
- Scanner type (ZAP is noisier than Nuclei/Trivy)
- CWE type (some CWEs are frequently misreported)
- Whether evidence is provided
- Whether a CVE exists and is in CISA KEV
- Severity vs actual impact

Return a JSON array with ONE object per finding, each containing:
- "fp_probability": float (0.0 = definitely real, 1.0 = definitely false positive)
- "fp_reason": one short sentence explaining why

Return ONLY the JSON array. No markdown, no preamble."""

_REMEDIATION_SYSTEM_PROMPT = """You are an AppSec engineer writing ticket-ready remediation steps.

For each finding, write exactly 2 sentences:
1. Immediate mitigation (can be done TODAY, reduces risk right now)
2. Permanent root-cause fix

Be concrete — reference the actual endpoint, package version, or CVE.
Return a JSON array of strings, one per finding. No markdown, raw JSON only."""

_BRIEF_SYSTEM_PROMPT = """You are a CISO writing a concise executive security briefing for a non-technical audience.

Write exactly 3 sentences:
1. Overall risk posture from this scan run
2. The single most critical finding requiring immediate action
3. The top recommended action for the team

Use non-technical language. Be specific and direct."""


# ═══════════════════════════════════════════════════════════════════════════════
# JSON parsing helper
# ═══════════════════════════════════════════════════════════════════════════════


def _safe_json_array(raw: str, expected_len: int) -> List[Any]:
    """Strip markdown fences and parse a JSON array. Pad short results."""
    cleaned = raw.strip()
    for fence in ("```json", "```"):
        if cleaned.startswith(fence):
            cleaned = cleaned[len(fence) :]
    cleaned = cleaned.rstrip("`").strip()
    try:
        result = json.loads(cleaned)
        if isinstance(result, list):
            while len(result) < expected_len:
                result.append({})
            return result[:expected_len]
    except (json.JSONDecodeError, TypeError):
        pass
    return [{} for _ in range(expected_len)]


# ═══════════════════════════════════════════════════════════════════════════════
# LLM task functions (used by both Groq and Ollama)
# ═══════════════════════════════════════════════════════════════════════════════


def _escape_prompt(text: str) -> str:
    """Escape prompt injection delimiters in untrusted text."""
    return text.replace("<|", "<\\|").replace("|>", "|\\>")


def _llm_classify_fp(client, findings: List[Finding]) -> List[Dict[str, Any]]:
    """Ask the LLM to classify false-positive probability for a batch."""
    items = []
    for i, f in enumerate(findings):
        kev_tag = " [KEV]" if f.kev else ""
        exploit_tag = " [EXPLOIT]" if f.exploit_available else ""
        evidence = _escape_prompt(str(f.evidence)[:100] or "none")
        title = _escape_prompt(f.title)
        items.append(
            f"{i + 1}. [{f.scanner}] {title} "
            f"(severity={f.severity}, cwe={f.cwe or 'none'}, "
            f"cve={f.cve or 'none'}{kev_tag}{exploit_tag}) "
            f"endpoint={f.endpoint or 'none'} "
            f"evidence=<|EVIDENCE|>{evidence}<|/EVIDENCE|>"
        )
    user_msg = "Classify these findings:\n\n" + "\n".join(items)
    raw = client.chat(_FP_SYSTEM_PROMPT, user_msg)
    return _safe_json_array(raw, len(findings))


def _llm_remediation(client, findings: List[Finding]) -> List[str]:
    """Ask the LLM to generate remediation for a batch."""
    items = []
    for i, f in enumerate(findings):
        pkg = ""
        if f.package:
            pkg = (
                f" package={f.package}"
                f" installed={f.installed_version or '?'}"
                f" fixed={f.fixed_version or 'unknown'}"
            )
        items.append(
            f"{i + 1}. {f.title} "
            f"(cwe={f.cwe or 'none'}, cve={f.cve or 'none'}, "
            f"scanner={f.scanner}, severity={f.severity}) "
            f"endpoint={f.endpoint or 'none'}{pkg} "
            f"desc={f.description[:150] or 'none'}"
        )
    user_msg = "Write remediation for:\n\n" + "\n".join(items)
    raw = client.chat(_REMEDIATION_SYSTEM_PROMPT, user_msg)
    return _safe_json_array(raw, len(findings))


def _llm_executive_brief(client, ranked: List[Finding], summary_stats: Dict) -> str:
    """Ask the LLM to write an executive brief."""
    top_lines = []
    for f in ranked[:5]:
        kev_tag = " [KEV]" if f.kev else ""
        top_lines.append(
            f"  #{f.score_breakdown.get('rank', '?')} score={f.score}"
            f"{kev_tag} {f.title[:60]} ({f.product})"
        )
    user_msg = (
        f"Scan summary: {summary_stats.get('raw_findings', 0)} raw findings -> "
        f"{summary_stats.get('unique_findings', 0)} unique after dedup -> "
        f"{summary_stats.get('final_findings', 0)} active after filtering. "
        f"P1={summary_stats.get('p1', 0)} P2={summary_stats.get('p2', 0)} "
        f"P3={summary_stats.get('p3', 0)} P4={summary_stats.get('p4', 0)}.\n"
        f"Top findings:\n" + "\n".join(top_lines)
    )
    return client.chat(_BRIEF_SYSTEM_PROMPT, user_msg, temperature=0.5)


# ═══════════════════════════════════════════════════════════════════════════════
# Tier 3: Rule-based heuristics (always runs)
# ═══════════════════════════════════════════════════════════════════════════════

_FP_TITLE_PATTERNS = [
    "server header",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "content security policy",
    "strict transport",
    "hsts",
    "cookie without httponly",
    "cookie without secure",
    "cookie without samesite",
    "cross-domain",
    "x-powered-by",
    "server disclosure",
    "information disclosure - server",
    "clickjacking",
    "anti-clickjacking",
    "x-content-type",
    "cache-control",
    "pragma",
    "referrer-policy",
]

_FP_CWES = {"CWE-200", "CWE-319", "CWE-261", "CWE-16"}
_REAL_CWES = {
    "CWE-89",
    "CWE-78",
    "CWE-94",
    "CWE-22",
    "CWE-502",
    "CWE-434",
    "CWE-918",
    "CWE-352",
    "CWE-79",
    "CWE-798",
    "CWE-287",
}
_SCANNER_NOISE = {
    "zap": 0.15,
    "wapiti": 0.10,
    "nuclei": 0.05,
    "trivy": 0.03,
    "nmap": 0.12,
    "openvas": 0.08,
}


def _classify_fp(f: Finding) -> tuple[float, str]:
    """Rule-based FP classification. Returns (probability, reason)."""
    score = 0.3
    reasons = []
    title_lower = (f.title or "").lower()

    for pat in _FP_TITLE_PATTERNS:
        if pat in title_lower:
            score += 0.35
            reasons.append(f"title matches FP pattern '{pat}'")
            break

    cwe = (f.cwe or "").upper()
    if cwe in _FP_CWES:
        score += 0.15
        reasons.append(f"CWE {cwe} is commonly noisy")
    elif cwe in _REAL_CWES:
        score -= 0.25
        reasons.append(f"CWE {cwe} is typically a real vulnerability")

    noise = _SCANNER_NOISE.get(f.scanner, 0.1)
    score += noise

    severity = (f.severity or "").lower()
    has_evidence = bool(f.evidence and len(str(f.evidence).strip()) > 5)
    if severity in ("critical", "high") and not has_evidence:
        score += 0.1
        reasons.append("high severity but no evidence")
    elif severity in ("critical", "high") and has_evidence:
        score -= 0.1

    if f.cve:
        score -= 0.15
    if f.kev:
        score -= 0.25
        reasons.append("in CISA KEV")
    if f.exploit_available:
        score -= 0.15
    if f.epss_percentile is not None:
        if f.epss_percentile > 0.7:
            score -= 0.15
        elif f.epss_percentile < 0.05:
            score += 0.1

    scanners = []
    if isinstance(f.raw, dict):
        scanners = f.raw.get("scanners", [])
    if len(scanners) > 1:
        score -= 0.2
        reasons.append(f"confirmed by {len(scanners)} scanners")

    score = max(0.0, min(1.0, score))
    return round(score, 3), reasons[0] if reasons else "heuristic assessment"


# ── Rule-based remediation ───────────────────────────────────────────────────

_CONTEXTUAL_REMEDIATION: Dict[str, str] = {
    "CWE-89": "Block the endpoint via WAF. Migrate to parameterized queries and validate all input.",
    "CWE-79": "Add CSP header and enable output encoding. Use context-aware auto-escaping.",
    "CWE-200": "Remove or restrict the exposed resource behind authentication.",
    "CWE-287": "Enforce MFA, rotate tokens, fix the authentication flaw.",
    "CWE-284": "Revoke over-broad permissions. Implement per-object authorization checks.",
    "CWE-434": "Disable unauthenticated upload. Validate by content type, store outside webroot.",
    "CWE-502": "Disable deserialization of untrusted input. Use safe formats (JSON).",
    "CWE-918": "Block outbound requests to internal/metadata IP ranges. Use egress proxy.",
    "CWE-22": "Canonicalize file paths. Never join user input into filesystem paths.",
    "CWE-611": "Disable external entity processing in XML parser. Prefer JSON.",
    "CWE-522": "Rotate exposed credentials. Store secrets in a vault.",
    "CWE-798": "Rotate hardcoded credentials. Use a secrets manager + CI secret scanning.",
    "CWE-319": "Force HTTPS with HSTS. Disable cleartext listeners.",
    "CWE-352": "Add SameSite=Strict cookies and CSRF tokens on state-changing endpoints.",
    "CWE-601": "Validate redirect URLs against an allow-list.",
    "CWE-78": "Never pass user input to a shell. Use safe APIs with argument lists.",
    "CWE-94": "Remove code-execution paths for user input. Apply framework security policies.",
    "CWE-269": "Audit and revoke elevated permissions. Implement least-privilege access.",
}
_GENERIC_REMEDIATION = (
    "Disable the affected functionality at the perimeter (WAF/ACL) while the "
    "permanent fix is prepared. Patch to the latest version and re-scan."
)


def _ai_remediation(f: Finding) -> str:
    cwe = (f.cwe or "").upper()
    base = _CONTEXTUAL_REMEDIATION.get(cwe, _GENERIC_REMEDIATION)
    parts = [base]
    if f.scanner == "trivy" and f.fixed_version:
        parts.append(
            f"Upgrade {f.package} from {f.installed_version} to {f.fixed_version}."
        )
    elif f.kev:
        parts.append(f"({f.cve}) is in CISA KEV — treat as urgent.")
    elif f.epss_percentile and f.epss_percentile > 0.8:
        parts.append(f"High EPSS ({f.epss_percentile:.1%}) — prioritize this fix.")
    return " ".join(parts[:2])


def _enhance_remediation(findings: List[Finding]) -> int:
    count = 0
    for f in findings:
        if f.status != "active":
            continue
        has_ai = any(
            s.get("kind") == "ai_remediation" for s in f.remediation_suggestions
        )
        if not has_ai:
            f.remediation_suggestions.insert(
                0,
                {
                    "kind": "ai_remediation",
                    "text": _ai_remediation(f),
                    "source": "rule-based-heuristics",
                },
            )
            count += 1
    return count


# ── Rule-based executive brief ────────────────────────────────────────────────


def _executive_brief(ranked: List[Finding], summary_stats: Dict) -> str:
    total = summary_stats.get("raw_findings", 0)
    active = summary_stats.get("final_findings", 0)
    unique = summary_stats.get("unique_findings", 0)
    noise_pct = round((1 - active / max(total, 1)) * 100)

    # Count by severity
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in ranked:
        s = f.severity or "info"
        if s in sev:
            sev[s] += 1
        else:
            sev["info"] += 1

    top = ranked[0] if ranked else None
    top_line = ""
    if top:
        kev = " [KEV]" if top.kev else ""
        exploit = " [EXPLOIT]" if top.exploit_available else ""
        top_line = (
            f'Top risk: "{top.title}" ({top.severity}, score {top.score}/100){kev}{exploit}.'
        )

    return (
        f"Analyzed {total} findings → {unique} unique → "
        f"{active} actionable ({noise_pct}% noise removed). "
        f"Critical: {sev['critical']}, High: {sev['high']}, Medium: {sev['medium']}, Low: {sev['low']}. "
        f"{top_line or 'No active findings.'}"
    )



def ai_enrich(
    findings: List[Finding],
    summary_stats: Optional[Dict] = None,
    skip_remediation: bool = False,
    ollama_model: Optional[str] = None,
    groq_api_key: Optional[str] = None,
    groq_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Enrich findings with 3-tier hybrid AI: Groq → Ollama → Rule-based.

    Args:
        findings: Findings to enrich in-place.
        summary_stats: Pipeline summary for executive brief.
        skip_remediation: Skip remediation enhancement.
        ollama_model: Ollama model name. '' = disable Ollama.
        groq_api_key: Groq API key. '' = disable Groq.
        groq_model: Groq model override.

    Returns:
        Metadata dict with counts, executive brief, and which tier was used.
    """
    result: Dict[str, Any] = {
        "used": True,
        "llm_used": False,
        "llm_tier": "rule-based",
        "counts": {"fp_classified": 0, "remediation": 0},
        "executive_brief": "",
    }

    active = [f for f in findings if f.status == "active"]
    if not active:
        return result

    # ── Step 1: Rule-based heuristics (always runs) ──────────────────────
    print(f"  [ai-enrich] classifying {len(active)} findings (rule-based) …")
    for f in active:
        fp_prob, fp_reason = _classify_fp(f)
        f.score_breakdown["ai_fp_probability"] = fp_prob
        f.score_breakdown["ai_fp_reason"] = fp_reason
        f.score_breakdown["ai_fp_source"] = "rule-based"
        # DO NOT penalize score here — wait for final blended probability
        result["counts"]["fp_classified"] += 1

    if not skip_remediation:
        result["counts"]["remediation"] = _enhance_remediation(active)

    # ── Step 2: Try AI tiers ─────────────────────────────────────────────
    # Try Groq first (fastest, smartest), then Ollama (local, private)
    ranked_for_brief = sorted(active, key=lambda f: f.score or 0, reverse=True)
    ai_client = None

    # Tier 1: Groq
    if groq_api_key != "":
        groq = GroqClient(api_key=groq_api_key, model=groq_model or GROQ_MODEL)
        try:
            if groq.is_available():
                ai_client = groq
                result["llm_tier"] = "groq"
        except Exception:
            pass

    # Tier 2: Ollama (only if Groq didn't work)
    if ai_client is None and ollama_model != "":
        ollama = OllamaClient(model=ollama_model or OLLAMA_MODEL)
        try:
            if ollama.is_available():
                ai_client = ollama
                result["llm_tier"] = "ollama"
        except Exception:
            pass

    # ── Apply LLM enhancement ────────────────────────────────────────────
    if ai_client is not None:
        tier = result["llm_tier"]
        print(f"  [ai-enrich] enhancing with {tier} …")

        # LLM FP classification (batched to avoid truncation)
        try:
            llm_results = []
            batch_size = 10
            for i in range(0, len(active), batch_size):
                batch = active[i : i + batch_size]
                batch_results = _llm_classify_fp(ai_client, batch)
                llm_results.extend(batch_results)
            for f, llm in zip(active, llm_results):
                if isinstance(llm, dict) and "fp_probability" in llm:
                    llm_prob = float(llm["fp_probability"])
                    llm_reason = llm.get("fp_reason", "")
                    old_prob = f.score_breakdown.get("ai_fp_probability", 0.5)
                    blended = round(0.6 * llm_prob + 0.4 * old_prob, 3)
                    f.score_breakdown["ai_fp_probability"] = blended
                    f.score_breakdown["ai_fp_reason"] = (
                        f"[{tier}] {llm_reason}"
                        if llm_reason
                        else f"Rule: {f.score_breakdown.get('ai_fp_reason', '')}"
                    )
                    f.score_breakdown["ai_fp_source"] = f"{tier}+rule"
                    # Apply penalty ONCE based on blended probability
                    if f.score is not None:
                        if blended > 0.6:
                            penalty = round((blended - 0.6) * 25, 1)
                            f.score = max(0, round(f.score - penalty, 1))
                            f.score_breakdown["ai_fp_penalty"] = -penalty
                        elif "ai_fp_penalty" in f.score_breakdown:
                            # Remove penalty if blended <= 0.6
                            del f.score_breakdown["ai_fp_penalty"]
            result["llm_used"] = True
            print(f"  [ai-enrich] {tier} FP classification complete")
        except Exception as exc:
            print(f"  [ai-enrich] {tier} FP classification failed: {exc}")

        # LLM remediation (top 20)
        if not skip_remediation:
            try:
                top_20 = sorted(active, key=lambda f: f.score or 0, reverse=True)[:20]
                llm_rems = _llm_remediation(ai_client, top_20)
                enhanced = 0
                for f, rem_text in zip(top_20, llm_rems):
                    if isinstance(rem_text, str) and len(rem_text) > 20:
                        idx = next(
                            (
                                i
                                for i, s in enumerate(f.remediation_suggestions)
                                if s.get("kind") == "ai_remediation"
                            ),
                            None,
                        )
                        if idx is not None:
                            f.remediation_suggestions[idx]["text"] = rem_text
                            f.remediation_suggestions[idx]["source"] = (
                                f"{tier}:{ai_client.model}"
                            )
                            enhanced += 1
                result["counts"]["remediation"] += enhanced
                print(f"  [ai-enrich] {tier} remediation: {enhanced} enhanced")
            except Exception as exc:
                print(f"  [ai-enrich] {tier} remediation failed: {exc}")

        # LLM executive brief
        if summary_stats:
            try:
                brief = _llm_executive_brief(ai_client, ranked_for_brief, summary_stats)
                if brief and len(brief) > 20:
                    result["executive_brief"] = brief
                    print(f"  [ai-enrich] {tier} executive brief generated")
            except Exception as exc:
                print(f"  [ai-enrich] {tier} executive brief failed: {exc}")

    # ── Apply FP penalty for findings not processed by LLM ──────────────────
    # When LLM is unavailable, apply penalty from rule-based probability only
    for f in active:
        if "ai_fp_penalty" not in f.score_breakdown and f.score is not None:
            fp_prob = f.score_breakdown.get("ai_fp_probability", 0.5)
            if fp_prob > 0.6:
                penalty = round((fp_prob - 0.6) * 25, 1)
                f.score = max(0, round(f.score - penalty, 1))
                f.score_breakdown["ai_fp_penalty"] = -penalty

    # ── Rule-based executive brief (always, as fallback) ──────────────────
    if not result["executive_brief"] and summary_stats:
        result["executive_brief"] = _executive_brief(ranked_for_brief, summary_stats)

    tier = result["llm_tier"]
    llm_tag = f" ({tier})" if result["llm_used"] else ""
    print(
        f"  [ai-enrich] done{llm_tag} — FP: "
        f"{result['counts']['fp_classified']} · "
        f"Remediation: {result['counts']['remediation']}"
    )
    return result
