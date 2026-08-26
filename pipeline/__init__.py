"""DevSecOps Risk Intelligence Pipeline — 9-stage vulnerability processing.

Unified pipeline that consolidates pjt (v1 DefectDojo) and pjt2 (v2 custom)
into a single, production-ready system.

Stages:
  1. Normalize   — parse raw scanner reports into unified Finding schema
  2. Dedup       — cross-scanner deduplication (CVE / endpoint+CWE / title)
  3. Filter      — auditable quarantine (severity / FP / risk-accept)
  4. Enrich      — CISA KEV, EPSS, NVD, Exploit-DB
  5. Attack Path — CAPEC-inspired CWE chain mapping
  6. Score       — 8-factor 0-100 contextual risk score
  7. AI Enrich   — FP classification + smart remediation (Groq/Ollama/rule)
  8. Remediate   — first-aid + full remediation + scanner guidance
  9. Output      — ranking, CSV/JSON/markdown, dashboard, tickets
"""
__version__ = "2.0.0"
