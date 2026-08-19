"""Remediation suggestions.

Every active finding gets 2-3 actionable suggestions:

  1. first_aid        — quick mitigation to stop bleeding today (WAF rule,
                        disable endpoint, rotate credentials, restrict access)
  2. full_remediation — root fix (upgrade to fixed version, code fix, patch)
  3. scanner_guidance — the fix text the scanner itself provided (ZAP solution,
                        Wapiti sol, Trivy FixedVersion, Nuclei reference)

First-aid / full-fix texts come from a curated CWE -> guidance map with a
sensible generic fallback.
"""
from __future__ import annotations

from typing import Dict, List

from .models import Finding

# CWE -> (first_aid, full_remediation)
GUIDANCE: Dict[str, tuple] = {
    "CWE-89": ("Block the endpoint with a WAF SQLi rule and restrict DB account privileges.",
               "Use parameterized queries / prepared statements everywhere; never concatenate user input into SQL."),
    "CWE-79": ("Add a CSP and encode output; disable the affected input path temporarily.",
               "Encode all output contextually (HTML, attribute, JS) and sanitize rich input server-side."),
    "CWE-200": ("Restrict access to the exposed resource (auth, IP allow-list, remove from public routing).",
                "Redact/remove the sensitive data from responses and apply least-privilege access controls."),
    "CWE-287": ("Enforce MFA and lock out the affected account(s); rotate exposed credentials.",
                "Fix the authentication flaw (session validation, rate limiting, secure token handling) and re-test."),
    "CWE-284": ("Revoke the over-broad permissions immediately; audit who used them.",
                "Implement least-privilege authorization with per-object access checks."),
    "CWE-434": ("Disable the upload endpoint or restrict it to authenticated, allow-listed users.",
                "Validate file type/content, store uploads outside the webroot with random names, and never execute them."),
    "CWE-502": ("Disable deserialization of untrusted input at the perimeter (WAF/serialization filter).",
                "Replace native deserialization with safe formats (JSON) or validate/allow-list classes."),
    "CWE-918": ("Block outbound traffic to internal/metadata ranges at the firewall; disable the vulnerable fetcher.",
                "Validate and allow-list server-side request targets; use an outbound proxy with deny rules for RFC1918/metadata."),
    "CWE-22": ("Block traversal patterns at the WAF and disable symbolic links on the webroot.",
                "Use an allow-listed file API and canonicalize paths before access; never join user input into filesystem paths."),
    "CWE-611": ("Disable external entity processing in the XML parser configuration.",
                "Set XML parser flags (disallow-doctype, external-entities off) and prefer JSON over XML."),
    "CWE-522": ("Rotate the exposed credentials and revoke any tokens issued from them.",
                "Encrypt credentials at rest, use a vault, and stop transmitting/storing them insecurely."),
    "CWE-798": ("Rotate the hardcoded credential everywhere it is used; remove it from the codebase.",
                "Move secrets to a secrets manager and inject them at runtime; add secret scanning to CI."),
    "CWE-319": ("Force HTTPS on all endpoints (HSTS) and disable cleartext listeners.",
                "Serve everything over TLS with modern ciphers; migrate internal links to HTTPS."),
    "CWE-352": ("Add SameSite=Strict cookies and require a CSRF token on state-changing endpoints.",
                "Implement synchronizer CSRF tokens on all state-changing forms and APIs."),
    "CWE-601": ("Block open redirects at the WAF by validating redirect targets.",
                "Validate redirect URLs against an allow-list; never reflect user input in Location headers."),
    "CWE-78": ("Block the endpoint at the WAF and restrict shell access of the service account.",
                "Never pass user input to a shell; use safe APIs with argument lists and strict allow-lists."),
    "CWE-94": ("Isolate the vulnerable runtime; apply a WAF rule and disable the affected functionality.",
                "Remove code-execution paths for user input; apply framework security policies and patch the runtime."),
    "CWE-269": ("Audit and revoke elevated permissions held by the affected service accounts.",
                "Redesign privilege model to least-privilege with role-based access and separation of duties."),
}

GENERIC_FIRST_AID = ("Disable or restrict the affected functionality/endpoint at the perimeter "
                     "(WAF rule, network ACL, feature flag) while the fix is prepared.")
GENERIC_FULL = ("Patch or upgrade the affected component to the latest fixed version and "
                "re-run the scan to confirm the finding is gone.")


def suggest_remediation(f: Finding) -> List[Dict[str, str]]:
    """Returns 2-3 suggestions: first_aid, full_remediation, scanner_guidance."""
    suggestions: List[Dict[str, str]] = []
    cwe = (f.cwe or "").upper()
    first_aid, full = GUIDANCE.get(cwe, (GENERIC_FIRST_AID, GENERIC_FULL))

    if f.scanner == "trivy" and f.fixed_version:
        full = (f"Upgrade package {f.package} from {f.installed_version} "
                f"to {f.fixed_version} (fixed version) in the image and rebuild/redeploy.")
        first_aid = (f"Apply the vendor security patch for {f.cve or f.package}; "
                     "if unavailable, isolate the container and restrict egress.")

    suggestions.append({"kind": "first_aid", "text": first_aid, "source": "cwe-guidance"})
    suggestions.append({"kind": "full_remediation", "text": full, "source": "cwe-guidance"})

    scanner_text = f.remediation
    if scanner_text:
        suggestions.append({"kind": "scanner_guidance", "text": scanner_text,
                            "source": f"scanner:{f.scanner}"})
    return suggestions
