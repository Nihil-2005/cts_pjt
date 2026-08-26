"""CWE-based remediation suggestions: first_aid + full_remediation + scanner_guidance."""

from __future__ import annotations
from typing import Dict, List
from .models import Finding

GUIDANCE: Dict[str, tuple] = {
    "CWE-89": ("Block the endpoint with a WAF SQLi rule and restrict DB account privileges.",
               "Use parameterized queries / prepared statements everywhere."),
    "CWE-79": ("Add a CSP and encode output; disable the affected input path temporarily.",
               "Encode all output contextually (HTML, attribute, JS) and sanitize rich input."),
    "CWE-200": ("Restrict access to the exposed resource (auth, IP allow-list).",
                "Redact/remove sensitive data from responses and apply least-privilege access."),
    "CWE-287": ("Enforce MFA and lock out affected accounts; rotate exposed credentials.",
                "Fix the authentication flaw and re-test."),
    "CWE-284": ("Revoke over-broad permissions immediately; audit who used them.",
                "Implement least-privilege authorization with per-object access checks."),
    "CWE-434": ("Disable the upload endpoint or restrict to authenticated, allow-listed users.",
                "Validate file type/content, store uploads outside webroot with random names."),
    "CWE-502": ("Disable deserialization of untrusted input at the perimeter.",
                "Replace native deserialization with safe formats (JSON) or validate/allow-list classes."),
    "CWE-918": ("Block outbound traffic to internal/metadata ranges at the firewall.",
                "Validate and allow-list server-side request targets; use outbound proxy."),
    "CWE-22": ("Block traversal patterns at the WAF and disable symbolic links.",
                "Use an allow-listed file API and canonicalize paths before access."),
    "CWE-611": ("Disable external entity processing in the XML parser configuration.",
                "Set XML parser flags (disallow-doctype, external-entities off) and prefer JSON."),
    "CWE-522": ("Rotate exposed credentials and revoke any tokens issued from them.",
                "Encrypt credentials at rest, use a vault, stop transmitting/storing insecurely."),
    "CWE-798": ("Rotate the hardcoded credential everywhere; remove it from the codebase.",
                "Move secrets to a secrets manager and inject at runtime; add secret scanning to CI."),
    "CWE-319": ("Force HTTPS on all endpoints (HSTS) and disable cleartext listeners.",
                "Serve everything over TLS with modern ciphers; migrate internal links to HTTPS."),
    "CWE-352": ("Add SameSite=Strict cookies and require CSRF token on state-changing endpoints.",
                "Implement synchronizer CSRF tokens on all state-changing forms and APIs."),
    "CWE-601": ("Block open redirects at the WAF by validating redirect targets.",
                "Validate redirect URLs against an allow-list; never reflect user input in Location."),
    "CWE-78": ("Block the endpoint at the WAF and restrict shell access of the service account.",
                "Never pass user input to a shell; use safe APIs with argument lists."),
    "CWE-94": ("Isolate the vulnerable runtime; apply a WAF rule and disable affected functionality.",
                "Remove code-execution paths for user input; apply framework security policies."),
    "CWE-269": ("Audit and revoke elevated permissions held by affected service accounts.",
                "Redesign privilege model to least-privilege with role-based access."),
}

GENERIC_FIRST_AID = "Disable or restrict the affected functionality/endpoint at the perimeter while the fix is prepared."
GENERIC_FULL = "Patch or upgrade the affected component to the latest fixed version and re-run the scan."


def suggest_remediation(f: Finding) -> List[Dict[str, str]]:
    """Returns 2-3 suggestions: first_aid, full_remediation, scanner_guidance."""
    suggestions: List[Dict[str, str]] = []
    cwe = (f.cwe or "").upper()
    first_aid, full = GUIDANCE.get(cwe, (GENERIC_FIRST_AID, GENERIC_FULL))

    if f.scanner == "trivy" and f.fixed_version:
        full = f"Upgrade package {f.package} from {f.installed_version} to {f.fixed_version} and rebuild/redeploy."
        first_aid = f"Apply the vendor security patch for {f.cve or f.package}; if unavailable, isolate the container."

    suggestions.append({"kind": "first_aid", "text": first_aid, "source": "cwe-guidance"})
    suggestions.append({"kind": "full_remediation", "text": full, "source": "cwe-guidance"})
    if f.remediation:
        suggestions.append({"kind": "scanner_guidance", "text": f.remediation, "source": f"scanner:{f.scanner}"})
    return suggestions
