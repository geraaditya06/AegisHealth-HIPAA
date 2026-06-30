"""
access_control_check.py — HIPAA §164.312(a) Access Control

Checks for exposed admin panels, missing authentication on protected routes,
absence of RBAC indicators, and MFA detection heuristics.
"""

import re
from typing import List, Dict, Any
from .helpers import get_base, safe_get, probe_path, finding


# Endpoints that should require authentication
ADMIN_PATHS = [
    "/admin", "/admin/", "/dashboard", "/dashboard/",
    "/admin/users", "/admin/settings", "/management",
    "/console", "/panel", "/control-panel",
]

# Endpoint patterns that typically serve protected resources
PROTECTED_PATTERNS = [
    "/api/users", "/api/patients", "/api/records",
    "/api/profile", "/api/account", "/api/settings",
    "/api/reports",
]


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)

    # ── AC-01: Admin panel accessibility ─────────────────────────────────────
    exposed_admin: List[str] = []
    for path in ADMIN_PATHS:
        r = probe_path(base, path)
        if r is not None and r.status_code == 200 and len(r.text) > 100:
            exposed_admin.append(path)

    findings.append(finding(
        check_id="AC-01",
        category="Access Control",
        severity="high",
        passed=len(exposed_admin) == 0,
        description=(
            "No admin panels are publicly accessible without authentication"
            if not exposed_admin
            else f"Admin panel(s) accessible without authentication: {', '.join(exposed_admin)}"
        ),
        remediation=(
            "Protect all admin endpoints with authentication and IP allowlisting. "
            "Return HTTP 401/403 for unauthenticated requests per HIPAA §164.312(a)(1)."
        ),
    ))

    # ── AC-02: Protected API endpoints require authentication ────────────────
    unprotected_apis: List[str] = []
    for path in PROTECTED_PATTERNS:
        r = probe_path(base, path)
        if r is not None and r.status_code == 200:
            # If the endpoint returns actual data without an Authorization header it's exposed
            unprotected_apis.append(path)

    findings.append(finding(
        check_id="AC-02",
        category="Access Control",
        severity="high",
        passed=len(unprotected_apis) == 0,
        description=(
            "All tested API endpoints require authentication"
            if not unprotected_apis
            else f"API endpoint(s) accessible without auth: {', '.join(unprotected_apis)}"
        ),
        remediation=(
            "Enforce authentication middleware on every API route that returns "
            "PHI or PII. Use JWT or OAuth2 bearer tokens and return 401 for "
            "unauthenticated callers."
        ),
    ))

    # ── AC-03: RBAC / role indicators ────────────────────────────────────────
    # Look for role-based access hints in the main page or API responses.
    rbac_detected = False
    r = safe_get(base)
    if r is not None:
        body = r.text.lower()
        rbac_keywords = ["role", "permission", "rbac", "admin", "user-role",
                         "access-level", "privilege", "authorization"]
        if any(kw in body for kw in rbac_keywords):
            rbac_detected = True

    # Also inspect response headers / meta
    if not rbac_detected:
        for path in ["/api/me", "/api/profile", "/api/auth/me"]:
            r = probe_path(base, path)
            if r is not None and r.status_code in (200, 401, 403):
                body = r.text.lower()
                if any(kw in body for kw in ("role", "permission", "scope")):
                    rbac_detected = True
                    break

    findings.append(finding(
        check_id="AC-03",
        category="Access Control",
        severity="medium",
        passed=rbac_detected,
        description=(
            "RBAC / role-based access indicators detected"
            if rbac_detected
            else "No role-based access control indicators found"
        ),
        remediation=(
            "Implement role-based access control (RBAC) so that users can only "
            "access the minimum necessary PHI for their role, as required by "
            "HIPAA §164.312(a)(1) and the Minimum Necessary Rule."
        ),
    ))

    # ── AC-04: MFA indicators ───────────────────────────────────────────────
    mfa_detected = False
    mfa_keywords = [
        "mfa", "2fa", "two-factor", "multi-factor", "totp", "otp",
        "authenticator", "verification-code", "sms-code",
    ]
    # Check the main page and common auth pages
    for path in ["", "/login", "/signin", "/auth/login", "/api/auth/mfa"]:
        r = safe_get(f"{base}{path}")
        if r is not None:
            body = r.text.lower()
            if any(kw in body for kw in mfa_keywords):
                mfa_detected = True
                break

    findings.append(finding(
        check_id="AC-04",
        category="Access Control",
        severity="high",
        passed=mfa_detected,
        description=(
            "Multi-factor authentication (MFA) indicators detected"
            if mfa_detected
            else "No MFA indicators found — single-factor authentication only"
        ),
        remediation=(
            "Implement multi-factor authentication (MFA) for all users accessing ePHI. "
            "Use TOTP, hardware keys, or SMS-based verification as a second factor. "
            "HIPAA §164.312(d) requires person-or-entity authentication."
        ),
    ))

    # ── AC-05: Directory traversal resistance ────────────────────────────────
    traversal_payloads = [
        "/../../../etc/passwd",
        "/..%2f..%2f..%2fetc%2fpasswd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ]
    traversal_vulnerable = False
    for payload in traversal_payloads:
        r = safe_get(f"{base}{payload}", allow_redirects=False)
        if r is not None and r.status_code == 200:
            if "root:" in r.text or "/bin/" in r.text:
                traversal_vulnerable = True
                break

    findings.append(finding(
        check_id="AC-05",
        category="Access Control",
        severity="high",
        passed=not traversal_vulnerable,
        description=(
            "No directory traversal vulnerability detected"
            if not traversal_vulnerable
            else "Directory traversal vulnerability — server returned sensitive file contents"
        ),
        remediation=(
            "Sanitise file path parameters and use chroot or jail the web root. "
            "Never map user-supplied path components directly to the filesystem."
        ),
    ))

    return findings
