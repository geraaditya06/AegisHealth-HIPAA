"""
audit_logging_check.py — HIPAA §164.312(b) Audit Controls

Checks whether the target application exposes audit / logging indicators
and whether failed-login attempts appear to be tracked.
"""

import requests
import re
from typing import List, Dict, Any
from .helpers import get_base, safe_get, safe_post, probe_path, finding


# Common paths where audit / logging endpoints are exposed
AUDIT_PATHS = [
    "/api/audit", "/api/audit-log", "/api/logs", "/api/events",
    "/audit", "/audit-log", "/logs", "/admin/logs",
    "/admin/audit", "/api/activity", "/api/event-log",
]

# Headers that indicate logging / tracing infrastructure is in place
LOGGING_HEADERS = [
    "x-request-id", "x-trace-id", "x-correlation-id",
    "x-amzn-requestid", "x-amzn-trace-id", "traceparent",
]

# Common login endpoints to probe for failed-login tracking
LOGIN_ENDPOINTS = [
    "/api/login", "/api/auth/login", "/api/auth", "/login",
    "/auth/token", "/api/auth/token",
]


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    """Run all audit-logging related checks against *target_url*."""
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)

    # ── AL-01: Audit / logging endpoint detection ────────────────────────────
    audit_found: List[str] = []
    for path in AUDIT_PATHS:
        r = probe_path(base, path)
        if r is not None and r.status_code in (200, 401, 403):
            audit_found.append(path)

    findings.append(finding(
        check_id="AL-01",
        category="Audit",
        severity="high",
        passed=len(audit_found) > 0,
        description=(
            f"Audit/logging endpoint(s) detected: {', '.join(audit_found)}"
            if audit_found
            else "No audit or logging endpoints detected"
        ),
        remediation=(
            "Implement a centralised audit-logging system that records access events, "
            "authentication attempts, and data modifications as required by "
            "HIPAA §164.312(b). Expose an internal audit-log API for review."
        ),
    ))

    # ── AL-02: Request-tracing headers present ───────────────────────────────
    r = safe_get(base)
    trace_headers_found: List[str] = []
    if r is not None:
        lower_headers = {k.lower(): v for k, v in r.headers.items()}
        trace_headers_found = [h for h in LOGGING_HEADERS if h in lower_headers]

    findings.append(finding(
        check_id="AL-02",
        category="Audit",
        severity="medium",
        passed=len(trace_headers_found) > 0,
        description=(
            f"Request tracing header(s) found: {', '.join(trace_headers_found)}"
            if trace_headers_found
            else "No request-tracing headers (X-Request-Id etc.) detected"
        ),
        remediation=(
            "Add X-Request-Id or a similar correlation header to every HTTP response. "
            "This enables tracing individual requests across services and is essential "
            "for HIPAA audit trails."
        ),
    ))

    # ── AL-03: Failed-login tracking ─────────────────────────────────────────
    # We attempt 3 invalid logins and observe whether the server signals
    # account-lockout, rate-limiting, or tracking behaviour.
    lockout_detected = False
    status_codes: List[int] = []
    for endpoint in LOGIN_ENDPOINTS:
        for _ in range(3):
            r = safe_post(
                f"{base}{endpoint}",
                json={"username": "aegis_scanner_probe", "password": "invalid_pwd_probe"},
                allow_redirects=False,
            )
            if r is not None:
                status_codes.append(r.status_code)
                # 429 = rate-limited; 423 = locked
                if r.status_code in (429, 423):
                    lockout_detected = True
                    break
                body = r.text.lower()
                if any(kw in body for kw in ("locked", "too many", "rate limit", "blocked")):
                    lockout_detected = True
                    break
        if lockout_detected:
            break

    findings.append(finding(
        check_id="AL-03",
        category="Audit",
        severity="high",
        passed=lockout_detected,
        description=(
            "Failed-login tracking / lockout mechanism detected"
            if lockout_detected
            else "No evidence of failed-login tracking or account lockout"
        ),
        remediation=(
            "Implement account-lockout or progressive delay after repeated failed "
            "login attempts. Log every authentication failure with timestamp, "
            "source IP, and username per HIPAA §164.312(b)."
        ),
    ))

    # ── AL-04: Cache-Control / no-store on sensitive responses ───────────────
    # Audit-sensitive pages should not be cached by intermediaries.
    sensitive_paths = ["/api/audit", "/api/logs", "/admin", "/dashboard"]
    cache_issues: List[str] = []
    for path in sensitive_paths:
        r = probe_path(base, path)
        if r is not None and r.status_code == 200:
            cc = r.headers.get("Cache-Control", "").lower()
            if "no-store" not in cc and "private" not in cc:
                cache_issues.append(path)

    findings.append(finding(
        check_id="AL-04",
        category="Audit",
        severity="medium",
        passed=len(cache_issues) == 0,
        description=(
            "Sensitive endpoints set Cache-Control: no-store or private"
            if not cache_issues
            else f"Sensitive endpoint(s) missing no-store/private cache directive: {', '.join(cache_issues)}"
        ),
        remediation=(
            "Add 'Cache-Control: no-store' to responses from audit/admin endpoints "
            "to prevent sensitive data from being cached by proxies or browsers."
        ),
    ))

    return findings
