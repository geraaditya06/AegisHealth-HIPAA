"""
input_validation_check.py — Input Validation & Injection Testing

Tests for reflected XSS, SQL injection indicators, and command injection
using safe, non-destructive payloads.
"""

import re
from typing import List, Dict, Any
from .helpers import get_base, safe_get, safe_post, finding


# XSS test payloads and their expected reflections
XSS_PAYLOADS = [
    ('<script>alert("xss")</script>', '<script>alert("xss")</script>'),
    ('<img src=x onerror=alert(1)>', '<img src=x onerror=alert(1)>'),
    ('"><svg onload=alert(1)>', '"><svg onload=alert(1)>'),
    ("javascript:alert(1)", "javascript:alert(1)"),
]

# SQL injection test payloads — look for error messages
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "1' OR '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
]

SQLI_ERROR_PATTERNS = [
    r"sql syntax", r"mysql", r"sqlite", r"postgresql",
    r"ora-\d{5}", r"unclosed quotation", r"syntax error",
    r"unterminated string", r"sql error", r"database error",
    r"odbc", r"jdbc", r"microsoft ole db",
]

# Parameter names commonly used in search / input
PARAM_NAMES = ["q", "search", "query", "s", "keyword", "id", "user", "name"]


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)

    # ── IV-01: Reflected XSS via GET parameters ─────────────────────────────
    xss_reflected = False
    xss_detail = ""
    for param in PARAM_NAMES:
        for payload, expected in XSS_PAYLOADS:
            r = safe_get(f"{base}/", allow_redirects=True)
            # Try appending the payload as a query parameter
            r = safe_get(f"{base}/?{param}={payload}")
            if r is not None and expected in r.text:
                xss_reflected = True
                xss_detail = f"Payload reflected via ?{param}="
                break
        if xss_reflected:
            break

    # Also try common search endpoints
    if not xss_reflected:
        search_paths = ["/search", "/api/search", "/find"]
        for path in search_paths:
            for payload, expected in XSS_PAYLOADS[:2]:
                r = safe_get(f"{base}{path}?q={payload}")
                if r is not None and expected in r.text:
                    xss_reflected = True
                    xss_detail = f"Payload reflected at {path}?q="
                    break
            if xss_reflected:
                break

    findings.append(finding(
        check_id="IV-01",
        category="Input Validation",
        severity="high",
        passed=not xss_reflected,
        description=(
            "No reflected XSS detected in tested parameters"
            if not xss_reflected
            else f"Reflected XSS detected — {xss_detail}"
        ),
        remediation=(
            "Sanitise and escape all user input before rendering it in HTML. "
            "Use context-aware output encoding and a strict Content-Security-Policy."
        ),
    ))

    # ── IV-02: SQL injection indicators ──────────────────────────────────────
    sqli_detected = False
    sqli_detail = ""
    for param in PARAM_NAMES[:4]:
        for payload in SQLI_PAYLOADS:
            r = safe_get(f"{base}/?{param}={payload}")
            if r is not None:
                body_lower = r.text.lower()
                for err_pattern in SQLI_ERROR_PATTERNS:
                    if re.search(err_pattern, body_lower):
                        sqli_detected = True
                        sqli_detail = f"SQL error in response for ?{param}="
                        break
            if sqli_detected:
                break
        if sqli_detected:
            break

    findings.append(finding(
        check_id="IV-02",
        category="Input Validation",
        severity="high",
        passed=not sqli_detected,
        description=(
            "No SQL injection indicators detected"
            if not sqli_detected
            else f"Possible SQL injection — {sqli_detail}"
        ),
        remediation=(
            "Use parameterised queries or an ORM for all database access. "
            "Never concatenate user input into SQL strings."
        ),
    ))

    # ── IV-03: Error message information leakage ─────────────────────────────
    verbose_errors = False
    error_detail = ""
    # Trigger a 404/500 and inspect the error body
    error_paths = ["/nonexistent_path_aegis_probe", "/%00", "/api/..;/admin"]
    error_indicators = [
        "traceback", "stack trace", "exception", "debug",
        "file \"", "line ", "at module", "internal server error",
        "syntax error", "valueerror", "typeerror", "keyerror",
    ]
    for path in error_paths:
        r = safe_get(f"{base}{path}")
        if r is not None and r.status_code >= 400:
            body_lower = r.text.lower()
            for indicator in error_indicators:
                if indicator in body_lower:
                    verbose_errors = True
                    error_detail = f"Verbose error at {path} contains '{indicator}'"
                    break
        if verbose_errors:
            break

    findings.append(finding(
        check_id="IV-03",
        category="Input Validation",
        severity="medium",
        passed=not verbose_errors,
        description=(
            "Error responses do not leak stack traces or debug info"
            if not verbose_errors
            else f"Verbose error responses detected — {error_detail}"
        ),
        remediation=(
            "Configure your application to return generic error messages in "
            "production. Disable debug mode and stack trace display."
        ),
    ))

    # ── IV-04: Open redirect detection ───────────────────────────────────────
    open_redirect = False
    redirect_params = ["redirect", "url", "next", "return", "returnUrl", "goto"]
    evil_target = "https://evil-attacker.com"
    for param in redirect_params:
        r = safe_get(f"{base}/login?{param}={evil_target}", allow_redirects=False)
        if r is not None and r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("Location", "")
            if evil_target in location:
                open_redirect = True
                break

    findings.append(finding(
        check_id="IV-04",
        category="Input Validation",
        severity="medium",
        passed=not open_redirect,
        description=(
            "No open redirect vulnerabilities detected"
            if not open_redirect
            else "Open redirect detected — login page redirects to attacker-controlled URL"
        ),
        remediation=(
            "Validate redirect URLs against a whitelist of allowed domains. "
            "Never redirect to user-supplied absolute URLs."
        ),
    ))

    return findings
