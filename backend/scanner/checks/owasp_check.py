"""
owasp_check.py — Passive OWASP Top 10 Detection.

Non-intrusive, read-only detection of the most common OWASP risk classes. Each
finding is mapped to the most relevant executive scoring category so it folds
naturally into the multi-category score.

    OWASP-A03-SQLI     SQL Injection (error-based signal)
    OWASP-A03-XSS      Reflected Cross-Site Scripting
    OWASP-A01-CSRF     Missing CSRF protection on forms
    OWASP-A05-CLICK    Clickjacking (X-Frame-Options / frame-ancestors)
    OWASP-A01-IDOR     Insecure Direct Object Reference (numeric id heuristic)
    OWASP-A05-DIRLIST  Directory listing enabled
    OWASP-A05-HEADERS  Missing security headers
    OWASP-A01-REDIR    Open redirect
    OWASP-A09-INFO     Information disclosure (server banner / comments / stack)
    OWASP-A07-AUTH     Weak authentication transport (login over HTTP)

These complement (not replace) the deeper input_validation / headers modules.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .helpers import finding, get_base, get_domain, safe_get

# Reflected-input probes
XSS_PAYLOAD = '<svg/onload=alert(1)>'
SQLI_PAYLOAD = "'"
SQLI_ERRORS = [
    "sql syntax", "mysql", "sqlite", "postgresql", "ora-", "odbc",
    "unclosed quotation", "syntax error", "sqlstate", "psqlexception",
]
PARAMS = ["q", "search", "id", "query", "name", "page"]
REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "dest"]
SECURITY_HEADERS = {
    "Content-Security-Policy": "high",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "medium",
    "Referrer-Policy": "low",
    "Strict-Transport-Security": "high",
}
INFO_LEAK_TOKENS = ["traceback", "stack trace", "exception", "debug=true", "<!-- todo", "<!-- fixme", "x-powered-by"]


def _xss(base: str) -> Dict[str, Any]:
    reflected = False
    for param in PARAMS:
        r = safe_get(f"{base}/?{param}={XSS_PAYLOAD}")
        if r is not None and XSS_PAYLOAD in r.text:
            reflected = True
            break
    return finding(
        check_id="OWASP-A03-XSS", category="Input Validation", severity="high",
        passed=not reflected,
        description=("No reflected XSS detected" if not reflected else "Reflected XSS — payload echoed unencoded"),
        remediation="Context-encode all output and apply a strict Content-Security-Policy.",
    )


def _sqli(base: str) -> Dict[str, Any]:
    detected = False
    for param in PARAMS[:4]:
        r = safe_get(f"{base}/?{param}={SQLI_PAYLOAD}")
        if r is not None:
            low = r.text.lower()
            if any(e in low for e in SQLI_ERRORS):
                detected = True
                break
    return finding(
        check_id="OWASP-A03-SQLI", category="Input Validation", severity="high",
        passed=not detected,
        description=("No SQL error-based injection signals" if not detected else "SQL error leaked on crafted input"),
        remediation="Use parameterised queries/ORM and suppress database error details in responses.",
    )


def _csrf(base: str) -> Dict[str, Any]:
    """Heuristic: POST forms without a CSRF token / no SameSite cookie."""
    r = safe_get(base)
    forms_missing = 0
    if r is not None:
        for form in re.findall(r"<form[^>]*method=[\"']?post[\"']?[^>]*>(.*?)</form>", r.text, re.IGNORECASE | re.DOTALL):
            if not re.search(r"csrf|xsrf|_token|authenticity_token", form, re.IGNORECASE):
                forms_missing += 1
    return finding(
        check_id="OWASP-A01-CSRF", category="Session", severity="medium",
        passed=forms_missing == 0,
        description=("State-changing forms include anti-CSRF tokens" if forms_missing == 0
                     else f"{forms_missing} POST form(s) without a visible CSRF token"),
        remediation="Add per-session CSRF tokens to state-changing forms and set SameSite cookies.",
    )


def _clickjacking(base: str) -> Dict[str, Any]:
    r = safe_get(base)
    protected = False
    if r is not None:
        xfo = r.headers.get("X-Frame-Options", "").lower()
        csp = r.headers.get("Content-Security-Policy", "").lower()
        protected = ("deny" in xfo or "sameorigin" in xfo) or ("frame-ancestors" in csp)
    return finding(
        check_id="OWASP-A05-CLICK", category="Headers", severity="medium",
        passed=protected,
        description=("Clickjacking protection present" if protected else "No X-Frame-Options / frame-ancestors protection"),
        remediation="Send 'X-Frame-Options: DENY' or CSP 'frame-ancestors none' to prevent UI redressing.",
    )


def _dir_listing(base: str) -> Dict[str, Any]:
    listing = []
    for path in ["/", "/static/", "/assets/", "/uploads/", "/files/", "/images/"]:
        r = safe_get(f"{base}{path}")
        if r is not None and r.status_code == 200 and "index of /" in r.text.lower():
            listing.append(path)
    return finding(
        check_id="OWASP-A05-DIRLIST", category="Storage Exposure", severity="medium",
        passed=len(listing) == 0,
        description=("No directory listing enabled" if not listing else f"Directory listing at: {', '.join(listing)}"),
        remediation="Disable automatic directory indexing (e.g. nginx 'autoindex off').",
    )


def _security_headers(base: str) -> Dict[str, Any]:
    r = safe_get(base)
    missing = []
    if r is not None:
        for header in SECURITY_HEADERS:
            if header not in r.headers:
                missing.append(header)
    else:
        missing = list(SECURITY_HEADERS)
    return finding(
        check_id="OWASP-A05-HEADERS",
        category="Headers",
        severity="high" if "Content-Security-Policy" in missing else "medium",
        passed=len(missing) == 0,
        description=("All key security headers present" if not missing else f"Missing security header(s): {', '.join(missing)}"),
        remediation="Add CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and HSTS.",
    )


def _open_redirect(base: str) -> Dict[str, Any]:
    vulnerable = False
    evil = "https://evil.example/x"
    for param in REDIRECT_PARAMS:
        r = safe_get(f"{base}/?{param}={evil}", allow_redirects=False)
        if r is not None and r.status_code in (301, 302, 303, 307, 308):
            if evil in r.headers.get("Location", ""):
                vulnerable = True
                break
    return finding(
        check_id="OWASP-A01-REDIR", category="Input Validation", severity="medium",
        passed=not vulnerable,
        description=("No open redirect detected" if not vulnerable else "Open redirect to attacker-controlled URL"),
        remediation="Validate redirect targets against an allow-list; never trust user-supplied absolute URLs.",
    )


def _info_disclosure(base: str) -> Dict[str, Any]:
    leaks = []
    r = safe_get(base)
    if r is not None:
        low = r.text.lower()
        for token in INFO_LEAK_TOKENS:
            if token in low or token in str(r.headers).lower():
                leaks.append(token)
    # Trigger a likely 404 for stack traces
    err = safe_get(f"{base}/aegis_probe_{abs(hash(base)) % 9999}")
    if err is not None and err.status_code >= 400:
        low = err.text.lower()
        if "traceback" in low or "exception" in low:
            leaks.append("verbose error page")
    leaks = list(dict.fromkeys(leaks))
    return finding(
        check_id="OWASP-A09-INFO", category="Infrastructure", severity="medium",
        passed=len(leaks) == 0,
        description=("No obvious information disclosure" if not leaks else f"Information disclosure: {', '.join(leaks[:5])}"),
        remediation="Disable debug mode, strip tech banners, and remove sensitive HTML comments in production.",
    )


def _weak_auth_transport(target_url: str, base: str) -> Dict[str, Any]:
    domain = get_domain(target_url)
    insecure = False
    detail = "Authentication appears to be served over HTTPS"
    for path in ["/login", "/signin", "/auth/login", ""]:
        r = safe_get(f"http://{domain}{path}", allow_redirects=False)
        if r is not None and r.status_code == 200 and ("password" in r.text.lower()):
            insecure = True
            detail = f"Login content served over plaintext HTTP at {path or '/'}"
            break
    return finding(
        check_id="OWASP-A07-AUTH", category="Auth", severity="high",
        passed=not insecure, description=detail,
        remediation="Force HTTPS for all authentication pages and POSTs (HSTS + HTTP→HTTPS redirect).",
    )


def _idor(base: str) -> Dict[str, Any]:
    """Heuristic: object endpoints keyed by guessable sequential ids returning data."""
    suspicious = []
    for path in ["/api/users/1", "/api/user/1", "/api/orders/1", "/users/1", "/api/records/1"]:
        r = safe_get(f"{base}{path}")
        if r is not None and r.status_code == 200 and len(r.text) > 20:
            suspicious.append(path)
    return finding(
        check_id="OWASP-A01-IDOR", category="Access Control", severity="high",
        passed=len(suspicious) == 0,
        description=("No obvious IDOR-style object endpoints reachable anonymously"
                     if not suspicious else f"Object endpoints reachable without auth: {', '.join(suspicious[:4])}"),
        remediation="Enforce per-object authorization checks; never rely on unguessable ids alone.",
    )


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    base = get_base(target_url)
    findings: List[Dict[str, Any]] = []
    probes = [
        lambda: _xss(base), lambda: _sqli(base), lambda: _csrf(base),
        lambda: _clickjacking(base), lambda: _idor(base), lambda: _dir_listing(base),
        lambda: _security_headers(base), lambda: _open_redirect(base),
        lambda: _info_disclosure(base), lambda: _weak_auth_transport(target_url, base),
    ]
    for probe in probes:
        try:
            findings.append(probe())
        except Exception:
            continue
    return findings
