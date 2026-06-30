"""
monitoring_alerting_check.py — Monitoring & Alerting

Detects whether the application responds to repeated failed login
attempts with blocking, rate-limiting, or CAPTCHA challenges.
"""

import time
from typing import List, Dict, Any
from .helpers import get_base, safe_post, safe_get, finding


LOGIN_ENDPOINTS = [
    "/api/login", "/api/auth/login", "/api/auth",
    "/login", "/auth/token",
]


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)

    # ── MA-01: Brute-force protection / lockout ──────────────────────────────
    lockout_detected = False
    captcha_detected = False
    status_progression: List[int] = []

    for endpoint in LOGIN_ENDPOINTS:
        for i in range(8):
            r = safe_post(
                f"{base}{endpoint}",
                json={"username": "probe_user_aegis", "password": f"bad_pw_{i}"},
                allow_redirects=False,
            )
            if r is not None:
                status_progression.append(r.status_code)
                body = r.text.lower()
                if r.status_code == 429:
                    lockout_detected = True
                    break
                if r.status_code == 423:
                    lockout_detected = True
                    break
                if any(kw in body for kw in (
                    "locked", "too many", "rate limit", "blocked",
                    "temporarily disabled", "try again later",
                )):
                    lockout_detected = True
                    break
                if any(kw in body for kw in ("captcha", "recaptcha", "hcaptcha")):
                    captcha_detected = True
                    break
            time.sleep(0.1)

        if lockout_detected or captcha_detected:
            break

    findings.append(finding(
        check_id="MA-01",
        category="Monitoring",
        severity="high",
        passed=lockout_detected or captcha_detected,
        description=(
            "Brute-force protection detected (lockout or CAPTCHA)"
            if lockout_detected or captcha_detected
            else "No brute-force protection detected after repeated failed logins"
        ),
        remediation=(
            "Implement progressive lockout or CAPTCHA after 5 failed login "
            "attempts. Log all failures and alert on anomalous patterns. "
            "HIPAA §164.312(a)(2)(i) requires unique user identification."
        ),
    ))

    # ── MA-02: Security monitoring headers ───────────────────────────────────
    monitoring_headers = [
        "x-request-id", "x-correlation-id", "x-trace-id",
        "x-amzn-trace-id", "traceparent",
    ]
    r = safe_get(base)
    found_headers = []
    if r is not None:
        lower = {k.lower(): v for k, v in r.headers.items()}
        found_headers = [h for h in monitoring_headers if h in lower]

    findings.append(finding(
        check_id="MA-02",
        category="Monitoring",
        severity="medium",
        passed=len(found_headers) > 0,
        description=(
            f"Monitoring/tracing header(s) present: {', '.join(found_headers)}"
            if found_headers
            else "No monitoring/tracing headers detected in responses"
        ),
        remediation=(
            "Add X-Request-Id or traceparent headers to all responses for "
            "request tracing and incident investigation."
        ),
    ))

    # ── MA-03: Health / status endpoint ──────────────────────────────────────
    health_paths = ["/health", "/healthz", "/api/health",
                    "/status", "/api/status", "/ping"]
    health_found = False
    for path in health_paths:
        r = safe_get(f"{base}{path}")
        if r is not None and r.status_code == 200:
            health_found = True
            break

    findings.append(finding(
        check_id="MA-03",
        category="Monitoring",
        severity="low",
        passed=health_found,
        description=(
            "Health/status endpoint is available"
            if health_found
            else "No health or status endpoint detected"
        ),
        remediation=(
            "Expose a /health or /healthz endpoint for uptime monitoring. "
            "Integrate with alerting systems (PagerDuty, CloudWatch, etc.) "
            "to detect outages quickly."
        ),
    ))

    return findings
