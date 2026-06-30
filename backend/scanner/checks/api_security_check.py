"""
api_security_check.py — API Security Checks

Discovers API endpoints, checks authentication requirements, detects
rate-limiting behaviour, and identifies sensitive data leakage in responses.
"""

import re
import time
from typing import List, Dict, Any
from .helpers import get_base, safe_get, safe_post, probe_path, finding


# Common API endpoint patterns to discover
API_DISCOVERY_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v2",
    "/api/docs", "/api/swagger", "/swagger.json", "/openapi.json",
    "/api/schema", "/docs", "/redoc",
    "/graphql", "/api/graphql",
    "/api/health", "/api/status",
]

# Endpoints likely to return sensitive data
SENSITIVE_API_PATHS = [
    "/api/users", "/api/patients", "/api/records",
    "/api/profile", "/api/account", "/api/billing",
    "/api/health-records", "/api/prescriptions",
    "/api/admin/users",
]

# Patterns indicating PHI / PII in API responses
SENSITIVE_DATA_PATTERNS = [
    r'"ssn"\s*:', r'"social_security"\s*:', r'"date_of_birth"\s*:',
    r'"dob"\s*:', r'"diagnosis"\s*:', r'"medical_record"\s*:',
    r'"patient_id"\s*:', r'"mrn"\s*:', r'"insurance_id"\s*:',
    r'"credit_card"\s*:', r'"password"\s*:',
    # Unmasked phone / email in list endpoints
    r'"phone"\s*:\s*"\+?\d{10,}',
    r'"email"\s*:\s*"[^"]+@[^"]+"',
]


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)

    # ── API-01: API endpoint discovery ───────────────────────────────────────
    discovered: List[str] = []
    for path in API_DISCOVERY_PATHS:
        r = probe_path(base, path)
        if r is not None and r.status_code in (200, 401, 403):
            discovered.append(f"{path} ({r.status_code})")

    findings.append(finding(
        check_id="API-01",
        category="API Security",
        severity="medium",
        passed=True,  # informational — always "pass" but report what was found
        description=(
            f"Discovered API endpoint(s): {', '.join(discovered)}"
            if discovered
            else "No common API endpoints detected"
        ),
        remediation=(
            "Ensure all API endpoints are documented, versioned, and properly "
            "secured. Disable Swagger/OpenAPI docs in production environments."
        ),
    ))

    # ── API-02: API documentation exposed in production ──────────────────────
    docs_paths = ["/docs", "/redoc", "/swagger.json", "/openapi.json",
                  "/api/docs", "/api/swagger", "/api/swagger-ui"]
    docs_exposed: List[str] = []
    for path in docs_paths:
        r = probe_path(base, path)
        if r is not None and r.status_code == 200 and len(r.text) > 100:
            docs_exposed.append(path)

    findings.append(finding(
        check_id="API-02",
        category="API Security",
        severity="medium",
        passed=len(docs_exposed) == 0,
        description=(
            "No API documentation endpoints are publicly exposed"
            if not docs_exposed
            else f"API documentation publicly accessible: {', '.join(docs_exposed)}"
        ),
        remediation=(
            "Disable or restrict access to API documentation (Swagger, ReDoc) "
            "in production. API schemas reveal endpoint structure and can aid attackers."
        ),
    ))

    # ── API-03: Unauthenticated access to sensitive API endpoints ────────────
    leaking_endpoints: List[str] = []
    for path in SENSITIVE_API_PATHS:
        r = probe_path(base, path)
        if r is not None and r.status_code == 200 and len(r.text) > 20:
            leaking_endpoints.append(path)

    findings.append(finding(
        check_id="API-03",
        category="API Security",
        severity="high",
        passed=len(leaking_endpoints) == 0,
        description=(
            "All sensitive API endpoints require authentication"
            if not leaking_endpoints
            else f"Sensitive API endpoint(s) accessible without auth: {', '.join(leaking_endpoints)}"
        ),
        remediation=(
            "Add authentication middleware to all endpoints returning PHI/PII. "
            "Return HTTP 401 for unauthenticated requests."
        ),
    ))

    # ── API-04: Rate limiting detection ──────────────────────────────────────
    rate_limited = False
    rate_test_url = f"{base}/api/login"
    # Fall back to base if no login endpoint
    r_test = safe_get(rate_test_url)
    if r_test is None or r_test.status_code == 404:
        rate_test_url = base

    status_codes = []
    for i in range(15):
        r = safe_get(rate_test_url)
        if r is not None:
            status_codes.append(r.status_code)
            if r.status_code == 429:
                rate_limited = True
                break
            # Check for rate-limit headers
            if any(h in r.headers for h in ("X-RateLimit-Limit", "X-RateLimit-Remaining",
                                             "RateLimit-Limit", "Retry-After")):
                rate_limited = True
                break
        time.sleep(0.05)  # small delay to avoid self-DoS

    findings.append(finding(
        check_id="API-04",
        category="API Security",
        severity="high",
        passed=rate_limited,
        description=(
            "Rate limiting detected on API endpoints"
            if rate_limited
            else "No rate limiting detected — API may be vulnerable to brute-force attacks"
        ),
        remediation=(
            "Implement rate limiting (e.g., 100 requests/minute per IP) on all "
            "API endpoints using a middleware like slowapi or a reverse-proxy rule. "
            "Return HTTP 429 with a Retry-After header when limits are exceeded."
        ),
    ))

    # ── API-05: Sensitive data in API responses ──────────────────────────────
    sensitive_leaks: List[str] = []
    for path in SENSITIVE_API_PATHS[:5]:
        r = probe_path(base, path)
        if r is not None and r.status_code == 200:
            for pattern in SENSITIVE_DATA_PATTERNS:
                match = re.search(pattern, r.text, re.IGNORECASE)
                if match:
                    # Capture the field name
                    field = pattern.split('"')[1] if '"' in pattern else "unknown"
                    sensitive_leaks.append(f"{field} in {path}")

    sensitive_leaks = list(set(sensitive_leaks))

    findings.append(finding(
        check_id="API-05",
        category="API Security",
        severity="high",
        passed=len(sensitive_leaks) == 0,
        description=(
            "No unmasked sensitive data detected in API responses"
            if not sensitive_leaks
            else f"Sensitive data patterns found: {', '.join(sensitive_leaks[:5])}"
        ),
        remediation=(
            "Mask or redact PHI/PII fields in API responses. Use field-level "
            "encryption and response filters to prevent accidental data exposure."
        ),
    ))

    # ── API-06: CORS misconfiguration ────────────────────────────────────────
    cors_misconfigured = False
    import requests as req
    try:
        r = req.options(
            base,
            headers={"Origin": "https://evil-attacker.com",
                     "Access-Control-Request-Method": "GET"},
            timeout=5,
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or "evil-attacker.com" in acao:
            cors_misconfigured = True
    except Exception:
        pass

    findings.append(finding(
        check_id="API-06",
        category="API Security",
        severity="high",
        passed=not cors_misconfigured,
        description=(
            "CORS policy does not allow arbitrary origins"
            if not cors_misconfigured
            else "CORS policy allows wildcard (*) or reflects arbitrary origins"
        ),
        remediation=(
            "Set Access-Control-Allow-Origin to specific trusted domains only. "
            "Never use '*' on APIs that handle authenticated requests or PHI."
        ),
    ))

    return findings
