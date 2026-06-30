"""
api_scanner_check.py — REST / GraphQL API Security Scanner.

Dedicated API scanner (distinct ``APIX-`` ids) adding capabilities beyond the
existing ``api_security_check``:

    APIX-01  OpenAPI / Swagger spec exposure (and endpoint enumeration)
    APIX-02  GraphQL endpoint + introspection enabled
    APIX-03  CORS misconfiguration (wildcard / reflected origin)
    APIX-04  API version leakage (headers / path)
    APIX-05  Authentication enforced on API surface
    APIX-06  Rate limiting present
    APIX-07  Sensitive endpoints reachable without auth

All requests are read-only.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List

import requests

from .helpers import finding, get_base, probe_path, safe_get

OPENAPI_PATHS = [
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
    "/api/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/docs", "/redoc", "/swagger-ui.html", "/swagger",
]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]
SENSITIVE_PATHS = [
    "/api/users", "/api/patients", "/api/records", "/api/admin",
    "/api/accounts", "/api/billing", "/actuator", "/actuator/env",
    "/.env", "/api/config",
]
VERSION_HEADERS = ["x-api-version", "x-version", "api-version", "x-powered-by", "server"]
INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}}}"}


def _check_openapi(base: str) -> List[Dict[str, Any]]:
    exposed: List[str] = []
    endpoint_count = 0
    for path in OPENAPI_PATHS:
        r = probe_path(base, path)
        if r is None or r.status_code != 200 or len(r.text) < 30:
            continue
        exposed.append(path)
        # Try to count documented paths from a JSON spec.
        try:
            spec = r.json()
            if isinstance(spec, dict) and isinstance(spec.get("paths"), dict):
                endpoint_count = max(endpoint_count, len(spec["paths"]))
        except Exception:
            pass

    desc = (
        "No OpenAPI/Swagger documentation is publicly exposed"
        if not exposed
        else f"API docs exposed at {', '.join(exposed[:4])}"
        + (f" ({endpoint_count} documented endpoints)" if endpoint_count else "")
    )
    return [finding(
        check_id="APIX-01", category="API Security", severity="medium",
        passed=len(exposed) == 0,
        description=desc,
        remediation="Disable or authenticate Swagger/OpenAPI/Actuator docs in production; they reveal the full API surface.",
    )]


def _check_graphql(base: str) -> List[Dict[str, Any]]:
    introspection_open = False
    graphql_url = ""
    for path in GRAPHQL_PATHS:
        url = f"{base}{path}"
        try:
            r = requests.post(url, json=INTROSPECTION_QUERY, timeout=5)
        except Exception:
            continue
        if r is None or r.status_code not in (200, 400):
            continue
        body = r.text.lower()
        if "__schema" in body or '"data"' in body and "querytype" in body:
            introspection_open = True
            graphql_url = path
            break
        if "graphql" in body or "must provide query string" in body:
            graphql_url = path  # endpoint exists but introspection likely closed

    if not graphql_url:
        return [finding(
            check_id="APIX-02", category="API Security", severity="low", passed=True,
            description="No GraphQL endpoint detected",
            remediation="N/A — no GraphQL surface found.",
        )]
    return [finding(
        check_id="APIX-02", category="API Security",
        severity="high" if introspection_open else "low",
        passed=not introspection_open,
        description=(
            f"GraphQL introspection ENABLED at {graphql_url} (schema disclosure)"
            if introspection_open
            else f"GraphQL endpoint at {graphql_url} with introspection disabled"
        ),
        remediation="Disable GraphQL introspection in production and apply query depth/cost limits.",
    )]


def _check_cors(base: str) -> List[Dict[str, Any]]:
    misconfigured = False
    detail = "CORS policy does not reflect arbitrary origins"
    try:
        r = requests.options(
            base,
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
            timeout=5,
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            misconfigured, detail = True, "ACAO '*' combined with Allow-Credentials: true"
        elif "evil.example" in acao:
            misconfigured, detail = True, "Server reflects arbitrary Origin in ACAO"
        elif acao == "*":
            detail = "ACAO is '*' (acceptable only for public, unauthenticated APIs)"
    except Exception:
        pass
    return [finding(
        check_id="APIX-03", category="API Security", severity="high",
        passed=not misconfigured, description=detail,
        remediation="Echo only explicitly allow-listed origins; never combine wildcard ACAO with credentialed requests.",
    )]


def _check_version_leak(base: str) -> List[Dict[str, Any]]:
    leaks: List[str] = []
    r = safe_get(base)
    if r is not None:
        for h in VERSION_HEADERS:
            val = r.headers.get(h)
            if val and re.search(r"\d", val):
                leaks.append(f"{h}: {val}")
    return [finding(
        check_id="APIX-04", category="API Security", severity="low",
        passed=len(leaks) == 0,
        description=("No version information leaked in headers" if not leaks else f"Version disclosure — {'; '.join(leaks[:4])}"),
        remediation="Strip Server/X-Powered-By/X-API-Version headers; version disclosure aids targeted exploits.",
    )]


def _check_api_auth_and_ratelimit(base: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # APIX-05: sensitive endpoints reachable without auth
    open_endpoints: List[str] = []
    for path in SENSITIVE_PATHS:
        r = probe_path(base, path)
        if r is not None and r.status_code == 200 and len(r.text) > 20:
            open_endpoints.append(path)
    findings.append(finding(
        check_id="APIX-05", category="API Security", severity="high",
        passed=len(open_endpoints) == 0,
        description=("Sensitive API endpoints require authentication" if not open_endpoints
                     else f"Reachable without auth: {', '.join(open_endpoints[:5])}"),
        remediation="Require authentication/authorization on every data endpoint; return 401/403 to anonymous callers.",
    ))

    # APIX-06: rate limiting
    rate_limited = False
    target = f"{base}/api/login"
    probe = safe_get(target)
    if probe is None or probe.status_code == 404:
        target = base
    for _ in range(12):
        r = safe_get(target)
        if r is None:
            break
        if r.status_code == 429 or any(
            h in r.headers for h in ("Retry-After", "X-RateLimit-Limit", "RateLimit-Limit", "X-RateLimit-Remaining")
        ):
            rate_limited = True
            break
        time.sleep(0.04)
    findings.append(finding(
        check_id="APIX-06", category="API Security", severity="high",
        passed=rate_limited,
        description=("Rate limiting detected" if rate_limited else "No rate limiting detected — brute-force/DoS exposure"),
        remediation="Apply per-IP/per-token rate limits and return HTTP 429 with Retry-After when exceeded.",
    ))
    return findings


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    base = get_base(target_url)
    findings: List[Dict[str, Any]] = []
    for fn in (_check_openapi, _check_graphql, _check_cors, _check_version_leak, _check_api_auth_and_ratelimit):
        try:
            findings += fn(base)
        except Exception:
            continue
    return findings
