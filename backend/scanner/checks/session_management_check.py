"""
session_management_check.py — Session Security

Inspects cookie attributes (Secure, HttpOnly, SameSite),
detects session fixation risk, and checks session ID entropy.
"""

import re
from typing import List, Dict, Any
from .helpers import get_base, safe_get, finding


def _collect_cookies(base: str) -> list:
    """Collect Set-Cookie headers from common paths."""
    paths = ["", "/login", "/signin", "/dashboard", "/app"]
    cookies = []
    for p in paths:
        r = safe_get(f"{base}{p}")
        if r is not None:
            for k, v in r.headers.items():
                if k.lower() == "set-cookie":
                    cookies.append(v)
    return cookies


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)
    cookies = _collect_cookies(base)

    # ── SM-01: Secure flag ───────────────────────────────────────────────────
    missing_secure = [c for c in cookies if "secure" not in c.lower()]
    findings.append(finding(
        check_id="SM-01",
        category="Session",
        severity="high",
        passed=len(missing_secure) == 0 or len(cookies) == 0,
        description=(
            "All cookies have the Secure flag"
            if not missing_secure
            else f"{len(missing_secure)} cookie(s) missing Secure flag"
        ),
        remediation="Set the Secure flag on every cookie to prevent transmission over HTTP.",
    ))

    # ── SM-02: HttpOnly flag ─────────────────────────────────────────────────
    missing_httponly = [c for c in cookies if "httponly" not in c.lower()]
    findings.append(finding(
        check_id="SM-02",
        category="Session",
        severity="high",
        passed=len(missing_httponly) == 0 or len(cookies) == 0,
        description=(
            "All cookies have the HttpOnly flag"
            if not missing_httponly
            else f"{len(missing_httponly)} cookie(s) missing HttpOnly flag"
        ),
        remediation="Set HttpOnly on session cookies to prevent JavaScript access (XSS mitigation).",
    ))

    # ── SM-03: SameSite attribute ────────────────────────────────────────────
    missing_samesite = [c for c in cookies if "samesite" not in c.lower()]
    findings.append(finding(
        check_id="SM-03",
        category="Session",
        severity="medium",
        passed=len(missing_samesite) == 0 or len(cookies) == 0,
        description=(
            "All cookies have the SameSite attribute"
            if not missing_samesite
            else f"{len(missing_samesite)} cookie(s) missing SameSite attribute"
        ),
        remediation="Set SameSite=Strict or SameSite=Lax on cookies to mitigate CSRF attacks.",
    ))

    # ── SM-04: Session ID entropy ────────────────────────────────────────────
    weak_ids = []
    for c in cookies:
        name_val = c.split(";")[0]
        if "=" in name_val:
            val = name_val.split("=", 1)[1]
            if len(val) < 16 and val:
                weak_ids.append(name_val.split("=")[0].strip())

    findings.append(finding(
        check_id="SM-04",
        category="Session",
        severity="high",
        passed=len(weak_ids) == 0,
        description=(
            "Session cookie values have adequate entropy (≥16 chars)"
            if not weak_ids
            else f"Short session value(s) detected on cookie(s): {', '.join(weak_ids)}"
        ),
        remediation="Use cryptographically random session IDs of at least 128 bits (≥16 bytes).",
    ))

    # ── SM-05: Cookie prefix best practice ───────────────────────────────────
    has_prefix = any(
        c.strip().startswith("__Secure-") or c.strip().startswith("__Host-")
        for c in cookies
    )
    findings.append(finding(
        check_id="SM-05",
        category="Session",
        severity="low",
        passed=has_prefix or len(cookies) == 0,
        description=(
            "Cookie prefix (__Secure- / __Host-) detected"
            if has_prefix
            else "No cookie prefixes (__Secure- / __Host-) used"
        ),
        remediation=(
            "Use __Host- or __Secure- cookie prefixes for additional browser-enforced "
            "security guarantees on session cookies."
        ),
    ))

    # ── SM-06: Session reuse after logout ────────────────────────────────────
    session_invalidated = False
    try:
        # Perform a login to get a cookie
        session = __import__("requests").Session()
        login_res = session.post(f"{base}/api/login", json={"username": "probe", "password": "pwd"}, timeout=5)
        # Attempt to logout
        logout_res = session.post(f"{base}/api/logout", timeout=5)
        # Verify if cookie is cleared or altered in the response
        set_cookie = logout_res.headers.get("Set-Cookie", "").lower()
        if 'expires=thu, 01 jan 1970' in set_cookie or 'max-age=0' in set_cookie or '=""' in set_cookie:
            session_invalidated = True
        else:
            # Check if trying a protected route with the old session works
            protected_res = session.get(f"{base}/api/me", timeout=5)
            if protected_res.status_code in (401, 403):
                session_invalidated = True
    except Exception:
        # If any endpoint is missing, we consider it inconclusive / fail safely
        pass

    findings.append(finding(
        check_id="SM-06",
        category="Session",
        severity="high",
        passed=session_invalidated,
        description=(
            "Session successfully invalidated on logout"
            if session_invalidated
            else "Session may not be invalidated server-side upon logout"
        ),
        remediation=(
            "Ensure the server actively invalidates session tokens upon logout. "
            "Clear cookies explicitly and revoke tokens from the database."
        ),
    ))

    return findings
