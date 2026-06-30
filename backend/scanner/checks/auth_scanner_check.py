"""
auth_scanner_check.py — Authentication Surface Scanner.

A dedicated authentication scanner (distinct ``ATH-`` ids) that maps the auth
surface and inspects auth-related controls:

    ATH-01  Login form discovery
    ATH-02  Registration endpoint discovery
    ATH-03  Password-reset flow discovery
    ATH-04  JWT inspection (alg=none / missing exp)
    ATH-05  OAuth / social-login support
    ATH-06  Session timeout / cookie max-age
    ATH-07  "Remember me" persistent-login feature
    ATH-08  MFA / 2FA availability
    ATH-09  Secure cookie flag
    ATH-10  HttpOnly cookie flag
    ATH-11  SameSite cookie attribute

Read-only probing only — no credential brute forcing or account creation.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List

import requests

from .helpers import finding, get_base, safe_get

LOGIN_PATHS = ["/login", "/signin", "/auth/login", "/account/login", "/users/sign_in"]
REGISTER_PATHS = ["/register", "/signup", "/sign-up", "/auth/register", "/users/sign_up"]
RESET_PATHS = ["/forgot-password", "/reset-password", "/password/reset", "/auth/forgot", "/recover"]
TOKEN_LOGIN_ENDPOINTS = ["/api/login", "/api/auth/login", "/auth/token", "/oauth/token"]

OAUTH_KEYWORDS = [
    "oauth", "sign in with google", "continue with google", "login with github",
    "sign in with apple", "facebook login", "auth0", "okta", "saml", "sso",
    "openid", "accounts.google.com", "github.com/login/oauth",
]
MFA_KEYWORDS = [
    "mfa", "2fa", "two-factor", "two factor", "multi-factor", "totp", "otp",
    "authenticator", "verification code", "sms code", "second factor",
]
REMEMBER_KEYWORDS = ["remember me", "remember-me", "rememberme", "keep me signed in", "stay signed in"]


def _find_paths(base: str, paths: List[str], keywords: List[str]) -> List[str]:
    """Return paths that return 200 and look like the expected page."""
    found = []
    for p in paths:
        r = safe_get(f"{base}{p}")
        if r is not None and r.status_code == 200:
            body = r.text.lower()
            if any(kw in body for kw in keywords) or "<form" in body:
                found.append(p)
    return found


def _collect_set_cookies(base: str) -> List[str]:
    cookies: List[str] = []
    for p in ["", "/login", "/signin", "/api/login", "/dashboard"]:
        r = safe_get(f"{base}{p}")
        if r is None:
            continue
        for k, v in r.headers.items():
            if k.lower() == "set-cookie":
                cookies.append(v)
    return cookies


def _try_get_jwt(base: str) -> str | None:
    for ep in TOKEN_LOGIN_ENDPOINTS:
        try:
            r = requests.post(f"{base}{ep}", json={"username": "probe", "password": "probe"}, timeout=5)
            if r.status_code == 200:
                data = r.json()
                for key in ("token", "access_token", "jwt", "id_token"):
                    if isinstance(data, dict) and key in data:
                        return data[key]
        except Exception:
            continue
    return None


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)
    root = safe_get(base)
    root_body = root.text.lower() if root is not None else ""

    # ── ATH-01: Login form discovery ─────────────────────────────────────────
    login_found = bool(_find_paths(base, LOGIN_PATHS, ["password", "login", "sign in"])) or (
        'type="password"' in root_body
    )
    findings.append(finding(
        check_id="ATH-01", category="Auth", severity="low", passed=login_found,
        description="Login form/endpoint discovered" if login_found else "No login form discovered",
        remediation="Ensure authentication is served over HTTPS with anti-automation controls.",
    ))

    # ── ATH-02: Registration discovery ───────────────────────────────────────
    reg = _find_paths(base, REGISTER_PATHS, ["register", "sign up", "create account"])
    findings.append(finding(
        check_id="ATH-02", category="Auth", severity="low", passed=True,
        description=(f"Registration endpoint(s): {', '.join(reg)}" if reg else "No public registration endpoint found"),
        remediation="Protect registration with email verification, CAPTCHA and rate limiting.",
    ))

    # ── ATH-03: Password-reset discovery ─────────────────────────────────────
    reset = _find_paths(base, RESET_PATHS, ["forgot", "reset", "recover"])
    findings.append(finding(
        check_id="ATH-03", category="Auth", severity="low", passed=True,
        description=(f"Password-reset flow(s): {', '.join(reset)}" if reset else "No password-reset flow detected"),
        remediation="Use single-use, time-limited reset tokens and avoid account enumeration in responses.",
    ))

    # ── ATH-04: JWT inspection ───────────────────────────────────────────────
    jwt_issues: List[str] = []
    token = _try_get_jwt(base)
    if token and token.count(".") >= 2:
        try:
            header_b64 = token.split(".")[0] + "=" * (-len(token.split(".")[0]) % 4)
            payload_b64 = token.split(".")[1] + "=" * (-len(token.split(".")[1]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            if str(header.get("alg", "")).lower() == "none":
                jwt_issues.append("alg=none (signature can be stripped)")
            if "exp" not in payload:
                jwt_issues.append("missing 'exp' (no expiry)")
        except Exception:
            pass
    findings.append(finding(
        check_id="ATH-04",
        category="Auth",
        severity="high" if any("none" in i for i in jwt_issues) else "medium",
        passed=len(jwt_issues) == 0,
        description=("No JWT weaknesses detected" if not jwt_issues else f"JWT issue(s): {'; '.join(jwt_issues)}"),
        remediation="Sign JWTs with RS256/ES256, always set short 'exp', and reject the 'none' algorithm.",
    ))

    # ── ATH-05: OAuth / SSO support ──────────────────────────────────────────
    oauth = any(kw in root_body for kw in OAUTH_KEYWORDS)
    if not oauth:
        for p in LOGIN_PATHS[:2]:
            r = safe_get(f"{base}{p}")
            if r is not None and any(kw in r.text.lower() for kw in OAUTH_KEYWORDS):
                oauth = True
                break
    findings.append(finding(
        check_id="ATH-05", category="Auth", severity="low", passed=oauth,
        description=("OAuth/SSO sign-in option detected" if oauth else "No OAuth/SSO sign-in detected"),
        remediation="Prefer federated identity (OAuth2/OIDC/SAML) to reduce password handling risk.",
    ))

    # ── Cookie-based checks ──────────────────────────────────────────────────
    cookies = _collect_set_cookies(base)

    # ATH-06: session timeout / max-age
    has_expiry = any(("max-age=" in c.lower() or "expires=" in c.lower()) for c in cookies)
    findings.append(finding(
        check_id="ATH-06", category="Session", severity="medium",
        passed=has_expiry or not cookies,
        description=("Session cookies define an expiry/max-age" if has_expiry else "Session cookies have no explicit expiry"),
        remediation="Set a bounded Max-Age on session cookies and enforce server-side idle/absolute timeouts.",
    ))

    # ATH-07: remember-me
    remember = any(kw in root_body for kw in REMEMBER_KEYWORDS)
    findings.append(finding(
        check_id="ATH-07", category="Auth", severity="low", passed=True,
        description=("'Remember me' persistent login detected" if remember else "No 'remember me' feature detected"),
        remediation="If offered, bind persistent tokens to device, rotate them, and allow revocation.",
    ))

    # ATH-08: MFA availability
    mfa = any(kw in root_body for kw in MFA_KEYWORDS)
    if not mfa:
        for p in LOGIN_PATHS[:2] + ["/security", "/account/security", "/settings/security"]:
            r = safe_get(f"{base}{p}")
            if r is not None and any(kw in r.text.lower() for kw in MFA_KEYWORDS):
                mfa = True
                break
    findings.append(finding(
        check_id="ATH-08", category="Auth", severity="high", passed=mfa,
        description=("MFA/2FA availability detected" if mfa else "No MFA/2FA indicators found"),
        remediation="Offer (and for privileged users require) MFA. HIPAA §164.312(d) requires entity authentication.",
    ))

    # ATH-09/10/11: cookie flags
    missing_secure = [c for c in cookies if "secure" not in c.lower()]
    missing_httponly = [c for c in cookies if "httponly" not in c.lower()]
    missing_samesite = [c for c in cookies if "samesite" not in c.lower()]

    findings.append(finding(
        check_id="ATH-09", category="Session", severity="high",
        passed=not missing_secure or not cookies,
        description=("All cookies set the Secure flag" if not missing_secure else f"{len(missing_secure)} cookie(s) missing Secure"),
        remediation="Set Secure on every cookie so it is never transmitted over plaintext HTTP.",
    ))
    findings.append(finding(
        check_id="ATH-10", category="Session", severity="high",
        passed=not missing_httponly or not cookies,
        description=("All cookies set HttpOnly" if not missing_httponly else f"{len(missing_httponly)} cookie(s) missing HttpOnly"),
        remediation="Set HttpOnly on session cookies to block JavaScript access (XSS token theft).",
    ))
    findings.append(finding(
        check_id="ATH-11", category="Session", severity="medium",
        passed=not missing_samesite or not cookies,
        description=("All cookies set SameSite" if not missing_samesite else f"{len(missing_samesite)} cookie(s) missing SameSite"),
        remediation="Set SameSite=Lax or Strict on cookies to mitigate CSRF.",
    ))

    return findings
