import requests
import re
import base64
import json
from urllib.parse import urlparse

# Common default credential pairs to probe
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("administrator", "administrator"),
]

# Common exposed admin/sensitive paths
SENSITIVE_PATHS = [
    "/admin",
    "/admin/",
    "/administrator",
    "/.env",
    "/config",
    "/config.php",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/.git/config",
    "/server-status",
]


def _get_base(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    return f"{scheme}://{parsed.netloc or parsed.path.split('/')[0]}"


def check_auth(url: str):
    findings = []
    base = _get_base(url)

    # ── C-04: Login forms use HTTPS ──────────────────────────────────────────
    login_paths = ["/login", "/signin", "/auth/login", "/user/login", "/account/login"]
    login_over_https = True
    login_found = False

    for path in login_paths:
        try:
            r = requests.get(f"{base}{path}", timeout=5, allow_redirects=True)
            if r.status_code == 200:
                login_found = True
                if not r.url.startswith("https://"):
                    login_over_https = False
                    break
                content = r.text.lower()
                if 'action="http://' in content or "action='http://" in content:
                    login_over_https = False
                    break
        except Exception:
            continue

    if not login_found:
        try:
            r = requests.get(base, timeout=5, allow_redirects=True)
            if r.status_code == 200:
                content = r.text.lower()
                if "<form" in content and ('type="password"' in content or "type='password'" in content):
                    login_found = True
                    login_over_https = r.url.startswith("https://") and \
                        'action="http://' not in content and \
                        "action='http://" not in content
        except Exception:
            pass

    findings.append({
        "check_id": "C-04",
        "category": "Auth",
        "severity": "critical",
        "passed": login_over_https,
        "description": "Login forms are served over HTTPS" if login_over_https
                       else "Login form found over HTTP or with insecure form action",
        "remediation": "Ensure all login pages are served exclusively over HTTPS and form "
                       "action attributes point to HTTPS endpoints"
    })

    # ── C-05: No default credentials accepted ────────────────────────────────
    default_creds_accepted = False
    login_endpoints = ["/api/login", "/api/auth", "/login", "/auth/token"]

    for endpoint in login_endpoints:
        for username, password in DEFAULT_CREDENTIALS:
            try:
                r = requests.post(
                    f"{base}{endpoint}",
                    json={"username": username, "password": password,
                          "email": username},
                    timeout=5,
                    allow_redirects=False
                )
                if r.status_code == 200:
                    body = r.text.lower()
                    if any(k in body for k in ("token", "session", "access_token", "jwt")):
                        default_creds_accepted = True
                        break
                if r.status_code in (301, 302) and "login" not in (r.headers.get("location") or ""):
                    default_creds_accepted = True
                    break
            except Exception:
                continue
        if default_creds_accepted:
            break

    findings.append({
        "check_id": "C-05",
        "category": "Auth",
        "severity": "critical",
        "passed": not default_creds_accepted,
        "description": "No default credentials accepted" if not default_creds_accepted
                       else "Default credentials (admin/admin etc.) appear to be accepted",
        "remediation": "Disable or change all default credentials. Enforce strong password "
                       "policies and remove any factory-default accounts before deployment"
    })

    # ── C-10: No exposed admin panels / sensitive files ───────────────────────
    exposed_paths = []

    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(f"{base}{path}", timeout=5, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 50:
                exposed_paths.append(path)
        except Exception:
            continue

    findings.append({
        "check_id": "C-10",
        "category": "Auth",
        "severity": "critical",
        "passed": len(exposed_paths) == 0,
        "description": "No exposed admin panels or sensitive files detected" if not exposed_paths
                       else f"Exposed sensitive path(s) found: {', '.join(exposed_paths)}",
        "remediation": "Restrict access to admin panels with IP allowlisting or authentication. "
                       "Remove .env, .git, and config files from the web root. "
                       "Return 401/403 for admin paths, not 200"
    })

    # ── NEW: AUTH-01 MFA detection ──────────────────────────────────────────
    mfa_detected = False
    mfa_keywords = [
        "mfa", "2fa", "two-factor", "multi-factor", "totp", "otp",
        "authenticator", "verification-code", "sms-code",
        "second factor", "two step",
    ]
    for path in ["", "/login", "/signin", "/auth/login", "/api/auth/mfa",
                  "/api/auth/2fa", "/mfa", "/2fa"]:
        try:
            r = requests.get(f"{base}{path}", timeout=5)
            if r.status_code == 200:
                body = r.text.lower()
                if any(kw in body for kw in mfa_keywords):
                    mfa_detected = True
                    break
        except:
            continue

    findings.append({
        "check_id": "AUTH-01",
        "category": "Auth",
        "severity": "critical",
        "passed": mfa_detected,
        "description": (
            "Multi-factor authentication indicators detected"
            if mfa_detected
            else "No MFA indicators found — single-factor auth only"
        ),
        "remediation": (
            "Implement MFA (TOTP, SMS, or hardware key) for all users "
            "accessing ePHI. HIPAA §164.312(d) requires person-or-entity "
            "authentication."
        )
    })

    # ── NEW: AUTH-02 JWT issues detection ───────────────────────────────────
    jwt_issues = []
    # Try to obtain a JWT via a login attempt
    jwt_token = None
    for endpoint in login_endpoints:
        try:
            r = requests.post(
                f"{base}{endpoint}",
                json={"username": "test", "password": "test"},
                timeout=5,
            )
            if r.status_code == 200:
                try:
                    data = r.json()
                    for key in ("token", "access_token", "jwt", "id_token"):
                        if key in data:
                            jwt_token = data[key]
                            break
                except:
                    pass
        except:
            continue
        if jwt_token:
            break

    if jwt_token:
        # Decode JWT header and payload (without verification)
        parts = jwt_token.split(".")
        if len(parts) >= 2:
            try:
                # Decode header
                header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))

                # Check for 'none' algorithm
                if header.get("alg", "").lower() == "none":
                    jwt_issues.append("JWT uses 'none' algorithm (critical vulnerability)")

                # Check for weak algorithm
                if header.get("alg", "") in ("HS256",):
                    jwt_issues.append("JWT uses HS256 — consider RS256 for better security")

                # Decode payload
                payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                # Check for missing expiry
                if "exp" not in payload:
                    jwt_issues.append("JWT payload missing 'exp' (expiration) claim")

                # Check for missing 'iss' (issuer)
                if "iss" not in payload:
                    jwt_issues.append("JWT payload missing 'iss' (issuer) claim")

            except Exception:
                pass

    findings.append({
        "check_id": "AUTH-02",
        "category": "Auth",
        "severity": "critical" if any("none" in i.lower() for i in jwt_issues) else "warning",
        "passed": len(jwt_issues) == 0,
        "description": (
            "No JWT security issues detected"
            if not jwt_issues
            else f"JWT issue(s): {'; '.join(jwt_issues)}"
        ),
        "remediation": (
            "Use RS256 or ES256 for JWT signing. Always include 'exp', 'iss', "
            "and 'aud' claims. Never use the 'none' algorithm. Keep token "
            "lifetimes short (≤ 15 minutes) with refresh token rotation."
        )
    })

    # ── NEW: AUTH-03 Password policy indicators ─────────────────────────────
    password_policy = False
    policy_keywords = [
        "password requirement", "password policy", "must contain",
        "minimum.*character", "uppercase", "lowercase", "special character",
        "password strength", "strong password",
    ]
    for path in ["/register", "/signup", "/api/auth/register", "/join"]:
        try:
            r = requests.get(f"{base}{path}", timeout=5)
            if r.status_code == 200:
                body = r.text.lower()
                if any(re.search(kw, body) for kw in policy_keywords):
                    password_policy = True
                    break
        except:
            continue

    findings.append({
        "check_id": "AUTH-03",
        "category": "Auth",
        "severity": "warning",
        "passed": password_policy,
        "description": (
            "Password policy indicators detected on registration page"
            if password_policy
            else "No password policy indicators found"
        ),
        "remediation": (
            "Enforce a password policy requiring minimum 12 characters, mixed "
            "case, numbers, and special characters. Display requirements on the "
            "registration form."
        )
    })

    return findings
