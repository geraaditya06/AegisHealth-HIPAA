import requests

def check_headers(url: str):
    findings = []
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
    except:
        return []

    checks = [
        ("C-07", "Headers", "critical", "Strict-Transport-Security",
         "HSTS header is present", "HSTS header is missing",
         "Add Strict-Transport-Security: max-age=31536000 to your response headers"),
        ("W-01", "Headers", "warning", "Content-Security-Policy",
         "CSP header is present", "Content-Security-Policy header is missing",
         "Add a Content-Security-Policy header to prevent XSS attacks"),
        ("W-02", "Headers", "warning", "X-Frame-Options",
         "X-Frame-Options is set", "X-Frame-Options header is missing",
         "Add X-Frame-Options: DENY to prevent clickjacking"),
        ("W-03", "Headers", "warning", "X-Content-Type-Options",
         "X-Content-Type-Options is set", "X-Content-Type-Options header is missing",
         "Add X-Content-Type-Options: nosniff to your headers"),
    ]

    for check_id, category, severity, header, pass_msg, fail_msg, remediation in checks:
        passed = header in headers
        findings.append({
            "check_id": check_id, "category": category, "severity": severity,
            "passed": passed,
            "description": pass_msg if passed else fail_msg,
            "remediation": remediation if not passed else "No action needed"
        })

    cookies = r.headers.get("Set-Cookie", "")
    passed = "HttpOnly" in cookies and "Secure" in cookies
    findings.append({
        "check_id": "C-08", "category": "Auth", "severity": "critical",
        "passed": passed,
        "description": "Session cookies have HttpOnly and Secure flags" if passed else "Cookies missing HttpOnly or Secure flags",
        "remediation": "Set HttpOnly and Secure flags on all session cookies"
    })

    # ── NEW: W-04 Referrer-Policy ───────────────────────────────────────────
    referrer = headers.get("Referrer-Policy", "")
    safe_values = [
        "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
        "same-origin", "no-referrer-when-downgrade",
    ]
    ref_passed = any(v in referrer.lower() for v in safe_values) if referrer else False
    findings.append({
        "check_id": "W-04", "category": "Headers", "severity": "warning",
        "passed": ref_passed,
        "description": (
            f"Referrer-Policy header is set: {referrer}"
            if ref_passed
            else "Referrer-Policy header is missing or set to an unsafe value"
        ),
        "remediation": (
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' to prevent "
            "leaking full URLs (which may contain PHI) to third-party sites."
        )
    })

    # ── NEW: W-05 Permissions-Policy ────────────────────────────────────────
    permissions = headers.get("Permissions-Policy", "") or headers.get("Feature-Policy", "")
    perm_passed = bool(permissions)
    findings.append({
        "check_id": "W-05", "category": "Headers", "severity": "warning",
        "passed": perm_passed,
        "description": (
            f"Permissions-Policy header is set: {permissions[:80]}"
            if perm_passed
            else "Permissions-Policy (or Feature-Policy) header is missing"
        ),
        "remediation": (
            "Add a Permissions-Policy header to restrict browser features. "
            "Example: Permissions-Policy: camera=(), microphone=(), geolocation=() "
            "to disable unnecessary APIs that could be exploited."
        )
    })

    # ── NEW: W-06 X-XSS-Protection ─────────────────────────────────────────
    xss_prot = headers.get("X-XSS-Protection", "")
    xss_passed = xss_prot.startswith("1") if xss_prot else False
    findings.append({
        "check_id": "W-06", "category": "Headers", "severity": "warning",
        "passed": xss_passed,
        "description": (
            f"X-XSS-Protection header is set: {xss_prot}"
            if xss_passed
            else "X-XSS-Protection header is missing or disabled"
        ),
        "remediation": (
            "Add 'X-XSS-Protection: 1; mode=block' as a defence-in-depth measure. "
            "While CSP is the primary XSS defence, this header adds a legacy safety net."
        )
    })

    return findings