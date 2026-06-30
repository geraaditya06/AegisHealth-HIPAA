"""
recommendation_engine.py — AI Recommendation Engine.

Enriches every scan finding with actionable, audience-aware context:

    explanation             Plain-English description of the issue
    business_impact         What it means for the organisation / patients
    technical_impact        What it means technically (attack consequence)
    hipaa_rule              Mapped HIPAA Security Rule safeguard
    owasp_category          Mapped OWASP Top 10 (2021) category
    fix_steps               Ordered, concrete remediation steps
    code_example            {language, label, code} when one is available
    estimated_risk_reduction  % of the scan's open risk removed by this fix

The engine is fully deterministic and offline-first (no external calls), so it
is fast and reliable. ``estimated_risk_reduction`` is contextual — it weights a
finding's severity against the total open risk in the same scan.

This module is read-time only: it derives enrichment from stored findings, so
no database schema changes are required.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# Severity → relative weight (kept consistent with scanner.scorer).
_SEVERITY_POINTS = {"critical": 5, "high": 5, "warning": 3, "medium": 3, "low": 1, "good": 1}


# ── HIPAA Security Rule mapping (by check-id alpha prefix) ────────────────────
_HIPAA_RULES = {
    "EN": "§164.312(e)(1) — Transmission Security (encryption in transit)",
    "TLS": "§164.312(e)(1) — Transmission Security",
    "SSL": "§164.312(e)(1) — Transmission Security",
    "C": "§164.312 — Technical Safeguards",
    "AUTH": "§164.312(d) — Person or Entity Authentication",
    "ATH": "§164.312(d) — Person or Entity Authentication",
    "AC": "§164.312(a)(1) — Access Control",
    "SM": "§164.312(a)(2)(iii) — Automatic Logoff / Session Security",
    "API": "§164.312(a)(1) — Access Control (API surface)",
    "APIX": "§164.312(a)(1) — Access Control (API surface)",
    "PHI": "§164.502(b) — Minimum Necessary Use & Disclosure",
    "IS": "§164.308(a)(1) — Security Management Process",
    "SE": "§164.312(c)(1) — Integrity / Storage Protection",
    "BR": "§164.308(a)(7) — Contingency Plan (backup & recovery)",
    "AL": "§164.312(b) — Audit Controls",
    "MA": "§164.308(a)(1)(ii)(D) — Information System Activity Review",
    "IV": "§164.312(c)(1) — Integrity (input validation)",
    "DI": "§164.312(c)(1) — Integrity",
    "TP": "§164.308(b)(1) — Business Associate / Third-Party Controls",
    "DK": "§164.308(a)(1) — Security Management Process (infrastructure)",
    "DEP": "§164.308(a)(1) — Risk Management (vulnerable components)",
    "W": "§164.312 — Technical Safeguards (HTTP security headers)",
    "G": "§164.530 — Administrative / Trust Requirements",
    "OWASP": "§164.308(a)(1)(ii)(A) — Risk Analysis",
}

# ── OWASP Top 10 (2021) mapping ───────────────────────────────────────────────
_OWASP_BY_PREFIX = {
    "AC": ("A01", "Broken Access Control"),
    "IDOR": ("A01", "Broken Access Control"),
    "EN": ("A02", "Cryptographic Failures"),
    "TLS": ("A02", "Cryptographic Failures"),
    "SSL": ("A02", "Cryptographic Failures"),
    "PHI": ("A02", "Cryptographic Failures"),
    "IV": ("A03", "Injection"),
    "IS": ("A05", "Security Misconfiguration"),
    "SE": ("A05", "Security Misconfiguration"),
    "W": ("A05", "Security Misconfiguration"),
    "DI": ("A08", "Software & Data Integrity Failures"),
    "BR": ("A08", "Software & Data Integrity Failures"),
    "DEP": ("A06", "Vulnerable & Outdated Components"),
    "TP": ("A06", "Vulnerable & Outdated Components"),
    "DK": ("A06", "Vulnerable & Outdated Components"),
    "AUTH": ("A07", "Identification & Authentication Failures"),
    "ATH": ("A07", "Identification & Authentication Failures"),
    "SM": ("A07", "Identification & Authentication Failures"),
    "AL": ("A09", "Security Logging & Monitoring Failures"),
    "MA": ("A09", "Security Logging & Monitoring Failures"),
    "API": ("A01", "Broken Access Control"),
    "APIX": ("A01", "Broken Access Control"),
}

# ── Category-level impact narratives ──────────────────────────────────────────
_BUSINESS_IMPACT = {
    "Encryption": "Unencrypted patient data in transit can be intercepted, triggering HIPAA breach notification, OCR penalties, and loss of patient trust.",
    "SSL": "Certificate or TLS weaknesses erode trust, can take the service offline, and may expose ePHI to interception.",
    "Auth": "Weak authentication enables account takeover and unauthorized access to protected health information.",
    "Session": "Poor session controls let attackers hijack authenticated sessions and impersonate clinicians or patients.",
    "Access Control": "Broken access control can expose entire patient records to unauthorized parties — a reportable breach.",
    "API Security": "Exposed or unprotected APIs can leak PHI at scale and are a leading cause of large healthcare data breaches.",
    "Data": "Exposure of PHI/PII directly violates HIPAA and can result in regulatory fines and litigation.",
    "Infrastructure": "Misconfigured infrastructure widens the attack surface and can lead to full system compromise.",
    "Input Validation": "Injection flaws can result in data theft, tampering, or full database compromise.",
    "Headers": "Missing security headers increase the chance of client-side attacks that steal session tokens or PHI.",
    "Container Security": "Insecure container images can introduce vulnerable software and secrets into production.",
    "Dependencies": "Vulnerable third-party components are a top breach vector and may already have public exploits.",
}
_TECHNICAL_IMPACT = {
    "Encryption": "Man-in-the-middle attackers can read or modify traffic; downgrade attacks become feasible.",
    "SSL": "Clients may reject connections or be exposed to spoofing and protocol-downgrade attacks.",
    "Auth": "Credential stuffing, brute force, or token forgery can yield authenticated access.",
    "Session": "Session fixation/hijacking and CSRF become possible, bypassing authentication.",
    "Access Control": "Horizontal/vertical privilege escalation and IDOR allow reading or modifying others' data.",
    "API Security": "Unauthenticated data access, enumeration, and mass extraction of records.",
    "Data": "Direct disclosure of sensitive fields (SSN, MRN, DOB) in responses, URLs, or logs.",
    "Infrastructure": "Service fingerprinting, exposed admin/debug surfaces, and lateral movement.",
    "Input Validation": "Reflected/stored XSS or SQL injection leading to data exfiltration.",
    "Headers": "Clickjacking, MIME sniffing, and XSS exploitation due to missing browser protections.",
    "Container Security": "Privilege escalation from root containers and leakage of baked-in secrets.",
    "Dependencies": "Known CVEs may be directly exploitable for RCE, DoS, or data disclosure.",
}

# ── Concrete code-fix examples (by check id) ──────────────────────────────────
_CODE_EXAMPLES: Dict[str, Tuple[str, str, str]] = {
    "C-01": ("nginx", "Force HTTPS redirect", "server {\n  listen 80;\n  return 301 https://$host$request_uri;\n}"),
    "EN-01": ("nginx", "Force HTTPS redirect", "server {\n  listen 80;\n  return 301 https://$host$request_uri;\n}"),
    "EN-02": ("nginx", "Enable HSTS", 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;'),
    "TLS-05": ("nginx", "Enable HSTS", 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;'),
    "TLS-01": ("nginx", "Require TLS 1.2+", "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5;"),
    "SM-01": ("python", "Set Secure cookie", 'response.set_cookie("session", token, secure=True, httponly=True, samesite="strict")'),
    "ATH-09": ("python", "Set Secure cookie", 'response.set_cookie("session", token, secure=True, httponly=True, samesite="strict")'),
    "API-04": ("python", "Add rate limiting (slowapi)", 'from slowapi import Limiter\nlimiter = Limiter(key_func=get_remote_address)\n@limiter.limit("100/minute")\ndef endpoint(): ...'),
    "APIX-06": ("python", "Add rate limiting (slowapi)", 'from slowapi import Limiter\nlimiter = Limiter(key_func=get_remote_address)\n@limiter.limit("100/minute")\ndef endpoint(): ...'),
    "IV-01": ("python", "Escape user input", "from markupsafe import escape\nsafe = escape(user_input)"),
    "OWASP-A03-XSS": ("python", "Escape user input", "from markupsafe import escape\nsafe = escape(user_input)"),
    "IV-02": ("python", "Parameterised query", 'cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))'),
    "OWASP-A03-SQLI": ("python", "Parameterised query", 'cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))'),
    "AC-04": ("python", "TOTP-based MFA", "import pyotp\nif not pyotp.TOTP(user.mfa_secret).verify(code):\n    raise HTTPException(401, 'Invalid MFA code')"),
    "ATH-08": ("python", "TOTP-based MFA", "import pyotp\nif not pyotp.TOTP(user.mfa_secret).verify(code):\n    raise HTTPException(401, 'Invalid MFA code')"),
    "OWASP-A05-CLICK": ("nginx", "Prevent clickjacking", 'add_header X-Frame-Options DENY always;\nadd_header Content-Security-Policy "frame-ancestors \'none\'" always;'),
    "OWASP-A05-HEADERS": ("nginx", "Add security headers", 'add_header X-Content-Type-Options nosniff;\nadd_header X-Frame-Options DENY;\nadd_header Referrer-Policy strict-origin-when-cross-origin;'),
    "DK-02": ("dockerfile", "Run as non-root user", "RUN useradd -m appuser\nUSER appuser"),
    "DK-01": ("dockerfile", "Pin base image", "FROM python:3.12.3-slim@sha256:<digest>"),
    "APIX-02": ("text", "Disable GraphQL introspection", "Set introspection: false in production (e.g. Apollo: introspection: process.env.NODE_ENV !== 'production')."),
}

# Checks that are typically low-effort, high-value (quick wins).
_QUICK_WIN_PREFIXES = ("W", "SM", "ATH-09", "ATH-10", "ATH-11", "EN-02", "EN-03",
                       "TLS-05", "IS-03", "IS-04", "API-02", "APIX-04", "G-06",
                       "OWASP-A05-HEADERS", "OWASP-A05-CLICK", "DI-04")
# Checks that usually need architectural / longer-term work.
_LONG_TERM_PREFIXES = ("AC-03", "AC-04", "AUTH-01", "ATH-08", "EN-01", "EN-04",
                       "TLS-01", "MA", "BR", "AL", "DEP", "DK-09", "API-04",
                       "APIX-06", "IV-02")


def _prefix(check_id: str) -> str:
    return "".join(ch for ch in (check_id or "") if ch.isalpha()).upper()


def _lookup_by_prefix(check_id: str, table: Dict[str, Any], default: Any) -> Any:
    pfx = _prefix(check_id)
    for key in sorted(table, key=len, reverse=True):
        if pfx.startswith(key):
            return table[key]
    return default


def hipaa_rule(check_id: str) -> str:
    return _lookup_by_prefix(check_id, _HIPAA_RULES, "HIPAA Security Rule — General Technical Safeguards")


def owasp_category(check_id: str, category: str = "") -> str:
    code_name = _lookup_by_prefix(check_id, _OWASP_BY_PREFIX, None)
    if code_name is None:
        # Fall back on the raw category text.
        cat = (category or "").lower()
        if "header" in cat or "infrastructure" in cat or "storage" in cat:
            code_name = ("A05", "Security Misconfiguration")
        elif "data" in cat or "encrypt" in cat:
            code_name = ("A02", "Cryptographic Failures")
        else:
            code_name = ("A04", "Insecure Design")
    return f"{code_name[0]}:2021 — {code_name[1]}"


def _fix_steps(finding: Dict[str, Any]) -> List[str]:
    """Turn the remediation text into ordered, concrete steps."""
    remediation = (finding.get("remediation") or "").strip()
    if not remediation:
        return ["Review the finding and apply the recommended security control."]
    # Split on sentence boundaries / list markers into discrete steps.
    parts = [p.strip(" .") for p in remediation.replace(";", ". ").split(". ") if p.strip(" .")]
    steps = [
        "Confirm and reproduce the issue on the affected component.",
        *parts,
        "Re-scan to verify the finding is resolved and document the change.",
    ]
    # De-duplicate while preserving order.
    seen, ordered = set(), []
    for s in steps:
        if s.lower() not in seen:
            seen.add(s.lower())
            ordered.append(s if s.endswith(".") else s + ".")
    return ordered


def _code_example(check_id: str) -> Optional[Dict[str, str]]:
    entry = _CODE_EXAMPLES.get(check_id)
    if not entry:
        return None
    language, label, code = entry
    return {"language": language, "label": label, "code": code}


def effort_class(check_id: str) -> str:
    """Classify remediation effort: 'quick' | 'long' | 'standard'."""
    cid = (check_id or "").upper()
    if any(cid.startswith(p) for p in _QUICK_WIN_PREFIXES):
        return "quick"
    if any(cid.startswith(p) for p in _LONG_TERM_PREFIXES):
        return "long"
    return "standard"


def severity_points(severity: str) -> int:
    return _SEVERITY_POINTS.get((severity or "good").lower(), 1)


def enrich_finding(finding: Dict[str, Any], total_open_points: int) -> Dict[str, Any]:
    """Return a copy of *finding* with an attached ``recommendation`` block."""
    category = finding.get("category", "")
    severity = finding.get("severity", "good")
    passed = finding.get("passed", False)
    points = severity_points(severity)

    # Risk reduction is only meaningful for open (failed) findings.
    if passed or total_open_points <= 0:
        risk_reduction = 0
    else:
        risk_reduction = round(points / total_open_points * 100, 1)

    recommendation = {
        "explanation": finding.get("description", ""),
        "business_impact": _BUSINESS_IMPACT.get(category, _BUSINESS_IMPACT.get(
            category.split()[0] if category else "",
            "May contribute to a compliance gap or security weakness affecting protected data.")),
        "technical_impact": _TECHNICAL_IMPACT.get(category, _TECHNICAL_IMPACT.get(
            category.split()[0] if category else "",
            "Could be leveraged by an attacker to weaken the application's security posture.")),
        "hipaa_rule": hipaa_rule(finding.get("check_id", "")),
        "owasp_category": owasp_category(finding.get("check_id", ""), category),
        "fix_steps": _fix_steps(finding),
        "code_example": _code_example(finding.get("check_id", "")),
        "estimated_risk_reduction": risk_reduction,
        "effort": effort_class(finding.get("check_id", "")),
    }
    enriched = dict(finding)
    enriched["recommendation"] = recommendation
    return enriched


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach recommendation blocks to every finding (contextual risk reduction)."""
    total_open_points = sum(
        severity_points(f.get("severity", "good"))
        for f in findings if not f.get("passed", False)
    )
    return [enrich_finding(f, total_open_points) for f in findings]
