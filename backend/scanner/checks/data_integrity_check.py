"""
data_integrity_check.py — HIPAA §164.312(c)(1) Integrity Controls

Checks for ETag / integrity headers, content checksums, and
mechanisms that ensure data has not been altered in transit.
"""

import re
from typing import List, Dict, Any
from .helpers import get_base, safe_get, finding


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)

    r = safe_get(base)
    headers = r.headers if r else {}

    # ── DI-01: ETag header present ───────────────────────────────────────────
    etag = headers.get("ETag", "")
    findings.append(finding(
        check_id="DI-01",
        category="Data Integrity",
        severity="medium",
        passed=bool(etag),
        description=(
            f"ETag header present: {etag[:40]}"
            if etag
            else "ETag header is missing — no content integrity indicator"
        ),
        remediation=(
            "Configure your web server or application to return ETag headers. "
            "ETags enable clients to verify content integrity and support "
            "conditional requests (If-None-Match)."
        ),
    ))

    # ── DI-02: Content-MD5 or Digest header ──────────────────────────────────
    digest = headers.get("Digest", "") or headers.get("Content-MD5", "")
    findings.append(finding(
        check_id="DI-02",
        category="Data Integrity",
        severity="low",
        passed=bool(digest),
        description=(
            f"Content integrity digest header found: {digest[:60]}"
            if digest
            else "No Digest or Content-MD5 header — no cryptographic integrity check on responses"
        ),
        remediation=(
            "Add a Digest header (e.g., Digest: sha-256=...) to API responses "
            "containing PHI. This allows clients to verify the response body "
            "was not tampered with in transit."
        ),
    ))

    # ── DI-03: Subresource Integrity (SRI) on external scripts ───────────────
    sri_missing: List[str] = []
    if r is not None:
        # Find <script src="..."> without integrity attribute
        script_tags = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
            r.text, re.IGNORECASE,
        )
        for tag_match in re.finditer(
            r'<script([^>]+)src=["\']([^"\']+)["\']([^>]*)>',
            r.text, re.IGNORECASE,
        ):
            attrs = tag_match.group(1) + tag_match.group(3)
            src = tag_match.group(2)
            # Only check external scripts (CDN / third-party)
            if src.startswith("http") or src.startswith("//"):
                if "integrity=" not in attrs.lower():
                    sri_missing.append(src[:80])

    findings.append(finding(
        check_id="DI-03",
        category="Data Integrity",
        severity="medium",
        passed=len(sri_missing) == 0,
        description=(
            "All external scripts use Subresource Integrity (SRI)"
            if not sri_missing
            else f"External script(s) without SRI: {', '.join(sri_missing[:3])}"
        ),
        remediation=(
            "Add integrity='sha384-...' and crossorigin='anonymous' attributes "
            "to all external <script> and <link> tags. SRI prevents compromised "
            "CDNs from injecting malicious code."
        ),
    ))

    # ── DI-04: X-Content-Type-Options: nosniff ───────────────────────────────
    xcto = headers.get("X-Content-Type-Options", "").lower()
    findings.append(finding(
        check_id="DI-04",
        category="Data Integrity",
        severity="medium",
        passed=xcto == "nosniff",
        description=(
            "X-Content-Type-Options: nosniff header is set"
            if xcto == "nosniff"
            else "X-Content-Type-Options header missing or not set to 'nosniff'"
        ),
        remediation=(
            "Add 'X-Content-Type-Options: nosniff' to prevent browsers from "
            "MIME-sniffing responses, which can lead to XSS via content-type confusion."
        ),
    ))

    # ── DI-05: Content-Security-Policy with script-src ───────────────────────
    csp = headers.get("Content-Security-Policy", "")
    has_script_src = "script-src" in csp.lower() if csp else False
    has_unsafe_inline = "'unsafe-inline'" in csp.lower() if csp else False

    findings.append(finding(
        check_id="DI-05",
        category="Data Integrity",
        severity="medium",
        passed=has_script_src and not has_unsafe_inline,
        description=(
            "CSP restricts script sources without 'unsafe-inline'"
            if has_script_src and not has_unsafe_inline
            else (
                "CSP allows 'unsafe-inline' scripts" if has_unsafe_inline
                else "Content-Security-Policy does not define script-src"
            )
        ),
        remediation=(
            "Set a Content-Security-Policy header with a restrictive script-src "
            "directive. Avoid 'unsafe-inline' — use nonces or hashes instead."
        ),
    ))

    return findings
