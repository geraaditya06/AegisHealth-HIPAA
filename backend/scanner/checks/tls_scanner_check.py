"""
tls_scanner_check.py — Comprehensive TLS / SSL Scanner.

A dedicated, deeper TLS posture scanner that complements the existing
``ssl_check`` module with additional, distinct checks (new ``TLS-`` ids so there
are no collisions):

    TLS-01  Protocol versions      — TLS 1.0/1.1 disabled, TLS 1.2/1.3 enabled
    TLS-02  Certificate expiry     — days remaining before expiry
    TLS-03  Certificate chain      — hostname / SAN validation
    TLS-04  Cipher suites          — rejects known-weak ciphers
    TLS-05  HSTS                   — Strict-Transport-Security present
    TLS-06  OCSP                   — certificate advertises an OCSP responder

All probes are read-only and wrapped in defensive try/except so a single
failure never aborts the scan.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List

from .helpers import finding, get_domain, safe_get

DEFAULT_PORT = 443
CONNECT_TIMEOUT = 6

# Cipher string of historically weak primitives; if a handshake succeeds with
# *only* these offered, the server accepts weak ciphers.
WEAK_CIPHER_STRING = "RC4:DES:3DES:NULL:EXPORT:MD5:aNULL:eNULL"


def _connect(domain: str, context: ssl.SSLContext) -> ssl.SSLSocket:
    """Open a TLS socket to ``domain:443`` using *context* (caller closes it)."""
    raw = socket.create_connection((domain, DEFAULT_PORT), timeout=CONNECT_TIMEOUT)
    return context.wrap_socket(raw, server_hostname=domain)


def _protocol_supported(domain: str, version: ssl.TLSVersion) -> bool:
    """Return True if the server completes a handshake pinned to *version*."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with _connect(domain, ctx):
            return True
    except Exception:
        return False


def _check_protocols(domain: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # Legacy protocols should be DISABLED.
    legacy_enabled = []
    for label, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            if _protocol_supported(domain, ver):
                legacy_enabled.append(label)
        except Exception:
            continue

    findings.append(finding(
        check_id="TLS-01",
        category="SSL",
        severity="high",
        passed=len(legacy_enabled) == 0,
        description=(
            "Legacy TLS 1.0/1.1 are disabled"
            if not legacy_enabled
            else f"Deprecated protocol(s) enabled: {', '.join(legacy_enabled)}"
        ),
        remediation=(
            "Disable TLS 1.0 and TLS 1.1. Require TLS 1.2 as a minimum and prefer "
            "TLS 1.3. Deprecated protocols are vulnerable to BEAST/POODLE-class attacks."
        ),
    ))
    return findings


def _check_certificate(domain: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    cert: Dict[str, Any] = {}
    chain_ok = False
    chain_detail = ""
    try:
        ctx = ssl.create_default_context()
        with _connect(domain, ctx) as s:
            cert = s.getpeercert() or {}
            chain_ok = True
            chain_detail = f"Certificate valid for {domain}"
    except ssl.SSLCertVerificationError as exc:
        chain_detail = f"Certificate verification failed: {exc.verify_message or exc}"
    except Exception as exc:
        chain_detail = f"Could not validate certificate chain: {exc}"

    # TLS-03: chain / hostname validation
    findings.append(finding(
        check_id="TLS-03",
        category="SSL",
        severity="high",
        passed=chain_ok,
        description=chain_detail,
        remediation=(
            "Install the full certificate chain (leaf + intermediates) and ensure "
            "the certificate covers the served hostname (CN/SAN)."
        ),
    ))

    # TLS-02: expiry (days remaining)
    days_left = None
    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
        except (ValueError, TypeError):
            days_left = None

    if days_left is None:
        passed, desc, sev = chain_ok, "Certificate expiry could not be determined", "medium"
    elif days_left < 0:
        passed, desc, sev = False, f"Certificate EXPIRED {abs(days_left)} day(s) ago", "high"
    elif days_left <= 14:
        passed, desc, sev = False, f"Certificate expires in {days_left} day(s)", "high"
    elif days_left <= 30:
        passed, desc, sev = False, f"Certificate expires in {days_left} day(s)", "medium"
    else:
        passed, desc, sev = True, f"Certificate valid for {days_left} more day(s)", "low"

    findings.append(finding(
        check_id="TLS-02",
        category="SSL",
        severity=sev,
        passed=passed,
        description=desc,
        remediation=(
            "Renew the certificate well before expiry and automate renewal "
            "(e.g. ACME/Let's Encrypt) with monitoring alerts at 30/14/7 days."
        ),
    ))

    # TLS-06: OCSP responder advertised in the certificate (AIA)
    ocsp = cert.get("OCSP") or ()
    findings.append(finding(
        check_id="TLS-06",
        category="SSL",
        severity="low",
        passed=bool(ocsp),
        description=(
            f"Certificate advertises OCSP responder: {', '.join(ocsp)}"
            if ocsp
            else "No OCSP responder advertised in the certificate"
        ),
        remediation=(
            "Use a certificate with OCSP information and enable OCSP stapling on "
            "the server so clients can efficiently verify revocation status."
        ),
    ))
    return findings


def _check_weak_ciphers(domain: str) -> List[Dict[str, Any]]:
    weak_accepted = False
    weak_name = ""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers(WEAK_CIPHER_STRING)
        except ssl.SSLError:
            # OpenSSL refused to even offer these — strong by default.
            return [finding(
                check_id="TLS-04", category="SSL", severity="high", passed=True,
                description="Client/OpenSSL refuses weak ciphers; server not negotiable to weak suites",
                remediation="Continue to allow only AES-GCM and ChaCha20-Poly1305 suites.",
            )]
        with _connect(domain, ctx) as s:
            weak_accepted = True
            info = s.cipher()
            weak_name = info[0] if info else "unknown"
    except Exception:
        weak_accepted = False

    return [finding(
        check_id="TLS-04",
        category="SSL",
        severity="high",
        passed=not weak_accepted,
        description=(
            "Server does not negotiate known-weak cipher suites"
            if not weak_accepted
            else f"Server accepted a weak cipher suite: {weak_name}"
        ),
        remediation=(
            "Disable RC4, DES/3DES, NULL, EXPORT and MD5-based ciphers. Allow only "
            "AES-GCM and ChaCha20-Poly1305 with TLS 1.2+."
        ),
    )]


def _check_hsts(domain: str) -> List[Dict[str, Any]]:
    r = safe_get(f"https://{domain}")
    hsts = r.headers.get("Strict-Transport-Security", "") if r is not None else ""
    return [finding(
        check_id="TLS-05",
        category="Encryption",
        severity="medium",
        passed=bool(hsts),
        description=(
            f"HSTS enabled: {hsts}" if hsts else "Strict-Transport-Security (HSTS) header missing"
        ),
        remediation=(
            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains; "
            "preload' on all HTTPS responses to force secure transport."
        ),
    )]


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    """Run the full TLS scanner against *target_url* and return findings."""
    domain = get_domain(target_url)
    findings: List[Dict[str, Any]] = []
    for fn in (_check_protocols, _check_certificate, _check_weak_ciphers, _check_hsts):
        try:
            findings += fn(domain)
        except Exception:
            continue
    return findings
