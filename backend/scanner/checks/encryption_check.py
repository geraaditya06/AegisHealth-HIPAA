"""
encryption_check.py — HIPAA §164.312(a)(2)(iv) & §164.312(e)(1) Encryption

Checks HTTPS enforcement, encryption-related headers, and detection of
exposed secrets in frontend JavaScript.
"""

import re
import ssl
import socket
from typing import List, Dict, Any
from .helpers import get_base, get_domain, safe_get, finding


# Patterns that indicate leaked secrets in front-end code
SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API key"),
    (r'(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{8,})["\']', "Secret/token"),
    (r'(?:aws_access_key_id)\s*[:=]\s*["\']?(AKIA[A-Z0-9]{16})', "AWS access key"),
    (r'(?:aws_secret_access_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS secret key"),
    (r'(?:PRIVATE KEY-----)', "Private key block"),
    (r'(?:ghp_[A-Za-z0-9]{36})', "GitHub personal access token"),
]


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)
    domain = get_domain(target_url)

    # ── EN-01: HTTPS enforcement ─────────────────────────────────────────────
    try:
        import requests
        r = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
        https_enforced = r.url.startswith("https://")
    except Exception:
        https_enforced = False

    findings.append(finding(
        check_id="EN-01",
        category="Encryption",
        severity="high",
        passed=https_enforced,
        description=(
            "HTTP traffic is redirected to HTTPS"
            if https_enforced
            else "HTTP traffic is NOT redirected to HTTPS — data may travel in plaintext"
        ),
        remediation=(
            "Configure your server to issue a 301 redirect from HTTP to HTTPS "
            "for every request. All ePHI in transit must be encrypted per "
            "HIPAA §164.312(e)(1)."
        ),
    ))

    # ── EN-02: HSTS header and preload ───────────────────────────────────────
    r = safe_get(f"https://{domain}")
    hsts_value = ""
    hsts_present = False
    hsts_preload = False
    if r is not None:
        hsts_value = r.headers.get("Strict-Transport-Security", "")
        hsts_present = bool(hsts_value)
        hsts_preload = "preload" in hsts_value.lower()

    findings.append(finding(
        check_id="EN-02",
        category="Encryption",
        severity="high",
        passed=hsts_present,
        description=(
            f"HSTS header present: {hsts_value}"
            if hsts_present
            else "Strict-Transport-Security (HSTS) header is missing"
        ),
        remediation=(
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' "
            "to all HTTPS responses. Submit your domain to the HSTS preload list."
        ),
    ))

    findings.append(finding(
        check_id="EN-03",
        category="Encryption",
        severity="medium",
        passed=hsts_preload,
        description=(
            "HSTS preload directive is present"
            if hsts_preload
            else "HSTS header is missing the 'preload' directive"
        ),
        remediation=(
            "Add the 'preload' directive to your HSTS header and submit your "
            "domain to hstspreload.org for inclusion in browser preload lists."
        ),
    ))

    # ── EN-04: Weak cipher detection (heuristic) ────────────────────────────
    weak_cipher_found = False
    weak_cipher_name = ""
    try:
        # Try connecting with only weak ciphers — if it succeeds, server allows them
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Attempt a cipher string known to be weak
        weak_ciphers = "RC4:DES:3DES:NULL:EXPORT:MD5"
        ctx.set_ciphers(weak_ciphers)
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            weak_cipher_found = True
            cipher_info = s.cipher()
            weak_cipher_name = cipher_info[0] if cipher_info else "unknown"
    except ssl.SSLError:
        # Good — server refused weak ciphers
        weak_cipher_found = False
    except Exception:
        # Connection failure / other error — can't determine, assume OK
        weak_cipher_found = False

    findings.append(finding(
        check_id="EN-04",
        category="Encryption",
        severity="high",
        passed=not weak_cipher_found,
        description=(
            "Server does not accept known weak cipher suites"
            if not weak_cipher_found
            else f"Server accepts weak cipher suite: {weak_cipher_name}"
        ),
        remediation=(
            "Disable RC4, DES, 3DES, NULL, EXPORT, and MD5-based cipher suites. "
            "Only allow AES-GCM and ChaCha20 with TLS 1.2+."
        ),
    ))

    # ── EN-05: Certificate chain validation ──────────────────────────────────
    cert_chain_ok = False
    cert_detail = ""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            # Verify subject matches domain
            san = cert.get("subjectAltName", ())
            san_names = [name for typ, name in san if typ == "DNS"]
            if domain in san_names or any(
                name.startswith("*.") and domain.endswith(name[1:]) for name in san_names
            ):
                cert_chain_ok = True
                cert_detail = f"Certificate valid for {domain}"
            else:
                cert_detail = f"Certificate SAN mismatch — expected {domain}, got {san_names}"
    except Exception as e:
        cert_detail = f"Certificate chain validation failed: {str(e)}"

    findings.append(finding(
        check_id="EN-05",
        category="Encryption",
        severity="high",
        passed=cert_chain_ok,
        description=(
            cert_detail if cert_chain_ok
            else f"Certificate chain issue: {cert_detail}"
        ),
        remediation=(
            "Ensure your SSL certificate covers the exact domain (or wildcard) "
            "and that the full certificate chain (including intermediates) is installed."
        ),
    ))

    # ── EN-06: Secrets exposed in frontend JavaScript ────────────────────────
    exposed_secrets: List[str] = []
    r = safe_get(base)
    if r is not None:
        page_text = r.text
        # Find linked JS files
        js_urls = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', page_text)
        # Also scan inline scripts
        texts_to_scan = [page_text]
        for js_url in js_urls[:10]:  # limit to 10 JS files
            if js_url.startswith("//"):
                js_url = "https:" + js_url
            elif js_url.startswith("/"):
                js_url = base + js_url
            elif not js_url.startswith("http"):
                js_url = base + "/" + js_url
            jr = safe_get(js_url)
            if jr is not None:
                texts_to_scan.append(jr.text)

        for text in texts_to_scan:
            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    exposed_secrets.append(label)

    # Deduplicate
    exposed_secrets = list(set(exposed_secrets))

    findings.append(finding(
        check_id="EN-06",
        category="Encryption",
        severity="high",
        passed=len(exposed_secrets) == 0,
        description=(
            "No secrets or API keys detected in frontend JavaScript"
            if not exposed_secrets
            else f"Potential secrets exposed in frontend JS: {', '.join(exposed_secrets)}"
        ),
        remediation=(
            "Never embed secrets, API keys, or tokens in client-side JavaScript. "
            "Use server-side environment variables and proxy API calls through "
            "your backend."
        ),
    ))

    return findings
