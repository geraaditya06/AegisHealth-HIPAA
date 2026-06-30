import requests
import ssl
import socket
from datetime import datetime

def check_ssl(url: str):
    findings = []
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    # C-01 HTTPS enforcement
    try:
        r = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
        passed = r.url.startswith("https://")
    except:
        passed = False
    findings.append({
        "check_id": "C-01", "category": "Encryption", "severity": "critical",
        "passed": passed,
        "description": "Site redirects HTTP to HTTPS" if passed else "Site does not enforce HTTPS",
        "remediation": "Configure your server to redirect all HTTP traffic to HTTPS"
    })

    # C-02 SSL certificate valid
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expire = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            passed = expire > datetime.utcnow()
    except:
        passed = False
    findings.append({
        "check_id": "C-02", "category": "SSL", "severity": "critical",
        "passed": passed,
        "description": "SSL certificate is valid" if passed else "SSL certificate is invalid or expired",
        "remediation": "Renew your SSL certificate immediately"
    })

    # C-03 TLS version
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            passed = True
    except:
        passed = False
    findings.append({
        "check_id": "C-03", "category": "SSL", "severity": "critical",
        "passed": passed,
        "description": "TLS 1.2 or higher is supported" if passed else "TLS version is below 1.2",
        "remediation": "Disable TLS 1.0 and 1.1 on your server and enable TLS 1.2+"
    })

    # ── NEW: SSL-01 Weak cipher detection (heuristic) ───────────────────────
    weak_cipher_found = False
    weak_cipher_name = ""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        weak_ciphers = "RC4:DES:3DES:NULL:EXPORT:MD5"
        ctx.set_ciphers(weak_ciphers)
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            weak_cipher_found = True
            cipher_info = s.cipher()
            weak_cipher_name = cipher_info[0] if cipher_info else "unknown"
    except ssl.SSLError:
        weak_cipher_found = False
    except Exception:
        weak_cipher_found = False

    findings.append({
        "check_id": "SSL-01", "category": "SSL", "severity": "critical",
        "passed": not weak_cipher_found,
        "description": (
            "Server does not accept known weak cipher suites"
            if not weak_cipher_found
            else f"Server accepts weak cipher: {weak_cipher_name}"
        ),
        "remediation": (
            "Disable RC4, DES, 3DES, NULL, EXPORT, and MD5-based cipher suites. "
            "Only allow AES-GCM and ChaCha20-Poly1305 with TLS 1.2+."
        )
    })

    # ── NEW: SSL-02 Certificate chain validation ────────────────────────────
    chain_ok = False
    chain_detail = ""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            san = cert.get("subjectAltName", ())
            san_names = [name for typ, name in san if typ == "DNS"]
            if domain in san_names or any(
                name.startswith("*.") and domain.endswith(name[1:])
                for name in san_names
            ):
                chain_ok = True
                chain_detail = f"Certificate valid for {domain}"
            else:
                chain_detail = f"SAN mismatch — expected {domain}"
    except Exception as e:
        chain_detail = f"Chain validation failed: {str(e)}"

    findings.append({
        "check_id": "SSL-02", "category": "SSL", "severity": "critical",
        "passed": chain_ok,
        "description": chain_detail if chain_ok else f"Certificate chain issue: {chain_detail}",
        "remediation": (
            "Ensure your SSL certificate covers the domain and the full "
            "certificate chain (including intermediates) is installed."
        )
    })

    # ── NEW: SSL-03 HSTS preload check ──────────────────────────────────────
    hsts_preload = False
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        hsts_value = r.headers.get("Strict-Transport-Security", "")
        hsts_preload = "preload" in hsts_value.lower()
    except:
        pass

    findings.append({
        "check_id": "SSL-03", "category": "SSL", "severity": "warning",
        "passed": hsts_preload,
        "description": (
            "HSTS header includes preload directive"
            if hsts_preload
            else "HSTS header missing 'preload' directive"
        ),
        "remediation": (
            "Add 'preload' to your HSTS header and submit to hstspreload.org "
            "for browser preload list inclusion."
        )
    })

    return findings