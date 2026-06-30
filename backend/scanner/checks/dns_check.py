import subprocess
import requests
from urllib.parse import urlparse


def _get_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split("/")[0]


def _get_base_https(url: str) -> str:
    domain = _get_domain(url)
    return f"https://{domain}"


def _check_dnssec(domain: str) -> tuple[bool, str]:
    """
    Query for DNSKEY records using the system resolver (dig).
    Returns (passed, detail_message).
    Falls back gracefully if dig is unavailable.
    """
    try:
        result = subprocess.run(
            ["dig", "+short", "+dnssec", "DNSKEY", domain],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        # A non-empty DNSKEY answer means DNSSEC is configured
        if output:
            return True, f"DNSKEY record found for {domain}"

        # Also try checking for DS record at parent (indicates delegation is signed)
        result_ds = subprocess.run(
            ["dig", "+short", "DS", domain],
            capture_output=True, text=True, timeout=10
        )
        if result_ds.stdout.strip():
            return True, f"DS record found — DNSSEC delegation signed for {domain}"

        return False, "No DNSKEY or DS records found"

    except FileNotFoundError:
        # dig not available — try dnspython if installed
        try:
            import dns.resolver
            import dns.rdatatype

            answers = dns.resolver.resolve(domain, "DNSKEY")
            if answers:
                return True, f"DNSKEY record found via dnspython for {domain}"
        except ImportError:
            return False, "Cannot verify DNSSEC: dig and dnspython are both unavailable"
        except Exception as e:
            return False, f"DNSSEC lookup failed: {str(e)}"

    except subprocess.TimeoutExpired:
        return False, "DNSSEC lookup timed out"
    except Exception as e:
        return False, f"DNSSEC check error: {str(e)}"


def check_dns(url: str):
    findings = []
    domain = _get_domain(url)
    base_https = _get_base_https(url)

    # ── G-03: DNSSEC ─────────────────────────────────────────────────────────
    dnssec_passed, dnssec_detail = _check_dnssec(domain)

    findings.append({
        "check_id": "G-03",
        "category": "DNS",
        "severity": "good",
        "passed": dnssec_passed,
        "description": f"DNSSEC is enabled — {dnssec_detail}"
                       if dnssec_passed
                       else f"DNSSEC is not configured — {dnssec_detail}",
        "remediation": "Enable DNSSEC through your DNS registrar or DNS provider. "
                       "DNSSEC signs DNS records cryptographically, preventing cache-poisoning "
                       "and man-in-the-middle attacks that could redirect patients to fraudulent sites. "
                       "Most major registrars (Cloudflare, Route53, GoDaddy) support one-click DNSSEC activation"
    })

    # ── G-06: security.txt at /.well-known/security.txt ──────────────────────
    security_txt_found = False
    security_txt_detail = ""

    # RFC 9116 canonical location
    canonical_url = f"{base_https}/.well-known/security.txt"
    # Legacy location (still commonly checked)
    legacy_url = f"{base_https}/security.txt"

    for check_url in (canonical_url, legacy_url):
        try:
            r = requests.get(check_url, timeout=5, allow_redirects=True)
            if r.status_code == 200 and len(r.text.strip()) > 0:
                # Validate it looks like a real security.txt (contains Contact: field)
                content = r.text
                if "Contact:" in content or "contact:" in content:
                    security_txt_found = True
                    security_txt_detail = f"Found at {check_url} with Contact field"
                    break
                else:
                    # File exists but may be a placeholder without required fields
                    security_txt_found = False
                    security_txt_detail = f"File exists at {check_url} but missing required 'Contact:' field"
                    break
        except Exception:
            continue

    if not security_txt_found and not security_txt_detail:
        security_txt_detail = "Not found at /.well-known/security.txt or /security.txt"

    findings.append({
        "check_id": "G-06",
        "category": "Disclosure",
        "severity": "good",
        "passed": security_txt_found,
        "description": f"security.txt is present and valid — {security_txt_detail}"
                       if security_txt_found
                       else f"security.txt is missing — {security_txt_detail}",
        "remediation": "Create a security.txt file at /.well-known/security.txt per RFC 9116. "
                       "It must include a 'Contact:' field (e.g. mailto:security@yourorg.com) and "
                       "optionally 'Expires:' and 'Policy:' fields. This enables security researchers "
                       "to responsibly disclose vulnerabilities, an important part of a HIPAA risk management program"
    })

    return findings
