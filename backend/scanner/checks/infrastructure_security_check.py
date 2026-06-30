"""
infrastructure_security_check.py — Infrastructure Security

Basic port scanning on common services, server header disclosure,
and detection of exposed development/debug services.
"""

import re
from typing import List, Dict, Any
from .helpers import get_base, get_domain, safe_get, check_port_open, finding


# Common ports and associated services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}

# Ports that should never be publicly exposed for a web application
DANGEROUS_PORTS = {23, 3306, 5432, 6379, 27017, 9200, 11211}

# Known server software with version patterns
SERVER_VERSION_PATTERNS = [
    (r"(Apache/[\d.]+)", "Apache"),
    (r"(nginx/[\d.]+)", "nginx"),
    (r"(Microsoft-IIS/[\d.]+)", "IIS"),
    (r"(LiteSpeed/[\d.]+)", "LiteSpeed"),
    (r"(openresty/[\d.]+)", "OpenResty"),
]


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)
    domain = get_domain(target_url)

    # ── IS-01: Dangerous open ports ──────────────────────────────────────────
    open_dangerous: List[str] = []
    open_informational: List[str] = []
    for port, service in COMMON_PORTS.items():
        if check_port_open(domain, port, timeout=2):
            label = f"{port}/{service}"
            if port in DANGEROUS_PORTS:
                open_dangerous.append(label)
            else:
                open_informational.append(label)

    findings.append(finding(
        check_id="IS-01",
        category="Infrastructure",
        severity="high",
        passed=len(open_dangerous) == 0,
        description=(
            "No dangerous database/service ports are publicly accessible"
            if not open_dangerous
            else f"Dangerous open port(s): {', '.join(open_dangerous)}"
        ),
        remediation=(
            "Close database and cache ports (MySQL 3306, PostgreSQL 5432, "
            "Redis 6379, MongoDB 27017, Elasticsearch 9200) to the public. "
            "Use firewalls / security groups to restrict access to trusted IPs only."
        ),
    ))

    if open_informational:
        findings.append(finding(
            check_id="IS-02",
            category="Infrastructure",
            severity="low",
            passed=True,  # informational
            description=f"Other open port(s) detected: {', '.join(open_informational)}",
            remediation="Review whether all open ports are intentional and necessary.",
        ))

    # ── IS-03: Server header version disclosure ──────────────────────────────
    r = safe_get(base)
    server_header = ""
    version_disclosed = False
    server_software = ""
    if r is not None:
        server_header = r.headers.get("Server", "")
        for pattern, name in SERVER_VERSION_PATTERNS:
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                version_disclosed = True
                server_software = match.group(1)
                break

    findings.append(finding(
        check_id="IS-03",
        category="Infrastructure",
        severity="medium",
        passed=not version_disclosed,
        description=(
            "Server header does not disclose software version"
            if not version_disclosed
            else f"Server header discloses version: {server_software}"
        ),
        remediation=(
            "Configure your web server to suppress or genericize the Server header. "
            "Disclosing exact versions helps attackers identify known vulnerabilities. "
            "For nginx: server_tokens off; For Apache: ServerTokens Prod."
        ),
    ))

    # ── IS-04: X-Powered-By header disclosure ────────────────────────────────
    powered_by = ""
    if r is not None:
        powered_by = r.headers.get("X-Powered-By", "")

    findings.append(finding(
        check_id="IS-04",
        category="Infrastructure",
        severity="medium",
        passed=not bool(powered_by),
        description=(
            "X-Powered-By header is not present"
            if not powered_by
            else f"X-Powered-By header reveals technology: {powered_by}"
        ),
        remediation=(
            "Remove the X-Powered-By header. It reveals your backend framework "
            "and aids targeted attacks. In Express: app.disable('x-powered-by')."
        ),
    ))

    # ── IS-05: Exposed debug/development endpoints ───────────────────────────
    debug_paths = [
        "/debug", "/debug/", "/_debug", "/trace",
        "/__debug__", "/elmah.axd", "/errorlog",
        "/server-info", "/server-status",
        "/phpinfo.php", "/info.php",
    ]
    exposed_debug: List[str] = []
    for path in debug_paths:
        r_debug = safe_get(f"{base}{path}", allow_redirects=False)
        if r_debug is not None and r_debug.status_code == 200 and len(r_debug.text) > 100:
            exposed_debug.append(path)

    findings.append(finding(
        check_id="IS-05",
        category="Infrastructure",
        severity="high",
        passed=len(exposed_debug) == 0,
        description=(
            "No debug or development endpoints are publicly accessible"
            if not exposed_debug
            else f"Debug endpoint(s) exposed: {', '.join(exposed_debug)}"
        ),
        remediation=(
            "Disable debug endpoints (phpinfo, server-status, error logs) in "
            "production. These expose configuration details, environment variables, "
            "and internal paths that could lead to a data breach."
        ),
    ))

    return findings
