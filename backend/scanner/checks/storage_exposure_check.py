"""
storage_exposure_check.py — Storage & File Exposure

Checks for accessible backup files, environment files, log directories,
directory listing, and other sensitive file paths that should never be
publicly reachable.
"""

import re
from typing import List, Dict, Any
from .helpers import get_base, safe_get, finding


# Files / paths that should never be publicly accessible
SENSITIVE_PATHS = [
    ("/.env", "Environment configuration file"),
    ("/.env.local", "Local environment file"),
    ("/.env.production", "Production environment file"),
    ("/backup.zip", "Backup archive"),
    ("/backup.tar.gz", "Backup archive"),
    ("/backup.sql", "Database backup"),
    ("/dump.sql", "Database dump"),
    ("/database.sql", "Database export"),
    ("/db.sqlite", "SQLite database"),
    ("/db.sqlite3", "SQLite database"),
    ("/.git/config", "Git repository config"),
    ("/.git/HEAD", "Git HEAD reference"),
    ("/.svn/entries", "SVN entries file"),
    ("/.htaccess", "Apache config"),
    ("/.htpasswd", "Apache password file"),
    ("/wp-config.php", "WordPress config"),
    ("/config.php", "PHP config"),
    ("/config.yml", "YAML config"),
    ("/config.json", "JSON config"),
    ("/composer.json", "PHP Composer manifest"),
    ("/package.json", "Node.js manifest"),
    ("/Dockerfile", "Docker build file"),
    ("/docker-compose.yml", "Docker Compose config"),
]

# Directories that should not have listing enabled
DIRECTORY_PATHS = [
    "/logs/", "/log/", "/tmp/", "/temp/",
    "/uploads/", "/upload/", "/files/",
    "/backup/", "/backups/", "/data/",
    "/private/", "/internal/", "/storage/",
]


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)

    # ── SE-01: Sensitive files exposed ────────────────────────────────────────
    exposed_files: List[str] = []
    for path, label in SENSITIVE_PATHS:
        r = safe_get(f"{base}{path}", allow_redirects=False)
        if r is not None and r.status_code == 200 and len(r.text) > 10:
            # Extra validation — make sure it's not a generic 404 page
            if "not found" not in r.text.lower()[:200]:
                exposed_files.append(f"{path} ({label})")

    findings.append(finding(
        check_id="SE-01",
        category="Storage Exposure",
        severity="high",
        passed=len(exposed_files) == 0,
        description=(
            "No sensitive files are publicly accessible"
            if not exposed_files
            else f"Sensitive file(s) exposed: {'; '.join(exposed_files[:5])}"
        ),
        remediation=(
            "Remove or restrict access to backup files, .env, .git, database "
            "dumps, and config files. Block these paths in your reverse proxy "
            "or return 403/404."
        ),
    ))

    # ── SE-02: Directory listing enabled ─────────────────────────────────────
    listing_dirs: List[str] = []
    directory_listing_indicators = [
        "index of /", "directory listing", "<title>index of",
        "parent directory", "[to parent directory]",
    ]
    for path in DIRECTORY_PATHS:
        r = safe_get(f"{base}{path}", allow_redirects=False)
        if r is not None and r.status_code == 200:
            lower_body = r.text.lower()[:2000]
            if any(indicator in lower_body for indicator in directory_listing_indicators):
                listing_dirs.append(path)

    findings.append(finding(
        check_id="SE-02",
        category="Storage Exposure",
        severity="high",
        passed=len(listing_dirs) == 0,
        description=(
            "Directory listing is disabled on tested paths"
            if not listing_dirs
            else f"Directory listing enabled on: {', '.join(listing_dirs)}"
        ),
        remediation=(
            "Disable directory listing on your web server. "
            "For nginx: autoindex off; For Apache: Options -Indexes."
        ),
    ))

    # ── SE-03: Robots.txt reveals sensitive paths ────────────────────────────
    sensitive_in_robots: List[str] = []
    r = safe_get(f"{base}/robots.txt")
    if r is not None and r.status_code == 200:
        # Look for Disallow entries pointing to sensitive-sounding paths
        for line in r.text.splitlines():
            line_lower = line.strip().lower()
            if line_lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                sensitive_keywords = [
                    "admin", "backup", "log", "config", "private",
                    "secret", "internal", "api", "database", "upload",
                ]
                if any(kw in path.lower() for kw in sensitive_keywords):
                    sensitive_in_robots.append(path)

    findings.append(finding(
        check_id="SE-03",
        category="Storage Exposure",
        severity="medium",
        passed=len(sensitive_in_robots) == 0,
        description=(
            "robots.txt does not reveal sensitive path patterns"
            if not sensitive_in_robots
            else f"robots.txt exposes sensitive paths: {', '.join(sensitive_in_robots[:5])}"
        ),
        remediation=(
            "While robots.txt is useful for SEO, listing admin or internal paths "
            "reveals their existence to attackers. Protect them with authentication "
            "instead of relying on Disallow directives."
        ),
    ))

    # ── SE-04: Source map files accessible ────────────────────────────────────
    source_maps: List[str] = []
    r = safe_get(base)
    if r is not None:
        # Find JS files and check for .map companions
        js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', r.text)
        for js_url in js_files[:10]:
            map_url = js_url + ".map"
            if map_url.startswith("/"):
                map_url = base + map_url
            elif not map_url.startswith("http"):
                map_url = base + "/" + map_url
            r_map = safe_get(map_url, allow_redirects=False)
            if r_map is not None and r_map.status_code == 200:
                if '"sources"' in r_map.text[:500] or '"mappings"' in r_map.text[:500]:
                    source_maps.append(js_url + ".map")

    findings.append(finding(
        check_id="SE-04",
        category="Storage Exposure",
        severity="medium",
        passed=len(source_maps) == 0,
        description=(
            "No JavaScript source map files are publicly accessible"
            if not source_maps
            else f"Source map(s) exposed: {', '.join(source_maps[:3])}"
        ),
        remediation=(
            "Do not deploy .map files in production. They expose original "
            "source code, making it easier for attackers to find vulnerabilities. "
            "Remove them from your build output or block access via server config."
        ),
    ))

    return findings
