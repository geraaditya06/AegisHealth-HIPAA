"""
backup_recovery_check.py — Backup & Recovery Exposure

Detects publicly accessible backup files, database dumps, and
archive artifacts that violate HIPAA data protection requirements.
"""

from typing import List, Dict, Any
from .helpers import get_base, safe_get, finding


BACKUP_PATHS = [
    "/backup.zip", "/backup.tar.gz", "/backup.tar",
    "/backup.sql", "/backup.sql.gz", "/backup.bak",
    "/site-backup.zip", "/full-backup.zip",
    "/db-backup.sql", "/db.sql", "/dump.sql",
    "/database.sql", "/data.sql",
    "/www.zip", "/site.zip", "/public.zip",
    "/wp-content/backup-db/", "/backups/",
    "/old/", "/archive/", "/export/",
    "/backup/", "/bak/", "/save/",
]

ARCHIVE_EXTENSIONS = [".zip", ".tar", ".tar.gz", ".gz", ".rar", ".7z", ".bak", ".sql"]


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)

    # ── BR-01: Backup files accessible ───────────────────────────────────────
    exposed: List[str] = []
    for path in BACKUP_PATHS:
        r = safe_get(f"{base}{path}", allow_redirects=False)
        if r is not None and r.status_code == 200:
            content_type = r.headers.get("Content-Type", "").lower()
            # Verify it's actually a file and not a custom 404
            is_archive = any(
                ct in content_type
                for ct in ("application/zip", "application/gzip",
                           "application/x-tar", "application/octet-stream",
                           "application/sql", "text/sql")
            )
            is_large_enough = len(r.content) > 100
            if is_archive or (is_large_enough and "not found" not in r.text.lower()[:200]):
                exposed.append(path)

    findings.append(finding(
        check_id="BR-01",
        category="Backup & Recovery",
        severity="high",
        passed=len(exposed) == 0,
        description=(
            "No backup or archive files are publicly accessible"
            if not exposed
            else f"Backup/archive file(s) exposed: {', '.join(exposed[:5])}"
        ),
        remediation=(
            "Remove backup files from the web root. Store backups in a secure, "
            "access-controlled location (e.g., S3 with encryption). "
            "HIPAA §164.308(a)(7)(ii)(A) requires secure backup procedures."
        ),
    ))

    # ── BR-02: Database dump files ───────────────────────────────────────────
    db_paths = [
        "/db.sqlite", "/db.sqlite3", "/database.db",
        "/app.db", "/data.db", "/aegishealth.db",
        "/production.sqlite3", "/dev.db",
    ]
    exposed_db: List[str] = []
    for path in db_paths:
        r = safe_get(f"{base}{path}", allow_redirects=False)
        if r is not None and r.status_code == 200 and len(r.content) > 50:
            exposed_db.append(path)

    findings.append(finding(
        check_id="BR-02",
        category="Backup & Recovery",
        severity="high",
        passed=len(exposed_db) == 0,
        description=(
            "No database files are publicly downloadable"
            if not exposed_db
            else f"Database file(s) accessible: {', '.join(exposed_db)}"
        ),
        remediation=(
            "Never store database files in the web-accessible directory. "
            "Move them outside the document root and restrict file permissions."
        ),
    ))

    # ── BR-03: Version control artifacts ─────────────────────────────────────
    vcs_paths = [
        ("/.git/config", "Git config"),
        ("/.git/HEAD", "Git HEAD"),
        ("/.svn/entries", "SVN entries"),
        ("/.hg/store", "Mercurial store"),
    ]
    exposed_vcs: List[str] = []
    for path, label in vcs_paths:
        r = safe_get(f"{base}{path}", allow_redirects=False)
        if r is not None and r.status_code == 200 and len(r.text) > 5:
            exposed_vcs.append(f"{path} ({label})")

    findings.append(finding(
        check_id="BR-03",
        category="Backup & Recovery",
        severity="high",
        passed=len(exposed_vcs) == 0,
        description=(
            "No version control artifacts are publicly accessible"
            if not exposed_vcs
            else f"VCS artifact(s) exposed: {', '.join(exposed_vcs)}"
        ),
        remediation=(
            "Block access to .git, .svn, and .hg directories. These expose "
            "full source code history including potential credentials."
        ),
    ))

    return findings
