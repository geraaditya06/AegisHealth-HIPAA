"""
scan_service.py — Persistence and querying for scans, findings, and history.

All SQLite access related to scans lives here so route handlers and the
background queue never hand-write SQL. This keeps the data model in one place
and makes the scan lifecycle easy to reason about and test.

Scan status values
-------------------
``queued`` → ``running`` → (``completed`` | ``failed`` | ``cancelled``)

The legacy synchronous path historically wrote ``status='complete'`` and
``'running'``; read helpers treat both ``'complete'`` and ``'completed'`` as
terminal success so historical rows render correctly.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from db import get_connection, parse_json_field, rows_to_dicts
from core.logging_config import get_logger

logger = get_logger("scan_service")

# Statuses considered a successful, finished scan.
SUCCESS_STATUSES: Tuple[str, ...] = ("completed", "complete")
TERMINAL_STATUSES: Tuple[str, ...] = SUCCESS_STATUSES + ("failed", "cancelled")

_SORT_COLUMNS = {
    "date": "created_at",
    "score": "score",
    "status": "status",
    # Severity sort approximates risk: lower score == higher severity exposure.
    "severity": "score",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Lifecycle: create / progress / finalize ──────────────────────────────────

def create_scan(
    user_id: int,
    url: str,
    *,
    source: str = "sync",
    status: str = "queued",
    project_id: Optional[int] = None,
    max_attempts: int = 1,
) -> int:
    """Insert a new scan row and return its id."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO scans (user_id, url, status, source, project_id,
                               max_attempts, progress, phase, phase_message)
            VALUES (?, ?, ?, ?, ?, ?, 0, 'queued', 'Scan queued')
            """,
            (user_id, url, status, source, project_id, max_attempts),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def mark_running(scan_id: int) -> None:
    """Transition a scan to running and stamp the start time."""
    conn = get_connection()
    try:
        conn.execute(
            """
            UPDATE scans
            SET status='running', progress=COALESCE(NULLIF(progress,0),5),
                phase='crawler', phase_message='Starting scan…',
                started_at=?, error=NULL
            WHERE id=?
            """,
            (_utc_now_iso(), scan_id),
        )
        conn.commit()
    finally:
        conn.close()


def update_progress(
    scan_id: int,
    progress: int,
    phase: str,
    message: str,
    eta: Optional[str] = None,
) -> None:
    """Persist incremental progress so WebSocket clients can stream it."""
    conn = get_connection()
    try:
        conn.execute(
            """
            UPDATE scans
            SET progress=?, phase=?, phase_message=?, eta=COALESCE(?, eta)
            WHERE id=?
            """,
            (int(progress), phase, message, eta, scan_id),
        )
        conn.commit()
    finally:
        conn.close()


def increment_attempt(scan_id: int) -> int:
    """Increment and return the attempt counter for retry accounting."""
    conn = get_connection()
    try:
        conn.execute("UPDATE scans SET attempts = attempts + 1 WHERE id=?", (scan_id,))
        conn.commit()
        row = conn.execute("SELECT attempts FROM scans WHERE id=?", (scan_id,)).fetchone()
        return int(row["attempts"]) if row else 0
    finally:
        conn.close()


def save_results(scan_id: int, result: Dict[str, Any]) -> None:
    """Persist findings + scores and mark the scan completed."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        # Replace any prior findings (relevant on retry).
        cur.execute("DELETE FROM scan_findings WHERE scan_id=?", (scan_id,))
        for f in result.get("findings", []):
            cur.execute(
                """
                INSERT INTO scan_findings
                    (scan_id, check_id, category, severity, passed, description, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    f.get("check_id"),
                    f.get("category"),
                    f.get("severity"),
                    int(bool(f.get("passed"))),
                    f.get("description"),
                    f.get("remediation"),
                ),
            )

        started = cur.execute(
            "SELECT started_at FROM scans WHERE id=?", (scan_id,)
        ).fetchone()
        duration_ms = _duration_ms(started["started_at"] if started else None)

        cur.execute(
            """
            UPDATE scans
            SET score=?, rating=?, status='completed', progress=100,
                phase='report', phase_message='Scan complete',
                category_scores=?, severity_counts=?, report_path=?,
                finished_at=?, duration_ms=?, error=NULL
            WHERE id=?
            """,
            (
                result.get("score"),
                result.get("rating"),
                json.dumps(result.get("score_breakdown")),
                json.dumps(result.get("severity_counts")),
                result.get("report_path"),
                _utc_now_iso(),
                duration_ms,
                scan_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def mark_failed(scan_id: int, error: str) -> None:
    conn = get_connection()
    try:
        conn.execute(
            """
            UPDATE scans
            SET status='failed', phase='failed', phase_message='Scan failed',
                error=?, finished_at=?
            WHERE id=?
            """,
            (str(error)[:500], _utc_now_iso(), scan_id),
        )
        conn.commit()
    finally:
        conn.close()


def mark_cancelled(scan_id: int) -> None:
    conn = get_connection()
    try:
        conn.execute(
            """
            UPDATE scans
            SET status='cancelled', phase='cancelled',
                phase_message='Scan cancelled', finished_at=?
            WHERE id=?
            """,
            (_utc_now_iso(), scan_id),
        )
        conn.commit()
    finally:
        conn.close()


def reset_for_retry(scan_id: int) -> None:
    """Reset progress/state so a failed scan can be re-run."""
    conn = get_connection()
    try:
        conn.execute(
            """
            UPDATE scans
            SET status='queued', progress=0, phase='queued',
                phase_message='Re-queued for retry', error=NULL,
                started_at=NULL, finished_at=NULL
            WHERE id=?
            """,
            (scan_id,),
        )
        conn.commit()
    finally:
        conn.close()


def _duration_ms(started_at_iso: Optional[str]) -> Optional[int]:
    if not started_at_iso:
        return None
    try:
        started = datetime.fromisoformat(started_at_iso)
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - started
        return int(delta.total_seconds() * 1000)
    except (ValueError, TypeError):
        return None


# ── Read helpers ──────────────────────────────────────────────────────────────

def get_scan_owner(scan_id: int) -> Optional[int]:
    """Return the owning user id for a scan, or None if it doesn't exist."""
    conn = get_connection()
    try:
        row = conn.execute("SELECT user_id FROM scans WHERE id=?", (scan_id,)).fetchone()
        return int(row["user_id"]) if row else None
    finally:
        conn.close()


def get_scan_status(scan_id: int) -> Optional[Dict[str, Any]]:
    """Return a lightweight progress snapshot (used by the WebSocket stream)."""
    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT id, status, progress, phase, phase_message, eta, score, rating, error
            FROM scans WHERE id=?
            """,
            (scan_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_scan_detail(scan_id: int, user_id: int) -> Optional[Dict[str, Any]]:
    """Return a full scan record (with findings + score breakdown) for an owner."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, user_id)
        ).fetchone()
        if not row:
            return None
        scan = dict(row)
        scan["category_scores"] = parse_json_field(scan.get("category_scores"))
        scan["severity_counts"] = parse_json_field(scan.get("severity_counts"))

        findings = rows_to_dicts(
            conn.execute(
                """
                SELECT check_id, category, severity, passed, description, remediation
                FROM scan_findings WHERE scan_id=?
                """,
                (scan_id,),
            ).fetchall()
        )
        for f in findings:
            f["passed"] = bool(f["passed"])
        scan["findings"] = findings
        return scan
    finally:
        conn.close()


def list_scans(
    user_id: int,
    *,
    query: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    sort_by: str = "date",
    order: str = "desc",
    page: int = 1,
    page_size: int = 10,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> Dict[str, Any]:
    """Search, filter, sort, and paginate a user's scan history.

    Returns ``{items, total, page, page_size, pages}``.
    """
    page = max(1, int(page))
    page_size = max(1, min(100, int(page_size)))
    offset = (page - 1) * page_size

    where = ["user_id = ?"]
    params: List[Any] = [user_id]

    if query:
        where.append("url LIKE ?")
        params.append(f"%{query}%")

    if status:
        if status in SUCCESS_STATUSES:
            where.append("status IN ('completed', 'complete')")
        else:
            where.append("status = ?")
            params.append(status)

    if date_from:
        where.append("created_at >= ?")
        params.append(date_from)
    if date_to:
        where.append("created_at <= ?")
        params.append(date_to)

    # Severity filter: scans whose worst failed finding matches the level.
    if severity:
        sev_map = {
            "critical": ("critical", "high"),
            "warning": ("warning", "medium"),
            "good": ("low", "good"),
        }
        sevs = sev_map.get(severity.lower())
        if sevs:
            placeholders = ", ".join("?" for _ in sevs)
            where.append(
                f"id IN (SELECT scan_id FROM scan_findings "
                f"WHERE passed=0 AND lower(severity) IN ({placeholders}))"
            )
            params.extend(sevs)

    where_clause = " AND ".join(where)
    sort_col = _SORT_COLUMNS.get(sort_by, "created_at")
    sort_dir = "ASC" if str(order).lower() == "asc" else "DESC"

    conn = get_connection()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM scans WHERE {where_clause}", params
        ).fetchone()["c"]

        rows = conn.execute(
            f"""
            SELECT id, url, score, rating, status, progress, phase,
                   created_at, finished_at, duration_ms, project_id
            FROM scans
            WHERE {where_clause}
            ORDER BY {sort_col} {sort_dir}, id {sort_dir}
            LIMIT ? OFFSET ?
            """,
            params + [page_size, offset],
        ).fetchall()

        items = rows_to_dicts(rows)
        return {
            "items": items,
            "total": int(total),
            "page": page,
            "page_size": page_size,
            "pages": (int(total) + page_size - 1) // page_size,
        }
    finally:
        conn.close()
