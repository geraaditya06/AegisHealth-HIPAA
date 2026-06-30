"""
notifications.py — In-app notification service.

Creates and retrieves user notifications for key events:

* ``scan_complete``      — a scan finished successfully.
* ``critical_finding``   — a completed scan contains critical/high issues.
* ``scan_failed``        — a scan failed after exhausting retries.
* ``certificate_expiry`` — an SSL/TLS certificate is expired or near expiry.

Notifications are persisted in the ``notifications`` table and surfaced to the
frontend via the ``/api/notifications`` endpoints (and the notification bell).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from db import get_connection, parse_json_field, rows_to_dicts
from core.logging_config import get_logger

logger = get_logger("notifications")

# Notification type constants (avoid magic strings across the codebase).
TYPE_SCAN_COMPLETE = "scan_complete"
TYPE_CRITICAL_FINDING = "critical_finding"
TYPE_SCAN_FAILED = "scan_failed"
TYPE_CERT_EXPIRY = "certificate_expiry"


def create_notification(
    user_id: int,
    type_: str,
    title: str,
    message: str = "",
    *,
    severity: str = "info",
    link: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> int:
    """Persist a notification and return its id."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO notifications (user_id, type, title, message, severity, link, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                type_,
                title,
                message,
                severity,
                link,
                json.dumps(meta) if meta is not None else None,
            ),
        )
        conn.commit()
        logger.info("notification[%s] -> user %s: %s", type_, user_id, title)
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_notifications(
    user_id: int,
    *,
    unread_only: bool = False,
    limit: int = 30,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Return a user's notifications, newest first."""
    limit = max(1, min(100, int(limit)))
    where = "user_id = ?"
    params: List[Any] = [user_id]
    if unread_only:
        where += " AND is_read = 0"

    conn = get_connection()
    try:
        rows = conn.execute(
            f"""
            SELECT id, type, title, message, severity, is_read, link, meta, created_at
            FROM notifications WHERE {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, int(offset)],
        ).fetchall()
        items = rows_to_dicts(rows)
        for item in items:
            item["is_read"] = bool(item["is_read"])
            item["meta"] = parse_json_field(item.get("meta"))
        return items
    finally:
        conn.close()


def unread_count(user_id: int) -> int:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM notifications WHERE user_id=? AND is_read=0",
            (user_id,),
        ).fetchone()
        return int(row["c"]) if row else 0
    finally:
        conn.close()


def mark_read(user_id: int, notification_id: int) -> bool:
    conn = get_connection()
    try:
        cur = conn.execute(
            "UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?",
            (notification_id, user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def mark_all_read(user_id: int) -> int:
    conn = get_connection()
    try:
        cur = conn.execute(
            "UPDATE notifications SET is_read=1 WHERE user_id=? AND is_read=0",
            (user_id,),
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# ── Event helpers (called by the scan queue) ─────────────────────────────────

def notify_scan_complete(
    user_id: int, scan_id: int, url: str, score: int, rating: str
) -> None:
    create_notification(
        user_id,
        TYPE_SCAN_COMPLETE,
        title="Scan complete",
        message=f"{url} scored {score}/100 ({rating}).",
        severity="success" if score >= 85 else "info",
        link=f"/history?scan={scan_id}",
        meta={"scan_id": scan_id, "score": score, "rating": rating},
    )


def notify_critical_findings(
    user_id: int, scan_id: int, url: str, critical_count: int
) -> None:
    if critical_count <= 0:
        return
    create_notification(
        user_id,
        TYPE_CRITICAL_FINDING,
        title=f"{critical_count} critical finding(s) detected",
        message=f"{url} has {critical_count} critical/high-severity issue(s) needing attention.",
        severity="critical",
        link=f"/history?scan={scan_id}",
        meta={"scan_id": scan_id, "critical_count": critical_count},
    )


def notify_scan_failed(user_id: int, scan_id: int, url: str, error: str) -> None:
    create_notification(
        user_id,
        TYPE_SCAN_FAILED,
        title="Scan failed",
        message=f"The scan for {url} could not be completed: {error}",
        severity="warning",
        link=f"/history?scan={scan_id}",
        meta={"scan_id": scan_id},
    )


def notify_certificate_expiry(
    user_id: int, scan_id: int, url: str, detail: str
) -> None:
    create_notification(
        user_id,
        TYPE_CERT_EXPIRY,
        title="Certificate expiry risk",
        message=f"{url}: {detail}",
        severity="warning",
        link=f"/history?scan={scan_id}",
        meta={"scan_id": scan_id},
    )
