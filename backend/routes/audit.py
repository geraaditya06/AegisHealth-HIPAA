"""
audit.py — Audit-trail API.

    GET /api/audit   Paginated audit log for the authenticated user, including
                     timestamp, user, organization, IP address and browser.

Backward compatible: the original response key ``logs`` is preserved; the rows
now additionally expose ``organization`` and ``user_agent`` (null on older
records).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from core.logging_config import get_logger
from core.security import CurrentUser, get_current_user
from db import get_connection, rows_to_dicts

logger = get_logger("audit_route")

router = APIRouter()


@router.get("", summary="Audit log (paginated)")
def get_logs(
    user: CurrentUser = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    conn = get_connection()
    try:
        total = conn.execute(
            "SELECT COUNT(*) AS c FROM audit_logs WHERE user_id=?", (user.id,)
        ).fetchone()["c"]
        logs = rows_to_dicts(
            conn.execute(
                """
                SELECT action, resource, ip_address, user_agent, organization, created_at
                FROM audit_logs
                WHERE user_id=?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (user.id, limit, offset),
            ).fetchall()
        )
    finally:
        conn.close()
    return {"logs": logs, "total": int(total), "limit": limit, "offset": offset}
