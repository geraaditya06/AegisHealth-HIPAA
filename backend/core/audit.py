"""
audit.py — Enhanced audit-trail recording.

Centralises audit logging so every tracked action is recorded with consistent
context: timestamp (DB default), user, organization, IP address, and browser
(user-agent). This supports the SaaS requirement to track logins, logouts,
project/scan creation, settings changes, and exports.

The original ``routes/auth.py`` defined a local ``log_action(user_id, action,
resource, ip)``. This module supersedes it with a request-aware helper while
remaining backward compatible: :func:`record_action` accepts either a FastAPI
``Request`` (to auto-extract IP + user-agent) or explicit values.

Action constants are provided to avoid magic strings.
"""

from __future__ import annotations

from typing import Optional

from db import get_connection
from core.logging_config import get_logger

logger = get_logger("audit")

# ── Tracked action constants ─────────────────────────────────────────────────
ACTION_LOGIN = "login"
ACTION_LOGOUT = "logout"
ACTION_REGISTER = "register"
ACTION_GOOGLE_LOGIN = "google_login"
ACTION_PROJECT_CREATE = "project_create"
ACTION_SCAN_CREATE = "scan_create"
ACTION_SETTINGS_CHANGE = "settings_change"
ACTION_EXPORT = "export"


def _client_ip(request) -> Optional[str]:
    if request is None:
        return None
    # Honour reverse-proxy headers, then fall back to the socket peer.
    forwarded = request.headers.get("x-forwarded-for") if hasattr(request, "headers") else None
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = getattr(request, "client", None)
    return getattr(client, "host", None) if client else None


def _user_agent(request) -> Optional[str]:
    if request is None or not hasattr(request, "headers"):
        return None
    return request.headers.get("user-agent")


def record_action(
    user_id: Optional[int],
    action: str,
    resource: str,
    *,
    request=None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    organization: Optional[str] = None,
) -> None:
    """Insert an audit-log entry.

    Parameters
    ----------
    user_id:
        The acting user (may be None for anonymous/system events).
    action:
        One of the ``ACTION_*`` constants (free-form strings are accepted).
    resource:
        The affected resource (e.g. ``"users"``, ``"scans"``, a URL, an id).
    request:
        Optional FastAPI ``Request`` used to auto-extract IP + user-agent.
    ip_address / user_agent / organization:
        Explicit overrides (take precedence over values from ``request``).
    """
    ip = ip_address or _client_ip(request)
    ua = user_agent or _user_agent(request)

    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO audit_logs
                (user_id, action, resource, ip_address, user_agent, organization)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, action, resource, ip, ua, organization),
        )
        conn.commit()
    except Exception as exc:  # pragma: no cover - auditing must never break a request
        logger.error("Failed to record audit action '%s': %s", action, exc)
    finally:
        conn.close()
