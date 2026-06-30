"""
notifications.py — In-app notifications API.

    GET  /api/notifications               List notifications (newest first).
    GET  /api/notifications/unread-count  Unread badge count.
    POST /api/notifications/{id}/read     Mark one notification read.
    POST /api/notifications/read-all      Mark all read.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from core.logging_config import get_logger
from core.security import CurrentUser, get_current_user
from services import notifications as notif_service

logger = get_logger("notifications_route")

router = APIRouter()


@router.get("", summary="List notifications")
def list_notifications(
    user: CurrentUser = Depends(get_current_user),
    unread_only: bool = Query(False),
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    items = notif_service.list_notifications(
        user.id, unread_only=unread_only, limit=limit, offset=offset
    )
    return {"notifications": items, "unread_count": notif_service.unread_count(user.id)}


@router.get("/unread-count", summary="Unread notification count")
def unread_count(user: CurrentUser = Depends(get_current_user)):
    return {"unread_count": notif_service.unread_count(user.id)}


@router.post("/{notification_id}/read", summary="Mark a notification as read")
def mark_read(notification_id: int, user: CurrentUser = Depends(get_current_user)):
    if not notif_service.mark_read(user.id, notification_id):
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"status": "ok"}


@router.post("/read-all", summary="Mark all notifications as read")
def mark_all_read(user: CurrentUser = Depends(get_current_user)):
    updated = notif_service.mark_all_read(user.id)
    return {"status": "ok", "updated": updated}
