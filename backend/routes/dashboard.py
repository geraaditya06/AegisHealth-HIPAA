"""
dashboard.py — Enterprise dashboard API.

    GET /api/dashboard   Aggregated cards + chart series for the current user.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from core.logging_config import get_logger
from core.security import CurrentUser, get_current_user
from services import dashboard as dashboard_service

logger = get_logger("dashboard_route")

router = APIRouter()


@router.get("", summary="Dashboard metrics (cards + charts)")
def get_dashboard(user: CurrentUser = Depends(get_current_user)):
    """Return compliance cards and chart data for the dashboard."""
    return dashboard_service.get_dashboard(user.id)
