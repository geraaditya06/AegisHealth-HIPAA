"""
security.py — Shared authentication utilities and FastAPI dependencies.

The original codebase duplicated JWT decoding (``get_user``) across several
route modules. This module centralises that logic (DRY / Single Responsibility)
while remaining 100% backward compatible with the existing token format:

    payload = {"sub": str(user_id), "email": ..., "role": ..., "exp": ...}

It exposes:

* :class:`CurrentUser`         – a lightweight authenticated-principal value object.
* :func:`decode_token`         – verify a JWT and return its payload.
* :func:`get_current_user`     – FastAPI dependency reading the ``Authorization`` header.
* :func:`authenticate_websocket` – auth helper for WebSocket connections (token via query param).

Existing route-level ``get_user`` helpers can keep working untouched; new code
should prefer these dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi import Header, HTTPException, WebSocket, status
from jose import JWTError, jwt

from core.config import settings
from core.logging_config import get_logger

logger = get_logger("security")


@dataclass(frozen=True)
class CurrentUser:
    """Authenticated principal extracted from a verified JWT."""

    id: int
    email: Optional[str] = None
    role: Optional[str] = None


def decode_token(token: str) -> dict:
    """Decode and verify a JWT, returning its payload.

    Raises
    ------
    HTTPException
        401 if the token is missing, malformed, expired, or has no subject.
    """
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication token")

    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError as exc:
        logger.debug("JWT decode failed: %s", exc)
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    if "sub" not in payload:
        raise HTTPException(status_code=401, detail="Invalid token: missing subject")

    return payload


def user_from_payload(payload: dict) -> CurrentUser:
    """Build a :class:`CurrentUser` from a decoded JWT payload."""
    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid token subject") from exc
    return CurrentUser(id=user_id, email=payload.get("email"), role=payload.get("role"))


def get_current_user(authorization: str = Header(...)) -> CurrentUser:
    """FastAPI dependency that resolves the authenticated user.

    Reads the ``Authorization: Bearer <token>`` header, mirroring the behaviour
    of the legacy per-route ``get_user`` helpers but returning richer context.
    """
    payload = decode_token(authorization)
    return user_from_payload(payload)


async def authenticate_websocket(websocket: WebSocket, token: Optional[str]) -> Optional[CurrentUser]:
    """Authenticate a WebSocket using a token supplied as a query parameter.

    Browsers cannot set custom headers on the WebSocket handshake, so the token
    is passed via ``?token=...``. On failure the socket is closed with policy
    violation and ``None`` is returned.
    """
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None
    try:
        payload = decode_token(token)
        return user_from_payload(payload)
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None
