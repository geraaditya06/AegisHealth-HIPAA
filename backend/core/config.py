"""
config.py — Centralised application settings.

All configuration is sourced from environment variables (loaded from the
backend ``.env`` file via python-dotenv) with safe production-minded defaults.
A single, importable :data:`settings` instance is exposed so the rest of the
codebase never reads ``os.getenv`` directly — this keeps configuration in one
place (Single Responsibility) and makes the app easy to test and reconfigure.

Backward compatibility
-----------------------
The original code read ``SECRET_KEY``, ``ALGORITHM`` and
``ACCESS_TOKEN_EXPIRE_MINUTES`` directly. Those env vars are still honoured here,
so existing ``.env`` files keep working unchanged.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List

from dotenv import load_dotenv

load_dotenv()


def _get_int(name: str, default: int) -> int:
    """Read an integer env var, falling back to *default* on any error."""
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _get_list(name: str, default: List[str]) -> List[str]:
    """Read a comma-separated env var into a list of trimmed strings."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    """Immutable settings snapshot for the running process."""

    # ── Security / JWT ────────────────────────────────────────────────────
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", "secret"))
    algorithm: str = field(default_factory=lambda: os.getenv("ALGORITHM", "HS256"))
    access_token_expire_minutes: int = field(
        default_factory=lambda: _get_int("ACCESS_TOKEN_EXPIRE_MINUTES", 1440)
    )

    # ── Integrations ──────────────────────────────────────────────────────
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    google_client_id: str = field(default_factory=lambda: os.getenv("GOOGLE_CLIENT_ID", ""))

    # ── CORS ──────────────────────────────────────────────────────────────
    # Defaults preserve the original hard-coded Vite dev origin while allowing
    # deployments to override via the CORS_ORIGINS env var.
    cors_origins: List[str] = field(
        default_factory=lambda: _get_list(
            "CORS_ORIGINS",
            ["http://localhost:5173", "http://127.0.0.1:5173"],
        )
    )

    # ── Background scan queue ─────────────────────────────────────────────
    scan_workers: int = field(default_factory=lambda: _get_int("SCAN_WORKERS", 3))
    scan_max_retries: int = field(default_factory=lambda: _get_int("SCAN_MAX_RETRIES", 1))
    # A guard so a single hung scan cannot block a worker forever.
    scan_timeout_seconds: int = field(
        default_factory=lambda: _get_int("SCAN_TIMEOUT_SECONDS", 600)
    )

    # ── Logging ───────────────────────────────────────────────────────────
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    @property
    def is_secret_insecure(self) -> bool:
        """True when the JWT secret is still a known placeholder value."""
        return self.secret_key in ("secret", "change-me-in-production", "")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached, process-wide :class:`Settings` instance."""
    return Settings()


# Convenience module-level singleton.
settings = get_settings()
