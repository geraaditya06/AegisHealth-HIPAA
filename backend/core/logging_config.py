"""
logging_config.py — Idempotent logging configuration for the backend.

Calling :func:`configure_logging` once at application startup installs a
consistent console formatter for the root ``aegis`` logger namespace. All
backend modules obtain their logger via :func:`get_logger`, which guarantees
the configuration has been applied.

The function is safe to call multiple times (e.g. from tests and from the app
lifespan) — handlers are only attached once.
"""

from __future__ import annotations

import logging
import sys

from core.config import settings

_CONFIGURED = False

_LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def configure_logging(level: str | None = None) -> None:
    """Attach a single stream handler to the ``aegis`` logger namespace.

    Parameters
    ----------
    level:
        Optional override for the log level. Defaults to ``settings.log_level``.
    """
    global _CONFIGURED

    resolved_level = (level or settings.log_level or "INFO").upper()
    root = logging.getLogger("aegis")
    root.setLevel(resolved_level)

    if not _CONFIGURED:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
        root.addHandler(handler)
        # Prevent duplicate emission via the Python root logger.
        root.propagate = False
        _CONFIGURED = True

    if settings.is_secret_insecure:
        root.warning(
            "SECRET_KEY is using an insecure default — set a strong SECRET_KEY "
            "in the environment before deploying to production."
        )


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger, ensuring logging is configured.

    Example
    -------
    >>> log = get_logger("scan_queue")   # -> logger "aegis.scan_queue"
    """
    if not _CONFIGURED:
        configure_logging()
    return logging.getLogger(f"aegis.{name}")
