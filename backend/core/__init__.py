"""
core — Cross-cutting infrastructure for the AegisHealth backend.

This package groups foundational, framework-level concerns that are shared
across the application (configuration, logging, security/auth, and audit
logging). It is intentionally dependency-light so it can be imported from
routes, services, and the scanner without creating circular imports.

Modules
-------
config            : Centralised, environment-driven settings.
logging_config    : Idempotent logging setup for the whole backend.
security          : JWT decoding + FastAPI auth dependencies (HTTP and WS).
audit             : Enhanced audit-trail recording (IP + browser + org).
"""
