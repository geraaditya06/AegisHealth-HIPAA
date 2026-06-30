"""
migrations.py — Idempotent, hand-rolled schema migrations for SQLite.

AegisHealth uses raw SQLite (no ORM / Alembic). To evolve the schema for the
enterprise SaaS feature set *without breaking existing data*, this module
applies a series of additive, idempotent migrations:

* New columns are added to existing tables only when absent.
* New tables are created with ``CREATE TABLE IF NOT EXISTS``.
* Indexes are created with ``CREATE INDEX IF NOT EXISTS``.
* WAL journal mode + a busy timeout are enabled to support the concurrent
  background scan workers writing to SQLite.

Every operation is safe to run repeatedly, so :func:`run_migrations` can be
called on every startup. It is invoked automatically from ``db.init_db``.

Design note
-----------
We intentionally keep the original ``status`` values working. The legacy
synchronous scan path writes ``status='complete'``; the new queue writes
``status='completed'``. Read paths treat both as terminal-success (see
``services`` helpers), so no historical row needs rewriting.
"""

from __future__ import annotations

import sqlite3
from typing import Iterable

from core.logging_config import get_logger

logger = get_logger("migrations")


# ── Low-level helpers ────────────────────────────────────────────────────────

def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Return the set of column names for *table* (empty if it doesn't exist)."""
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except sqlite3.Error:
        return set()
    return {row[1] for row in rows}  # row[1] = column name


def _add_column_if_missing(
    conn: sqlite3.Connection, table: str, column: str, ddl: str
) -> bool:
    """Add ``column`` to ``table`` using ``ddl`` if it is not already present.

    Returns True when a column was added. SQLite only allows a constant default
    in ``ALTER TABLE ... ADD COLUMN``, which all callers respect.
    """
    if column in _columns(conn, table):
        return False
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
    logger.info("migration: added column %s.%s", table, column)
    return True


def _exec_all(conn: sqlite3.Connection, statements: Iterable[str]) -> None:
    for stmt in statements:
        conn.execute(stmt)


# ── Migration steps ──────────────────────────────────────────────────────────

def _enable_concurrency_pragmas(conn: sqlite3.Connection) -> None:
    """Enable WAL + a busy timeout so concurrent workers don't hit 'locked'."""
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.Error as exc:  # pragma: no cover - defensive
        logger.warning("Could not enable concurrency pragmas: %s", exc)


def _extend_scans_table(conn: sqlite3.Connection) -> None:
    """Add background-queue, progress, and multi-category scoring columns."""
    extensions = {
        "progress": "progress INTEGER DEFAULT 0",
        "phase": "phase TEXT",
        "phase_message": "phase_message TEXT",
        "eta": "eta TEXT",
        "attempts": "attempts INTEGER DEFAULT 0",
        "max_attempts": "max_attempts INTEGER DEFAULT 1",
        "error": "error TEXT",
        "category_scores": "category_scores TEXT",
        "severity_counts": "severity_counts TEXT",
        "report_path": "report_path TEXT",
        "project_id": "project_id INTEGER",
        "started_at": "started_at TIMESTAMP",
        "finished_at": "finished_at TIMESTAMP",
        "duration_ms": "duration_ms INTEGER",
        "source": "source TEXT DEFAULT 'sync'",
    }
    for column, ddl in extensions.items():
        _add_column_if_missing(conn, "scans", column, ddl)


def _extend_audit_logs_table(conn: sqlite3.Connection) -> None:
    """Add organization + browser (user-agent) context to audit logs."""
    _add_column_if_missing(conn, "audit_logs", "organization", "organization TEXT")
    _add_column_if_missing(conn, "audit_logs", "user_agent", "user_agent TEXT")


def _create_new_tables(conn: sqlite3.Connection) -> None:
    """Create tables introduced by the enterprise feature set."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            name TEXT NOT NULL,
            description TEXT,
            target_url TEXT,
            organization TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT,
            severity TEXT DEFAULT 'info',
            is_read INTEGER DEFAULT 0,
            link TEXT,
            meta TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            key TEXT NOT NULL,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, key)
        )
        """
    )


def _create_indexes(conn: sqlite3.Connection) -> None:
    """Create indexes that keep history/dashboard queries fast."""
    _exec_all(
        conn,
        [
            "CREATE INDEX IF NOT EXISTS idx_scans_user_created "
            "ON scans(user_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
            "CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_notifications_user "
            "ON notifications(user_id, is_read)",
            "CREATE INDEX IF NOT EXISTS idx_audit_user_created "
            "ON audit_logs(user_id, created_at)",
        ],
    )


def run_migrations(conn: sqlite3.Connection) -> None:
    """Apply all idempotent migrations on the given connection.

    Parameters
    ----------
    conn:
        An open SQLite connection. The caller is responsible for committing;
        this function performs the DDL and commits at the end.
    """
    _enable_concurrency_pragmas(conn)
    _extend_scans_table(conn)
    _extend_audit_logs_table(conn)
    _create_new_tables(conn)
    _create_indexes(conn)
    conn.commit()
    logger.info("Database migrations applied successfully")
