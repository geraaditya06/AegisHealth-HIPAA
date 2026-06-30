import json
import os
import sqlite3
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE_DIR / "aegishealth.db"


def _resolve_sqlite_path() -> Path:
    """Resolve the SQLite file path from DATABASE_URL.

    Relative paths are resolved against the backend directory (BASE_DIR) rather
    than the process working directory, so the app always uses the *same*
    database regardless of where ``uvicorn`` is launched from. (A CWD-relative
    path like ``sqlite:///./aegishealth.db`` would otherwise silently point at a
    different, empty database when started from another folder — making history
    and the dashboard appear empty.)
    """
    database_url = os.getenv("DATABASE_URL", "").strip()

    raw = ""
    if database_url.startswith("sqlite:///"):
        raw = database_url.replace("sqlite:///", "", 1)
    elif database_url:
        raw = database_url

    if not raw:
        return DEFAULT_DB_PATH

    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = (BASE_DIR / candidate).resolve()
    else:
        candidate = candidate.resolve()
    return candidate


def get_connection():
    db_path = _resolve_sqlite_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    # A generous busy timeout lets concurrent background scan workers wait for
    # write locks instead of immediately failing with "database is locked".
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def rows_to_dicts(rows):
    return [dict(row) for row in rows]


def parse_json_field(value):
    if not value:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return value


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'developer',
            auth_provider TEXT DEFAULT 'password',
            google_sub TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            url TEXT NOT NULL,
            score INTEGER,
            rating TEXT,
            status TEXT DEFAULT 'running',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            check_id TEXT,
            category TEXT,
            severity TEXT,
            passed INTEGER,
            description TEXT,
            remediation TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            repo_url TEXT,
            branch TEXT,
            status TEXT DEFAULT 'running',
            test_results TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            action TEXT,
            resource TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    existing_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(users)").fetchall()
    }
    if "auth_provider" not in existing_columns:
        cur.execute("ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'password'")
    if "google_sub" not in existing_columns:
        cur.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")

    conn.commit()

    # Apply additive enterprise-feature migrations (new columns/tables/indexes).
    # Imported lazily to avoid a circular import at module load time.
    try:
        from migrations import run_migrations

        run_migrations(conn)
    except Exception as exc:  # pragma: no cover - defensive, never block startup
        import logging

        logging.getLogger("aegis.db").error("Migration step failed: %s", exc)

    cur.close()
    conn.close()
