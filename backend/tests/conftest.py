"""
conftest.py — Shared pytest fixtures.

Points the application at an isolated, throwaway SQLite database so tests never
touch the real ``aegishealth.db``. The DB path is configured *before* the app or
any DB module is imported.
"""

from __future__ import annotations

import os
import pathlib
import uuid

import pytest

# ── Isolate the test database BEFORE importing the app ───────────────────────
_TEST_DB = pathlib.Path(__file__).parent / "_test_aegis.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB.as_posix()}"
os.environ.setdefault("SCAN_WORKERS", "1")
os.environ.setdefault("SECRET_KEY", "test-secret-key")


@pytest.fixture(scope="session", autouse=True)
def _clean_db():
    """Remove any leftover test DB before and after the test session."""
    for suffix in ("", "-wal", "-shm"):
        p = pathlib.Path(str(_TEST_DB) + suffix)
        if p.exists():
            p.unlink()
    yield
    for suffix in ("", "-wal", "-shm"):
        p = pathlib.Path(str(_TEST_DB) + suffix)
        if p.exists():
            try:
                p.unlink()
            except OSError:
                pass


@pytest.fixture(scope="session")
def client():
    """A TestClient with the app lifespan active (DB init + queue start)."""
    from fastapi.testclient import TestClient
    from main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth(client):
    """Register a fresh user and return (headers, token, email)."""
    email = f"user_{uuid.uuid4().hex[:8]}@test.com"
    res = client.post("/api/auth/register", json={"email": email, "password": "Password123!"})
    assert res.status_code == 200, res.text
    token = res.json()["token"]
    return {
        "headers": {"Authorization": f"Bearer {token}"},
        "token": token,
        "email": email,
    }
