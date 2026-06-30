"""Unit tests for the scan persistence/query service."""

import pytest

from db import get_connection, init_db
from services import scan_service


@pytest.fixture(scope="module", autouse=True)
def _init():
    init_db()
    # Ensure a user exists to satisfy the foreign key.
    conn = get_connection()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users (id, email, password_hash) "
            "VALUES (9001, 'svc@test.com', 'x')"
        )
        conn.commit()
    finally:
        conn.close()


def _finding(cid, cat, sev, passed):
    return {"check_id": cid, "category": cat, "severity": sev, "passed": passed,
            "description": "d", "remediation": "r"}


def test_scan_lifecycle_and_detail():
    sid = scan_service.create_scan(9001, "https://svc.example.com", source="queue")
    assert scan_service.get_scan_owner(sid) == 9001

    scan_service.mark_running(sid)
    snap = scan_service.get_scan_status(sid)
    assert snap["status"] == "running"

    scan_service.update_progress(sid, 60, "scanner", "halfway")
    assert scan_service.get_scan_status(sid)["progress"] == 60

    findings = [_finding("EN-01", "Encryption", "high", False)]
    from scanner.scorer import build_score_breakdown, count_by_severity
    scan_service.save_results(sid, {
        "findings": findings, "score": 30, "rating": "Non-Compliant",
        "score_breakdown": build_score_breakdown(findings),
        "severity_counts": count_by_severity(findings), "report_path": None,
    })

    detail = scan_service.get_scan_detail(sid, 9001)
    assert detail["status"] == "completed"
    assert detail["score"] == 30
    assert len(detail["findings"]) == 1
    assert detail["category_scores"]["categories"]["Encryption"]["score"] == 0


def test_list_filters_and_pagination():
    # Create a couple of scans to exercise filters.
    for _ in range(3):
        scan_service.create_scan(9001, "https://filtertest.com", source="queue")

    res = scan_service.list_scans(9001, query="filtertest", page=1, page_size=2)
    assert res["page_size"] == 2
    assert res["total"] >= 3
    assert len(res["items"]) <= 2
    assert res["pages"] >= 2


def test_retry_reset():
    sid = scan_service.create_scan(9001, "https://retry.com", source="queue")
    scan_service.mark_failed(sid, "boom")
    assert scan_service.get_scan_status(sid)["status"] == "failed"
    scan_service.reset_for_retry(sid)
    assert scan_service.get_scan_status(sid)["status"] == "queued"
