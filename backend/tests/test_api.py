"""Integration tests for the AegisHealth API (auth, scans, dashboard, etc.)."""

import time

import pytest


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"]


def test_register_and_login(client):
    email = "login_flow@test.com"
    r1 = client.post("/api/auth/register", json={"email": email, "password": "Pw123456!"})
    assert r1.status_code == 200
    r2 = client.post("/api/auth/login", json={"email": email, "password": "Pw123456!"})
    assert r2.status_code == 200
    assert r2.json()["token"]


def test_protected_endpoint_requires_auth(client):
    assert client.get("/api/scan/list").status_code == 422  # missing Authorization header
    bad = client.get("/api/scan/list", headers={"Authorization": "Bearer nonsense"})
    assert bad.status_code == 401


def test_scan_list_pagination_empty(client, auth):
    res = client.get("/api/scan/list", headers=auth["headers"])
    assert res.status_code == 200
    body = res.json()
    assert set(["items", "total", "page", "page_size", "pages"]) <= set(body)


def test_dashboard_shape(client, auth):
    res = client.get("/api/dashboard", headers=auth["headers"])
    assert res.status_code == 200
    body = res.json()
    assert "cards" in body and "charts" in body
    for key in ("compliance_score", "critical_findings", "projects", "scans_today", "average_risk"):
        assert key in body["cards"]
    for key in ("compliance_trend", "severity_distribution", "scan_timeline",
                "top_vulnerabilities", "category_scores"):
        assert key in body["charts"]


def test_audit_records_registration(client, auth):
    res = client.get("/api/audit", headers=auth["headers"])
    assert res.status_code == 200
    actions = [log["action"] for log in res.json()["logs"]]
    assert "register" in actions


def test_notifications_empty_then_count(client, auth):
    res = client.get("/api/notifications", headers=auth["headers"])
    assert res.status_code == 200
    assert res.json()["unread_count"] == 0


def test_logout_records_audit(client, auth):
    res = client.post("/api/auth/logout", headers=auth["headers"])
    assert res.status_code == 200
    logs = client.get("/api/audit", headers=auth["headers"]).json()["logs"]
    assert "logout" in [l["action"] for l in logs]


def test_queue_scan_completes_and_notifies(client, auth, monkeypatch):
    """End-to-end queue flow with a stubbed pipeline (no network)."""
    from services import scan_queue as sq

    def fake_pipeline(url, progress=None, is_cancelled=None, **_):
        if progress:
            progress("crawler", 25, "crawling")
            progress("scanner", 75, "scanning")
            progress("report", 100, "done")
        findings = [{
            "check_id": "C-04", "category": "Auth", "severity": "critical",
            "passed": False, "description": "no mfa", "remediation": "add mfa",
        }]
        from scanner.scorer import build_score_breakdown, count_by_severity
        return {
            "findings": findings,
            "score": 40,
            "rating": "Non-Compliant",
            "score_breakdown": build_score_breakdown(findings),
            "severity_counts": count_by_severity(findings),
            "report_path": None,
            "crawl_summary": {},
        }

    monkeypatch.setattr(sq, "run_pipeline", fake_pipeline)

    res = client.post("/api/scan/queue", json={"url": "https://example.com"}, headers=auth["headers"])
    assert res.status_code == 200
    scan_id = res.json()["scan_id"]
    assert res.json()["status"] == "queued"

    # Poll detail until terminal (worker runs in a background thread).
    status = None
    for _ in range(50):
        detail = client.get(f"/api/scan/{scan_id}", headers=auth["headers"]).json()
        status = detail["status"]
        if status in ("completed", "complete", "failed", "cancelled"):
            break
        time.sleep(0.1)

    assert status in ("completed", "complete")
    assert detail["score"] == 40
    assert len(detail["findings"]) == 1
    assert detail["category_scores"]["categories"]["Authentication"]["score"] == 0

    # Completion produced notifications (scan complete + critical finding).
    # The worker writes notifications immediately after flipping status to
    # 'completed', so poll briefly to avoid a check-too-soon race.
    notifs = None
    for _ in range(30):
        notifs = client.get("/api/notifications", headers=auth["headers"]).json()
        if notifs["unread_count"] >= 1:
            break
        time.sleep(0.1)
    assert notifs["unread_count"] >= 1
    types = [n["type"] for n in notifs["notifications"]]
    assert "scan_complete" in types
    assert "critical_finding" in types

    # The completed scan appears in the searchable, filterable history.
    listed = client.get(
        "/api/scan/list",
        params={"status": "completed", "q": "example.com", "sort_by": "score"},
        headers=auth["headers"],
    ).json()
    assert listed["total"] >= 1
    assert any(item["id"] == scan_id for item in listed["items"])


def test_cancel_unknown_scan_404(client, auth):
    res = client.post("/api/scan/999999/cancel", headers=auth["headers"])
    assert res.status_code == 404
