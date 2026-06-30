"""
Regression tests for live data synchronization (Phases 2-4, 10).

Proves that once a scan completes, the dashboard aggregation, charts, recent
history and the searchable history list all reflect it. These are the exact
endpoints the frontend re-fetches on scan events / focus / poll, so green here
means the UI will update without a manual refresh.
"""

import time

import pytest

from scanner.scorer import build_score_breakdown, count_by_severity


def _fake_pipeline_factory(score, findings):
    def fake_pipeline(url, progress=None, is_cancelled=None, **_):
        if progress:
            progress("crawler", 25, "crawl")
            progress("scanner", 75, "scan")
            progress("report", 100, "done")
        return {
            "findings": findings,
            "score": score,
            "rating": "Non-Compliant" if score < 60 else "Compliant",
            "score_breakdown": build_score_breakdown(findings),
            "severity_counts": count_by_severity(findings),
            "report_path": None,
            "crawl_summary": {},
        }
    return fake_pipeline


def _run_completed_scan(client, headers, monkeypatch, url, score, findings):
    from services import scan_queue as sq
    monkeypatch.setattr(sq, "run_pipeline", _fake_pipeline_factory(score, findings))
    scan_id = client.post("/api/scan/queue", json={"url": url}, headers=headers).json()["scan_id"]
    for _ in range(50):
        st = client.get(f"/api/scan/{scan_id}/status", headers=headers).json()["status"]
        if st in ("completed", "complete", "failed", "cancelled"):
            break
        time.sleep(0.1)
    return scan_id


def test_dashboard_reflects_completed_scan(client, auth, monkeypatch):
    headers = auth["headers"]

    # Baseline: a brand-new user has an empty dashboard.
    before = client.get("/api/dashboard", headers=headers).json()
    assert before["cards"]["scans_today"] == 0
    assert before["cards"]["compliance_score"] == 0

    findings = [
        {"check_id": "EN-01", "category": "Encryption", "severity": "high",
         "passed": False, "description": "no https", "remediation": "use https"},
        {"check_id": "AC-01", "category": "Access Control", "severity": "high",
         "passed": True, "description": "ok", "remediation": "-"},
    ]
    _run_completed_scan(client, headers, monkeypatch, "https://sync.example.com", 30, findings)

    after = client.get("/api/dashboard", headers=headers).json()
    # Cards updated.
    assert after["cards"]["scans_today"] >= 1
    assert after["cards"]["compliance_score"] == 30
    assert after["cards"]["average_risk"] == 70
    assert after["cards"]["critical_findings"] >= 1

    # Charts updated with live data (no placeholders).
    charts = after["charts"]
    assert len(charts["compliance_trend"]) >= 1
    assert any(d["name"] == "Critical" and d["value"] >= 1 for d in charts["severity_distribution"])
    assert any(v["check_id"] == "EN-01" for v in charts["top_vulnerabilities"])
    enc = next((c for c in charts["category_scores"] if c["name"] == "Encryption"), None)
    assert enc is not None and enc["value"] == 0  # the single Encryption check failed


def test_history_endpoints_reflect_completed_scan(client, auth, monkeypatch):
    headers = auth["headers"]
    findings = [
        {"check_id": "C-04", "category": "Auth", "severity": "critical",
         "passed": False, "description": "no mfa", "remediation": "add mfa"},
    ]
    scan_id = _run_completed_scan(client, headers, monkeypatch, "https://hist.example.com", 40, findings)

    # Recent-history endpoint (dashboard 'Recent Scans' table source).
    recent = client.get("/api/scan/history", headers=headers).json()["scans"]
    assert any(s["id"] == scan_id for s in recent)

    # Paginated/searchable history list (Scan History page source).
    listed = client.get("/api/scan/list", params={"q": "hist.example.com"}, headers=headers).json()
    assert listed["total"] >= 1
    row = next(s for s in listed["items"] if s["id"] == scan_id)
    assert row["status"] in ("completed", "complete")
    assert row["score"] == 40

    # Status filter works (filtering contract).
    completed_only = client.get("/api/scan/list", params={"status": "completed"}, headers=headers).json()
    assert all(s["status"] in ("completed", "complete") for s in completed_only["items"])
