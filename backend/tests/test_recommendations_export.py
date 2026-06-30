"""Tests for the AI recommendation engine, executive risk analysis, and export."""

from ml.recommendation_engine import (
    enrich_finding,
    enrich_findings,
    hipaa_rule,
    owasp_category,
    effort_class,
)
from ml.risk_analysis import build_executive_risk
from services import export_service
from scanner.scorer import build_score_breakdown


def _f(check_id, category, severity, passed, desc="desc", rem="do x. then y"):
    return {"check_id": check_id, "category": category, "severity": severity,
            "passed": passed, "description": desc, "remediation": rem}


FINDINGS = [
    _f("EN-01", "Encryption", "high", False),
    _f("AC-04", "Access Control", "high", False),
    _f("W-01", "Headers", "warning", False),
    _f("SM-01", "Session", "high", True),
]


# ── Recommendation engine ────────────────────────────────────────────────────

def test_enrich_finding_has_all_required_fields():
    enriched = enrich_finding(FINDINGS[0], total_open_points=13)
    rec = enriched["recommendation"]
    for field in ("explanation", "business_impact", "technical_impact", "hipaa_rule",
                  "owasp_category", "fix_steps", "code_example", "estimated_risk_reduction"):
        assert field in rec
    assert isinstance(rec["fix_steps"], list) and rec["fix_steps"]
    assert rec["estimated_risk_reduction"] > 0


def test_hipaa_and_owasp_mapping():
    assert "164.312(e)(1)" in hipaa_rule("EN-01")
    assert owasp_category("EN-01", "Encryption").startswith("A02")
    assert owasp_category("AC-04", "Access Control").startswith("A01")
    assert owasp_category("IV-02", "Input Validation").startswith("A03")


def test_effort_classification():
    assert effort_class("W-01") == "quick"
    assert effort_class("AC-04") == "long"
    assert effort_class("C-06") == "standard"


def test_risk_reduction_is_contextual_and_zero_for_passed():
    enriched = enrich_findings(FINDINGS)
    by_id = {e["check_id"]: e for e in enriched}
    # Passed finding contributes no risk reduction.
    assert by_id["SM-01"]["recommendation"]["estimated_risk_reduction"] == 0
    # Open high-severity findings carry meaningful reduction.
    assert by_id["EN-01"]["recommendation"]["estimated_risk_reduction"] > 0


def test_code_example_present_for_known_check():
    enriched = enrich_finding(_f("EN-02", "Encryption", "high", False), 5)
    assert enriched["recommendation"]["code_example"]
    assert "Strict-Transport-Security" in enriched["recommendation"]["code_example"]["code"]


# ── Executive risk analysis ──────────────────────────────────────────────────

def test_executive_risk_structure():
    breakdown = build_score_breakdown(FINDINGS)
    risk = build_executive_risk(FINDINGS, breakdown)
    for key in ("overall_risk", "business_risk", "technical_risk", "compliance_risk",
                "top_10_priorities", "quick_wins", "long_term_improvements", "summary"):
        assert key in risk
    assert risk["overall_risk"]["level"] in ("Critical", "High", "Medium", "Low")
    assert len(risk["top_10_priorities"]) <= 10
    # AC-04 (MFA) should be classified as a long-term improvement.
    assert any(p["check_id"] == "AC-04" for p in risk["long_term_improvements"])
    # W-01 (header) should be a quick win.
    assert any(p["check_id"] == "W-01" for p in risk["quick_wins"])


# ── Export ───────────────────────────────────────────────────────────────────

def test_csv_export_contains_enrichment_columns():
    enriched = enrich_findings(FINDINGS)
    csv_bytes = export_service.to_csv(enriched)
    text = csv_bytes.decode("utf-8")
    assert "hipaa_rule" in text and "owasp_category" in text and "estimated_risk_reduction" in text
    assert "EN-01" in text


def test_json_export_roundtrip():
    import json
    payload = {"findings": enrich_findings(FINDINGS), "score": 40}
    data = json.loads(export_service.to_json(payload))
    assert data["score"] == 40
    assert data["findings"][0]["recommendation"]["hipaa_rule"]


# ── API integration ──────────────────────────────────────────────────────────

def test_scan_export_endpoints(client, auth, monkeypatch):
    """Queue a stubbed scan, then export it as json and csv."""
    import time
    from services import scan_queue as sq

    def fake_pipeline(url, progress=None, is_cancelled=None, **_):
        findings = [_f("EN-01", "Encryption", "high", False)]
        return {
            "findings": findings, "score": 30, "rating": "Non-Compliant",
            "score_breakdown": build_score_breakdown(findings),
            "severity_counts": {"critical": 1}, "report_path": None, "crawl_summary": {},
        }

    monkeypatch.setattr(sq, "run_pipeline", fake_pipeline)
    sid = client.post("/api/scan/queue", json={"url": "https://exp.example.com"}, headers=auth["headers"]).json()["scan_id"]

    for _ in range(50):
        st = client.get(f"/api/scan/{sid}", headers=auth["headers"]).json()["status"]
        if st in ("completed", "complete"):
            break
        time.sleep(0.1)

    # JSON export
    rj = client.get(f"/api/scan/{sid}/export", params={"format": "json"}, headers=auth["headers"])
    assert rj.status_code == 200
    assert "application/json" in rj.headers["content-type"]
    assert "risk_analysis" in rj.json()

    # CSV export
    rc = client.get(f"/api/scan/{sid}/export", params={"format": "csv"}, headers=auth["headers"])
    assert rc.status_code == 200
    assert "EN-01" in rc.text

    # Detail enrich returns recommendations + risk analysis
    detail = client.get(f"/api/scan/{sid}", params={"enrich": "true"}, headers=auth["headers"]).json()
    assert "risk_analysis" in detail
    assert detail["findings"][0]["recommendation"]["estimated_risk_reduction"] >= 0


def test_unsupported_export_format(client, auth, monkeypatch):
    from services import scan_queue as sq

    def fake_pipeline(url, progress=None, is_cancelled=None, **_):
        f = [_f("EN-01", "Encryption", "high", False)]
        return {"findings": f, "score": 30, "rating": "Non-Compliant",
                "score_breakdown": build_score_breakdown(f), "severity_counts": {}, "report_path": None, "crawl_summary": {}}

    monkeypatch.setattr(sq, "run_pipeline", fake_pipeline)
    import time
    sid = client.post("/api/scan/queue", json={"url": "https://fmt.example.com"}, headers=auth["headers"]).json()["scan_id"]
    for _ in range(50):
        if client.get(f"/api/scan/{sid}", headers=auth["headers"]).json()["status"] in ("completed", "complete"):
            break
        time.sleep(0.1)
    res = client.get(f"/api/scan/{sid}/export", params={"format": "xml"}, headers=auth["headers"])
    assert res.status_code == 400
