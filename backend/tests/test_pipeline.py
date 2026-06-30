"""Unit tests for the scan pipeline (progress + cancellation + scoring).

Network-bound check functions and the crawler are monkeypatched so the test is
fast and hermetic.
"""

import pytest

from scanner import pipeline


@pytest.fixture(autouse=True)
def _stub_scanner(monkeypatch):
    """Replace crawler + checks with deterministic stubs (no network)."""
    monkeypatch.setattr(
        pipeline, "crawl_target",
        lambda url, max_depth=2: {"urls": [url], "api_endpoints": [], "forms": [], "query_params": []},
    )

    def fake_check(url):
        return [{
            "check_id": "EN-01", "category": "Encryption", "severity": "high",
            "passed": False, "description": "no https", "remediation": "use https",
        }]

    monkeypatch.setattr(pipeline, "_ROOT_ONLY_ORIGINAL", [fake_check])
    monkeypatch.setattr(pipeline, "_ROOT_ONLY_HIPAA", [])
    monkeypatch.setattr(pipeline, "_ROOT_ONLY_ADVANCED", [])
    monkeypatch.setattr(pipeline, "_PER_URL_CHECKS", [])
    # Avoid writing a real PDF during the unit test.
    monkeypatch.setattr(pipeline, "generate_report", lambda *a, **k: None)


def test_pipeline_runs_and_reports_progress():
    events = []
    result = pipeline.run_pipeline("https://example.com", progress=lambda p, pct, m: events.append((p, pct)))

    # Findings + scoring produced.
    assert len(result["findings"]) == 1
    assert "score_breakdown" in result
    assert result["score_breakdown"]["categories"]["Encryption"]["score"] == 0

    # Progress spans the phases and reaches 100.
    phases = {p for p, _ in events}
    assert {"crawler", "scanner", "rule_engine", "report"} <= phases
    assert events[-1][1] == 100


def test_pipeline_honours_cancellation():
    with pytest.raises(pipeline.ScanCancelled):
        pipeline.run_pipeline(
            "https://example.com",
            progress=lambda *a: None,
            is_cancelled=lambda: True,
        )
