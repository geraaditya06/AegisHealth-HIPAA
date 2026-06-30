"""Unit tests for the multi-category scoring engine (scanner.scorer)."""

from scanner.scorer import (
    SCORE_CATEGORIES,
    build_score_breakdown,
    calculate_category_scores,
    calculate_score,
    count_by_severity,
    map_to_score_category,
)


def _finding(check_id, category, severity, passed):
    return {
        "check_id": check_id,
        "category": category,
        "severity": severity,
        "passed": passed,
        "description": f"{check_id} desc",
        "remediation": "fix it",
    }


def test_category_mapping_folds_raw_categories():
    assert map_to_score_category("SSL") == "Encryption"
    assert map_to_score_category("Auth") == "Authentication"
    assert map_to_score_category("Session") == "Session Security"
    assert map_to_score_category("Data") == "PHI Protection"
    # Unknown categories fall back to Infrastructure (no finding is lost).
    assert map_to_score_category("Totally Unknown") == "Infrastructure"


def test_legacy_calculate_score_unchanged_contract():
    findings = [_finding("EN-01", "Encryption", "high", True)]
    score, rating = calculate_score(findings)
    assert score == 100
    assert rating == "Compliant"


def test_category_scores_explain_deductions():
    findings = [
        _finding("EN-01", "Encryption", "high", False),   # -5
        _finding("EN-02", "Encryption", "high", True),
        _finding("AC-01", "Access Control", "high", True),
    ]
    cats = calculate_category_scores(findings)
    assert "Encryption" in cats
    enc = cats["Encryption"]
    assert enc["total"] == 2 and enc["passed"] == 1 and enc["failed"] == 1
    # One of two equally-weighted checks failed -> 50.
    assert enc["score"] == 50
    assert enc["deductions"][0]["check_id"] == "EN-01"
    assert enc["deductions"][0]["points"] == 5
    # Access Control fully passed -> 100.
    assert cats["Access Control"]["score"] == 100


def test_build_score_breakdown_shape():
    findings = [_finding("C-04", "Auth", "critical", False)]
    breakdown = build_score_breakdown(findings)
    assert "overall" in breakdown and "categories" in breakdown
    assert "score" in breakdown["overall"] and "rating" in breakdown["overall"]
    assert "Authentication" in breakdown["categories"]


def test_count_by_severity_buckets():
    findings = [
        _finding("A", "Auth", "critical", False),
        _finding("B", "Auth", "high", False),
        _finding("C", "Headers", "medium", False),
        _finding("D", "Trust", "low", True),
    ]
    counts = count_by_severity(findings)
    assert counts["critical"] == 2   # critical + high
    assert counts["warning"] == 1    # medium
    assert counts["passed"] == 1
    assert counts["total"] == 4


def test_score_categories_constant_is_complete():
    assert "PHI Protection" in SCORE_CATEGORIES
    assert "API Security" in SCORE_CATEGORIES
    assert len(SCORE_CATEGORIES) == 7
