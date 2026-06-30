"""
scorer.py — Weighted HIPAA compliance scorer.

Scoring model
─────────────
Rather than flat point deductions, we bucket findings by severity and
compute a weighted percentage:

  • critical  → 70 % of total score
  • warning   → 20 % of total score
  • good      → 10 % of total score

Within each bucket, every check contributes equally.
Only severities that are actually present in the findings are scored,
so missing buckets do not receive free credit.
"""


def calculate_score(findings: list) -> tuple:
    """
    Parameters
    ----------
    findings : list of finding dicts, each with keys:
        check_id, category, severity, passed, description, remediation

    Returns
    -------
    (score: int, rating: str)
        score  – integer 0–100
        rating – "Compliant" | "Needs Work" | "Non-Compliant"
    """
    WEIGHTS = {
        "critical": 0.70,
        "warning":  0.20,
        "good":     0.10,
    }

    # Map extended severity levels to the three scoring buckets
    SEVERITY_MAP = {
        "critical": "critical",
        "high": "critical",
        "warning": "warning",
        "medium": "warning",
        "low": "good",
        "good": "good",
    }

    # Bucket findings by severity
    buckets = {"critical": [], "warning": [], "good": []}
    for f in findings:
        raw_sev = f.get("severity", "good").lower()
        sev = SEVERITY_MAP.get(raw_sev, "good")
        buckets[sev].append(f)

    active_weights = {
        severity: weight
        for severity, weight in WEIGHTS.items()
        if buckets.get(severity)
    }

    if not active_weights:
        return 0, "Non-Compliant"

    weighted_score = 0.0

    for severity, weight in active_weights.items():
        group = buckets.get(severity, [])

        passed_count = sum(1 for f in group if f.get("passed", False))
        bucket_pct = (passed_count / len(group)) * 100
        weighted_score += weight * bucket_pct

    normalized_score = weighted_score / sum(active_weights.values())
    score = max(0, min(100, round(normalized_score)))

    if score >= 85:
        rating = "Compliant"
    elif score >= 60:
        rating = "Needs Work"
    else:
        rating = "Non-Compliant"

    return score, rating


# ═════════════════════════════════════════════════════════════════════════════
#  Multi-category scoring (enterprise extension)
# ═════════════════════════════════════════════════════════════════════════════
#
# The original calculate_score() above returns a single aggregate score and is
# left untouched for backward compatibility. The functions below add a richer,
# per-category breakdown with explained deductions, without changing any
# existing behaviour.
#
# Findings carry a free-form ``category`` string (e.g. "Encryption", "SSL",
# "Auth", "Session", "API Security", "Access Control", "Data", "Infrastructure",
# "Headers", "DNS", "Storage Exposure", "Monitoring", "Input Validation",
# "Data Integrity", "Audit", "Backup & Recovery", "Third-Party", "Trust",
# "Disclosure"). We fold these raw categories into the eight executive score
# categories requested by the product, plus an Overall score.

from typing import Dict, List, Tuple  # noqa: E402  (intentional late import grouping)

# Severity → deduction weight (higher = more impactful when failing).
_SEVERITY_POINTS: Dict[str, int] = {
    "critical": 5,
    "high": 5,
    "warning": 3,
    "medium": 3,
    "low": 1,
    "good": 1,
}

# The eight executive score categories (Overall is computed separately).
SCORE_CATEGORIES: List[str] = [
    "Encryption",
    "Authentication",
    "Access Control",
    "Session Security",
    "Infrastructure",
    "API Security",
    "PHI Protection",
]

# Map every raw finding ``category`` onto one of the executive categories.
# Anything unmapped falls back to "Infrastructure" so no finding is lost.
_CATEGORY_MAP: Dict[str, str] = {
    # Encryption / transport security
    "encryption": "Encryption",
    "ssl": "Encryption",
    # Authentication
    "auth": "Authentication",
    "authentication": "Authentication",
    # Access control
    "access control": "Access Control",
    # Session security
    "session": "Session Security",
    "session security": "Session Security",
    # API security
    "api security": "API Security",
    # PHI / data protection
    "data": "PHI Protection",
    "phi": "PHI Protection",
    "phi protection": "PHI Protection",
    "data integrity": "PHI Protection",
    # Infrastructure & everything operational
    "infrastructure": "Infrastructure",
    "headers": "Infrastructure",
    "dns": "Infrastructure",
    "disclosure": "Infrastructure",
    "storage exposure": "Infrastructure",
    "monitoring": "Infrastructure",
    "input validation": "Infrastructure",
    "audit": "Infrastructure",
    "backup & recovery": "Infrastructure",
    "third-party": "Infrastructure",
    "trust": "Infrastructure",
}


def map_to_score_category(raw_category: str) -> str:
    """Fold a raw finding category into one of :data:`SCORE_CATEGORIES`."""
    return _CATEGORY_MAP.get((raw_category or "").strip().lower(), "Infrastructure")


def _severity_points(severity: str) -> int:
    return _SEVERITY_POINTS.get((severity or "good").lower(), 1)


def _rating_for(score: int) -> str:
    if score >= 85:
        return "Compliant"
    if score >= 60:
        return "Needs Work"
    return "Non-Compliant"


def calculate_category_scores(findings: List[dict]) -> Dict[str, dict]:
    """Compute a per-category compliance breakdown with explained deductions.

    Each category's score is a severity-weighted pass percentage: every check
    contributes points equal to its severity weight, and failing checks forfeit
    those points. The ``deductions`` list explains exactly which checks cost
    points and how many, so the UI/report can show *why* a category scored low.

    Parameters
    ----------
    findings:
        List of finding dicts (``check_id``, ``category``, ``severity``,
        ``passed``, ``description``, ``remediation``).

    Returns
    -------
    dict
        Mapping of category name → {
            "score": int (0-100),
            "rating": str,
            "total": int, "passed": int, "failed": int,
            "deductions": list of {check_id, severity, points, description},
        }
        Categories with no findings are omitted.
    """
    grouped: Dict[str, List[dict]] = {}
    for f in findings:
        cat = map_to_score_category(f.get("category", ""))
        grouped.setdefault(cat, []).append(f)

    result: Dict[str, dict] = {}
    for category, group in grouped.items():
        total_points = sum(_severity_points(f.get("severity", "good")) for f in group)
        lost_points = 0
        deductions: List[dict] = []
        passed_count = 0

        for f in group:
            points = _severity_points(f.get("severity", "good"))
            if f.get("passed", False):
                passed_count += 1
            else:
                lost_points += points
                deductions.append(
                    {
                        "check_id": f.get("check_id", ""),
                        "severity": f.get("severity", "good"),
                        "points": points,
                        "description": f.get("description", ""),
                    }
                )

        if total_points == 0:
            score = 100
        else:
            score = max(0, min(100, round((total_points - lost_points) / total_points * 100)))

        # Sort deductions by impact (largest first) for readable reports.
        deductions.sort(key=lambda d: d["points"], reverse=True)

        result[category] = {
            "score": score,
            "rating": _rating_for(score),
            "total": len(group),
            "passed": passed_count,
            "failed": len(group) - passed_count,
            "deductions": deductions,
        }

    return result


def build_score_breakdown(findings: List[dict]) -> dict:
    """Return the full scoring payload: overall score + per-category breakdown.

    The overall score reuses :func:`calculate_score` so the headline number
    stays identical to the legacy behaviour the dashboard and history already
    rely on.
    """
    overall_score, overall_rating = calculate_score(findings)
    categories = calculate_category_scores(findings)

    return {
        "overall": {
            "score": overall_score,
            "rating": overall_rating,
        },
        "categories": categories,
    }


def count_by_severity(findings: List[dict]) -> Dict[str, int]:
    """Count *failed* findings bucketed as critical / warning / good.

    Mirrors the buckets used by :func:`calculate_score` so dashboards and the
    scanner UI report consistent numbers.
    """
    buckets = {"critical": 0, "warning": 0, "good": 0, "passed": 0, "total": 0}
    severity_to_bucket = {
        "critical": "critical",
        "high": "critical",
        "warning": "warning",
        "medium": "warning",
        "low": "good",
        "good": "good",
    }
    for f in findings:
        buckets["total"] += 1
        if f.get("passed", False):
            buckets["passed"] += 1
            continue
        bucket = severity_to_bucket.get((f.get("severity", "good")).lower(), "good")
        buckets[bucket] += 1
    return buckets
