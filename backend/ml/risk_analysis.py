"""
risk_analysis.py — Executive Risk Analysis.

Synthesises scan findings into a board-level risk picture:

    overall_risk            Aggregate risk level + score (0-100, higher = worse)
    business_risk           Risk to the organisation / patients / compliance posture
    technical_risk          Risk from technical/architectural weaknesses
    compliance_risk         Risk of HIPAA non-compliance specifically
    top_10_priorities       The ten highest-impact open findings, ranked
    quick_wins              Low-effort, high-value fixes
    long_term_improvements  Strategic/architectural remediations

All values are derived deterministically from the findings and the multi-category
score breakdown, so the analysis is consistent with the rest of the platform.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ml.recommendation_engine import (
    effort_class,
    hipaa_rule,
    owasp_category,
    severity_points,
)

# Categories whose failures primarily drive each risk dimension.
_BUSINESS_CATEGORIES = {"Data", "PHI Protection", "Access Control", "Auth", "Authentication"}
_TECHNICAL_CATEGORIES = {
    "Infrastructure", "Input Validation", "API Security", "Headers",
    "SSL", "Encryption", "Session", "Container Security", "Dependencies",
}


def _risk_level(score: int) -> str:
    """Map a 0-100 risk score (higher = worse) to a level label."""
    if score >= 70:
        return "Critical"
    if score >= 45:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def _dimension_risk(findings: List[Dict[str, Any]], categories: set) -> Dict[str, Any]:
    """Compute a weighted risk score for a subset of categories."""
    relevant = [f for f in findings if (f.get("category") or "") in categories]
    total = sum(severity_points(f.get("severity", "good")) for f in relevant)
    lost = sum(
        severity_points(f.get("severity", "good"))
        for f in relevant if not f.get("passed", False)
    )
    score = round(lost / total * 100) if total else 0
    failed = sum(1 for f in relevant if not f.get("passed", False))
    return {"level": _risk_level(score), "score": score, "open_findings": failed}


def _finding_title(finding: Dict[str, Any]) -> str:
    desc = (finding.get("description") or "").strip()
    return desc[:120] + ("…" if len(desc) > 120 else "")


def build_executive_risk(
    findings: List[Dict[str, Any]],
    score_breakdown: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Build the full executive risk analysis payload."""
    failed = [f for f in findings if not f.get("passed", False)]
    total_open_points = sum(severity_points(f.get("severity", "good")) for f in failed)

    # Overall risk: prefer the inverse of the compliance score when available.
    overall_compliance = None
    if score_breakdown and isinstance(score_breakdown.get("overall"), dict):
        overall_compliance = score_breakdown["overall"].get("score")
    overall_risk_score = (100 - overall_compliance) if overall_compliance is not None else (
        min(100, round(total_open_points / max(1, sum(
            severity_points(f.get("severity", "good")) for f in findings)) * 100))
    )

    # Compliance risk: proportion of distinct HIPAA-mapped controls failing.
    failing_rules = {hipaa_rule(f.get("check_id", "")) for f in failed}
    all_rules = {hipaa_rule(f.get("check_id", "")) for f in findings} or {""}
    compliance_score = round(len(failing_rules) / len(all_rules) * 100)

    # Rank open findings by impact: severity weight first, then risk reduction.
    def _rank_key(f: Dict[str, Any]):
        pts = severity_points(f.get("severity", "good"))
        reduction = (pts / total_open_points * 100) if total_open_points else 0
        return (pts, reduction)

    ranked = sorted(failed, key=_rank_key, reverse=True)

    def _priority_row(f: Dict[str, Any]) -> Dict[str, Any]:
        pts = severity_points(f.get("severity", "good"))
        return {
            "check_id": f.get("check_id"),
            "category": f.get("category"),
            "severity": f.get("severity"),
            "title": _finding_title(f),
            "hipaa_rule": hipaa_rule(f.get("check_id", "")),
            "owasp_category": owasp_category(f.get("check_id", ""), f.get("category", "")),
            "estimated_risk_reduction": round(pts / total_open_points * 100, 1) if total_open_points else 0,
            "effort": effort_class(f.get("check_id", "")),
        }

    top_10 = [_priority_row(f) for f in ranked[:10]]
    quick_wins = [_priority_row(f) for f in ranked if effort_class(f.get("check_id", "")) == "quick"][:8]
    long_term = [_priority_row(f) for f in ranked if effort_class(f.get("check_id", "")) == "long"][:8]

    return {
        "overall_risk": {"level": _risk_level(overall_risk_score), "score": overall_risk_score},
        "business_risk": _dimension_risk(findings, _BUSINESS_CATEGORIES),
        "technical_risk": _dimension_risk(findings, _TECHNICAL_CATEGORIES),
        "compliance_risk": {
            "level": _risk_level(compliance_score),
            "score": compliance_score,
            "failing_safeguards": sorted(r for r in failing_rules if r),
        },
        "top_10_priorities": top_10,
        "quick_wins": quick_wins,
        "long_term_improvements": long_term,
        "summary": {
            "total_findings": len(findings),
            "open_findings": len(failed),
            "resolved_findings": len(findings) - len(failed),
        },
    }
