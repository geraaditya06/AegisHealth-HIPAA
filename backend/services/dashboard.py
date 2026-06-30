"""
dashboard.py — Aggregated metrics for the enterprise dashboard.

Produces the cards and chart series consumed by the frontend dashboard:

Cards
-----
* ``compliance_score``  — average score of recent completed scans.
* ``critical_findings`` — open critical/high findings across recent scans.
* ``projects``          — number of projects owned by the user.
* ``scans_today``       — scans created today.
* ``average_risk``      — 100 − average compliance score (risk index).

Charts
------
* ``compliance_trend``     — score over time (recent completed scans).
* ``severity_distribution``— failed findings grouped by severity bucket.
* ``scan_timeline``        — scans per day (last 14 days).
* ``top_vulnerabilities``  — most frequent failed checks.
* ``category_scores``      — average per-category score (replaces hardcoded bars).
"""

from __future__ import annotations

from typing import Any, Dict, List

from db import get_connection, parse_json_field, rows_to_dicts
from core.logging_config import get_logger
from scanner.scorer import SCORE_CATEGORIES, map_to_score_category

logger = get_logger("dashboard")

_SUCCESS = "status IN ('completed', 'complete')"


def get_dashboard(user_id: int) -> Dict[str, Any]:
    """Assemble the full dashboard payload for a user."""
    conn = get_connection()
    try:
        completed = rows_to_dicts(
            conn.execute(
                f"""
                SELECT id, url, score, rating, created_at, category_scores
                FROM scans
                WHERE user_id=? AND {_SUCCESS} AND score IS NOT NULL
                ORDER BY created_at DESC
                LIMIT 50
                """,
                (user_id,),
            ).fetchall()
        )

        recent_ids = [r["id"] for r in completed[:20]]

        # ── Cards ─────────────────────────────────────────────────────────
        scores = [r["score"] for r in completed if r["score"] is not None]
        avg_score = round(sum(scores) / len(scores)) if scores else 0

        critical_findings = _open_critical_count(conn, recent_ids)
        projects = conn.execute(
            "SELECT COUNT(*) AS c FROM projects WHERE user_id=?", (user_id,)
        ).fetchone()["c"]
        # NOTE: scans.created_at is stored in UTC (SQLite CURRENT_TIMESTAMP), so
        # we compare against SQLite's own UTC date('now') rather than the local
        # date.today() — otherwise the count is wrong for any non-UTC timezone
        # around midnight (it would read 0 even right after a scan).
        scans_today = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE user_id=? AND date(created_at)=date('now')",
            (user_id,),
        ).fetchone()["c"]

        cards = {
            "compliance_score": avg_score,
            "critical_findings": critical_findings,
            "projects": int(projects),
            "scans_today": int(scans_today),
            "average_risk": max(0, 100 - avg_score) if scores else 0,
        }

        # ── Charts ────────────────────────────────────────────────────────
        trend = [
            {"name": r["created_at"], "score": r["score"]}
            for r in reversed(completed[:15])
        ]

        charts = {
            "compliance_trend": trend,
            "severity_distribution": _severity_distribution(conn, recent_ids),
            "scan_timeline": _scan_timeline(conn, user_id),
            "top_vulnerabilities": _top_vulnerabilities(conn, recent_ids),
            "category_scores": _average_category_scores(completed),
        }

        return {"cards": cards, "charts": charts, "total_scans": len(completed)}
    finally:
        conn.close()


# ── Internal aggregation helpers ─────────────────────────────────────────────

def _placeholders(ids: List[int]) -> str:
    return ", ".join("?" for _ in ids)


def _open_critical_count(conn, scan_ids: List[int]) -> int:
    if not scan_ids:
        return 0
    ph = _placeholders(scan_ids)
    row = conn.execute(
        f"""
        SELECT COUNT(*) AS c FROM scan_findings
        WHERE scan_id IN ({ph}) AND passed=0
          AND lower(severity) IN ('critical', 'high')
        """,
        scan_ids,
    ).fetchone()
    return int(row["c"]) if row else 0


def _severity_distribution(conn, scan_ids: List[int]) -> List[Dict[str, Any]]:
    buckets = {"Critical": 0, "Warning": 0, "Low": 0}
    if not scan_ids:
        return [{"name": k, "value": v} for k, v in buckets.items()]
    ph = _placeholders(scan_ids)
    rows = conn.execute(
        f"""
        SELECT lower(severity) AS sev, COUNT(*) AS c FROM scan_findings
        WHERE scan_id IN ({ph}) AND passed=0
        GROUP BY lower(severity)
        """,
        scan_ids,
    ).fetchall()
    for r in rows:
        sev = r["sev"]
        if sev in ("critical", "high"):
            buckets["Critical"] += r["c"]
        elif sev in ("warning", "medium"):
            buckets["Warning"] += r["c"]
        else:
            buckets["Low"] += r["c"]
    return [{"name": k, "value": v} for k, v in buckets.items()]


def _scan_timeline(conn, user_id: int) -> List[Dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT date(created_at) AS day, COUNT(*) AS c
        FROM scans
        WHERE user_id=? AND created_at >= date('now', '-14 days')
        GROUP BY date(created_at)
        ORDER BY day ASC
        """,
        (user_id,),
    ).fetchall()
    return [{"name": r["day"], "value": r["c"]} for r in rows]


def _top_vulnerabilities(conn, scan_ids: List[int], limit: int = 6) -> List[Dict[str, Any]]:
    if not scan_ids:
        return []
    ph = _placeholders(scan_ids)
    rows = conn.execute(
        f"""
        SELECT check_id, category, severity, COUNT(*) AS c
        FROM scan_findings
        WHERE scan_id IN ({ph}) AND passed=0
        GROUP BY check_id
        ORDER BY c DESC
        LIMIT ?
        """,
        scan_ids + [limit],
    ).fetchall()
    return [
        {
            "check_id": r["check_id"],
            "category": r["category"],
            "severity": r["severity"],
            "count": r["c"],
        }
        for r in rows
    ]


def _average_category_scores(completed_scans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Average each executive category score across stored breakdowns."""
    totals: Dict[str, List[int]] = {cat: [] for cat in SCORE_CATEGORIES}
    for scan in completed_scans:
        breakdown = parse_json_field(scan.get("category_scores"))
        if not isinstance(breakdown, dict):
            continue
        categories = breakdown.get("categories", {})
        if not isinstance(categories, dict):
            continue
        for cat, data in categories.items():
            mapped = cat if cat in totals else map_to_score_category(cat)
            if mapped in totals and isinstance(data, dict) and "score" in data:
                totals[mapped].append(int(data["score"]))

    result = []
    for cat in SCORE_CATEGORIES:
        vals = totals[cat]
        result.append(
            {"name": cat, "value": round(sum(vals) / len(vals)) if vals else 0}
        )
    return result
