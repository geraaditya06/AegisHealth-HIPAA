"""
backend/ml/risk.py
──────────────────
Predicts whether the *next* scan score for a URL will improve or decline
by fitting a simple linear trend over historical scan scores.

Usage
-----
    from ml.risk import predict_risk

    # score_history is a list of (created_at, score) tuples ordered oldest→newest
    prediction = predict_risk(score_history)
    # prediction →
    # {
    #     "trend":           "improving" | "declining" | "stable",
    #     "predicted_score": int,          # projected next score (clamped 0–100)
    #     "confidence":      "high" | "medium" | "low",
    #     "message":         str            # human-readable summary
    # }
"""

import math
from datetime import datetime


# ── helpers ──────────────────────────────────────────────────────────────────

def _to_timestamp(value) -> float:
    """Convert a datetime object or ISO string to a float epoch timestamp."""
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, str):
        # Try common formats
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(value, fmt).timestamp()
            except ValueError:
                continue
    # Already a numeric timestamp
    return float(value)


def _linear_regression(x: list[float], y: list[float]) -> tuple[float, float]:
    """Return (slope, intercept) of the ordinary-least-squares line through (x, y)."""
    n = len(x)
    mean_x = sum(x) / n
    mean_y = sum(y) / n
    ss_xy = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))
    ss_xx = sum((xi - mean_x) ** 2 for xi in x)
    if ss_xx == 0:
        return 0.0, mean_y
    slope = ss_xy / ss_xx
    intercept = mean_y - slope * mean_x
    return slope, intercept


def _r_squared(x: list[float], y: list[float], slope: float, intercept: float) -> float:
    """Return R² as a measure of how well the line fits the data (0–1)."""
    mean_y = sum(y) / len(y)
    ss_res = sum((yi - (slope * xi + intercept)) ** 2 for xi, yi in zip(x, y))
    ss_tot = sum((yi - mean_y) ** 2 for yi in y)
    if ss_tot == 0:
        return 1.0
    return max(0.0, 1.0 - ss_res / ss_tot)


# ── public API ────────────────────────────────────────────────────────────────

def predict_risk(score_history: list) -> dict:
    """
    Parameters
    ----------
    score_history : list
        Each item must be indexable as item[0] = timestamp/datetime and
        item[1] = int score.  Accepts raw psycopg2 row tuples, dicts with
        keys ("created_at", "score"), or plain (datetime, int) tuples.

    Returns
    -------
    dict with keys:
        trend           – "improving" | "declining" | "stable"
        predicted_score – int, projected next scan score (clamped 0–100)
        confidence      – "high" | "medium" | "low"
        message         – human-readable summary string
        data_points     – int, number of scans used in the prediction
    """
    if not score_history:
        return _insufficient_data("No scan history available for this URL")

    # Normalise rows to (timestamp_float, score_int)
    pairs: list[tuple[float, int]] = []
    for row in score_history:
        try:
            if isinstance(row, dict):
                ts = _to_timestamp(row["created_at"])
                score = int(row["score"])
            else:
                ts = _to_timestamp(row[0])
                score = int(row[1])
            pairs.append((ts, score))
        except Exception:
            continue

    # Sort oldest → newest
    pairs.sort(key=lambda p: p[0])

    if len(pairs) < 2:
        last_score = pairs[0][1] if pairs else 50
        return {
            "trend": "stable",
            "predicted_score": last_score,
            "confidence": "low",
            "message": "Only one data point available — cannot determine trend yet.",
            "data_points": len(pairs),
        }

    x = [p[0] for p in pairs]
    y = [float(p[1]) for p in pairs]

    slope, intercept = _linear_regression(x, y)
    r2 = _r_squared(x, y, slope, intercept)

    # Project the next scan timestamp as "one average interval ahead"
    avg_interval = (x[-1] - x[0]) / max(len(x) - 1, 1)
    next_ts = x[-1] + max(avg_interval, 3600)  # at least 1 h ahead
    raw_prediction = slope * next_ts + intercept
    predicted_score = max(0, min(100, round(raw_prediction)))

    # Classify trend based on slope (in score-units per second → convert to per-day)
    slope_per_day = slope * 86400
    if abs(slope_per_day) < 0.5:
        trend = "stable"
    elif slope_per_day > 0:
        trend = "improving"
    else:
        trend = "declining"

    # Confidence based on R² and sample size
    if r2 >= 0.75 and len(pairs) >= 5:
        confidence = "high"
    elif r2 >= 0.40 or len(pairs) >= 3:
        confidence = "medium"
    else:
        confidence = "low"

    # Build human-readable message
    last = round(y[-1])
    change = predicted_score - last
    direction = f"+{change}" if change >= 0 else str(change)

    message_map = {
        "improving": (
            f"Score has been trending upward (≈{slope_per_day:+.1f} pts/day). "
            f"Predicted next score: {predicted_score} ({direction} from current {last})."
        ),
        "declining": (
            f"Score is trending downward (≈{slope_per_day:+.1f} pts/day). "
            f"Predicted next score: {predicted_score} ({direction} from current {last}). "
            f"Address open findings before the next scan."
        ),
        "stable": (
            f"Score has been stable around {last}. "
            f"Predicted next score: {predicted_score}."
        ),
    }

    return {
        "trend": trend,
        "predicted_score": predicted_score,
        "confidence": confidence,
        "message": message_map[trend],
        "data_points": len(pairs),
    }


def _insufficient_data(reason: str) -> dict:
    return {
        "trend": "stable",
        "predicted_score": 50,
        "confidence": "low",
        "message": reason,
        "data_points": 0,
    }
