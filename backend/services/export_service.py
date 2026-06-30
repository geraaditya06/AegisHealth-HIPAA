"""
export_service.py — Multi-format export of scan results.

Renders an (already enriched) scan payload to:

    * JSON  — the complete scan, recommendations and executive risk analysis.
    * CSV   — one row per finding, including recommendation/HIPAA/OWASP columns.
    * PDF   — delegated to the existing ``scanner.report_generator``.

Pure serialisation helpers; the route layer is responsible for auth, fetching
the scan, and choosing the HTTP response type.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List


def to_json(payload: Dict[str, Any]) -> bytes:
    """Serialise the full scan payload to pretty JSON bytes."""
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def to_csv(findings: List[Dict[str, Any]]) -> bytes:
    """Serialise findings (optionally enriched) to CSV bytes."""
    columns = [
        "check_id", "category", "severity", "status", "description", "remediation",
        "hipaa_rule", "owasp_category", "business_impact", "technical_impact",
        "estimated_risk_reduction", "effort",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        rec = f.get("recommendation", {}) or {}
        writer.writerow({
            "check_id": f.get("check_id", ""),
            "category": f.get("category", ""),
            "severity": f.get("severity", ""),
            "status": "PASS" if f.get("passed") else "FAIL",
            "description": f.get("description", ""),
            "remediation": f.get("remediation", ""),
            "hipaa_rule": rec.get("hipaa_rule", ""),
            "owasp_category": rec.get("owasp_category", ""),
            "business_impact": rec.get("business_impact", ""),
            "technical_impact": rec.get("technical_impact", ""),
            "estimated_risk_reduction": rec.get("estimated_risk_reduction", ""),
            "effort": rec.get("effort", ""),
        })
    return buffer.getvalue().encode("utf-8")
