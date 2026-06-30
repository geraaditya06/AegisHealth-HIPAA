"""
security_tools.py — Standalone security tooling API (non-URL scanners).

    POST /api/tools/docker        Scan a Dockerfile and/or image reference.
    POST /api/tools/dependencies  Scan requirements.txt / package.json content.

Both endpoints reuse the shared scorer so their results carry the same
multi-category breakdown and severity counts as URL scans, and both record an
audit event.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from core.audit import ACTION_EXPORT, ACTION_SCAN_CREATE, record_action
from core.logging_config import get_logger
from core.security import CurrentUser, get_current_user
from ml.recommendation_engine import enrich_findings
from ml.risk_analysis import build_executive_risk
from scanner.report_generator import generate_report
from scanner.scanners.dependency_scanner import scan_dependencies
from scanner.scanners.docker_scanner import scan_docker
from scanner.scorer import build_score_breakdown, count_by_severity
from services import export_service

logger = get_logger("security_tools")

router = APIRouter()


class DockerScanRequest(BaseModel):
    image: Optional[str] = Field(None, examples=["python:3.12-slim"], description="Image reference")
    dockerfile: Optional[str] = Field(
        None, description="Raw Dockerfile content",
        examples=["FROM python:latest\nCOPY . /app\nRUN pip install flask\nCMD [\"python\",\"app.py\"]"],
    )


class DependencyScanRequest(BaseModel):
    requirements: Optional[str] = Field(None, description="requirements.txt content")
    package_json: Optional[str] = Field(None, description="package.json content")


def _build_response(result: dict, target: str) -> dict:
    findings = result["findings"]
    score, rating = _score(findings)
    return {
        "target": target,
        "score": score,
        "rating": rating,
        "score_breakdown": build_score_breakdown(findings),
        "severity_counts": count_by_severity(findings),
        "findings": enrich_findings(findings),
        "risk_analysis": build_executive_risk(findings, build_score_breakdown(findings)),
        "summary": result.get("summary", {}),
    }


def _score(findings: list) -> tuple[int, str]:
    breakdown = build_score_breakdown(findings)
    overall = breakdown["overall"]
    return overall["score"], overall["rating"]


@router.post("/docker", summary="Scan a Dockerfile and/or Docker image")
def docker_scan(
    req: DockerScanRequest,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
):
    if not req.image and not req.dockerfile:
        raise HTTPException(status_code=400, detail="Provide an image reference or Dockerfile content")
    result = scan_docker(image=req.image, dockerfile=req.dockerfile)
    record_action(user.id, ACTION_SCAN_CREATE, f"docker:{req.image or 'Dockerfile'}", request=request)
    return _build_response(result, result.get("target", "Dockerfile"))


@router.post("/dependencies", summary="Scan dependency manifests for known CVEs")
def dependency_scan(
    req: DependencyScanRequest,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
):
    if not req.requirements and not req.package_json:
        raise HTTPException(status_code=400, detail="Provide requirements.txt and/or package.json content")
    result = scan_dependencies(requirements=req.requirements, package_json=req.package_json)
    record_action(user.id, ACTION_SCAN_CREATE, "dependencies", request=request)
    return _build_response(result, "dependencies")


class ToolExportRequest(BaseModel):
    findings: list = Field(..., description="Findings returned by a tool scan")
    target: str = Field("tool-scan", description="Label for the exported artifact")
    format: str = Field("json", description="pdf | json | csv")


@router.post("/export", summary="Export tool-scan results (PDF/JSON/CSV)")
def export_tool_results(
    req: ToolExportRequest,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
):
    """Export ad-hoc Docker/Dependency scan results in the requested format."""
    fmt = (req.format or "json").lower()
    enriched = enrich_findings(req.findings)
    safe_target = "".join(c if c.isalnum() else "_" for c in (req.target or "tool"))[:40]
    record_action(user.id, ACTION_EXPORT, f"tool:{safe_target}:{fmt}", request=request)

    if fmt == "json":
        payload = {
            "target": req.target,
            "score_breakdown": build_score_breakdown(req.findings),
            "severity_counts": count_by_severity(req.findings),
            "findings": enriched,
            "risk_analysis": build_executive_risk(req.findings, build_score_breakdown(req.findings)),
        }
        return Response(
            content=export_service.to_json(payload), media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{safe_target}.json"'},
        )
    if fmt == "csv":
        return Response(
            content=export_service.to_csv(enriched), media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{safe_target}.csv"'},
        )
    if fmt == "pdf":
        try:
            path = generate_report(req.findings, req.target, score_breakdown=build_score_breakdown(req.findings))
        except Exception as exc:
            logger.error("Tool PDF export failed: %s", exc)
            raise HTTPException(status_code=500, detail="Failed to generate PDF")
        import os
        if not path or not os.path.isfile(path):
            raise HTTPException(status_code=500, detail="Report file was not created")
        return FileResponse(path, media_type="application/pdf", filename=os.path.basename(path))
    raise HTTPException(status_code=400, detail="Unsupported format. Use pdf, json, or csv.")
