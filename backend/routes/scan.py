"""
scan.py — Scanner API.

Endpoints
---------
Legacy (preserved, backward compatible):
    POST   /api/scan                 Synchronous scan (blocks until complete).
    GET    /api/scan/history         Last 10 scans for the user.
    POST   /api/scan/generate-report On-demand PDF generation.
    GET    /api/scan/report/download Serve a generated PDF.

Enterprise additions:
    POST   /api/scan/queue              Queue a scan for background execution.
    GET    /api/scan/list               Search / filter / sort / paginate history.
    GET    /api/scan/{scan_id}          Full scan detail (findings + category scores).
    POST   /api/scan/{scan_id}/cancel   Cancel a queued/running scan.
    POST   /api/scan/{scan_id}/retry    Retry a failed/cancelled scan.
    WS     /api/scan/ws/{scan_id}       Real-time progress stream.

The synchronous endpoint now runs the shared :mod:`scanner.pipeline` and persists
the multi-category score breakdown, so its JSON response gains ``scan_id``,
``score_breakdown`` and ``severity_counts`` while keeping every original field.
"""

from __future__ import annotations

import asyncio
import os
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from core.audit import ACTION_EXPORT, ACTION_SCAN_CREATE, record_action
from core.config import settings
from core.logging_config import get_logger
from core.security import CurrentUser, authenticate_websocket, get_current_user
from db import get_connection, rows_to_dicts
from ml.recommendation_engine import enrich_findings
from ml.risk import predict_risk
from ml.risk_analysis import build_executive_risk
from ml.suggestions import generate_suggestions
from scanner.pipeline import run_pipeline
from scanner.report_generator import generate_report
from services import export_service, scan_service
from services.scan_queue import scan_queue

logger = get_logger("scan")

router = APIRouter()


# ── Request models (with OpenAPI examples) ───────────────────────────────────

class ScanRequest(BaseModel):
    url: str = Field(..., examples=["https://example.com"], description="Target URL to scan")


class QueueScanRequest(BaseModel):
    url: str = Field(..., examples=["https://example.com"], description="Target URL to scan")
    project_id: Optional[int] = Field(None, description="Optional project this scan belongs to")


class GenerateReportRequest(BaseModel):
    findings: list
    url: str


# ── Legacy synchronous scan (preserved) ──────────────────────────────────────

@router.post("", summary="Run a synchronous scan")
def run_scan(
    req: ScanRequest,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
):
    """Run a full scan synchronously and return the complete result.

    Retained for backward compatibility. New clients should prefer
    ``POST /api/scan/queue`` + the WebSocket progress stream.
    """
    scan_id = scan_service.create_scan(user.id, req.url, source="sync", status="running")
    scan_service.mark_running(scan_id)
    record_action(user.id, ACTION_SCAN_CREATE, req.url, request=request)

    try:
        result = run_pipeline(req.url)
    except Exception as exc:
        scan_service.mark_failed(scan_id, str(exc))
        logger.error("Synchronous scan %s failed: %s", scan_id, exc)
        raise HTTPException(status_code=500, detail="Scan failed") from exc

    scan_service.save_results(scan_id, result)

    findings = result["findings"]
    failed_findings = [f for f in findings if not f.get("passed", True)]
    suggestions = generate_suggestions(failed_findings)

    # AI recommendation engine + executive risk analysis (read-time enrichment).
    enriched_findings = enrich_findings(findings)
    risk_analysis = build_executive_risk(findings, result["score_breakdown"])

    # Predict next-scan risk from this URL's score history.
    conn = get_connection()
    try:
        history_rows = conn.execute(
            "SELECT created_at, score FROM scans "
            "WHERE url=? AND status IN ('completed','complete') AND score IS NOT NULL "
            "ORDER BY created_at ASC",
            (req.url,),
        ).fetchall()
    finally:
        conn.close()
    risk = predict_risk(history_rows)

    return {
        "scan_id": scan_id,
        "url": req.url,
        "score": result["score"],
        "rating": result["rating"],
        "score_breakdown": result["score_breakdown"],
        "severity_counts": result["severity_counts"],
        "findings": enriched_findings,
        "suggestions": suggestions,
        "risk_prediction": risk,
        "risk_analysis": risk_analysis,
        "report_path": result["report_path"],
        "crawl_summary": result["crawl_summary"],
    }


@router.get("/history", summary="Recent scan history (last 10)")
def scan_history(user: CurrentUser = Depends(get_current_user)):
    """Return the user's 10 most recent scans (unchanged legacy shape)."""
    conn = get_connection()
    try:
        scans = rows_to_dicts(
            conn.execute(
                "SELECT id, url, score, rating, status, created_at FROM scans "
                "WHERE user_id=? ORDER BY created_at DESC LIMIT 10",
                (user.id,),
            ).fetchall()
        )
    finally:
        conn.close()
    return {"scans": scans}


# ── Enterprise: background queue ──────────────────────────────────────────────

@router.post("/queue", summary="Queue a scan for background execution")
def queue_scan(
    req: QueueScanRequest,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
):
    """Create a scan record and hand it to the background worker pool.

    Returns immediately with ``{scan_id, status}``; clients then subscribe to
    ``WS /api/scan/ws/{scan_id}`` for live progress.
    """
    max_attempts = settings.scan_max_retries + 1
    scan_id = scan_service.create_scan(
        user.id,
        req.url,
        source="queue",
        status="queued",
        project_id=req.project_id,
        max_attempts=max_attempts,
    )
    record_action(user.id, ACTION_SCAN_CREATE, req.url, request=request)
    scan_queue.enqueue(scan_id, req.url, user.id, max_attempts=max_attempts)
    return {"scan_id": scan_id, "status": "queued"}


@router.get("/list", summary="Search, filter, sort and paginate scan history")
def list_scans(
    user: CurrentUser = Depends(get_current_user),
    q: Optional[str] = Query(None, description="Search by URL substring"),
    status: Optional[str] = Query(None, description="queued|running|completed|failed|cancelled"),
    severity: Optional[str] = Query(None, description="critical|warning|good"),
    sort_by: str = Query("date", description="date|score|severity|status"),
    order: str = Query("desc", description="asc|desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    date_from: Optional[str] = Query(None, description="ISO date lower bound"),
    date_to: Optional[str] = Query(None, description="ISO date upper bound"),
):
    """Paginated, filterable, sortable scan history for the authenticated user."""
    return scan_service.list_scans(
        user.id,
        query=q,
        status=status,
        severity=severity,
        sort_by=sort_by,
        order=order,
        page=page,
        page_size=page_size,
        date_from=date_from,
        date_to=date_to,
    )


@router.get("/{scan_id}", summary="Full scan detail")
def get_scan(
    scan_id: int,
    enrich: bool = Query(False, description="Include AI suggestions + risk prediction"),
    user: CurrentUser = Depends(get_current_user),
):
    """Return a scan with its findings and multi-category score breakdown.

    When ``enrich=true`` and the scan is complete, the response additionally
    includes AI remediation ``suggestions`` and a ``risk_prediction`` — matching
    the rich payload of the synchronous scan endpoint so the live scanner UI can
    render identical results after a queued scan finishes.
    """
    scan = scan_service.get_scan_detail(scan_id, user.id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if enrich and scan.get("status") in ("completed", "complete"):
        findings = scan.get("findings", [])
        failed = [f for f in findings if not f.get("passed", True)]
        scan["suggestions"] = generate_suggestions(failed)
        # AI recommendation engine: attach per-finding enrichment.
        scan["findings"] = enrich_findings(findings)
        # Executive risk analysis from findings + stored category breakdown.
        scan["risk_analysis"] = build_executive_risk(findings, scan.get("category_scores"))

        conn = get_connection()
        try:
            history_rows = conn.execute(
                "SELECT created_at, score FROM scans "
                "WHERE url=? AND status IN ('completed','complete') AND score IS NOT NULL "
                "ORDER BY created_at ASC",
                (scan["url"],),
            ).fetchall()
        finally:
            conn.close()
        scan["risk_prediction"] = predict_risk(history_rows)

    return scan


@router.get("/{scan_id}/export", summary="Export a scan as PDF, JSON, or CSV")
def export_scan(
    scan_id: int,
    request: Request,
    format: str = Query("json", description="pdf | json | csv"),
    user: CurrentUser = Depends(get_current_user),
):
    """Export a completed scan in the requested format.

    * ``pdf``  — the full executive PDF report (ReportLab).
    * ``json`` — complete scan + recommendations + executive risk analysis.
    * ``csv``  — one row per finding with HIPAA/OWASP/impact columns.
    """
    scan = scan_service.get_scan_detail(scan_id, user.id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    fmt = (format or "json").lower()
    findings = scan.get("findings", [])
    enriched = enrich_findings(findings)
    domain = (scan.get("url") or "scan").replace("https://", "").replace("http://", "").split("/")[0]
    record_action(user.id, ACTION_EXPORT, f"scan:{scan_id}:{fmt}", request=request)

    if fmt == "json":
        scan["findings"] = enriched
        scan["risk_analysis"] = build_executive_risk(findings, scan.get("category_scores"))
        body = export_service.to_json(scan)
        return Response(
            content=body, media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{domain}_scan_{scan_id}.json"'},
        )

    if fmt == "csv":
        body = export_service.to_csv(enriched)
        return Response(
            content=body, media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{domain}_scan_{scan_id}.csv"'},
        )

    if fmt == "pdf":
        try:
            report_path = generate_report(findings, scan.get("url", ""),
                                          score_breakdown=scan.get("category_scores"))
        except Exception as exc:
            logger.error("PDF export failed for scan %s: %s", scan_id, exc)
            raise HTTPException(status_code=500, detail="Failed to generate PDF")
        if not report_path or not os.path.isfile(report_path):
            raise HTTPException(status_code=500, detail="Report file was not created")
        return FileResponse(
            report_path, media_type="application/pdf",
            filename=os.path.basename(report_path),
            headers={"Content-Disposition": f'attachment; filename="{os.path.basename(report_path)}"'},
        )

    raise HTTPException(status_code=400, detail="Unsupported format. Use pdf, json, or csv.")


@router.get("/{scan_id}/status", summary="Lightweight scan progress snapshot (for polling)")
def scan_status(scan_id: int, user: CurrentUser = Depends(get_current_user)):
    """Return a small progress snapshot used by the WebSocket polling fallback.

    Cheap by design (no findings) so the frontend can poll it safely when the
    WebSocket is unavailable.
    """
    owner = scan_service.get_scan_owner(scan_id)
    if owner is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if owner != user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    snapshot = scan_service.get_scan_status(scan_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return snapshot


@router.post("/{scan_id}/cancel", summary="Cancel a queued/running scan")
def cancel_scan(scan_id: int, user: CurrentUser = Depends(get_current_user)):
    owner = scan_service.get_scan_owner(scan_id)
    if owner is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if owner != user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    scan_queue.cancel(scan_id)
    scan_service.mark_cancelled(scan_id)
    return {"scan_id": scan_id, "status": "cancelled"}


@router.post("/{scan_id}/retry", summary="Retry a failed/cancelled scan")
def retry_scan(scan_id: int, user: CurrentUser = Depends(get_current_user)):
    scan = scan_service.get_scan_detail(scan_id, user.id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") not in ("failed", "cancelled"):
        raise HTTPException(
            status_code=400, detail="Only failed or cancelled scans can be retried"
        )
    max_attempts = settings.scan_max_retries + 1
    scan_service.reset_for_retry(scan_id)
    scan_queue.enqueue(scan_id, scan["url"], user.id, max_attempts=max_attempts)
    return {"scan_id": scan_id, "status": "queued"}


# ── Enterprise: real-time progress over WebSocket ─────────────────────────────

@router.websocket("/ws/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: int, token: Optional[str] = None):
    """Stream live scan progress.

    The token is supplied via the ``?token=`` query parameter (browsers can't
    set headers on the WS handshake). Progress is read from the persisted scan
    state and pushed whenever it changes, until a terminal status is reached.
    """
    user = await authenticate_websocket(websocket, token)
    if user is None:
        return

    owner = scan_service.get_scan_owner(scan_id)
    if owner is None or owner != user.id:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    last_signature = None
    terminal = {"completed", "complete", "failed", "cancelled"}
    try:
        while True:
            status = scan_service.get_scan_status(scan_id)
            if status is None:
                await websocket.send_json({"error": "Scan not found"})
                break

            signature = (status.get("progress"), status.get("phase"), status.get("status"))
            if signature != last_signature:
                await websocket.send_json(status)
                last_signature = signature

            if status.get("status") in terminal:
                break
            await asyncio.sleep(0.4)
    except WebSocketDisconnect:
        logger.debug("WebSocket client disconnected from scan %s", scan_id)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("WebSocket error for scan %s: %s", scan_id, exc)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# ── PDF report endpoints (preserved) ──────────────────────────────────────────

@router.post("/generate-report", summary="Generate a PDF report on demand")
def generate_report_endpoint(
    req: GenerateReportRequest,
    user: CurrentUser = Depends(get_current_user),
):
    """Generate a PDF report on demand from scan findings."""
    try:
        report_path = generate_report(req.findings, req.url)
    except Exception as exc:
        logger.error("Report generation failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to generate report")

    if not report_path or not os.path.isfile(report_path):
        raise HTTPException(status_code=500, detail="Report file was not created")

    filename = os.path.basename(report_path)
    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/report/download", summary="Download a generated PDF report")
def download_report(
    file: str = Query(..., description="Absolute path to the report PDF"),
    user: CurrentUser = Depends(get_current_user),
):
    """Serve a generated PDF report for download (restricted to reports/)."""
    if not file or not os.path.isfile(file):
        raise HTTPException(status_code=404, detail="Report file not found")

    reports_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    )
    abs_file = os.path.abspath(file)
    if not abs_file.startswith(reports_dir):
        raise HTTPException(status_code=403, detail="Access denied")

    filename = os.path.basename(abs_file)
    return FileResponse(
        abs_file,
        media_type="application/pdf",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
