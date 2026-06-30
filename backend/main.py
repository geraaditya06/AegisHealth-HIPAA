"""
main.py — AegisHealth FastAPI application entrypoint.

Wires together configuration, logging, CORS, the background scan queue, and all
API routers. The OpenAPI schema is enriched with grouped tags, descriptions and
examples for a polished Swagger UI.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import settings
from core.logging_config import configure_logging, get_logger
from db import init_db
from routes import audit, auth, dashboard, deploy, notifications, scan, security_tools
from services.scan_queue import scan_queue

logger = get_logger("main")

# ── OpenAPI metadata ─────────────────────────────────────────────────────────
TAGS_METADATA = [
    {"name": "Auth", "description": "Registration, login (password + Google), logout."},
    {"name": "Scanner", "description": "Run scans synchronously or via the background "
                                       "queue, stream live progress, browse history, "
                                       "and download PDF reports."},
    {"name": "Security Tools", "description": "Standalone scanners: Docker image/Dockerfile "
                                              "analysis and dependency (requirements.txt / "
                                              "package.json) CVE scanning."},
    {"name": "Dashboard", "description": "Aggregated compliance metrics, trends and charts."},
    {"name": "Notifications", "description": "In-app notifications for scan and security events."},
    {"name": "Deploy", "description": "Deployment compliance gating checks."},
    {"name": "Audit", "description": "HIPAA-grade audit trail of user activity."},
]

DESCRIPTION = """
**AegisHealth** is an AI-powered HIPAA compliance scanner.

* Deep crawler + 28 security/compliance checks
* Multi-category compliance scoring with explained deductions
* Background scan queue with real-time WebSocket progress
* Executive PDF reports (risk matrix, HIPAA mapping, remediation roadmap)
* In-app notifications and a full audit trail
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialise DB + start/stop the scan queue."""
    configure_logging()
    init_db()
    scan_queue.start()
    logger.info("AegisHealth API started")
    try:
        yield
    finally:
        scan_queue.stop()
        logger.info("AegisHealth API shutting down")


app = FastAPI(
    title="AegisHealth API",
    version="2.0.0",
    description=DESCRIPTION,
    openapi_tags=TAGS_METADATA,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Log unexpected errors and return a sanitised 500 response."""
    logger.error("Unhandled error on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
app.include_router(scan.router, prefix="/api/scan", tags=["Scanner"])
app.include_router(security_tools.router, prefix="/api/tools", tags=["Security Tools"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["Notifications"])
app.include_router(deploy.router, prefix="/api/deploy", tags=["Deploy"])
app.include_router(audit.router, prefix="/api/audit", tags=["Audit"])


@app.get("/health", tags=["Dashboard"])
def health():
    return {"status": "AegisHealth API is running"}
