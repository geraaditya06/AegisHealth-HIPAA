"""
pipeline.py — Reusable, progress-emitting scan pipeline.

This module extracts the end-to-end scan flow that previously lived inline in
``routes/scan.py`` into a single, reusable function so it can be driven both by:

* the legacy **synchronous** endpoint (``POST /api/scan``), and
* the new **background scan queue** (concurrent workers + WebSocket progress).

The pipeline is intentionally free of any database or HTTP concerns (Single
Responsibility / Dependency Inversion): callers inject a ``progress`` callback
and an optional ``is_cancelled`` predicate. Persistence and broadcasting are the
caller's job.

Phases (and their contribution to the overall percentage)
---------------------------------------------------------
    crawler        5 → 25
    scanner       25 → 75   (security checks across discovered targets)
    rule_engine   75 → 85   (scoring + category breakdown)
    report        85 → 100  (PDF generation)
"""

from __future__ import annotations

import time
import traceback
from typing import Callable, Dict, List, Optional

from core.logging_config import get_logger
from scanner.crawler import crawl_target
from scanner.report_generator import generate_report
from scanner.scorer import (
    build_score_breakdown,
    calculate_score,
    count_by_severity,
)

# Original checks
from scanner.checks.ssl_check import check_ssl
from scanner.checks.headers_check import check_headers
from scanner.checks.phi_check import check_phi
from scanner.checks.auth_check import check_auth
from scanner.checks.timeout_check import check_timeout
from scanner.checks.dns_check import check_dns

# HIPAA check modules
from scanner.checks.audit_logging_check import run_checks as audit_logging_checks
from scanner.checks.access_control_check import run_checks as access_control_checks
from scanner.checks.encryption_check import run_checks as encryption_checks
from scanner.checks.api_security_check import run_checks as api_security_checks
from scanner.checks.data_integrity_check import run_checks as data_integrity_checks
from scanner.checks.infrastructure_security_check import run_checks as infrastructure_checks
from scanner.checks.storage_exposure_check import run_checks as storage_exposure_checks
from scanner.checks.session_management_check import run_checks as session_management_checks
from scanner.checks.input_validation_check import run_checks as input_validation_checks
from scanner.checks.monitoring_alerting_check import run_checks as monitoring_checks
from scanner.checks.backup_recovery_check import run_checks as backup_recovery_checks
from scanner.checks.third_party_integration_check import run_checks as third_party_checks

# Advanced enterprise scanners (TLS, Auth surface, API, OWASP Top 10)
from scanner.checks.tls_scanner_check import run_checks as tls_scanner_checks
from scanner.checks.auth_scanner_check import run_checks as auth_scanner_checks
from scanner.checks.api_scanner_check import run_checks as api_scanner_checks
from scanner.checks.owasp_check import run_checks as owasp_checks

logger = get_logger("pipeline")

# ── Callback type aliases ────────────────────────────────────────────────────
# progress(phase: str, percent: int, message: str) -> None
ProgressCallback = Callable[[str, int, str], None]
CancelPredicate = Callable[[], bool]

MAX_EXTRA_TARGETS = 15

# Per-URL checks (safe to run against every discovered page).
_PER_URL_CHECKS = [check_headers, check_phi]

# Checks that only need to run once against the root target.
_ROOT_ONLY_ORIGINAL = [check_ssl, check_auth, check_timeout, check_dns]

_ROOT_ONLY_HIPAA = [
    audit_logging_checks,
    access_control_checks,
    encryption_checks,
    api_security_checks,
    data_integrity_checks,
    infrastructure_checks,
    storage_exposure_checks,
    session_management_checks,
    input_validation_checks,
    monitoring_checks,
    backup_recovery_checks,
    third_party_checks,
]

# Advanced enterprise scanners — deeper TLS/Auth/API coverage + OWASP Top 10.
# Kept in a separate list so the set is easy to reason about and extend.
_ROOT_ONLY_ADVANCED = [
    tls_scanner_checks,
    auth_scanner_checks,
    api_scanner_checks,
    owasp_checks,
]


class ScanCancelled(Exception):
    """Raised internally when a scan is cancelled mid-flight."""


def _noop_progress(phase: str, percent: int, message: str) -> None:
    """Default progress callback used by the legacy synchronous path."""


def _never_cancelled() -> bool:
    return False


def _check_cancel(is_cancelled: CancelPredicate) -> None:
    if is_cancelled():
        raise ScanCancelled()


def run_pipeline(
    url: str,
    progress: Optional[ProgressCallback] = None,
    is_cancelled: Optional[CancelPredicate] = None,
    scan_id: Optional[int] = None,
) -> Dict:
    """Execute the full scan pipeline for *url*.

    Parameters
    ----------
    url:
        The target URL to scan.
    progress:
        Optional callback invoked as ``progress(phase, percent, message)`` to
        report real-time progress. Defaults to a no-op.
    is_cancelled:
        Optional predicate; when it returns True the pipeline raises
        :class:`ScanCancelled` at the next checkpoint.

    Returns
    -------
    dict
        ``{findings, score, rating, score_breakdown, severity_counts,
        report_path, crawl_summary}``.

    Raises
    ------
    ScanCancelled
        If cancellation was requested while the scan was running.
    """
    progress = progress or _noop_progress
    is_cancelled = is_cancelled or _never_cancelled
    ctx = f"scan={scan_id} " if scan_id is not None else ""
    pipeline_start = time.time()
    logger.info("%spipeline START url=%s", ctx, url)

    # ── Phase 1: Crawl ────────────────────────────────────────────────────
    progress("crawler", 5, "Crawling target to discover endpoints…")
    _check_cancel(is_cancelled)
    crawl_start = time.time()
    try:
        crawl_result = crawl_target(url, max_depth=2)
    except Exception as exc:
        logger.warning(
            "%scrawler FAILED: %s — recovery: falling back to single-URL scan",
            ctx, exc,
        )
        crawl_result = {"urls": [url], "api_endpoints": [], "forms": [], "query_params": []}
    logger.info(
        "%scrawler END in %.2fs — %d urls, %d api endpoints",
        ctx, time.time() - crawl_start,
        len(crawl_result["urls"]), len(crawl_result["api_endpoints"]),
    )

    scan_targets: List[str] = []
    seen = set()
    for candidate in [url] + crawl_result["urls"] + crawl_result["api_endpoints"]:
        if candidate not in seen:
            seen.add(candidate)
            scan_targets.append(candidate)
    extra_targets = scan_targets[1 : MAX_EXTRA_TARGETS + 1]

    progress(
        "crawler",
        25,
        f"Discovered {len(crawl_result['urls'])} URLs and "
        f"{len(crawl_result['api_endpoints'])} API endpoints",
    )

    # ── Phase 2: Run checks ───────────────────────────────────────────────
    findings: List[dict] = []
    root_checks = _ROOT_ONLY_ORIGINAL + _ROOT_ONLY_HIPAA + _ROOT_ONLY_ADVANCED
    total_root = len(root_checks)

    progress("scanner", 28, "Running root-level compliance checks…")
    scanner_start = time.time()
    for idx, check_fn in enumerate(root_checks):
        _check_cancel(is_cancelled)
        module_name = getattr(check_fn, "__module__", getattr(check_fn, "__name__", "?"))
        module_start = time.time()
        try:
            findings += check_fn(url)
            logger.debug("%smodule %s OK in %.2fs", ctx, module_name, time.time() - module_start)
        except Exception as exc:
            # Structured per-module error (Phase 8): one scanner failing must
            # never abort the others.
            logger.warning(
                "%smodule %s FAILED: %s — recovery: skipping this module, "
                "continuing scan\n%s",
                ctx, module_name, exc, traceback.format_exc(),
            )
        # Root checks span roughly 28% → 60%.
        pct = 28 + int((idx + 1) / max(total_root, 1) * 32)
        progress("scanner", pct, f"Completed {idx + 1}/{total_root} root checks")

    # Per-URL checks on the root target.
    for check_fn in _PER_URL_CHECKS:
        _check_cancel(is_cancelled)
        try:
            findings += check_fn(url)
        except Exception:
            continue

    # Per-URL checks across discovered pages (60% → 75%).
    total_extra = len(extra_targets)
    for idx, target_url in enumerate(extra_targets):
        _check_cancel(is_cancelled)
        for check_fn in _PER_URL_CHECKS:
            try:
                extra_findings = check_fn(target_url)
                for f in extra_findings:
                    if not f.get("passed", True):
                        f["description"] = f"[{target_url}] {f['description']}"
                findings += extra_findings
            except Exception:
                continue
        if total_extra:
            pct = 60 + int((idx + 1) / total_extra * 15)
            progress("scanner", pct, f"Scanned {idx + 1}/{total_extra} discovered pages")

    progress("scanner", 75, f"Security checks complete — {len(findings)} findings")
    logger.info("%sscanner END in %.2fs — %d findings", ctx, time.time() - scanner_start, len(findings))

    # ── Phase 3: Rule engine / scoring ────────────────────────────────────
    _check_cancel(is_cancelled)
    progress("rule_engine", 78, "Calculating compliance scores…")
    rule_start = time.time()
    score, rating = calculate_score(findings)
    score_breakdown = build_score_breakdown(findings)
    severity_counts = count_by_severity(findings)
    progress("rule_engine", 85, f"Overall compliance score: {score}/100 ({rating})")
    logger.info("%srule_engine END in %.2fs — score=%d (%s)", ctx, time.time() - rule_start, score, rating)

    # ── Phase 4: Report generation ────────────────────────────────────────
    _check_cancel(is_cancelled)
    progress("report", 88, "Generating PDF compliance report…")
    report_start = time.time()
    report_path: Optional[str] = None
    try:
        report_path = generate_report(findings, url, score_breakdown=score_breakdown)
    except TypeError:
        # Backward compatibility if an older generate_report signature is present.
        try:
            report_path = generate_report(findings, url)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("%sreport FAILED: %s — recovery: continuing without PDF", ctx, exc)
    except Exception as exc:
        logger.warning("%sreport FAILED: %s — recovery: continuing without PDF", ctx, exc)

    progress("report", 100, "Scan complete")
    logger.info("%sreport END in %.2fs — report=%s", ctx, time.time() - report_start,
                "yes" if report_path else "no")
    logger.info("%spipeline COMPLETE in %.2fs — %d findings, score=%d",
                ctx, time.time() - pipeline_start, len(findings), score)

    return {
        "findings": findings,
        "score": score,
        "rating": rating,
        "score_breakdown": score_breakdown,
        "severity_counts": severity_counts,
        "report_path": report_path,
        "crawl_summary": {
            "urls_discovered": len(crawl_result["urls"]),
            "api_endpoints_discovered": len(crawl_result["api_endpoints"]),
            "forms_discovered": len(crawl_result["forms"]),
            "query_params_discovered": len(crawl_result["query_params"]),
            "js_files_discovered": len(crawl_result.get("js_files", [])),
            "assets_discovered": len(crawl_result.get("assets", [])),
            "hidden_links_discovered": len(crawl_result.get("hidden_links", [])),
            "robots_present": bool(crawl_result.get("robots", {}).get("present")),
            "sitemap_urls_discovered": len(crawl_result.get("sitemap_urls", [])),
            "scan_targets_used": len([url] + extra_targets),
        },
    }
