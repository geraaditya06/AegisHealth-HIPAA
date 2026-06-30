"""
scan_queue.py — Background scan queue with concurrent workers.

Replaces the previous synchronous, request-blocking scan with an asynchronous
queue backed by a thread pool. Features required by the SaaS platform:

* **Queue** scans for execution without blocking the HTTP request.
* **Concurrent workers** (configurable via ``SCAN_WORKERS``).
* **Retry** failed scans up to ``max_attempts``.
* **Cancel** queued or running scans (cooperative cancellation).
* **Progress percentage** + **estimated completion (ETA)** streamed to the DB
  (and onward to WebSocket clients).
* Status lifecycle: ``queued → running → completed | failed | cancelled``.

Why a thread pool (not Celery/RQ)?
----------------------------------
The scan workload is I/O-bound (HTTP probes), the existing stack is a single
FastAPI process with SQLite, and the brief is to *extend* — not add heavy infra
like Redis/Celery. A ``ThreadPoolExecutor`` satisfies every requirement while
keeping deployment unchanged. WAL mode + busy timeouts (see ``migrations.py``)
make concurrent SQLite writes safe.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Optional

from core.config import settings
from core.logging_config import get_logger
from scanner.pipeline import ScanCancelled, run_pipeline
from services import notifications, scan_service

logger = get_logger("scan_queue")


class ScanQueue:
    """Singleton-style background scan executor.

    Instantiated once and started during application lifespan. Thread-safe.
    """

    def __init__(self, workers: Optional[int] = None, max_retries: Optional[int] = None):
        self._workers = workers or settings.scan_workers
        self._default_max_retries = (
            max_retries if max_retries is not None else settings.scan_max_retries
        )
        self._executor: Optional[ThreadPoolExecutor] = None
        self._cancelled: set[int] = set()
        self._lock = threading.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self._workers, thread_name_prefix="scan-worker"
            )
            logger.info("Scan queue started with %d worker(s)", self._workers)

    def stop(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None
            logger.info("Scan queue stopped")

    # ── Public API ────────────────────────────────────────────────────────

    def enqueue(self, scan_id: int, url: str, user_id: int, max_attempts: int = 1) -> None:
        """Submit a scan for background execution."""
        if self._executor is None:
            self.start()
        with self._lock:
            self._cancelled.discard(scan_id)
        assert self._executor is not None
        self._executor.submit(self._run_job, scan_id, url, user_id, max_attempts)
        logger.info("Enqueued scan %s for %s", scan_id, url)

    def cancel(self, scan_id: int) -> None:
        """Request cooperative cancellation of a queued/running scan."""
        with self._lock:
            self._cancelled.add(scan_id)
        logger.info("Cancellation requested for scan %s", scan_id)

    def is_cancelled(self, scan_id: int) -> bool:
        with self._lock:
            return scan_id in self._cancelled

    # ── Worker body ───────────────────────────────────────────────────────

    def _run_job(self, scan_id: int, url: str, user_id: int, max_attempts: int) -> None:
        """Execute a single scan with retry, progress, and notifications."""
        if self.is_cancelled(scan_id):
            scan_service.mark_cancelled(scan_id)
            return

        attempt = 0
        last_error = "Unknown error"

        while attempt < max(1, max_attempts):
            attempt += 1
            scan_service.increment_attempt(scan_id)
            scan_service.mark_running(scan_id)
            start_time = datetime.now(timezone.utc)

            def progress(phase: str, percent: int, message: str) -> None:
                eta = self._estimate_eta(start_time, percent)
                scan_service.update_progress(scan_id, percent, phase, message, eta)

            try:
                result = run_pipeline(
                    url,
                    progress=progress,
                    is_cancelled=lambda: self.is_cancelled(scan_id),
                    scan_id=scan_id,
                )
                scan_service.save_results(scan_id, result)
                self._emit_success_notifications(user_id, scan_id, url, result)
                logger.info("Scan %s completed (score=%s)", scan_id, result.get("score"))
                return

            except ScanCancelled:
                scan_service.mark_cancelled(scan_id)
                logger.info("Scan %s cancelled", scan_id)
                return

            except Exception as exc:  # noqa: BLE001 - we want to retry on any failure
                last_error = str(exc)
                logger.warning(
                    "Scan %s attempt %d/%d failed: %s",
                    scan_id, attempt, max_attempts, exc,
                )
                if attempt < max_attempts and not self.is_cancelled(scan_id):
                    continue
                break

        # Exhausted retries (or cancelled between attempts).
        if self.is_cancelled(scan_id):
            scan_service.mark_cancelled(scan_id)
            return
        scan_service.mark_failed(scan_id, last_error)
        try:
            notifications.notify_scan_failed(user_id, scan_id, url, last_error)
        except Exception as exc:  # pragma: no cover - notification must never crash a worker
            logger.error("Failed to create scan-failed notification: %s", exc)

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _estimate_eta(start_time: datetime, percent: int) -> Optional[str]:
        """Estimate completion time from elapsed time and progress percentage."""
        if percent <= 0 or percent >= 100:
            return None
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        if elapsed <= 0:
            return None
        total_estimate = elapsed / (percent / 100.0)
        remaining = max(0.0, total_estimate - elapsed)
        eta = datetime.now(timezone.utc) + timedelta(seconds=remaining)
        return eta.isoformat()

    @staticmethod
    def _emit_success_notifications(
        user_id: int, scan_id: int, url: str, result: dict
    ) -> None:
        """Create scan-complete + critical-finding + cert-expiry notifications."""
        try:
            score = int(result.get("score") or 0)
            rating = result.get("rating") or "Unknown"
            notifications.notify_scan_complete(user_id, scan_id, url, score, rating)

            findings = result.get("findings", [])
            critical = sum(
                1
                for f in findings
                if not f.get("passed", True)
                and (f.get("severity", "").lower() in ("critical", "high"))
            )
            notifications.notify_critical_findings(user_id, scan_id, url, critical)

            # Certificate expiry detection from SSL findings.
            for f in findings:
                if (
                    f.get("check_id") in ("C-02", "EN-05", "SSL-02")
                    and not f.get("passed", True)
                    and any(
                        kw in (f.get("description", "").lower())
                        for kw in ("expired", "invalid", "chain", "expir")
                    )
                ):
                    notifications.notify_certificate_expiry(
                        user_id, scan_id, url, f.get("description", "Certificate issue")
                    )
                    break
        except Exception as exc:  # pragma: no cover
            logger.error("Failed to emit success notifications: %s", exc)


# Process-wide singleton.
scan_queue = ScanQueue()
