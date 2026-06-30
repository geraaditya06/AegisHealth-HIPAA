"""
services — Application service layer for AegisHealth.

These modules encapsulate business logic and database access behind small,
testable functions so that route handlers stay thin (Single Responsibility).

Modules
-------
scan_service   : Persistence + querying for scans, findings, and history.
scan_queue     : Background worker pool (queue / retry / cancel / progress).
notifications  : In-app notification creation and retrieval.
dashboard      : Aggregated metrics for the enterprise dashboard.
"""
