"""
scanner.scanners — Standalone scanners for non-URL inputs.

These scanners analyse artifacts that aren't web targets:

* :mod:`docker_scanner`      — Docker images / Dockerfiles.
* :mod:`dependency_scanner`  — requirements.txt / package.json dependency files.

Both return findings in the same canonical shape used by the URL scanner
(``check_id, category, severity, passed, description, remediation``) so they can
reuse the existing scorer and report generator.
"""
