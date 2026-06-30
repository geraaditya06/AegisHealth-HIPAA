"""
docker_scanner.py — Docker image & Dockerfile security scanner.

Accepts either:
  * Raw **Dockerfile** content (always analysed statically), and/or
  * A Docker **image** reference (enriched via the local ``docker`` CLI and,
    when available, ``trivy`` for known-CVE detection).

Checks (``DK-`` ids, category "Container Security"):
    DK-01  Base image is pinned (no ``:latest`` / untagged)
    DK-02  Container does not run as root
    DK-03  No hard-coded secrets in ENV/ARG
    DK-04  Uses COPY instead of ADD (no remote ADD)
    DK-05  Package manager caches are cleaned (smaller, safer images)
    DK-06  No risky shell patterns (curl|bash, sudo, --privileged)
    DK-07  No sensitive/admin ports exposed
    DK-08  Pinned package versions (pip/npm/apt)
    DK-09  Known CVEs in the image (via trivy, when installed)

All external tooling is optional and time-bounded; the scanner degrades
gracefully to static analysis when ``docker``/``trivy`` are unavailable.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from core.logging_config import get_logger

logger = get_logger("docker_scanner")

CATEGORY = "Container Security"
_CLI_TIMEOUT = 60

SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|api[_-]?key|apikey|token|access[_-]?key|"
    r"private[_-]?key|aws_secret|client_secret)",
    re.IGNORECASE,
)
SENSITIVE_PORTS = {22, 23, 3306, 5432, 6379, 27017, 9200, 11211, 2375, 2376}


def _finding(check_id: str, severity: str, passed: bool, description: str, remediation: str) -> Dict[str, Any]:
    return {
        "check_id": check_id,
        "category": CATEGORY,
        "severity": severity,
        "passed": passed,
        "description": description,
        "remediation": remediation,
    }


# ── Dockerfile parsing ────────────────────────────────────────────────────────

def _parse_instructions(dockerfile: str) -> List[tuple[str, str]]:
    """Return a list of (INSTRUCTION, argument) tuples, joining line continuations."""
    instructions: List[tuple[str, str]] = []
    buffer = ""
    for raw in dockerfile.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        buffer += line
        if buffer.endswith("\\"):
            buffer = buffer[:-1] + " "
            continue
        parts = buffer.split(None, 1)
        if parts:
            instr = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            instructions.append((instr, arg))
        buffer = ""
    return instructions


def analyze_dockerfile(dockerfile: str) -> List[Dict[str, Any]]:
    """Statically analyse Dockerfile content and return findings."""
    instr = _parse_instructions(dockerfile)
    findings: List[Dict[str, Any]] = []

    froms = [a for i, a in instr if i == "FROM"]
    users = [a.lower() for i, a in instr if i == "USER"]

    # DK-01: base image pinned
    unpinned = []
    for base in froms:
        image = base.split(" as ")[0].strip()
        if ":" not in image.split("/")[-1] or image.endswith(":latest"):
            unpinned.append(image)
    findings.append(_finding(
        "DK-01", "medium", len(unpinned) == 0,
        ("Base image(s) are pinned to a specific tag" if not unpinned
         else f"Unpinned/`latest` base image(s): {', '.join(unpinned)}"),
        "Pin base images to an immutable tag or digest (e.g. python:3.12.3-slim@sha256:...).",
    ))

    # DK-02: non-root user
    runs_as_root = (not users) or users[-1] in ("root", "0")
    findings.append(_finding(
        "DK-02", "high", not runs_as_root,
        ("Container drops to a non-root USER" if not runs_as_root
         else "Container runs as root (no non-root USER set)"),
        "Add a non-root 'USER' instruction so the container does not run as root.",
    ))

    # DK-03: hard-coded secrets
    secret_hits = []
    for i, a in instr:
        if i in ("ENV", "ARG") and SECRET_KEY_PATTERN.search(a) and "=" in a:
            value = a.split("=", 1)[1].strip().strip('"').strip("'")
            if value and value.lower() not in ("", "changeme", "${arg}"):
                secret_hits.append(a.split("=", 1)[0].strip().split()[-1])
    findings.append(_finding(
        "DK-03", "high", len(secret_hits) == 0,
        ("No hard-coded secrets detected in ENV/ARG" if not secret_hits
         else f"Possible hard-coded secret(s): {', '.join(secret_hits[:6])}"),
        "Never bake secrets into images; inject them at runtime via secret stores or env files.",
    ))

    # DK-04: ADD vs COPY
    add_remote = [a for i, a in instr if i == "ADD"]
    findings.append(_finding(
        "DK-04", "low", len(add_remote) == 0,
        ("No use of ADD (COPY preferred)" if not add_remote
         else f"{len(add_remote)} ADD instruction(s) found — prefer COPY"),
        "Use COPY for local files; ADD can fetch remote URLs and auto-extract archives unexpectedly.",
    ))

    # DK-05: package cache cleanup
    run_text = " ".join(a.lower() for i, a in instr if i == "RUN")
    uses_apt = "apt-get install" in run_text or "apt install" in run_text
    cleaned = "rm -rf /var/lib/apt/lists" in run_text or "--no-install-recommends" in run_text
    findings.append(_finding(
        "DK-05", "low", (not uses_apt) or cleaned,
        ("Package caches are cleaned / minimal install used" if (not uses_apt or cleaned)
         else "apt-get install without cache cleanup or --no-install-recommends"),
        "Clean package caches in the same RUN layer and use --no-install-recommends.",
    ))

    # DK-06: risky shell patterns
    risky = []
    if re.search(r"curl[^\n|]*\|\s*(sudo\s+)?(ba)?sh", run_text):
        risky.append("curl | bash")
    if "wget" in run_text and "| sh" in run_text:
        risky.append("wget | sh")
    if "sudo " in run_text:
        risky.append("sudo")
    findings.append(_finding(
        "DK-06", "medium", len(risky) == 0,
        ("No risky shell execution patterns" if not risky else f"Risky pattern(s): {', '.join(risky)}"),
        "Avoid piping remote scripts directly to a shell; verify checksums and drop sudo in images.",
    ))

    # DK-07: sensitive exposed ports
    exposed_ports: List[int] = []
    for i, a in instr:
        if i == "EXPOSE":
            for tok in a.split():
                m = re.match(r"(\d+)", tok)
                if m:
                    exposed_ports.append(int(m.group(1)))
    sensitive = [p for p in exposed_ports if p in SENSITIVE_PORTS]
    findings.append(_finding(
        "DK-07", "high", len(sensitive) == 0,
        ("No sensitive admin/database ports exposed" if not sensitive
         else f"Sensitive port(s) exposed: {', '.join(map(str, sensitive))}"),
        "Do not EXPOSE database/admin ports (22, 3306, 5432, 6379, 2375…) from application images.",
    ))

    # DK-08: pinned package versions
    unpinned_pkgs = bool(re.search(r"pip install\s+(?!.*==)[a-z0-9_\-]+", run_text)) or \
        bool(re.search(r"npm install\s+(?!.*@)[a-z0-9_\-/]+", run_text))
    findings.append(_finding(
        "DK-08", "low", not unpinned_pkgs,
        ("Package installs appear version-pinned" if not unpinned_pkgs
         else "Unpinned pip/npm package install detected"),
        "Pin all package versions (pip ==, npm @version) for reproducible, auditable builds.",
    ))

    return findings


# ── Optional docker / trivy enrichment ────────────────────────────────────────

def _run_cli(args: List[str]) -> Optional[str]:
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=_CLI_TIMEOUT, check=False
        )
        return result.stdout
    except Exception as exc:
        logger.debug("CLI %s failed: %s", args[:2], exc)
        return None


def _inspect_image(image: str) -> List[Dict[str, Any]]:
    """Use the docker CLI to inspect a built image (if docker is installed)."""
    findings: List[Dict[str, Any]] = []
    if shutil.which("docker") is None:
        return findings
    out = _run_cli(["docker", "inspect", image])
    if not out:
        return findings
    try:
        data = json.loads(out)[0]
        config = data.get("Config", {}) or {}
        user = (config.get("User") or "").lower()
        findings.append(_finding(
            "DK-02", "high", bool(user) and user not in ("root", "0"),
            f"Image runtime user: '{user or 'root (default)'}'",
            "Set a non-root USER in the image configuration.",
        ))
        env = config.get("Env", []) or []
        secrets = [e.split("=", 1)[0] for e in env if SECRET_KEY_PATTERN.search(e)]
        findings.append(_finding(
            "DK-03", "high", len(secrets) == 0,
            ("No secret-like env vars baked into image" if not secrets
             else f"Secret-like env var(s) in image: {', '.join(secrets[:6])}"),
            "Remove secret env vars from the image; supply them at runtime.",
        ))
    except Exception as exc:
        logger.debug("docker inspect parse failed: %s", exc)
    return findings


def _trivy_scan(image: str) -> List[Dict[str, Any]]:
    """Run trivy for known-CVE detection (if trivy is installed)."""
    if shutil.which("trivy") is None:
        return [_finding(
            "DK-09", "medium", True,
            "CVE scan skipped — 'trivy' not installed (static analysis only)",
            "Install Trivy (https://aquasecurity.github.io/trivy) for image CVE scanning.",
        )]
    out = _run_cli(["trivy", "image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL", image])
    if not out:
        return []
    try:
        data = json.loads(out)
        vulns = []
        for result in data.get("Results", []) or []:
            for v in result.get("Vulnerabilities", []) or []:
                vulns.append(f"{v.get('VulnerabilityID')} ({v.get('PkgName')})")
        return [_finding(
            "DK-09", "high", len(vulns) == 0,
            ("No HIGH/CRITICAL CVEs found by Trivy" if not vulns
             else f"{len(vulns)} HIGH/CRITICAL CVE(s): {', '.join(vulns[:8])}"),
            "Update vulnerable OS/library packages or switch to a patched base image.",
        )]
    except Exception:
        return []


def scan_docker(image: Optional[str] = None, dockerfile: Optional[str] = None) -> Dict[str, Any]:
    """Scan a Dockerfile and/or image; return ``{findings, target}``.

    At least one of *image* or *dockerfile* must be provided.
    """
    findings: List[Dict[str, Any]] = []
    target = image or "Dockerfile"

    if dockerfile:
        findings += analyze_dockerfile(dockerfile)

    if image:
        # Image inspection may override the static DK-02/DK-03 with runtime facts;
        # de-duplicate by keeping the image-derived finding when present.
        image_findings = _inspect_image(image)
        overridden = {f["check_id"] for f in image_findings}
        findings = [f for f in findings if f["check_id"] not in overridden] + image_findings
        findings += _trivy_scan(image)

    if not findings:
        findings.append(_finding(
            "DK-00", "medium", False,
            "No Dockerfile content or reachable image was provided to analyse",
            "Provide Dockerfile content or an image reference that the host can inspect.",
        ))

    return {"findings": findings, "target": target}
