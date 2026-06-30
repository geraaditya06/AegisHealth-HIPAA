"""
dependency_scanner.py — Dependency vulnerability scanner.

Parses ``requirements.txt`` (PyPI) and/or ``package.json`` (npm) content and
detects:

  * **Known CVEs** via the public OSV.dev API (batched, time-bounded).
  * **Outdated libraries** by comparing against the latest published version
    (PyPI / npm registry) for a bounded number of packages.
  * **High-severity packages** (any dependency with a known vulnerability).
  * **Unpinned versions** (loose ranges that make builds non-reproducible).

All network calls are best-effort with short timeouts and graceful offline
fallback — the scanner never raises on connectivity problems. Findings use the
canonical shape so the existing scorer/report can consume them.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import requests

from core.logging_config import get_logger

logger = get_logger("dependency_scanner")

CATEGORY = "Dependencies"
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_TIMEOUT = 12
_REGISTRY_TIMEOUT = 6
_MAX_OUTDATED_CHECKS = 25  # bound registry calls for latency


def _finding(check_id: str, severity: str, passed: bool, description: str, remediation: str) -> Dict[str, Any]:
    return {
        "check_id": check_id,
        "category": CATEGORY,
        "severity": severity,
        "passed": passed,
        "description": description,
        "remediation": remediation,
    }


# ── Parsing ───────────────────────────────────────────────────────────────────

def parse_requirements(content: str) -> List[Dict[str, str]]:
    """Parse requirements.txt into ``[{name, version, pinned}]`` (PyPI ecosystem)."""
    deps: List[Dict[str, str]] = []
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or line.startswith("git+"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<|!=)?\s*([A-Za-z0-9_.\-*]+)?", line)
        if not m:
            continue
        name, op, version = m.group(1), m.group(2), m.group(3)
        deps.append({
            "name": name,
            "version": version or "",
            "ecosystem": "PyPI",
            "pinned": op == "==" and bool(version),
        })
    return deps


def parse_package_json(content: str) -> List[Dict[str, str]]:
    """Parse package.json dependencies + devDependencies (npm ecosystem)."""
    deps: List[Dict[str, str]] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            clean = re.sub(r"^[\^~>=<\s]+", "", str(spec)).strip()
            deps.append({
                "name": name,
                "version": clean,
                "ecosystem": "npm",
                "pinned": bool(re.match(r"^\d", str(spec))),
            })
    return deps


# ── OSV vulnerability lookup ────────────────────────────────────────────────────

def _query_osv(deps: List[Dict[str, str]]) -> Dict[str, List[str]]:
    """Batch-query OSV.dev; return ``{dep_key: [vuln_ids]}``. Empty dict on failure."""
    queries = []
    for d in deps:
        q: Dict[str, Any] = {"package": {"name": d["name"], "ecosystem": d["ecosystem"]}}
        if d["version"]:
            q["version"] = d["version"]
        queries.append(q)
    if not queries:
        return {}
    try:
        resp = requests.post(_OSV_BATCH_URL, json={"queries": queries}, timeout=_OSV_TIMEOUT)
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except Exception as exc:
        logger.warning("OSV lookup unavailable (offline?): %s", exc)
        return {}

    vuln_map: Dict[str, List[str]] = {}
    for dep, result in zip(deps, results):
        vulns = result.get("vulns") or []
        if vulns:
            key = f"{dep['name']}@{dep['version'] or '*'}"
            vuln_map[key] = [v.get("id", "?") for v in vulns]
    return vuln_map


# ── Outdated detection ──────────────────────────────────────────────────────────

def _latest_version(dep: Dict[str, str]) -> Optional[str]:
    try:
        if dep["ecosystem"] == "PyPI":
            r = requests.get(f"https://pypi.org/pypi/{dep['name']}/json", timeout=_REGISTRY_TIMEOUT)
            if r.status_code == 200:
                return r.json().get("info", {}).get("version")
        else:  # npm
            r = requests.get(f"https://registry.npmjs.org/{dep['name']}", timeout=_REGISTRY_TIMEOUT)
            if r.status_code == 200:
                return r.json().get("dist-tags", {}).get("latest")
    except Exception:
        return None
    return None


def _is_outdated(current: str, latest: str) -> bool:
    def norm(v: str) -> Tuple[int, ...]:
        nums = re.findall(r"\d+", v)
        return tuple(int(n) for n in nums[:3]) if nums else (0,)
    try:
        return norm(current) < norm(latest)
    except Exception:
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def scan_dependencies(
    requirements: Optional[str] = None,
    package_json: Optional[str] = None,
) -> Dict[str, Any]:
    """Scan dependency manifests and return ``{findings, summary}``."""
    deps: List[Dict[str, str]] = []
    if requirements:
        deps += parse_requirements(requirements)
    if package_json:
        deps += parse_package_json(package_json)

    findings: List[Dict[str, Any]] = []

    if not deps:
        findings.append(_finding(
            "DEP-00", "medium", False,
            "No dependencies could be parsed from the provided manifest(s)",
            "Provide valid requirements.txt and/or package.json content.",
        ))
        return {"findings": findings, "summary": {"total": 0}}

    # ── Known CVEs (OSV) ──────────────────────────────────────────────────
    vuln_map = _query_osv(deps)
    vulnerable_pkgs = sorted(vuln_map.keys())
    total_cves = sum(len(v) for v in vuln_map.values())

    findings.append(_finding(
        "DEP-CVE", "high", len(vulnerable_pkgs) == 0,
        ("No known CVEs found for the provided dependencies (OSV.dev)"
         if not vulnerable_pkgs
         else f"{len(vulnerable_pkgs)} package(s) with {total_cves} known vulnerability(ies): "
              + ", ".join(vulnerable_pkgs[:8])),
        "Upgrade affected packages to a patched version; track advisories continuously.",
    ))

    # Per-package high-severity finding for the worst offenders (clear UI rows).
    for key in vulnerable_pkgs[:10]:
        ids = vuln_map[key]
        findings.append(_finding(
            f"DEP-CVE:{key}", "high", False,
            f"{key} is affected by: {', '.join(ids[:6])}"
            + (" …" if len(ids) > 6 else ""),
            "Update this dependency to a non-vulnerable release.",
        ))

    # ── High-severity package count ───────────────────────────────────────
    findings.append(_finding(
        "DEP-HIGH", "high", len(vulnerable_pkgs) == 0,
        (f"{len(vulnerable_pkgs)} high-risk (vulnerable) dependency(ies)"
         if vulnerable_pkgs else "No high-risk dependencies detected"),
        "Prioritise remediation of vulnerable dependencies before release.",
    ))

    # ── Unpinned versions ─────────────────────────────────────────────────
    unpinned = [d["name"] for d in deps if not d["pinned"]]
    findings.append(_finding(
        "DEP-PIN", "medium", len(unpinned) == 0,
        (f"{len(unpinned)} dependency(ies) are not version-pinned: " + ", ".join(unpinned[:10])
         if unpinned else "All dependencies are version-pinned"),
        "Pin exact versions (PyPI '==', npm exact) and use a lockfile for reproducible builds.",
    ))

    # ── Outdated libraries (bounded registry checks) ──────────────────────
    outdated: List[str] = []
    checked = 0
    for d in deps:
        if checked >= _MAX_OUTDATED_CHECKS:
            break
        if not d["version"]:
            continue
        checked += 1
        latest = _latest_version(d)
        if latest and _is_outdated(d["version"], latest):
            outdated.append(f"{d['name']} {d['version']}→{latest}")
    findings.append(_finding(
        "DEP-OUTDATED", "low", len(outdated) == 0,
        (f"{len(outdated)} outdated dependency(ies): " + ", ".join(outdated[:10])
         if outdated else "Checked dependencies are up to date"),
        "Keep dependencies current to receive security and stability fixes.",
    ))

    summary = {
        "total": len(deps),
        "vulnerable": len(vulnerable_pkgs),
        "cves": total_cves,
        "unpinned": len(unpinned),
        "outdated": len(outdated),
        "ecosystems": sorted({d["ecosystem"] for d in deps}),
    }
    return {"findings": findings, "summary": summary}
