"""
helpers.py — Shared utility functions for scanner check modules.

Centralises common operations (URL parsing, HTTP probing, domain extraction)
so individual check modules stay small and DRY.
"""

import requests
import socket
import re
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any

# ── Default timeout for all outbound probe requests ─────────────────────────
REQUEST_TIMEOUT = 5


def get_domain(url: str) -> str:
    """Extract bare hostname from a URL string."""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split("/")[0]


def get_base(url: str) -> str:
    """Return scheme://host for the given URL (defaults to https)."""
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    return f"{scheme}://{parsed.netloc or parsed.path.split('/')[0]}"


def safe_get(url: str, **kwargs) -> Optional[requests.Response]:
    """Perform a GET request, returning None on any failure."""
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    kwargs.setdefault("allow_redirects", True)
    try:
        return requests.get(url, **kwargs)
    except Exception:
        return None


def safe_post(url: str, **kwargs) -> Optional[requests.Response]:
    """Perform a POST request, returning None on any failure."""
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    try:
        return requests.post(url, **kwargs)
    except Exception:
        return None


def safe_head(url: str, **kwargs) -> Optional[requests.Response]:
    """Perform a HEAD request, returning None on any failure."""
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    try:
        return requests.head(url, **kwargs)
    except Exception:
        return None


def probe_path(base_url: str, path: str, allow_redirects: bool = False) -> Optional[requests.Response]:
    """GET base_url + path, returning the response or None."""
    return safe_get(f"{base_url}{path}", allow_redirects=allow_redirects)


def probe_paths(base_url: str, paths: List[str]) -> List[str]:
    """
    Return the subset of *paths* that return HTTP 200 with a non-trivial body.
    Useful for detecting exposed files/endpoints.
    """
    exposed = []
    for path in paths:
        r = probe_path(base_url, path)
        if r is not None and r.status_code == 200 and len(r.text) > 50:
            exposed.append(path)
    return exposed


def check_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def finding(check_id: str, category: str, severity: str,
            passed: bool, description: str, remediation: str) -> Dict[str, Any]:
    """Build a standardised finding dict."""
    return {
        "check_id": check_id,
        "category": category,
        "severity": severity,
        "passed": passed,
        "description": description,
        "remediation": remediation,
    }


def fetch_page_text(url: str) -> str:
    """Fetch a page and return its body text, or empty string on error."""
    r = safe_get(url)
    return r.text if r else ""
