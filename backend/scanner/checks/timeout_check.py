import requests
import re
from typing import Optional
from urllib.parse import urlparse


def _get_base(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    return f"{scheme}://{parsed.netloc or parsed.path.split('/')[0]}"


def _parse_cookie_max_age(set_cookie_header: str) -> Optional[int]:
    """Return Max-Age seconds from a Set-Cookie header string, or None."""
    match = re.search(r"max-age=(\d+)", set_cookie_header, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


def _has_expires(set_cookie_header: str) -> bool:
    """Return True if the Set-Cookie header contains an Expires attribute."""
    return bool(re.search(r"expires=", set_cookie_header, re.IGNORECASE))


def check_timeout(url: str):
    findings = []
    base = _get_base(url)

    # Collect Set-Cookie headers from both the root and common auth endpoints
    probe_paths = ["", "/login", "/dashboard", "/app"]
    all_set_cookie: list[str] = []

    for path in probe_paths:
        try:
            r = requests.get(f"{base}{path}", timeout=5, allow_redirects=True)
            # requests merges duplicate headers; use raw response headers list
            cookies_raw = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") \
                else [v for k, v in r.raw.headers.items() if k.lower() == "set-cookie"]
            all_set_cookie.extend(cookies_raw)
        except Exception:
            continue

    # ── W-07: Session cookie has expiry ──────────────────────────────────────
    # A session cookie without Max-Age or Expires lives only until the browser
    # closes — this is fine for security, BUT HIPAA guidance recommends explicit
    # short-lived expiry to enforce inactivity timeout even across browser sessions.
    session_cookie_keywords = ("session", "sess", "auth", "token", "jwt", "id")

    session_cookies = [
        c for c in all_set_cookie
        if any(kw in c.lower() for kw in session_cookie_keywords)
    ]

    if not session_cookies:
        # No identifiable session cookie found — treat as inconclusive but flag
        cookie_has_expiry = False
    else:
        # Pass if at least one session cookie carries Max-Age or Expires
        cookie_has_expiry = any(
            _parse_cookie_max_age(c) is not None or _has_expires(c)
            for c in session_cookies
        )

    findings.append({
        "check_id": "W-07",
        "category": "Session",
        "severity": "warning",
        "passed": cookie_has_expiry,
        "description": "Session cookie includes an expiry attribute (Max-Age or Expires)"
                       if cookie_has_expiry
                       else "Session cookie has no Max-Age or Expires — session never expires server-side",
        "remediation": "Set a short Max-Age (e.g. 900 for 15 minutes) on session cookies. "
                       "Combine with server-side session invalidation after inactivity to "
                       "comply with HIPAA access-control requirements (§164.312(a)(2)(iii))"
    })

    # ── W-10: Session timeout exists ─────────────────────────────────────────
    # Check for meta-refresh, JS-based auto-logout hints, or Max-Age ≤ 1800s
    session_timeout_present = False
    timeout_evidence: list[str] = []

    # 1. Cookie-level: Max-Age ≤ 1800 seconds (30 min) counts as timeout
    for c in session_cookies:
        max_age = _parse_cookie_max_age(c)
        if max_age is not None and max_age <= 1800:
            session_timeout_present = True
            timeout_evidence.append(f"Cookie Max-Age={max_age}s")
            break

    # 2. Page-level: look for auto-logout or session-timeout signals in HTML
    if not session_timeout_present:
        timeout_hints = [
            "sessiontimeout", "session_timeout", "auto_logout", "autologout",
            "idle_timeout", "inactivity", "session-expired", "sessionexpired",
        ]
        try:
            r = requests.get(base, timeout=5)
            content = r.text.lower()
            for hint in timeout_hints:
                if hint in content:
                    session_timeout_present = True
                    timeout_evidence.append(f"JS/HTML hint: '{hint}'")
                    break
        except Exception:
            pass

    # 3. Check for meta http-equiv="refresh" with short timeout (≤ 1800s)
    if not session_timeout_present:
        try:
            r = requests.get(base, timeout=5)
            meta_matches = re.findall(
                r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?(\d+)',
                r.text, re.IGNORECASE
            )
            for secs_str in meta_matches:
                if int(secs_str) <= 1800:
                    session_timeout_present = True
                    timeout_evidence.append(f"Meta refresh={secs_str}s")
                    break
        except Exception:
            pass

    findings.append({
        "check_id": "W-10",
        "category": "Session",
        "severity": "warning",
        "passed": session_timeout_present,
        "description": f"Session timeout mechanism detected ({'; '.join(timeout_evidence)})"
                       if session_timeout_present
                       else "No session timeout mechanism detected",
        "remediation": "Implement automatic session termination after ≤15 minutes of inactivity "
                       "as required by HIPAA §164.312(a)(2)(iii). Use server-side session "
                       "expiry combined with client-side idle detection and a logout redirect"
    })

    return findings
