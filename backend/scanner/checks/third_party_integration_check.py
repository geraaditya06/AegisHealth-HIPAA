"""
third_party_integration_check.py — Third-Party Integration Security

Inspects frontend JavaScript for external API calls, detects non-HTTPS
third-party endpoints, and identifies risky third-party script loading.
"""

import re
from typing import List, Dict, Any
from .helpers import get_base, safe_get, finding


# Known analytics / tracking domains that handle data
TRACKING_DOMAINS = [
    "google-analytics.com", "googletagmanager.com",
    "facebook.net", "facebook.com", "fb.com",
    "hotjar.com", "mixpanel.com", "segment.com",
    "intercom.io", "crisp.chat", "drift.com",
    "fullstory.com", "mouseflow.com", "clarity.ms",
]


def _extract_external_urls(text: str) -> list:
    """Pull all http(s) URLs from text."""
    return re.findall(r'https?://[^\s"\'<>)\]]+', text)


def run_checks(target_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = get_base(target_url)

    r = safe_get(base)
    page_text = r.text if r else ""

    # Collect JS file contents
    js_texts = [page_text]
    js_srcs = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', page_text)
    for src in js_srcs[:15]:
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = base + src
        elif not src.startswith("http"):
            src = base + "/" + src
        jr = safe_get(src)
        if jr is not None:
            js_texts.append(jr.text)

    combined_text = "\n".join(js_texts)

    # ── TP-01: Non-HTTPS third-party endpoints ──────────────────────────────
    all_urls = _extract_external_urls(combined_text)
    base_domain = re.sub(r'^https?://', '', base).split('/')[0]

    http_third_party = []
    for url in all_urls:
        if url.startswith("http://"):
            domain = url.replace("http://", "").split("/")[0]
            if domain != base_domain and domain not in ("localhost", "127.0.0.1"):
                http_third_party.append(url[:80])

    http_third_party = list(set(http_third_party))[:5]

    findings.append(finding(
        check_id="TP-01",
        category="Third-Party",
        severity="high",
        passed=len(http_third_party) == 0,
        description=(
            "All third-party integrations use HTTPS"
            if not http_third_party
            else f"Non-HTTPS third-party endpoint(s): {'; '.join(http_third_party)}"
        ),
        remediation=(
            "Ensure every third-party API call uses HTTPS. Unencrypted "
            "connections to external services can leak PHI in transit, "
            "violating HIPAA §164.312(e)(1)."
        ),
    ))

    # ── TP-02: Third-party tracking scripts ─────────────────────────────────
    trackers_found = []
    for tracker in TRACKING_DOMAINS:
        if tracker in combined_text.lower():
            trackers_found.append(tracker)

    findings.append(finding(
        check_id="TP-02",
        category="Third-Party",
        severity="medium",
        passed=True,  # informational
        description=(
            f"Third-party tracking detected: {', '.join(trackers_found)}"
            if trackers_found
            else "No common third-party tracking scripts detected"
        ),
        remediation=(
            "Ensure all third-party trackers comply with your BAA requirements. "
            "Under HIPAA, sharing patient browsing data with analytics providers "
            "may constitute a PHI disclosure. Review each tracker's data handling."
        ),
    ))

    # ── TP-03: External scripts without SRI ─────────────────────────────────
    external_no_sri = []
    for match in re.finditer(
        r'<script([^>]+)src=["\']([^"\']+)["\']([^>]*)>',
        page_text, re.IGNORECASE,
    ):
        attrs = match.group(1) + match.group(3)
        src = match.group(2)
        if src.startswith("http") or src.startswith("//"):
            if "integrity=" not in attrs.lower():
                external_no_sri.append(src[:80])

    findings.append(finding(
        check_id="TP-03",
        category="Third-Party",
        severity="medium",
        passed=len(external_no_sri) == 0,
        description=(
            "All external scripts include Subresource Integrity (SRI)"
            if not external_no_sri
            else f"External script(s) without SRI: {'; '.join(external_no_sri[:3])}"
        ),
        remediation=(
            "Add integrity and crossorigin attributes to all external script "
            "tags. SRI protects against compromised third-party CDNs."
        ),
    ))

    # ── TP-04: Iframe sandboxing ────────────────────────────────────────────
    iframes_without_sandbox = []
    for match in re.finditer(r'<iframe([^>]*)>', page_text, re.IGNORECASE):
        attrs = match.group(1)
        if "sandbox" not in attrs.lower():
            src_match = re.search(r'src=["\']([^"\']+)', attrs)
            src = src_match.group(1) if src_match else "unknown"
            iframes_without_sandbox.append(src[:60])

    findings.append(finding(
        check_id="TP-04",
        category="Third-Party",
        severity="medium",
        passed=len(iframes_without_sandbox) == 0,
        description=(
            "All iframes use the sandbox attribute"
            if not iframes_without_sandbox
            else f"Iframe(s) without sandbox: {'; '.join(iframes_without_sandbox[:3])}"
        ),
        remediation=(
            "Add the sandbox attribute to all <iframe> elements to restrict "
            "their capabilities. Use sandbox='allow-scripts allow-same-origin' "
            "only when necessary."
        ),
    ))

    return findings
