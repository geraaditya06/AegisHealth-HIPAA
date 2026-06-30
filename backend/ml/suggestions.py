"""
backend/ml/suggestions.py
─────────────────────────
Generates plain-English remediation advice for failed findings.

By default this uses a built-in local rules engine, so it works for free
without any external API key. If OPENAI_API_KEY is present, the app can
still try OpenAI first and fall back safely to the local generator.
"""

import json
import logging
import os

try:
    from openai import OpenAI
except Exception:  # pragma: no cover - optional dependency at runtime
    OpenAI = None

logger = logging.getLogger(__name__)


SEVERITY_INTRO = {
    "critical": "This is a high-priority issue because it can directly weaken the protection of patient data and should be fixed before treating the site as compliant.",
    "warning": "This is an important hardening issue. It may not be the most urgent problem, but it still affects the overall security posture and should be addressed soon.",
    "good": "This item is lower risk than a critical finding, but improving it will still strengthen the site and reduce avoidable exposure.",
}

CATEGORY_GUIDANCE = {
    "encryption": "Focus on transport security first so data is encrypted consistently in transit.",
    "ssl": "Review certificate validity, chain configuration, and TLS settings so browsers and clients can trust the service.",
    "session": "Tighten session lifetime and cookie settings so access is limited and easier to revoke.",
    "headers": "Use standard security headers to reduce common browser-based attacks and accidental data leakage.",
    "authentication": "Strengthen access control so only authorized users can reach sensitive areas.",
    "dns": "Harden DNS and public disclosure settings so users are routed safely and security contacts are visible.",
    "disclosure": "Publish the right disclosure information so security issues can be reported and handled responsibly.",
}

CHECK_GUIDANCE = {
    "C-01": "Redirect every HTTP request to HTTPS and update links, callbacks, and reverse-proxy settings so insecure traffic is not served at all.",
    "C-02": "Install a valid certificate from a trusted CA and monitor expiry so the service does not fall back into an untrusted state.",
    "C-03": "Disable old TLS versions and weak ciphers, then keep TLS 1.2+ enabled everywhere traffic enters the app.",
    "W-07": "Set an explicit cookie expiry and pair it with server-side invalidation so sessions do not remain valid longer than intended.",
    "W-10": "Add inactivity-based logout behavior and enforce timeout rules on the server so users are signed out even if the client is bypassed.",
    "G-03": "Enable DNSSEC with your DNS provider or registrar so users are less exposed to DNS tampering and redirection attacks.",
    "G-06": "Add a proper `security.txt` file with a real contact path so researchers know how to report issues safely.",
}


def generate_suggestions(failed_findings: list[dict]) -> list[dict]:
    if not failed_findings:
        return []

    api_key = os.getenv("OPENAI_API_KEY")
    if api_key and OpenAI is not None:
        suggestions = _generate_openai_suggestions(failed_findings, api_key)
        if suggestions:
            return suggestions

    return _generate_local_suggestions(failed_findings)


def _generate_openai_suggestions(failed_findings: list[dict], api_key: str) -> list[dict]:
    client = OpenAI(api_key=api_key)

    check_summaries = "\n".join(
        f"- [{f['check_id']}] ({f['severity'].upper()}) {f['description']}. "
        f"Standard remediation: {f.get('remediation', 'N/A')}"
        for f in failed_findings
    )

    system_prompt = (
        "You are a HIPAA compliance expert advising a healthcare software team. "
        "For each failed security check listed, write a single concise paragraph of plain-English advice aimed at a developer. "
        "Focus on why it matters and the most important first action to fix it. "
        "Respond only with JSON in the shape "
        '[{"check_id": "X-XX", "suggestion": "..."}, ...]'
    )
    user_prompt = (
        "The following HIPAA compliance checks failed for a healthcare web application:\n\n"
        f"{check_summaries}\n\n"
        "Provide one suggestion for each check_id."
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=1200,
        )
        raw = response.choices[0].message.content.strip()
        raw = raw.lstrip("```json").lstrip("```").rstrip("```").strip()
        suggestions = json.loads(raw)
        suggestion_map = {
            item["check_id"]: item["suggestion"]
            for item in suggestions
            if "check_id" in item and "suggestion" in item
        }
        return [
            {
                "check_id": finding["check_id"],
                "suggestion": suggestion_map.get(
                    finding["check_id"],
                    _build_local_suggestion(finding),
                ),
            }
            for finding in failed_findings
        ]
    except Exception as exc:
        logger.warning("OpenAI suggestions unavailable, using local generator: %s", exc)
        return []


def _generate_local_suggestions(failed_findings: list[dict]) -> list[dict]:
    return [
        {
            "check_id": finding["check_id"],
            "suggestion": _build_local_suggestion(finding),
        }
        for finding in failed_findings
    ]


def _build_local_suggestion(finding: dict) -> str:
    severity = str(finding.get("severity", "warning")).lower()
    category = str(finding.get("category", "")).lower()
    check_id = str(finding.get("check_id", "")).upper()
    description = str(finding.get("description", "This check failed.")).strip()
    remediation = str(finding.get("remediation", "Review and remediate this finding.")).strip()

    intro = SEVERITY_INTRO.get(severity, SEVERITY_INTRO["warning"])
    category_line = CATEGORY_GUIDANCE.get(category, "Start by fixing the root cause and then retest the affected area to confirm the control is working.")
    action_line = CHECK_GUIDANCE.get(check_id, remediation)

    return " ".join([
        intro,
        f"The scan found: {description}.",
        category_line,
        f"Recommended next step: {action_line}",
    ])
