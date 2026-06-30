"""
report_generator.py — Professional PDF Report Generator for AegisHealth Scanner.

Converts structured scan findings into a polished, multi-section PDF report
suitable for executives, developers, and compliance auditors.

Sections:
  1. Title Page
  2. Executive Summary (non-technical)
  3. Risk Score & Compliance Meter
  4. Critical Findings (high-severity only)
  5. Full Technical Findings Table
  6. Developer Fix Guide
"""

import os
import math
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Circle
from reportlab.graphics.charts.piecharts import Pie


# ── Severity weights for risk scoring ────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "high": 10,
    "critical": 10,
    "medium": 5,
    "warning": 5,
    "low": 2,
    "good": 2,
}

# ── Colour palette ───────────────────────────────────────────────────────────
COLOR_PRIMARY   = colors.HexColor("#1a237e")   # Deep indigo
COLOR_ACCENT    = colors.HexColor("#0d47a1")   # Dark blue
COLOR_HIGH      = colors.HexColor("#c62828")   # Red
COLOR_MEDIUM    = colors.HexColor("#ef6c00")   # Orange
COLOR_LOW       = colors.HexColor("#2e7d32")   # Green
COLOR_PASS      = colors.HexColor("#1b5e20")   # Dark green
COLOR_FAIL      = colors.HexColor("#b71c1c")   # Dark red
COLOR_LIGHT_BG  = colors.HexColor("#f5f5f5")   # Light grey background
COLOR_TABLE_HEAD = colors.HexColor("#1a237e")  # Table header background

SEVERITY_COLORS = {
    "high": COLOR_HIGH, "critical": COLOR_HIGH,
    "medium": COLOR_MEDIUM, "warning": COLOR_MEDIUM,
    "low": COLOR_LOW, "good": COLOR_LOW,
}

# ── Reports output directory ────────────────────────────────────────────────
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")


# ─────────────────────────────────────────────────────────────────────────────
#  Helper utilities
# ─────────────────────────────────────────────────────────────────────────────

def _ensure_reports_dir() -> str:
    """Create the reports/ directory if it doesn't exist."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    return REPORTS_DIR


def _severity_key(sev: str) -> str:
    """Normalise severity into high / medium / low."""
    s = sev.lower()
    if s in ("high", "critical"):
        return "high"
    if s in ("medium", "warning"):
        return "medium"
    return "low"


def _count_by_severity(findings: List[Dict]) -> Dict[str, int]:
    """Count findings grouped by normalised severity."""
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[_severity_key(f.get("severity", "low"))] += 1
    return counts


def _count_failed(findings: List[Dict]) -> int:
    return sum(1 for f in findings if not f.get("passed", True))


def _calculate_risk_score(findings: List[Dict]) -> tuple:
    """
    Returns (raw_score, max_possible, compliance_pct).
    Lower raw_score = better.
    """
    failed = [f for f in findings if not f.get("passed", True)]
    raw = sum(SEVERITY_WEIGHTS.get(f.get("severity", "low").lower(), 2) for f in failed)
    max_possible = sum(SEVERITY_WEIGHTS.get(f.get("severity", "low").lower(), 2) for f in findings)
    if max_possible == 0:
        return 0, 0, 100.0
    compliance = ((max_possible - raw) / max_possible) * 100
    return raw, max_possible, round(compliance, 1)


def _truncate(text: str, max_len: int = 120) -> str:
    """Truncate long text for table cells."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def _build_styles() -> dict:
    """Create all paragraph styles used throughout the report."""
    base = getSampleStyleSheet()
    styles = {}

    styles["title"] = ParagraphStyle(
        "ReportTitle", parent=base["Title"],
        fontSize=28, leading=34, textColor=COLOR_PRIMARY,
        alignment=TA_CENTER, spaceAfter=6,
    )
    styles["subtitle"] = ParagraphStyle(
        "ReportSubtitle", parent=base["Normal"],
        fontSize=14, leading=18, textColor=colors.grey,
        alignment=TA_CENTER, spaceAfter=20,
    )
    styles["heading1"] = ParagraphStyle(
        "H1", parent=base["Heading1"],
        fontSize=20, leading=24, textColor=COLOR_PRIMARY,
        spaceBefore=20, spaceAfter=10,
    )
    styles["heading2"] = ParagraphStyle(
        "H2", parent=base["Heading2"],
        fontSize=15, leading=19, textColor=COLOR_ACCENT,
        spaceBefore=14, spaceAfter=6,
    )
    styles["body"] = ParagraphStyle(
        "BodyText", parent=base["Normal"],
        fontSize=10, leading=14, alignment=TA_JUSTIFY,
        spaceAfter=8,
    )
    styles["body_bold"] = ParagraphStyle(
        "BodyBold", parent=styles["body"],
        fontName="Helvetica-Bold",
    )
    styles["code"] = ParagraphStyle(
        "CodeBlock", parent=base["Code"],
        fontSize=8, leading=11, fontName="Courier",
        backColor=COLOR_LIGHT_BG, borderPadding=6,
        leftIndent=12, spaceAfter=8,
    )
    styles["small"] = ParagraphStyle(
        "SmallText", parent=base["Normal"],
        fontSize=8, leading=10, textColor=colors.grey,
    )
    styles["center"] = ParagraphStyle(
        "CenterText", parent=base["Normal"],
        fontSize=11, leading=14, alignment=TA_CENTER,
        spaceAfter=6,
    )
    styles["center_large"] = ParagraphStyle(
        "CenterLarge", parent=base["Normal"],
        fontSize=48, leading=56, alignment=TA_CENTER,
        textColor=COLOR_PRIMARY, fontName="Helvetica-Bold",
    )
    return styles


# ─────────────────────────────────────────────────────────────────────────────
#  Drawing helpers (risk gauge, severity pie)
# ─────────────────────────────────────────────────────────────────────────────

def _make_severity_pie(counts: Dict[str, int]) -> Drawing:
    """Create a pie chart showing high / medium / low distribution."""
    d = Drawing(260, 160)
    pie = Pie()
    pie.x = 50
    pie.y = 10
    pie.width = 120
    pie.height = 120

    labels = []
    data = []
    pie_colors = []
    for sev, color in [("high", COLOR_HIGH), ("medium", COLOR_MEDIUM), ("low", COLOR_LOW)]:
        count = counts.get(sev, 0)
        if count > 0:
            labels.append(f"{sev.capitalize()}: {count}")
            data.append(count)
            pie_colors.append(color)

    if not data:
        data = [1]
        labels = ["No issues"]
        pie_colors = [COLOR_PASS]

    pie.data = data
    pie.labels = labels
    for i, c in enumerate(pie_colors):
        pie.slices[i].fillColor = c
        pie.slices[i].strokeColor = colors.white
        pie.slices[i].strokeWidth = 1.5

    pie.sideLabels = True
    pie.slices.fontName = "Helvetica"
    pie.slices.fontSize = 8
    d.add(pie)
    return d


def _make_compliance_badge(pct: float) -> Drawing:
    """Draw a large circular compliance badge."""
    d = Drawing(180, 180)

    # Outer ring
    if pct >= 85:
        ring_color = COLOR_PASS
    elif pct >= 60:
        ring_color = COLOR_MEDIUM
    else:
        ring_color = COLOR_HIGH

    d.add(Circle(90, 90, 80, fillColor=colors.white,
                 strokeColor=ring_color, strokeWidth=8))
    d.add(Circle(90, 90, 65, fillColor=colors.white,
                 strokeColor=ring_color, strokeWidth=2))

    # Percentage text
    d.add(String(90, 95, f"{pct:.0f}%",
                 fontSize=30, fontName="Helvetica-Bold",
                 fillColor=ring_color, textAnchor="middle"))
    d.add(String(90, 72, "Compliance",
                 fontSize=10, fontName="Helvetica",
                 fillColor=colors.grey, textAnchor="middle"))
    return d


# ─────────────────────────────────────────────────────────────────────────────
#  Section builders
# ─────────────────────────────────────────────────────────────────────────────

def _section_title_page(
    story: list, styles: dict,
    target_url: str, score: float, scan_date: str,
):
    """Section 1: Title page."""
    story.append(Spacer(1, 80))
    story.append(Paragraph("AegisHealth", styles["title"]))
    story.append(Paragraph("Security &amp; Compliance Report", styles["subtitle"]))
    story.append(Spacer(1, 30))
    story.append(HRFlowable(
        width="60%", thickness=2, lineCap="round",
        color=COLOR_PRIMARY, spaceAfter=20,
    ))
    story.append(Paragraph(f"<b>Target:</b>  {target_url}", styles["center"]))
    story.append(Paragraph(f"<b>Date:</b>  {scan_date}", styles["center"]))
    story.append(Paragraph(f"<b>Overall Risk Score:</b>  {score:.0f}% compliant", styles["center"]))
    story.append(Spacer(1, 40))
    story.append(Paragraph(
        "This report was generated automatically by AegisHealth Scanner. "
        "It assesses the target application against HIPAA technical safeguards, "
        "industry best practices, and common security vulnerabilities.",
        styles["body"],
    ))
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "CONFIDENTIAL — For authorised recipients only.",
        styles["small"],
    ))
    story.append(PageBreak())


def _section_executive_summary(
    story: list, styles: dict,
    findings: List[Dict], counts: Dict[str, int],
    compliance_pct: float, target_url: str,
):
    """Section 2: Executive summary (non-technical)."""
    story.append(Paragraph("1. Executive Summary", styles["heading1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_ACCENT, spaceAfter=12))

    total = len(findings)
    failed = _count_failed(findings)
    passed = total - failed

    # Plain-English summary
    if compliance_pct >= 85:
        risk_statement = (
            f"The application at <b>{target_url}</b> demonstrates a <b>strong security posture</b>. "
            f"The majority of checks passed successfully, and only minor issues were identified."
        )
    elif compliance_pct >= 60:
        risk_statement = (
            f"The application at <b>{target_url}</b> has <b>moderate security concerns</b> that "
            f"should be addressed promptly. Several issues were found that could expose "
            f"sensitive healthcare data if left unresolved."
        )
    else:
        risk_statement = (
            f"The application at <b>{target_url}</b> has <b>significant security risks</b> that "
            f"require immediate attention. Multiple high-severity vulnerabilities were detected "
            f"that may expose protected health information (PHI) and violate HIPAA requirements."
        )

    story.append(Paragraph(risk_statement, styles["body"]))
    story.append(Spacer(1, 10))

    # Summary stats table
    summary_data = [
        ["Metric", "Value"],
        ["Total Checks Performed", str(total)],
        ["Checks Passed", str(passed)],
        ["Issues Found", str(failed)],
        ["High Severity Issues", str(counts.get("high", 0))],
        ["Medium Severity Issues", str(counts.get("medium", 0))],
        ["Low Severity Issues", str(counts.get("low", 0))],
        ["Compliance Score", f"{compliance_pct:.1f}%"],
    ]
    t = Table(summary_data, colWidths=[200, 150])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_TABLE_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(PageBreak())


def _section_risk_score(
    story: list, styles: dict,
    raw_score: int, max_possible: int, compliance_pct: float,
    counts: Dict[str, int],
):
    """Section 3: Risk score and compliance visualisation."""
    story.append(Paragraph("2. Risk Score &amp; Compliance", styles["heading1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_ACCENT, spaceAfter=12))

    # Compliance badge + pie chart side by side
    badge = _make_compliance_badge(compliance_pct)
    pie = _make_severity_pie(counts)

    vis_table = Table(
        [[badge, pie]],
        colWidths=[200, 280],
    )
    vis_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(vis_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph(
        f"<b>Raw Risk Score:</b> {raw_score} / {max_possible} "
        f"(lower is better)", styles["body"],
    ))
    story.append(Paragraph(
        f"<b>Compliance Percentage:</b> {compliance_pct:.1f}%", styles["body"],
    ))

    if compliance_pct >= 85:
        verdict = "COMPLIANT — The application meets baseline HIPAA technical safeguard requirements."
        verdict_color = "green"
    elif compliance_pct >= 60:
        verdict = "NEEDS WORK — Several areas require improvement before full HIPAA compliance."
        verdict_color = "#ef6c00"
    else:
        verdict = "NON-COMPLIANT — Critical gaps exist. Immediate remediation is required."
        verdict_color = "red"

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f'<font color="{verdict_color}"><b>{verdict}</b></font>',
        styles["body"],
    ))
    story.append(PageBreak())


def _section_critical_findings(
    story: list, styles: dict, findings: List[Dict],
):
    """Section 4: High-severity findings only."""
    story.append(Paragraph("3. Critical Findings", styles["heading1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_HIGH, spaceAfter=12))

    high_findings = [
        f for f in findings
        if _severity_key(f.get("severity", "")) == "high" and not f.get("passed", True)
    ]

    if not high_findings:
        story.append(Paragraph(
            '<font color="green"><b>No critical findings.</b></font> '
            "All high-severity checks passed successfully.",
            styles["body"],
        ))
        story.append(PageBreak())
        return

    story.append(Paragraph(
        f"<b>{len(high_findings)} critical issue(s)</b> require immediate attention:",
        styles["body"],
    ))
    story.append(Spacer(1, 8))

    for i, f in enumerate(high_findings, 1):
        story.append(Paragraph(
            f'<font color="#c62828"><b>{i}. [{f["check_id"]}] {f["category"]}</b></font>',
            styles["heading2"],
        ))
        story.append(Paragraph(
            f"<b>Description:</b> {f['description']}", styles["body"],
        ))
        story.append(Paragraph(
            f"<b>Impact:</b> This issue may expose sensitive healthcare data or violate "
            f"HIPAA technical safeguard requirements, potentially resulting in regulatory "
            f"penalties and data breaches.",
            styles["body"],
        ))
        story.append(Paragraph(
            f"<b>Remediation:</b> {f['remediation']}", styles["body"],
        ))
        story.append(Spacer(1, 6))

    story.append(PageBreak())


def _section_full_findings(story: list, styles: dict, findings: List[Dict]):
    """Section 5: Complete technical findings table."""
    story.append(Paragraph("4. Full Technical Findings", styles["heading1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_ACCENT, spaceAfter=12))

    # Table header
    header = ["Check ID", "Category", "Severity", "Status", "Description"]
    col_widths = [55, 70, 55, 40, 280]

    rows = [header]
    for f in findings:
        status = "PASS" if f.get("passed", False) else "FAIL"
        rows.append([
            f.get("check_id", ""),
            f.get("category", ""),
            _severity_key(f.get("severity", "low")).upper(),
            status,
            _truncate(f.get("description", ""), 95),
        ])

    t = Table(rows, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        # Header
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_TABLE_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        # Body
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("ALIGN", (0, 0), (3, -1), "CENTER"),
        ("ALIGN", (4, 0), (4, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.8, 0.8, 0.8)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]

    # Colour-code severity and status cells
    for row_idx in range(1, len(rows)):
        sev = rows[row_idx][2]
        if sev == "HIGH":
            style_cmds.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), COLOR_HIGH))
        elif sev == "MEDIUM":
            style_cmds.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), COLOR_MEDIUM))
        else:
            style_cmds.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), COLOR_LOW))

        status = rows[row_idx][3]
        if status == "FAIL":
            style_cmds.append(("TEXTCOLOR", (3, row_idx), (3, row_idx), COLOR_FAIL))
            style_cmds.append(("FONTNAME", (3, row_idx), (3, row_idx), "Helvetica-Bold"))
        else:
            style_cmds.append(("TEXTCOLOR", (3, row_idx), (3, row_idx), COLOR_PASS))

    t.setStyle(TableStyle(style_cmds))
    story.append(t)
    story.append(PageBreak())


# ── Code-snippet remediation map ─────────────────────────────────────────────
# Maps check categories / IDs to concrete code fix examples
_CODE_FIXES = {
    "C-07": (
        "Add HSTS header (Nginx):",
        "add_header Strict-Transport-Security\n"
        '  "max-age=31536000; includeSubDomains; preload"\n'
        "  always;",
    ),
    "W-01": (
        "Add Content-Security-Policy (Nginx):",
        "add_header Content-Security-Policy\n"
        '  "default-src \'self\'; script-src \'self\'"',
    ),
    "W-02": (
        "Add X-Frame-Options (Nginx):",
        "add_header X-Frame-Options DENY;",
    ),
    "W-03": (
        "Add X-Content-Type-Options (Nginx):",
        "add_header X-Content-Type-Options nosniff;",
    ),
    "W-04": (
        "Add Referrer-Policy (Nginx):",
        "add_header Referrer-Policy\n"
        "  strict-origin-when-cross-origin;",
    ),
    "W-05": (
        "Add Permissions-Policy (Nginx):",
        "add_header Permissions-Policy\n"
        '  "camera=(), microphone=(), geolocation=()";',
    ),
    "C-01": (
        "Force HTTPS redirect (Nginx):",
        "server {\n"
        "  listen 80;\n"
        "  return 301 https://$host$request_uri;\n"
        "}",
    ),
    "SM-01": (
        "Set Secure flag on cookies (Python / FastAPI):",
        'response.set_cookie(\n'
        '  key="session", value=token,\n'
        '  secure=True, httponly=True,\n'
        '  samesite="strict"\n'
        ')',
    ),
    "API-04": (
        "Add rate limiting (FastAPI + slowapi):",
        "from slowapi import Limiter\n"
        "limiter = Limiter(key_func=get_remote_address)\n"
        '@app.get("/api/endpoint")\n'
        '@limiter.limit("100/minute")\n'
        "def my_endpoint(): ...",
    ),
    "IV-01": (
        "Escape user input (Python):",
        "from markupsafe import escape\n"
        "safe_value = escape(user_input)",
    ),
    "IV-02": (
        "Use parameterised queries (Python):",
        "cursor.execute(\n"
        '  "SELECT * FROM users WHERE id = ?",\n'
        "  (user_id,)\n"
        ")",
    ),
    "AC-04": (
        "Add TOTP-based MFA (Python):",
        "import pyotp\n"
        "totp = pyotp.TOTP(user.mfa_secret)\n"
        "if not totp.verify(code):\n"
        '    raise HTTPException(401, "Invalid MFA code")',
    ),
}


def _section_fix_guide(story: list, styles: dict, findings: List[Dict]):
    """Section 6: Developer fix guide with actionable remediation."""
    story.append(Paragraph("5. Developer Fix Guide", styles["heading1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_ACCENT, spaceAfter=12))

    failed = [f for f in findings if not f.get("passed", True)]
    if not failed:
        story.append(Paragraph(
            "All checks passed — no fixes required at this time.",
            styles["body"],
        ))
        return

    story.append(Paragraph(
        f"The following <b>{len(failed)} issue(s)</b> require developer action. "
        f"Each entry includes the problem description, recommended fix, and "
        f"a code example where applicable.",
        styles["body"],
    ))
    story.append(Spacer(1, 10))

    for i, f in enumerate(failed, 1):
        check_id = f.get("check_id", "")
        story.append(Paragraph(
            f"<b>{i}. [{check_id}] {f.get('category', '')} — "
            f"{_severity_key(f.get('severity', 'low')).upper()}</b>",
            styles["heading2"],
        ))
        story.append(Paragraph(
            f"<b>Problem:</b> {f['description']}", styles["body"],
        ))
        story.append(Paragraph(
            f"<b>Fix:</b> {f['remediation']}", styles["body"],
        ))

        # Insert code snippet if available
        if check_id in _CODE_FIXES:
            label, code = _CODE_FIXES[check_id]
            story.append(Paragraph(f"<i>{label}</i>", styles["body"]))
            # Escape XML special chars for Paragraph
            safe_code = (
                code.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
            )
            story.append(Paragraph(safe_code, styles["code"]))

        story.append(Spacer(1, 6))


# ─────────────────────────────────────────────────────────────────────────────
#  Footer callback
# ─────────────────────────────────────────────────────────────────────────────

def _add_page_footer(canvas, doc):
    """Draw a footer on every page with page number and branding."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawString(40, 25, "AegisHealth — Security & Compliance Report")
    canvas.drawRightString(A4[0] - 40, 25, f"Page {doc.page}")
    canvas.restoreState()


# ─────────────────────────────────────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(scan_results: list[dict], target_url: str,
                    score_breakdown: dict = None) -> str:
    """
    Generate a professional PDF compliance report.

    Parameters
    ----------
    scan_results : list of finding dicts from the scanner.
    target_url   : the scanned URL.
    score_breakdown : optional dict from ``scanner.scorer.build_score_breakdown``
        ``{"overall": {...}, "categories": {...}}``. When provided, the report
        gains Compliance-Categories and Risk-Matrix sections driven by the
        per-category scores. The parameter is optional so older callers (and the
        on-demand report endpoint) keep working unchanged.

    Returns
    -------
    Absolute path to the generated PDF file.
    """
    _ensure_reports_dir()

    # Derive filename from domain
    domain = urlparse(target_url).netloc or "unknown"
    domain_safe = domain.replace(":", "_").replace("/", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{domain_safe}_report_{timestamp}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    scan_date = datetime.now().strftime("%B %d, %Y at %H:%M")

    # Pre-compute metrics
    counts = _count_by_severity(scan_results)
    raw_score, max_possible, compliance_pct = _calculate_risk_score(scan_results)
    styles = _build_styles()

    # Build the PDF
    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        topMargin=40,
        bottomMargin=50,
        leftMargin=40,
        rightMargin=40,
        title="AegisHealth Security & Compliance Report",
        author="AegisHealth Scanner",
    )

    story = []

    # Section 1: Title page
    _section_title_page(story, styles, target_url, compliance_pct, scan_date)

    # Section 2: Executive summary
    _section_executive_summary(
        story, styles, scan_results, counts, compliance_pct, target_url,
    )

    # Section 3: Risk score
    _section_risk_score(story, styles, raw_score, max_possible, compliance_pct, counts)

    # Section 3b: Risk matrix (severity × likelihood) — enterprise extension
    _section_risk_matrix(story, styles, scan_results)

    # Section 3c: Compliance categories (per-category scores + deductions)
    if score_breakdown:
        _section_compliance_categories(story, styles, score_breakdown)

    # Section 3d: HIPAA safeguard mapping
    _section_hipaa_mapping(story, styles, scan_results)

    # Section 4: Critical findings
    _section_critical_findings(story, styles, scan_results)

    # Section 5: Full findings table
    _section_full_findings(story, styles, scan_results)

    # Section 6: Fix guide
    _section_fix_guide(story, styles, scan_results)

    # Section 7: Remediation roadmap (prioritised action plan)
    _section_remediation_roadmap(story, styles, scan_results)

    # Build PDF with footer
    doc.build(story, onFirstPage=_add_page_footer, onLaterPages=_add_page_footer)

    return os.path.abspath(filepath)


# ─────────────────────────────────────────────────────────────────────────────
#  Enterprise report sections (additive)
# ─────────────────────────────────────────────────────────────────────────────

# HIPAA technical-safeguard mapping by check-id prefix.
_HIPAA_MAPPING = {
    "EN": "§164.312(e)(1) — Transmission Security (encryption in transit)",
    "C": "§164.312 — Technical Safeguards",
    "SSL": "§164.312(e)(1) — Transmission Security",
    "AUTH": "§164.312(d) — Person or Entity Authentication",
    "AC": "§164.312(a)(1) — Access Control",
    "SM": "§164.312(a)(2)(iii) — Automatic Logoff / Session Security",
    "API": "§164.312(a)(1) — Access Control (API surface)",
    "PHI": "§164.502(b) — Minimum Necessary Use & Disclosure",
    "IS": "§164.308(a)(1) — Security Management Process",
    "SE": "§164.312(c)(1) — Integrity / Storage Protection",
    "BR": "§164.308(a)(7) — Contingency Plan (backup & recovery)",
    "AL": "§164.312(b) — Audit Controls",
    "MA": "§164.308(a)(1)(ii)(D) — Information System Activity Review",
    "IV": "§164.312(c)(1) — Integrity (input validation)",
    "DI": "§164.312(c)(1) — Integrity",
    "TP": "§164.308(b)(1) — Business Associate / Third-Party Controls",
    "W": "§164.312 — Technical Safeguards (HTTP security headers)",
    "G": "§164.530 — Administrative / Trust Requirements",
}


def _hipaa_clause(check_id: str) -> str:
    """Resolve a HIPAA clause for a check id by its alpha prefix."""
    prefix = "".join(ch for ch in (check_id or "") if ch.isalpha())
    # Try the longest matching prefix first (e.g. "AUTH" before "A").
    for key in sorted(_HIPAA_MAPPING, key=len, reverse=True):
        if prefix.upper().startswith(key):
            return _HIPAA_MAPPING[key]
    return "HIPAA Security Rule — General Technical Safeguards"


def _section_risk_matrix(story: list, styles: dict, findings: List[Dict]):
    """Risk matrix: severity × status, summarising exposure at a glance."""
    story.append(Paragraph("Risk Matrix", styles["heading1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_ACCENT, spaceAfter=12))

    counts = {"high": {"fail": 0, "pass": 0},
              "medium": {"fail": 0, "pass": 0},
              "low": {"fail": 0, "pass": 0}}
    for f in findings:
        sev = _severity_key(f.get("severity", "low"))
        bucket = "pass" if f.get("passed", False) else "fail"
        counts[sev][bucket] += 1

    rows = [
        ["Severity", "Failing (Exposure)", "Passing", "Risk Level"],
        ["High", str(counts["high"]["fail"]), str(counts["high"]["pass"]),
         "CRITICAL" if counts["high"]["fail"] else "Controlled"],
        ["Medium", str(counts["medium"]["fail"]), str(counts["medium"]["pass"]),
         "ELEVATED" if counts["medium"]["fail"] else "Controlled"],
        ["Low", str(counts["low"]["fail"]), str(counts["low"]["pass"]),
         "LOW" if counts["low"]["fail"] else "Controlled"],
    ]
    t = Table(rows, colWidths=[110, 130, 100, 130])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_TABLE_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    severity_colors = [COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW]
    for i, color in enumerate(severity_colors, start=1):
        style_cmds.append(("TEXTCOLOR", (0, i), (0, i), color))
        style_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style_cmds))
    story.append(t)
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "The matrix prioritises remediation: failing high-severity controls "
        "represent the greatest risk to protected health information and should "
        "be addressed first.",
        styles["body"],
    ))
    story.append(PageBreak())


def _section_compliance_categories(story: list, styles: dict, score_breakdown: Dict):
    """Per-category compliance scores with explained deductions."""
    story.append(Paragraph("Compliance Categories", styles["heading1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_ACCENT, spaceAfter=12))

    overall = score_breakdown.get("overall", {})
    story.append(Paragraph(
        f"<b>Overall Compliance Score:</b> {overall.get('score', 'N/A')}/100 "
        f"({overall.get('rating', 'N/A')})",
        styles["body"],
    ))
    story.append(Spacer(1, 8))

    categories = score_breakdown.get("categories", {})
    if not categories:
        story.append(Paragraph("No category data available.", styles["body"]))
        story.append(PageBreak())
        return

    header = ["Category", "Score", "Rating", "Passed", "Failed"]
    rows = [header]
    for name, data in categories.items():
        rows.append([
            name,
            f"{data.get('score', 0)}/100",
            data.get("rating", ""),
            str(data.get("passed", 0)),
            str(data.get("failed", 0)),
        ])
    t = Table(rows, colWidths=[150, 70, 100, 60, 60])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_TABLE_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # Explain the largest deductions per category.
    for name, data in categories.items():
        deductions = data.get("deductions", [])
        if not deductions:
            continue
        story.append(Paragraph(f"<b>{name}</b> — why points were lost:", styles["heading2"]))
        for d in deductions[:5]:
            story.append(Paragraph(
                f"• [{d.get('check_id', '')}] ({str(d.get('severity', '')).upper()}, "
                f"−{d.get('points', 0)} pts) {_truncate(d.get('description', ''), 120)}",
                styles["body"],
            ))
        story.append(Spacer(1, 6))
    story.append(PageBreak())


def _section_hipaa_mapping(story: list, styles: dict, findings: List[Dict]):
    """Map each failed control to its HIPAA Security Rule clause."""
    story.append(Paragraph("HIPAA Safeguard Mapping", styles["heading1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_ACCENT, spaceAfter=12))

    failed = [f for f in findings if not f.get("passed", True)]
    if not failed:
        story.append(Paragraph(
            "All controls passed — no HIPAA safeguard gaps identified.",
            styles["body"],
        ))
        story.append(PageBreak())
        return

    header = ["Check", "Category", "HIPAA Safeguard"]
    rows = [header]
    seen = set()
    for f in failed:
        cid = f.get("check_id", "")
        if cid in seen:
            continue
        seen.add(cid)
        rows.append([cid, f.get("category", ""), _hipaa_clause(cid)])

    t = Table(rows, colWidths=[55, 95, 300], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_TABLE_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.8, 0.8, 0.8)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(PageBreak())


def _section_remediation_roadmap(story: list, styles: dict, findings: List[Dict]):
    """Prioritised remediation plan grouped into 30/60/90-day phases."""
    story.append(Paragraph("Remediation Roadmap", styles["heading1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_ACCENT, spaceAfter=12))

    failed = [f for f in findings if not f.get("passed", True)]
    if not failed:
        story.append(Paragraph(
            "No remediation required — all checks passed.", styles["body"],
        ))
        return

    phases = {
        "Phase 1 — Immediate (0–30 days): Critical & High": [
            f for f in failed if _severity_key(f.get("severity", "low")) == "high"
        ],
        "Phase 2 — Near-term (30–60 days): Medium": [
            f for f in failed if _severity_key(f.get("severity", "low")) == "medium"
        ],
        "Phase 3 — Ongoing (60–90 days): Low & Hardening": [
            f for f in failed if _severity_key(f.get("severity", "low")) == "low"
        ],
    }

    for phase_title, items in phases.items():
        story.append(Paragraph(phase_title, styles["heading2"]))
        if not items:
            story.append(Paragraph("• No items in this phase.", styles["body"]))
            story.append(Spacer(1, 4))
            continue
        for f in items[:12]:
            story.append(Paragraph(
                f"• [{f.get('check_id', '')}] {f.get('category', '')}: "
                f"{_truncate(f.get('remediation', ''), 140)}",
                styles["body"],
            ))
        story.append(Spacer(1, 6))
