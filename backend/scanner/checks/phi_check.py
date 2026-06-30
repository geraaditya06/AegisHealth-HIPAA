import requests
from bs4 import BeautifulSoup
import re

PHI_PATTERNS = [
    r'\bssn\b', r'\bdob\b', r'\bdiagnosis\b', r'\bmedical.record\b',
    r'\bpatient.id\b', r'\bmrn\b', r'\bdate.of.birth\b'
]

# Extended patterns for deeper PHI detection
PHI_EXTENDED_PATTERNS = [
    r'\binsurance.id\b', r'\bpolicy.number\b', r'\bhealth.plan\b',
    r'\bprescription\b', r'\bmedication\b', r'\blab.result\b',
    r'\bblood.type\b', r'\ballergy\b', r'\bcondition\b',
    r'\btreatment\b', r'\bprovider.id\b', r'\bnpi\b',
]

# Patterns indicating unmasked PII/PHI data values
PHI_DATA_PATTERNS = [
    (r'\b\d{3}-\d{2}-\d{4}\b', "SSN format (XXX-XX-XXXX)"),
    (r'\b\d{9}\b', "9-digit number (possible SSN)"),
    (r'"(?:ssn|social_security)"\s*:\s*"\d', "Unmasked SSN in JSON"),
    (r'"(?:dob|date_of_birth)"\s*:\s*"\d{4}-\d{2}-\d{2}', "Unmasked DOB in JSON"),
    (r'"(?:mrn|medical_record_number)"\s*:\s*"[^"]{3,}', "Unmasked MRN in JSON"),
]


def check_phi(url: str):
    findings = []
    try:
        r = requests.get(url, timeout=5)
        full_url = r.url.lower()
    except:
        return []

    # C-06 PHI in URL
    phi_in_url = any(re.search(p, full_url) for p in PHI_PATTERNS)
    findings.append({
        "check_id": "C-06",
        "category": "Data",
        "severity": "critical",
        "passed": not phi_in_url,
        "description": "No PHI patterns detected in URL" if not phi_in_url else "PHI pattern detected in URL parameters",
        "remediation": "Never pass sensitive health information in URL parameters"
    })

    # C-09 Autocomplete on sensitive fields
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        inputs = soup.find_all("input", {"type": ["password", "text"]})
        bad_inputs = [i for i in inputs if i.get("autocomplete") != "off"]
        passed = len(bad_inputs) == 0
    except:
        passed = True

    findings.append({
        "check_id": "C-09",
        "category": "Data",
        "severity": "critical",
        "passed": passed,
        "description": "Sensitive inputs have autocomplete disabled" if passed else "Some inputs allow autocomplete",
        "remediation": "Add autocomplete='off' to all sensitive form fields"
    })

    # G-02 Privacy policy
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        privacy_links = soup.find_all("a", href=re.compile(r'privacy', re.I))
        passed = len(privacy_links) > 0
    except:
        passed = False

    findings.append({
        "check_id": "G-02",
        "category": "Trust",
        "severity": "good",
        "passed": passed,
        "description": "Privacy policy link found" if passed else "No privacy policy link found",
        "remediation": "Add a visible link to your privacy policy on every page"
    })

    # ── NEW: PHI-01 PHI detection in API responses ──────────────────────────
    from urllib.parse import urlparse
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    api_paths = [
        "/api/users", "/api/patients", "/api/records",
        "/api/profile", "/api/health-records", "/api/reports",
    ]
    phi_in_api = []
    for path in api_paths:
        try:
            ar = requests.get(f"{base}{path}", timeout=5)
            if ar.status_code == 200:
                body = ar.text.lower()
                for pattern in PHI_PATTERNS + PHI_EXTENDED_PATTERNS:
                    if re.search(pattern, body):
                        phi_in_api.append(path)
                        break
                # Check for unmasked data values
                for data_pattern, label in PHI_DATA_PATTERNS:
                    if re.search(data_pattern, ar.text):
                        phi_in_api.append(f"{path} ({label})")
                        break
        except:
            continue

    phi_in_api = list(set(phi_in_api))
    findings.append({
        "check_id": "PHI-01",
        "category": "Data",
        "severity": "critical",
        "passed": len(phi_in_api) == 0,
        "description": (
            "No PHI patterns detected in API responses"
            if not phi_in_api
            else f"PHI patterns found in API response(s): {', '.join(phi_in_api[:5])}"
        ),
        "remediation": (
            "Ensure all API responses mask or redact PHI fields. Use field-level "
            "encryption and response filters. Never expose raw SSN, DOB, or MRN."
        )
    })

    # ── NEW: PHI-02 PHI in log endpoints ────────────────────────────────────
    log_paths = ["/api/logs", "/logs", "/api/audit", "/api/events"]
    phi_in_logs = []
    for path in log_paths:
        try:
            lr = requests.get(f"{base}{path}", timeout=5)
            if lr.status_code == 200:
                body = lr.text.lower()
                for pattern in PHI_PATTERNS:
                    if re.search(pattern, body):
                        phi_in_logs.append(path)
                        break
        except:
            continue

    findings.append({
        "check_id": "PHI-02",
        "category": "Data",
        "severity": "critical",
        "passed": len(phi_in_logs) == 0,
        "description": (
            "No PHI patterns detected in log endpoints"
            if not phi_in_logs
            else f"PHI patterns found in log endpoint(s): {', '.join(phi_in_logs)}"
        ),
        "remediation": (
            "Scrub PHI from all log entries. Use tokenised identifiers in logs "
            "instead of real patient data. HIPAA requires minimum necessary "
            "use of PHI."
        )
    })

    # ── NEW: PHI-03 File upload form without restrictions ───────────────────
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        file_inputs = soup.find_all("input", {"type": "file"})
        unrestricted_uploads = []
        for fi in file_inputs:
            accept = fi.get("accept", "")
            if not accept:
                unrestricted_uploads.append(fi.get("name", "unnamed"))
    except:
        unrestricted_uploads = []

    findings.append({
        "check_id": "PHI-03",
        "category": "Data",
        "severity": "warning",
        "passed": len(unrestricted_uploads) == 0,
        "description": (
            "All file upload fields have type restrictions (accept attribute)"
            if not unrestricted_uploads
            else f"Unrestricted file upload field(s): {', '.join(unrestricted_uploads)}"
        ),
        "remediation": (
            "Add accept attributes to file upload inputs to restrict allowed "
            "file types. Validate file types server-side as well to prevent "
            "malicious file uploads."
        )
    })

    # ── NEW: PHI-04 Data masking absence (forms expose full field values) ───
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        sensitive_fields = soup.find_all("input", attrs={
            "name": re.compile(r'ssn|dob|mrn|patient|medical|insurance', re.I)
        })
        unmasked = [
            f.get("name", "unknown")
            for f in sensitive_fields
            if f.get("type", "text") not in ("password", "hidden")
        ]
    except:
        unmasked = []

    findings.append({
        "check_id": "PHI-04",
        "category": "Data",
        "severity": "warning",
        "passed": len(unmasked) == 0,
        "description": (
            "Sensitive form fields use masking (password type or hidden)"
            if not unmasked
            else f"Sensitive field(s) rendered as plain text: {', '.join(unmasked)}"
        ),
        "remediation": (
            "Mask sensitive input fields by using type='password' or displaying "
            "only the last 4 characters. Apply input masking libraries for "
            "fields like SSN and MRN."
        )
    })

    return findings