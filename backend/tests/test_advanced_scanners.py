"""Unit + integration tests for the advanced enterprise scanners.

Network-bound scanners (Docker image / OSV) are exercised in their offline,
static paths so the suite stays hermetic.
"""

from scanner.scanners.docker_scanner import analyze_dockerfile, scan_docker
from scanner.scanners.dependency_scanner import (
    parse_package_json,
    parse_requirements,
    _is_outdated,
)


# ── Docker scanner ────────────────────────────────────────────────────────────

INSECURE_DOCKERFILE = """
FROM python:latest
ENV SECRET_TOKEN=hardcoded_value_123
ADD https://example.com/app.tar /app
RUN pip install flask && apt-get install -y curl
EXPOSE 22 5432 8000
CMD ["python", "app.py"]
"""

SECURE_DOCKERFILE = """
FROM python:3.12.3-slim@sha256:abc
RUN pip install flask==3.0.0 --no-install-recommends && rm -rf /var/lib/apt/lists/*
COPY . /app
USER appuser
EXPOSE 8000
CMD ["python", "app.py"]
"""


def _by_id(findings):
    return {f["check_id"]: f for f in findings}


def test_docker_flags_insecure_dockerfile():
    findings = analyze_dockerfile(INSECURE_DOCKERFILE)
    by = _by_id(findings)
    assert by["DK-01"]["passed"] is False   # :latest base
    assert by["DK-02"]["passed"] is False   # root user
    assert by["DK-03"]["passed"] is False   # hardcoded secret
    assert by["DK-04"]["passed"] is False   # ADD used
    assert by["DK-07"]["passed"] is False   # ports 22/5432 exposed


def test_docker_passes_hardened_dockerfile():
    findings = analyze_dockerfile(SECURE_DOCKERFILE)
    by = _by_id(findings)
    assert by["DK-01"]["passed"] is True
    assert by["DK-02"]["passed"] is True
    assert by["DK-03"]["passed"] is True
    assert by["DK-07"]["passed"] is True


def test_scan_docker_requires_input_returns_finding():
    result = scan_docker()  # nothing provided
    assert any(f["check_id"] == "DK-00" for f in result["findings"])


# ── Dependency scanner parsing ──────────────────────────────────────────────────

def test_parse_requirements_pinning():
    deps = parse_requirements("flask==1.0\nrequests>=2.0\nujson\n# comment\n-e .")
    by_name = {d["name"]: d for d in deps}
    assert by_name["flask"]["pinned"] is True
    assert by_name["requests"]["pinned"] is False
    assert by_name["ujson"]["pinned"] is False
    assert all(d["ecosystem"] == "PyPI" for d in deps)


def test_parse_package_json():
    deps = parse_package_json('{"dependencies":{"lodash":"^4.17.0"},"devDependencies":{"jest":"29.0.0"}}')
    by_name = {d["name"]: d for d in deps}
    assert by_name["lodash"]["pinned"] is False
    assert by_name["jest"]["pinned"] is True
    assert all(d["ecosystem"] == "npm" for d in deps)


def test_outdated_comparison():
    assert _is_outdated("1.0.0", "2.0.0") is True
    assert _is_outdated("2.0.0", "2.0.0") is False
    assert _is_outdated("3.1.0", "3.0.9") is False


# ── API surface (integration) ───────────────────────────────────────────────────

def test_docker_endpoint(client, auth):
    res = client.post("/api/tools/docker", json={"dockerfile": INSECURE_DOCKERFILE}, headers=auth["headers"])
    assert res.status_code == 200
    body = res.json()
    assert body["score"] < 60
    assert "score_breakdown" in body and "severity_counts" in body
    ids = [f["check_id"] for f in body["findings"]]
    assert "DK-02" in ids


def test_docker_endpoint_requires_input(client, auth):
    res = client.post("/api/tools/docker", json={}, headers=auth["headers"])
    assert res.status_code == 400


def test_dependency_endpoint_offline_safe(client, auth):
    # No network is required for parsing/pinning; OSV/registry calls degrade gracefully.
    res = client.post(
        "/api/tools/dependencies",
        json={"requirements": "flask==1.0\nrequests\n"},
        headers=auth["headers"],
    )
    assert res.status_code == 200
    body = res.json()
    assert body["summary"]["total"] == 2
    ids = [f["check_id"] for f in body["findings"]]
    assert "DEP-PIN" in ids and "DEP-CVE" in ids


def test_dependency_endpoint_requires_input(client, auth):
    res = client.post("/api/tools/dependencies", json={}, headers=auth["headers"])
    assert res.status_code == 400


# ── Pipeline wiring ──────────────────────────────────────────────────────────

def test_advanced_scanners_registered_in_pipeline():
    from scanner import pipeline
    names = {fn.__module__ for fn in pipeline._ROOT_ONLY_ADVANCED}
    assert any("tls_scanner_check" in n for n in names)
    assert any("auth_scanner_check" in n for n in names)
    assert any("api_scanner_check" in n for n in names)
    assert any("owasp_check" in n for n in names)


def test_crawler_returns_advanced_discovery_keys(monkeypatch):
    """crawl_target must expose the new discovery keys (additive contract)."""
    import scanner.crawler as cr

    # Avoid real network: robots/sitemap discovery + fetch all return empty/None.
    monkeypatch.setattr(cr, "_discover_robots", lambda base: {"present": False, "disallow": [], "sitemaps": []})
    monkeypatch.setattr(cr, "_discover_sitemap", lambda base, extra: [])
    monkeypatch.setattr(cr, "_fetch", lambda url: None)
    monkeypatch.setattr(cr, "_try_playwright_fetch", lambda url: None)

    result = cr.crawl_target("https://unreachable.invalid", max_depth=0)
    for key in ("urls", "api_endpoints", "forms", "query_params",
                "js_files", "assets", "hidden_links", "robots", "sitemap_urls"):
        assert key in result
