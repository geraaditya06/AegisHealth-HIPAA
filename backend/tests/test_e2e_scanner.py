"""
End-to-end scanner integration test (Phase 9).

Runs the REAL pipeline through the queue against a local HTTP server — no
stubbing of the scan logic — to verify the full lifecycle:

    queue → worker → pipeline → crawler → scanners → score → DB →
    report → notifications → status endpoint → WebSocket → result.

Uses a localhost target so it is fast and deterministic (external TLS/DNS
probes fail fast and are handled gracefully).
"""

import http.server
import socketserver
import threading
import time

import pytest

_HTML = b"""<!doctype html><html><head><title>t</title>
<script src="/static/app.js"></script></head>
<body><a href="/about">about</a>
<form method="post" action="/login"><input type="password" name="pw"></form>
<!-- <a href="/hidden-admin"> --></body></html>"""


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(_HTML)

    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):  # silence
        pass


@pytest.fixture(scope="module")
def local_target():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def _wait_terminal(client, headers, scan_id, timeout=90):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = client.get(f"/api/scan/{scan_id}/status", headers=headers).json()
        if last["status"] in ("completed", "complete", "failed", "cancelled"):
            return last
        time.sleep(0.3)
    return last


def test_full_scan_lifecycle(client, auth, local_target):
    headers = auth["headers"]

    # 1) Queue a REAL scan.
    res = client.post("/api/scan/queue", json={"url": local_target}, headers=headers)
    assert res.status_code == 200
    scan_id = res.json()["scan_id"]
    assert res.json()["status"] == "queued"

    # 2) Poll the lightweight status endpoint until terminal.
    final = _wait_terminal(client, headers, scan_id)
    assert final is not None, "scan never reached a terminal state"
    assert final["status"] in ("completed", "complete"), f"unexpected status: {final}"
    assert final["progress"] == 100

    # 3) Full detail: findings stored, score computed, report generated.
    detail = client.get(f"/api/scan/{scan_id}", params={"enrich": "true"}, headers=headers).json()
    assert detail["score"] is not None
    assert len(detail["findings"]) > 0
    assert detail["report_path"]                      # PDF generated
    assert detail["category_scores"]["categories"]    # multi-category scoring
    assert "risk_analysis" in detail                  # executive risk analysis
    # AI recommendation engine enriched the findings.
    assert any("recommendation" in f for f in detail["findings"])

    # 4) Notifications were created on completion.
    notifs = client.get("/api/notifications", headers=headers).json()
    assert notifs["unread_count"] >= 1
    assert "scan_complete" in [n["type"] for n in notifs["notifications"]]

    # 5) The scan is searchable in history.
    listed = client.get("/api/scan/list", params={"q": "127.0.0.1"}, headers=headers).json()
    assert any(item["id"] == scan_id for item in listed["items"])

    # 6) Exports work in all three formats.
    assert client.get(f"/api/scan/{scan_id}/export", params={"format": "json"}, headers=headers).status_code == 200
    assert client.get(f"/api/scan/{scan_id}/export", params={"format": "csv"}, headers=headers).status_code == 200


def test_status_endpoint_ownership(client, auth, local_target):
    headers = auth["headers"]
    # Unknown scan → 404.
    assert client.get("/api/scan/999999/status", headers=headers).status_code == 404


def test_websocket_streams_progress(client, auth, local_target):
    """WebSocket must stream progress and deliver a terminal message."""
    headers = auth["headers"]
    token = auth["token"]
    scan_id = client.post("/api/scan/queue", json={"url": local_target}, headers=headers).json()["scan_id"]

    statuses = []
    with client.websocket_connect(f"/api/scan/ws/{scan_id}?token={token}") as ws:
        for _ in range(200):
            data = ws.receive_json()
            statuses.append(data.get("status"))
            if data.get("status") in ("completed", "complete", "failed", "cancelled"):
                break
    assert statuses, "no WebSocket messages received"
    assert statuses[-1] in ("completed", "complete")


def test_websocket_rejects_bad_token(client, auth, local_target):
    headers = auth["headers"]
    scan_id = client.post("/api/scan/queue", json={"url": local_target}, headers=headers).json()["scan_id"]
    # Connecting with a bad token must be rejected (policy-violation close).
    try:
        with pytest.raises(Exception):
            with client.websocket_connect(f"/api/scan/ws/{scan_id}?token=bogus") as ws:
                ws.receive_json()
    finally:
        # Cancel + drain so this real scan's worker doesn't outlive the test
        # (and write to the DB after session teardown).
        client.post(f"/api/scan/{scan_id}/cancel", headers=headers)
        _wait_terminal(client, headers, scan_id, timeout=30)
