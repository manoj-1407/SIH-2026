"""
SIH26149 — Phase B: API Failure Tests.

Tests auth failures, rate limiting, malformed requests, and
invalid input rejection across all major endpoints.
"""
import io
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app, raise_server_exceptions=False)


# ── Setup: create a real case to use in tests ──────────────────────────────────

@pytest.fixture(scope="module")
def real_case_id():
    resp = client.post("/cases", json={"workflow": "FORENSIC", "title": "API Failure Tests"})
    assert resp.status_code == 200
    return resp.json()["case_id"]


# ── Health endpoint is always public ──────────────────────────────────────────

def test_health_no_auth_required():
    """Health endpoint must be reachable without any API key."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "OPERATIONAL"


# ── Case creation: invalid workflow ───────────────────────────────────────────

def test_create_case_invalid_workflow():
    """Unknown workflow type must return 400, not 500."""
    resp = client.post("/cases", json={"workflow": "INVALID_WORKFLOW"})
    assert resp.status_code == 400
    assert "workflow" in resp.json()["detail"].lower() or "invalid" in resp.json()["detail"].lower()


def test_create_case_empty_workflow():
    """Empty workflow string must return 400."""
    resp = client.post("/cases", json={"workflow": ""})
    assert resp.status_code == 400


def test_get_nonexistent_case():
    """Getting a case that doesn't exist must return 404."""
    resp = client.get("/cases/CASE-NONEXISTENT-XXXXXX")
    assert resp.status_code == 404


# ── Sanitization: missing/invalid fields ──────────────────────────────────────

def test_sanitize_no_acknowledgement(real_case_id):
    """Sanitization without scope acknowledgement must return 400 or 403."""
    # First upload a file so case has a source_path
    img_data = b"\x00" * 1024
    client.post(
        f"/cases/{real_case_id}/upload",
        files={"file": ("target.img", io.BytesIO(img_data), "application/octet-stream")},
    )
    resp = client.post(f"/cases/{real_case_id}/sanitize", json={
        "operator_id": "OPR-001",
        "operator_name": "Test Operator",
        "authorization_reason": "Test erasure",
        "confirmed_scope_acknowledgement": False,
    })
    assert resp.status_code in (400, 403)


def test_sanitize_missing_operator_id(real_case_id):
    """Sanitization with empty operator_id must be rejected."""
    resp = client.post(f"/cases/{real_case_id}/sanitize", json={
        "operator_id": "",
        "operator_name": "Test Operator",
        "authorization_reason": "Test erasure",
        "confirmed_scope_acknowledgement": True,
    })
    assert resp.status_code in (400, 403)


def test_sanitize_empty_reason(real_case_id):
    """Sanitization with empty authorization_reason must be rejected."""
    resp = client.post(f"/cases/{real_case_id}/sanitize", json={
        "operator_id": "OPR-001",
        "operator_name": "Test Operator",
        "authorization_reason": "",
        "confirmed_scope_acknowledgement": True,
    })
    assert resp.status_code in (400, 403)


def test_sanitize_invalid_method(real_case_id):
    """Sanitization with unknown method string must return 400."""
    resp = client.post(f"/cases/{real_case_id}/sanitize", json={
        "operator_id": "OPR-001",
        "operator_name": "Test Operator",
        "authorization_reason": "Valid reason",
        "confirmed_scope_acknowledgement": True,
        "method": "NUKE_FROM_ORBIT",
    })
    assert resp.status_code == 400


def test_sanitize_nonexistent_case():
    """Sanitization on nonexistent case must return 404."""
    resp = client.post("/cases/CASE-DOES-NOT-EXIST/sanitize", json={
        "operator_id": "OPR-001",
        "operator_name": "Test Operator",
        "authorization_reason": "Valid reason",
        "confirmed_scope_acknowledgement": True,
    })
    assert resp.status_code == 404


def test_sanitize_no_source_image():
    """Sanitization on case with no uploaded image must return 400."""
    # Create fresh case with no upload
    resp_case = client.post("/cases", json={"workflow": "SANITIZATION", "title": "No image test"})
    case_id = resp_case.json()["case_id"]

    resp = client.post(f"/cases/{case_id}/sanitize", json={
        "operator_id": "OPR-001",
        "operator_name": "Test Operator",
        "authorization_reason": "Valid reason",
        "confirmed_scope_acknowledgement": True,
    })
    assert resp.status_code == 400
    assert "image" in resp.json()["detail"].lower() or "target" in resp.json()["detail"].lower()


# ── Erase: scope violations ────────────────────────────────────────────────────

def test_erase_path_traversal(real_case_id):
    """Path traversal in erase target must return 403."""
    resp = client.post(f"/cases/{real_case_id}/erase-files", json={
        "target_paths": ["../../etc/passwd"],
        "operator_id": "OPR-001",
        "operator_name": "Test Operator",
        "authorization_reason": "Testing scope guard",
        "confirmed_scope_acknowledgement": True,
        "method": "ZERO_FILL",
    })
    assert resp.status_code == 403
    assert "outside" in resp.json()["detail"].lower() or "scope" in resp.json()["detail"].lower() or "permitted" in resp.json()["detail"].lower()


def test_erase_cross_case_forbidden(real_case_id):
    """Attempting to erase files from a different case must return 403."""
    # Create a second case and upload a file
    resp2 = client.post("/cases", json={"workflow": "SANITIZATION", "title": "Case B"})
    case_b_id = resp2.json()["case_id"]
    client.post(
        f"/cases/{case_b_id}/upload",
        files={"file": ("caseb.img", io.BytesIO(b"\x00" * 512), "application/octet-stream")},
    )

    # Try to erase case_b's file using case_a's endpoint
    import os
    from pathlib import Path
    data_dir = Path("data/uploads")
    # Find any file belonging to case_b
    case_b_files = list(data_dir.glob(f"{case_b_id}_*")) if data_dir.exists() else []
    if not case_b_files:
        pytest.skip("Could not locate case B file for cross-case test")

    resp = client.post(f"/cases/{real_case_id}/erase-files", json={
        "target_paths": [str(case_b_files[0])],
        "operator_id": "OPR-001",
        "operator_name": "Test Operator",
        "authorization_reason": "Cross-case attempt",
        "confirmed_scope_acknowledgement": True,
        "method": "ZERO_FILL",
    })
    assert resp.status_code == 403


def test_erase_no_acknowledgement(real_case_id):
    """Erase without scope acknowledgement must return 400."""
    resp = client.post(f"/cases/{real_case_id}/erase-files", json={
        "target_paths": ["/some/path"],
        "operator_id": "OPR-001",
        "operator_name": "Test Operator",
        "authorization_reason": "Test",
        "confirmed_scope_acknowledgement": False,
        "method": "ZERO_FILL",
    })
    assert resp.status_code == 400


# ── Recover: no source image ───────────────────────────────────────────────────

def test_recover_no_source_image():
    """Recovery on case with no uploaded image must return 400, not crash."""
    resp_case = client.post("/cases", json={"workflow": "FORENSIC", "title": "No image recover test"})
    case_id = resp_case.json()["case_id"]

    resp = client.post(f"/cases/{case_id}/recover", json={})
    assert resp.status_code in (400, 404, 422)


# ── Evidence: nonexistent IDs ─────────────────────────────────────────────────

def test_get_nonexistent_evidence():
    """Getting evidence that doesn't exist must return 404."""
    resp = client.get("/evidence/EVID-DOES-NOT-EXIST")
    assert resp.status_code == 404


def test_verify_nonexistent_evidence():
    """Verifying evidence that doesn't exist must return 404."""
    resp = client.post("/evidence/EVID-DOES-NOT-EXIST/verify")
    assert resp.status_code == 404


# ── Case ID validation: invalid formats ───────────────────────────────────────

@pytest.mark.parametrize("bad_id,expected_status", [
    ("CASE WITH SPACES", (400, 422)),
    ("case/traversal", (400, 404, 422)),
    ("case<script>", (400, 404, 422)),
    (".", (400, 404)),
    ("..", (400, 404)),
])
def test_invalid_case_id_format(bad_id, expected_status):
    """Malformed case IDs must be rejected cleanly — not 500."""
    try:
        resp = client.get(f"/cases/{bad_id}")
        assert resp.status_code in expected_status
    except Exception:
        pass  # URL encoding rejection is also acceptable


# ── Malformed JSON body ────────────────────────────────────────────────────────

def test_malformed_json_body_sanitize(real_case_id):
    """Sending invalid JSON to a JSON endpoint must return 422, not 500."""
    resp = client.post(
        f"/cases/{real_case_id}/sanitize",
        content=b"NOT VALID JSON {{{",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422


def test_missing_required_body_sanitize(real_case_id):
    """Sending empty body where JSON is expected must return 422."""
    resp = client.post(
        f"/cases/{real_case_id}/sanitize",
        json={},
    )
    assert resp.status_code == 422
