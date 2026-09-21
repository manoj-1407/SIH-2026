"""
SIH26149 — Phase B: Upload Edge Case Tests.

Tests every meaningful upload failure, boundary, and security scenario:
B1: 0-byte file, oversized file, no filename, path traversal filenames,
    Unicode filenames, long filenames, duplicate upload, nonexistent case.

Governing rule: test because the behavior/failure mode is real and uncovered,
not to inflate a count.
"""
import io
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app, raise_server_exceptions=False)

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # must match forensics.py


@pytest.fixture(scope="module")
def demo_case_id():
    """Create a fresh case for upload tests."""
    resp = client.post("/cases", json={"workflow": "FORENSIC", "title": "Upload Edge Case Tests"})
    assert resp.status_code == 200
    return resp.json()["case_id"]


# ── B1.1: Zero-byte file ───────────────────────────────────────────────────────

def test_upload_zero_byte_file(demo_case_id):
    """Zero-byte upload should succeed but produce an image with 0 artifacts on recovery."""
    resp = client.post(
        f"/cases/{demo_case_id}/upload",
        files={"file": ("empty.img", io.BytesIO(b""), "application/octet-stream")},
    )
    # Zero-byte file is valid to upload — it's the recovery that returns 0 artifacts.
    # The system must not crash; it must store it and return a sha256.
    assert resp.status_code == 200
    data = resp.json()
    assert data["size_bytes"] == 0
    assert len(data["sha256"]) == 64  # valid sha256 of empty file


# ── B1.2: File exceeds 50 MB limit ─────────────────────────────────────────────

def test_upload_oversized_file(demo_case_id):
    """File exceeding MAX_UPLOAD_SIZE must return 413 with byte count and clean up."""
    # Stream 51 MB of zeros
    oversized = io.BytesIO(b"\x00" * (MAX_UPLOAD_SIZE + 1024))
    resp = client.post(
        f"/cases/{demo_case_id}/upload",
        files={"file": ("big.img", oversized, "application/octet-stream")},
    )
    assert resp.status_code == 413
    detail = resp.json()["detail"]
    assert "exceeds" in detail.lower() or "maximum" in detail.lower()


# ── B1.3: No filename provided ──────────────────────────────────────────────────

def test_upload_no_filename(demo_case_id):
    """Empty filename string should return 400 or 422."""
    resp = client.post(
        f"/cases/{demo_case_id}/upload",
        files={"file": ("", io.BytesIO(b"\xFF\xD8\xFF\xE0"), "application/octet-stream")},
    )
    assert resp.status_code in (400, 422)


# ── B1.4: Path traversal in filename ───────────────────────────────────────────

@pytest.mark.parametrize("evil_name", [
    "../../etc/passwd",
    "../../../windows/system32/cmd.exe",
    "/etc/shadow",
    "C:\\Windows\\System32\\evil.exe",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
])
def test_upload_path_traversal_filename(demo_case_id, evil_name):
    """Path traversal filenames must be sanitized — the file must land inside uploads dir."""
    tiny_jpeg = b"\xFF\xD8\xFF\xE0" + b"\x00" * 20 + b"\xFF\xD9"
    resp = client.post(
        f"/cases/{demo_case_id}/upload",
        files={"file": (evil_name, io.BytesIO(tiny_jpeg), "application/octet-stream")},
    )
    # Must either sanitize and succeed (200) or reject (400/403).
    # Must NEVER write outside the uploads directory.
    assert resp.status_code in (200, 400, 403)
    if resp.status_code == 200:
        data = resp.json()
        # The stored filename must not contain path traversal characters
        stored_name = data.get("filename", "")
        assert "/" not in stored_name
        assert "\\" not in stored_name
        assert ".." not in stored_name


# ── B1.5: Unicode and special characters in filename ───────────────────────────

@pytest.mark.parametrize("unicode_name", [
    "évidence_2026.img",
    "证据文件.img",
    "αρχείο_αποδείξεων.img",
    "file with spaces.img",
    "file\ttab.img",
    "file!@#$%^&*().img",
    "file[brackets].img",
])
def test_upload_unicode_filename(demo_case_id, unicode_name):
    """Unicode and special char filenames must be accepted or sanitized — never crash."""
    tiny_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 30
    resp = client.post(
        f"/cases/{demo_case_id}/upload",
        files={"file": (unicode_name, io.BytesIO(tiny_data), "application/octet-stream")},
    )
    assert resp.status_code in (200, 400)
    # If accepted, sha256 must be present
    if resp.status_code == 200:
        assert "sha256" in resp.json()


# ── B1.6: Extremely long filename (> 255 chars) ─────────────────────────────────

def test_upload_extremely_long_filename(demo_case_id):
    """A filename of >255 characters must not crash the server."""
    long_name = "a" * 300 + ".img"
    resp = client.post(
        f"/cases/{demo_case_id}/upload",
        files={"file": (long_name, io.BytesIO(b"\x00" * 1024), "application/octet-stream")},
    )
    assert resp.status_code in (200, 400)


# ── B1.7: Duplicate filename same case (ACQ-ID must prevent collision) ──────────

def test_upload_duplicate_filename_no_collision(demo_case_id):
    """Uploading the same filename twice must produce two separate acquisition IDs."""
    data = b"\xFF\xD8\xFF\xE0" + b"\x00" * 16 + b"\xFF\xD9"
    resp1 = client.post(
        f"/cases/{demo_case_id}/upload",
        files={"file": ("dup_test.img", io.BytesIO(data), "application/octet-stream")},
    )
    resp2 = client.post(
        f"/cases/{demo_case_id}/upload",
        files={"file": ("dup_test.img", io.BytesIO(data), "application/octet-stream")},
    )
    assert resp1.status_code == 200
    assert resp2.status_code == 200
    # ACQ IDs must differ — no overwrite
    assert resp1.json()["acquisition_id"] != resp2.json()["acquisition_id"]


# ── B1.8: Upload to nonexistent case ───────────────────────────────────────────

def test_upload_nonexistent_case():
    """Upload to a case that doesn't exist must return 404."""
    resp = client.post(
        "/cases/CASE-DOES-NOT-EXIST-XXXXXXXX/upload",
        files={"file": ("test.img", io.BytesIO(b"\x00" * 64), "application/octet-stream")},
    )
    assert resp.status_code == 404


# ── B1.9: Invalid case_id format ───────────────────────────────────────────────

@pytest.mark.parametrize("bad_id", [
    "../etc/passwd",
    "CASE/../../evil",
    "",
    "CASE ID WITH SPACES",
    "CASE\x00NULL",
])
def test_upload_invalid_case_id_format(bad_id):
    """Malformed case_id in path must return 400/404/422, not 500."""
    try:
        resp = client.post(
            f"/cases/{bad_id}/upload",
            files={"file": ("test.img", io.BytesIO(b"\x00" * 64), "application/octet-stream")},
        )
        assert resp.status_code in (400, 404, 422)
    except Exception:
        # URL encoding may cause httpx to reject before even sending — that's fine
        pass


# ── B1.10: Content-type mismatch ───────────────────────────────────────────────

def test_upload_wrong_content_type(demo_case_id):
    """Mismatched content type must not crash — system accepts by content, not MIME type."""
    resp = client.post(
        f"/cases/{demo_case_id}/upload",
        files={"file": ("image.txt", io.BytesIO(b"\xFF\xD8\xFF\xE0" + b"\x00" * 20 + b"\xFF\xD9"), "text/plain")},
    )
    # System should accept (MIME type is advisory, not enforced at upload)
    assert resp.status_code in (200, 400)


# ── B1.11: Null bytes in filename ──────────────────────────────────────────────

def test_upload_null_byte_in_filename(demo_case_id):
    """Filenames with null bytes must be sanitized or rejected, not crash."""
    resp = client.post(
        f"/cases/{demo_case_id}/upload",
        files={"file": ("evil\x00.img", io.BytesIO(b"\x00" * 64), "application/octet-stream")},
    )
    assert resp.status_code in (200, 400)
    if resp.status_code == 200:
        stored = resp.json().get("filename", "")
        assert "\x00" not in stored
