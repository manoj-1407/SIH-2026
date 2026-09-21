"""
SIH26149 — Phase B6: Storage Abuse & Filesystem Edge Case Tests.

Tests behavior under storage exhaustion, permission failures,
missing directories, and filesystem edge cases.

Note: Some tests require OS-level operations and will be skipped
on platforms where they cannot be safely reproduced (e.g., when
running as admin without safe sandbox).
"""
import io
import os
import stat
import shutil
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def storage_test_case():
    resp = client.post("/cases", json={"workflow": "FORENSIC", "title": "Storage Abuse Tests"})
    assert resp.status_code == 200
    cid = resp.json()["case_id"]
    # Upload a small valid image
    client.post(
        f"/cases/{cid}/upload",
        files={"file": ("storage_test.img", io.BytesIO(b"\x00" * 4096), "application/octet-stream")},
    )
    return cid


# ── B6.1: Recovery on zero-byte image ─────────────────────────────────────────

def test_recovery_on_zero_byte_image():
    """Carving on a zero-byte upload must return 0 artifacts, not crash."""
    resp_case = client.post("/cases", json={"workflow": "FORENSIC", "title": "Zero byte recovery"})
    cid = resp_case.json()["case_id"]
    # Upload a zero-byte file
    resp_up = client.post(
        f"/cases/{cid}/upload",
        files={"file": ("empty.img", io.BytesIO(b""), "application/octet-stream")},
    )
    assert resp_up.status_code == 200
    assert resp_up.json()["size_bytes"] == 0

    # Carving must handle it gracefully
    resp_rec = client.post(f"/cases/{cid}/carve", json={})
    assert resp_rec.status_code == 200
    data = resp_rec.json()
    # Must return 0 artifacts — not crash
    assert data.get("total_carved", 0) == 0 or data.get("artifacts_found", 0) == 0


# ── B6.2: Recovery on all-zeros image ─────────────────────────────────────────

def test_recovery_on_all_zeros_image():
    """Carving on all-zero image must return 0 artifacts, not crash."""
    resp_case = client.post("/cases", json={"workflow": "FORENSIC", "title": "All zeros recovery"})
    cid = resp_case.json()["case_id"]
    resp_up = client.post(
        f"/cases/{cid}/upload",
        files={"file": ("zeros.img", io.BytesIO(b"\x00" * 65536), "application/octet-stream")},
    )
    assert resp_up.status_code == 200

    resp_rec = client.post(f"/cases/{cid}/carve", json={})
    assert resp_rec.status_code == 200
    data = resp_rec.json()
    assert data.get("total_carved", 0) == 0 or data.get("artifacts_found", 0) == 0


# ── B6.3: False magic bytes — must be rejected by validation ──────────────────

def test_recovery_false_magic_bytes():
    """Data with JPEG magic bytes but invalid body must not be validated as VALID."""
    # JPEG header + garbage that fails structural validation
    bad_data = b"\xFF\xD8\xFF\xE0" + b"\xDE\xAD\xBE\xEF" * 512 + b"\xFF\xD9"
    # Wrap in surrounding noise
    stream = b"\x00" * 4096 + bad_data + b"\x00" * 4096

    resp_case = client.post("/cases", json={"workflow": "FORENSIC", "title": "False magic test"})
    cid = resp_case.json()["case_id"]
    resp_up = client.post(
        f"/cases/{cid}/upload",
        files={"file": ("falsemag.img", io.BytesIO(stream), "application/octet-stream")},
    )
    assert resp_up.status_code == 200

    resp_rec = client.post(f"/cases/{cid}/carve", json={})
    assert resp_rec.status_code == 200
    data = resp_rec.json()
    # Any carved artifacts must either be FAILED/INVALID validation, not VERIFIED
    artifacts = data.get("artifacts", []) or data.get("carved_artifacts", [])
    for art in artifacts:
        validation = art.get("validation_result", art.get("validation", {}).get("status", ""))
        if isinstance(validation, dict):
            validation = validation.get("status", "")
        # VERIFIED should not be claimed for a corrupt artifact
        assert validation != "VERIFIED", f"False-magic artifact incorrectly marked VERIFIED: {art}"


# ── B6.4: Scope invariant — erase must not touch files outside scope ──────────

def test_erase_scope_invariant():
    """
    Erasing files within scope must not affect files outside scope.
    This validates the central scope invariant: outside target → untouched.
    """
    # Create two cases
    resp_a = client.post("/cases", json={"workflow": "SANITIZATION", "title": "Scope Case A"})
    resp_b = client.post("/cases", json={"workflow": "SANITIZATION", "title": "Scope Case B"})
    cid_a = resp_a.json()["case_id"]
    cid_b = resp_b.json()["case_id"]

    # Upload distinct content to both cases
    sentinel_b = b"CASE_B_SENTINEL_DATA_MUST_NOT_BE_TOUCHED"
    client.post(f"/cases/{cid_a}/upload",
                files={"file": ("casea.img", io.BytesIO(b"\xAA" * 512), "application/octet-stream")})
    resp_b_up = client.post(f"/cases/{cid_b}/upload",
                             files={"file": ("caseb.img", io.BytesIO(sentinel_b), "application/octet-stream")})
    assert resp_b_up.status_code == 200

    # Find Case B's uploaded file on disk
    from app.api.deps import UPLOADS_DIR
    b_files = list(UPLOADS_DIR.glob(f"{cid_b}_*"))
    if not b_files:
        pytest.skip("Could not locate Case B upload file")
    b_file = b_files[0]
    original_content = b_file.read_bytes()

    # Erase Case A's scope — should have zero effect on Case B's files
    a_files = list(UPLOADS_DIR.glob(f"{cid_a}_*"))
    if not a_files:
        pytest.skip("Could not locate Case A upload file")

    resp_erase = client.post(f"/cases/{cid_a}/erase-files", json={
        "target_paths": [str(a_files[0])],
        "operator_id": "OPR-SCOPE-TEST",
        "operator_name": "Scope Test",
        "authorization_reason": "Scope invariant test",
        "confirmed_scope_acknowledgement": True,
        "method": "ZERO_FILL",
    })
    assert resp_erase.status_code == 200

    # Case B's file must be byte-for-byte unchanged
    assert b_file.read_bytes() == original_content, (
        "SCOPE VIOLATION: Case A erase affected Case B's file"
    )


# ── B6.5: Missing uploads directory ───────────────────────────────────────────

def test_upload_creates_directory_if_missing():
    """Upload must create the uploads directory if it was deleted."""
    from app.api.deps import UPLOADS_DIR

    # Temporarily rename the uploads dir to simulate it being missing
    tmp_backup = None
    if UPLOADS_DIR.exists():
        tmp_backup = UPLOADS_DIR.parent / (UPLOADS_DIR.name + "_backup_test")
        UPLOADS_DIR.rename(tmp_backup)

    try:
        resp_case = client.post("/cases", json={"workflow": "FORENSIC", "title": "Missing dir test"})
        cid = resp_case.json()["case_id"]
        resp = client.post(
            f"/cases/{cid}/upload",
            files={"file": ("test.img", io.BytesIO(b"\x00" * 1024), "application/octet-stream")},
        )
        # Must succeed — the upload handler calls UPLOADS_DIR.mkdir(exist_ok=True)
        assert resp.status_code == 200
    finally:
        # Restore backup
        if tmp_backup and tmp_backup.exists():
            if UPLOADS_DIR.exists():
                shutil.rmtree(str(UPLOADS_DIR))
            tmp_backup.rename(UPLOADS_DIR)


# ── B6.6: Read-only source file during recovery ───────────────────────────────

def test_recovery_source_read_only(tmp_path):
    """
    When the source file is read-only, recovery should still succeed
    (it reads but does not modify the source).
    """
    img_path = tmp_path / "readonly.img"
    # Write a small JPEG + noise image
    jpeg = b"\xFF\xD8\xFF\xE0" + b"\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    jpeg += b"\xFF\xD9"
    img_path.write_bytes(b"\x00" * 4096 + jpeg + b"\x00" * 4096)

    # Make read-only
    img_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    try:
        from app.forensics.carving import carve_image_summary
        result = carve_image_summary(str(img_path))
        # Must not crash — read-only is fine for reading
        assert isinstance(result, dict)
        assert "total_carved" in result or "by_type" in result
    finally:
        # Restore write permissions for cleanup
        img_path.chmod(stat.S_IRUSR | stat.S_IWUSR)


# ── B6.7: Evidence package integrity — partial directory ──────────────────────

def test_verify_incomplete_package(tmp_path):
    """
    A partially-written evidence package (missing signature file)
    must return INVALID with a diagnostic — not crash, not return VERIFIED.
    """
    from app.core.independent_verifier import verify_evidence_package
    from app.core.signing import generate_keypair
    from app.core.package import EvidencePackageBuilder
    from cryptography.hazmat.primitives import serialization

    priv_pem, _ = generate_keypair()
    priv_obj = serialization.load_pem_private_key(priv_pem, password=None)
    pub_pem = priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    builder = EvidencePackageBuilder("CASE-PARTIAL-TEST", tmp_path)
    builder.write_source_metadata({"size": 1024})
    builder.write_recovery_artifacts({"total_carved": 1})
    pkg_meta = builder.build_and_sign(priv_pem, pub_pem, "KEY-PARTIAL")
    pkg_path = Path(pkg_meta["package_path"])

    # Delete the signature file to simulate partial write
    sig_file = pkg_path / "cryptography" / "signature.json"
    if sig_file.exists():
        sig_file.unlink()

    valid, result = verify_evidence_package(pkg_path, public_key_pem=pub_pem)
    assert not valid, "CRITICAL: Verifier accepted a package with missing signature file"
    assert result.explanation, "Verifier must provide a diagnostic, not a bare failure"


# ── B6.8: Extra files injected into evidence package ─────────────────────────

def test_verify_package_with_injected_files(tmp_path):
    """
    An evidence package with extra unexpected files injected must return INVALID.
    """
    from app.core.independent_verifier import verify_evidence_package
    from app.core.signing import generate_keypair
    from app.core.package import EvidencePackageBuilder
    from cryptography.hazmat.primitives import serialization

    priv_pem, _ = generate_keypair()
    priv_obj = serialization.load_pem_private_key(priv_pem, password=None)
    pub_pem = priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    builder = EvidencePackageBuilder("CASE-INJECT-TEST", tmp_path)
    builder.write_source_metadata({"size": 512})
    builder.write_recovery_artifacts({"total_carved": 0})
    pkg_meta = builder.build_and_sign(priv_pem, pub_pem, "KEY-INJECT")
    pkg_path = Path(pkg_meta["package_path"])

    # Inject a rogue file into the package
    rogue = pkg_path / "rogue_payload.txt"
    rogue.write_text("INJECTED CONTENT")

    valid, result = verify_evidence_package(pkg_path, public_key_pem=pub_pem)
    # Package manifest does not include the rogue file — must be INVALID
    assert not valid, "CRITICAL: Verifier accepted package with injected files"
    assert result.explanation


# ── B6.9: Wrong public key for verification ───────────────────────────────────

def test_verify_package_wrong_public_key(tmp_path):
    """
    Using a different public key for verification must return INVALID,
    not a crash or a false VERIFIED.
    """
    from app.core.independent_verifier import verify_evidence_package
    from app.core.signing import generate_keypair
    from app.core.package import EvidencePackageBuilder
    from cryptography.hazmat.primitives import serialization

    priv_pem, _ = generate_keypair()
    priv_obj = serialization.load_pem_private_key(priv_pem, password=None)
    pub_pem_correct = priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Generate a completely different keypair
    priv_pem_wrong, _ = generate_keypair()
    priv_obj_wrong = serialization.load_pem_private_key(priv_pem_wrong, password=None)
    pub_pem_wrong = priv_obj_wrong.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    builder = EvidencePackageBuilder("CASE-WRONG-KEY-TEST", tmp_path)
    builder.write_source_metadata({"size": 256})
    builder.write_recovery_artifacts({"total_carved": 0})
    pkg_meta = builder.build_and_sign(priv_pem, pub_pem_correct, "KEY-CORRECT")
    pkg_path = Path(pkg_meta["package_path"])

    valid, result = verify_evidence_package(pkg_path, public_key_pem=pub_pem_wrong)
    assert not valid, "CRITICAL: Verifier accepted package verified with wrong public key"
    assert result.explanation
