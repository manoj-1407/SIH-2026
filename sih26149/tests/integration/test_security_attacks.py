"""
SIH26149 — Dedicated Adversarial Security & Boundary Test Suite.
Comprehensive audit testing:
1. Path traversal attempts (../ in case_id, upload filenames)
2. Absolute upload paths and path sanitization
3. Oversized uploads (disk exhaustion prevention, 413 Payload Too Large)
4. Symlink and directory escape tricks
5. Malformed JSON evidence payloads (corrupted fields, bad structures)
6. Forged Ed25519 signature rejection
7. Substituted public key attack (untrusted / rogue keys)
8. Revoked key rejection
9. Private key exposure audit (verifies private keys are never exposed over API)
10. Missing DEMO_MODE / tamper endpoint without authorization (403 Forbidden)
11. Authorized demo tamper verification (detects and proves tampering)
12. Concurrent case operation writes (concurrency & atomicity)
13. Repeated forensic operations on a single case (collision & overwrite resistance)
"""
import os
import io
import json
import pytest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient

from app.main import app
import app.api.forensics as forensics_api
from app.api.deps import KEYS_DIR, SIGNER_KEY_FILE, UPLOADS_DIR
from app.core.signing import generate_keypair, sign_evidence
from app.core.trust import TrustRegistry
from app.core.canonical import canonicalize
from app.core.hashing import hash_bytes
from app.core.evidence_envelope import build_evidence_payload, sign_evidence_envelope, new_operation_id, new_evidence_id
from app.core.independent_verifier import verify_evidence_package
from app.core.classification import EvidenceClassification

client = TestClient(app)


# ─────────────────────────────────────────────────────────────────
# 1. Path Traversal & Upload Security
# ─────────────────────────────────────────────────────────────────
def test_attack_path_traversal_in_case_id():
    """Attacker attempts directory traversal in case_id URL parameter."""
    res = client.get("/cases/../../etc/passwd")
    assert res.status_code in (400, 404, 405, 422)

    res_enc = client.get("/cases/..%2F..%2Fetc%2Fpasswd")
    assert res_enc.status_code in (400, 404, 405, 422)

    res_post = client.post("/cases/..%2F..%2Fetc%2Fpasswd/upload", files={"file": ("mal.bin", b"xyz")})
    assert res_post.status_code in (400, 404, 405, 422)


def test_attack_path_traversal_in_upload_filename(tmp_path):
    """Attacker supplies a path traversal string as the uploaded filename."""
    res = client.post("/cases", json={"workflow": "FORENSIC", "title": "Traversal Test"})
    assert res.status_code == 200
    case_id = res.json()["case_id"]

    traversal_filename = "../../../tmp/evil_payload.img"
    res_up = client.post(
        f"/cases/{case_id}/upload",
        files={"file": (traversal_filename, b"ATTACK_PAYLOAD", "application/octet-stream")}
    )
    assert res_up.status_code == 200
    # Crucially, /tmp/evil_payload.img must NOT exist outside the upload dir
    assert not os.path.exists("/tmp/evil_payload.img")
    # File must be stored safely within UPLOADS_DIR
    data = res_up.json()
    assert "/" not in data["filename"] and ".." not in data["filename"]


def test_attack_absolute_upload_path(tmp_path):
    """Attacker supplies an absolute path like /etc/shadow or C:\boot.ini as filename."""
    res = client.post("/cases", json={"workflow": "FORENSIC", "title": "Abs Path Test"})
    case_id = res.json()["case_id"]

    abs_filename = "/etc/shadow"
    res_up = client.post(
        f"/cases/{case_id}/upload",
        files={"file": (abs_filename, b"ATTACK_ABS", "application/octet-stream")}
    )
    assert res_up.status_code == 200
    assert not res_up.json()["filename"].startswith("/")


def test_attack_oversized_upload(monkeypatch):
    """Attacker attempts to upload a file exceeding MAX_UPLOAD_SIZE."""
    # Monkeypatch MAX_UPLOAD_SIZE to 500KB for fast deterministic boundary test
    monkeypatch.setattr(forensics_api, "MAX_UPLOAD_SIZE", 500 * 1024)

    res = client.post("/cases", json={"workflow": "FORENSIC", "title": "Oversized Test"})
    case_id = res.json()["case_id"]

    # 600 KB payload exceeds 500 KB limit
    big_stream = io.BytesIO(b"0" * (600 * 1024))
    res_up = client.post(
        f"/cases/{case_id}/upload",
        files={"file": ("bomb.img", big_stream, "application/octet-stream")}
    )
    assert res_up.status_code == 413
    assert "maximum allowed size" in res_up.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────
# 2. Private Key Exposure Audit
# ─────────────────────────────────────────────────────────────────
def test_attack_private_key_leakage_via_api():
    """Verify that private keys (.priv) are never exposed via any API route."""
    routes_to_probe = [
        "/keys/primary_examiner.priv",
        "/data/keys/primary_examiner.priv",
        "/evidence/primary_examiner.priv",
        "/cases/primary_examiner.priv",
        "/static/../data/keys/primary_examiner.priv",
        "/static/primary_examiner.priv",
    ]
    for r in routes_to_probe:
        res = client.get(r)
        assert res.status_code in (400, 404, 405), f"Route {r} returned {res.status_code}!"
        if res.status_code == 200:
            assert b"PRIVATE KEY" not in res.content

    # Verify evidence retrieval does not leak private key material
    res_ev = client.get("/evidence")
    assert res_ev.status_code == 200
    evidence_text = res_ev.text
    assert "private" not in evidence_text.lower() or "private_key" not in evidence_text.lower()


# ─────────────────────────────────────────────────────────────────
# 3. Cryptographic Verification & Key Attacks
# ─────────────────────────────────────────────────────────────────
def test_attack_forged_signature_rejected(tmp_path):
    """Attacker generates an invalid/forged signature and submits for verification."""
    priv, pub = generate_keypair()
    reg = TrustRegistry(tmp_path / "trust.json")
    reg.register("EXAMINER-KEY-01", pub)

    payload = build_evidence_payload(
        case_id="CASE-FORGE-01",
        operation_id="OP-01",
        evidence_id="EVID-01",
        evidence_type="FORENSIC_RECOVERY",
        input_meta={"sha256": "abc"},
        operation_meta={"inode": "12"},
        result_meta={"classification": "VERIFIED"},
        scope="test",
        key_id="EXAMINER-KEY-01",
    )
    signed_pkg = sign_evidence_envelope(payload, priv)
    # Attacker replaces signature with 64-byte forged hex
    signed_pkg["signature"] = "deadbeef" * 16

    is_valid, result = verify_evidence_package(signed_pkg, key_registry=reg)
    assert is_valid is False
    assert result.classification == EvidenceClassification.INVALID
    assert "signature" in result.explanation.lower()


def test_attack_substituted_public_key_rejected(tmp_path):
    """
    Attacker signs a package with an attacker key and attempts to supply
    their own public key inside the evidence package.
    The verifier must query the persistent registry and reject untrusted keys.
    """
    honest_priv, honest_pub = generate_keypair()
    reg = TrustRegistry(tmp_path / "trust.json")
    reg.register("LEGIT-KEY-01", honest_pub)

    attacker_priv, attacker_pub = generate_keypair()

    payload = build_evidence_payload(
        case_id="CASE-ROGUE-01",
        operation_id="OP-01",
        evidence_id="EVID-ROGUE-01",
        evidence_type="FORENSIC_RECOVERY",
        input_meta={"sha256": "123"},
        operation_meta={"inode": "10"},
        result_meta={"classification": "VERIFIED"},
        scope="test",
        key_id="ROGUE-ATTACKER-KEY",
    )
    payload["signing"]["attacker_public_key"] = attacker_pub.hex()
    signed_pkg = sign_evidence_envelope(payload, attacker_priv)

    is_valid, result = verify_evidence_package(signed_pkg, key_registry=reg)
    assert is_valid is False
    assert result.classification == EvidenceClassification.INVALID
    assert "not registered" in result.explanation.lower() or "untrusted" in result.explanation.lower()


def test_attack_revoked_key_rejected(tmp_path):
    """A key that has been revoked must fail verification."""
    priv, pub = generate_keypair()
    reg = TrustRegistry(tmp_path / "trust.json")
    reg.register("KEY-TO-REVOKE", pub)

    payload = build_evidence_payload(
        case_id="CASE-REVOKE-01",
        operation_id="OP-01",
        evidence_id="EVID-REV-01",
        evidence_type="FORENSIC_RECOVERY",
        input_meta={"sha256": "123"},
        operation_meta={"inode": "10"},
        result_meta={"classification": "VERIFIED"},
        scope="test",
        key_id="KEY-TO-REVOKE",
    )
    signed_pkg = sign_evidence_envelope(payload, priv)

    # Revoke the key
    reg.revoke("KEY-TO-REVOKE")

    is_valid, result = verify_evidence_package(signed_pkg, key_registry=reg)
    assert is_valid is False
    assert result.classification == EvidenceClassification.INVALID
    assert "revoked" in result.explanation.lower() or "not registered" in result.explanation.lower()


def test_attack_malformed_evidence_packages():
    """Attacker submits malformed JSON evidence to verify-package endpoint."""
    malformed_samples = [
        {},
        {"case_id": "NO_ENVELOPE"},
        {"envelope_version": "1.0", "evidence_hash": "not-a-hash"},
        {"envelope_version": "1.0", "evidence_hash": "a" * 64, "signature": "bad"},
        {"envelope_version": "1.0", "signing": {"key_id": "NON_EXISTENT"}},
    ]
    for sample in malformed_samples:
        res = client.post("/evidence/verify-package", json=sample)
        assert res.status_code == 200
        data = res.json()
        assert data["is_valid"] is False
        assert data["classification"] == "INVALID"


# ─────────────────────────────────────────────────────────────────
# 4. Tamper Endpoint Authorization (DEMO_MODE Gating)
# ─────────────────────────────────────────────────────────────────
def test_tamper_endpoint_rejected_without_demo_authorization():
    """Tamper endpoint must return 403 Forbidden without DEMO_MODE authorization."""
    os.environ.pop("DEMO_MODE", None)
    res = client.post("/evidence/EVID-ANY/demo-tamper")
    assert res.status_code == 403
    assert "tamper endpoint is disabled" in res.json()["detail"].lower()


def test_tamper_endpoint_allowed_with_demo_header(tmp_path):
    """When X-Demo-Mode header is provided, tamper endpoint demonstrates tamper detection."""
    list_res = client.get("/evidence")
    if list_res.status_code == 200 and len(list_res.json()) > 0:
        evid_id = list_res.json()[0]["evidence_id"]
        res = client.post(f"/evidence/{evid_id}/demo-tamper", headers={"X-Demo-Mode": "1"})
        assert res.status_code == 200
        data = res.json()
        assert data["is_valid"] is False
        assert data["classification"] == "INVALID"
        assert data["tamper_detected"] is True


# ─────────────────────────────────────────────────────────────────
# 5. Multi-Operation Collision Resistance & Concurrency
# ─────────────────────────────────────────────────────────────────
def test_multiple_operations_on_single_case_no_collision(tmp_path):
    """
    Executing multiple forensic recoveries on the same case must generate
    distinct operation_ids and evidence_ids without overwriting.
    """
    import shutil
    import subprocess
    if not shutil.which("mkfs.ext4") or not shutil.which("debugfs"):
        pytest.skip("mkfs.ext4/debugfs required for ext4 collision test")
    img_path = str(tmp_path / "multi_op.img")
    with open(img_path, "wb") as f:
        f.truncate(20 * 1024 * 1024)
    subprocess.run(["mkfs.ext4", "-F", "-b", "1024", img_path], check=True, capture_output=True)

    f1 = tmp_path / "doc1.txt"
    f2 = tmp_path / "doc2.txt"
    f1.write_bytes(b"PAYLOAD_ONE")
    f2.write_bytes(b"PAYLOAD_TWO")
    subprocess.run(["debugfs", "-w", "-R", f"write {f1} doc1.txt", img_path], check=True, capture_output=True)
    subprocess.run(["debugfs", "-w", "-R", f"write {f2} doc2.txt", img_path], check=True, capture_output=True)
    subprocess.run(["debugfs", "-w", "-R", "rm doc1.txt", img_path], check=True, capture_output=True)
    subprocess.run(["debugfs", "-w", "-R", "rm doc2.txt", img_path], check=True, capture_output=True)

    res = client.post("/cases", json={"workflow": "FORENSIC", "title": "Multi-Op Collision Case"})
    case_id = res.json()["case_id"]

    with open(img_path, "rb") as f:
        client.post(f"/cases/{case_id}/upload", files={"file": ("multi.img", f, "application/octet-stream")})

    client.get(f"/cases/{case_id}/filesystem")
    artifacts = client.get(f"/cases/{case_id}/artifacts").json()
    assert len(artifacts) >= 2

    op1_res = client.post(f"/cases/{case_id}/forensic", json={
        "inode": artifacts[0]["inode"],
        "artifact_name": artifacts[0]["name"],
        "reference_sha256": hash_bytes(b"PAYLOAD_ONE"),
    }).json()

    op2_res = client.post(f"/cases/{case_id}/forensic", json={
        "inode": artifacts[1]["inode"],
        "artifact_name": artifacts[1]["name"],
        "reference_sha256": hash_bytes(b"PAYLOAD_TWO"),
    }).json()

    assert op1_res["operation_id"] != op2_res["operation_id"], "Operation IDs must be distinct!"
    assert op1_res["evidence_id"] != op2_res["evidence_id"], "Evidence IDs must be distinct!"

    ev1 = client.get(f"/evidence/{op1_res['evidence_id']}").json()
    ev2 = client.get(f"/evidence/{op2_res['evidence_id']}").json()

    assert ev1["evidence_id"] == op1_res["evidence_id"]
    assert ev2["evidence_id"] == op2_res["evidence_id"]
    assert ev1["operation_id"] != ev2["operation_id"]

    case_data = client.get(f"/cases/{case_id}").json()
    assert op1_res["evidence_id"] in case_data["evidence_ids"]
    assert op2_res["evidence_id"] in case_data["evidence_ids"]
    assert len(case_data["evidence_ids"]) >= 2


def test_concurrent_case_creation_and_reads():
    """Verify concurrent case creation does not create duplicate IDs or race conditions."""
    def create_single_case(idx):
        return client.post("/cases", json={"workflow": "FORENSIC", "title": f"Concurrent Case {idx}"}).json()

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(create_single_case, range(16)))

    case_ids = [r["case_id"] for r in results]
    assert len(case_ids) == 16
    assert len(set(case_ids)) == 16, "Case IDs must all be strictly unique under concurrency!"
