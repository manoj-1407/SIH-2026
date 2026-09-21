"""
Comprehensive Adversarial Mutation & Tamper Detection Test Suite — SIH26149.

Tests all 11 adversarial attack vectors against the Independent Evidence Verifier:
1. Untouched evidence package -> VALID
2. Modified record/manifest field -> INVALID
3. Modified evidence hash -> INVALID
4. Modified signature -> INVALID
5. Wrong / Rogue public key -> INVALID
6. Truncated package / missing mandatory files -> INVALID
7. Deleted audit event -> INVALID (Chain Break)
8. Reordered audit events -> INVALID (Chain Break)
9. Duplicate audit event -> INVALID (Chain Break)
10. Modified timestamp -> INVALID
11. Modified artifact payload bytes -> INVALID
"""
import os
import json
import copy
import pytest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.signing import generate_keypair, sign_evidence
from app.core.canonical import canonicalize
from app.core.hashing import hash_bytes, hash_file
from app.core.package import EvidencePackageBuilder
from app.core.independent_verifier import verify_evidence_package, verify_envelope_dict, verify_directory_package
from app.core.classification import EvidenceClassification


@pytest.fixture
def keypair():
    priv_pem, pub_raw = generate_keypair()
    # Also generate public pem
    priv_obj = serialization.load_pem_private_key(priv_pem, password=None)
    pub_pem = priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {"priv_pem": priv_pem, "pub_raw": pub_raw, "pub_pem": pub_pem}


@pytest.fixture
def valid_package(tmp_path, keypair):
    builder = EvidencePackageBuilder("CASE-ADV-01", tmp_path)
    builder.write_source_metadata({
        "source_path": "/evidence/disk.raw",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "size_bytes": 1048576,
    })
    builder.write_recovery_artifacts({"total_carved": 2}, [
        {"offset": 1024, "type": "JPEG", "sha256": "aaa111"},
        {"offset": 4096, "type": "PNG", "sha256": "bbb222"},
    ])
    builder.write_sanitization_result({
        "target": "/dev/sdb",
        "method": "CLEAR_ZERO_FILL",
        "verified": True,
    })
    # Write sample audit chain
    ev1 = {
        "entry_index": 0, "previous_hash": "GENESIS", "event_type": "CASE_CREATED",
        "details": {"title": "Test"}
    }
    ev1["entry_hash"] = hash_bytes(canonicalize(ev1))
    ev2 = {
        "entry_index": 1, "previous_hash": ev1["entry_hash"], "event_type": "SOURCE_HASHED",
        "details": {"hash": "e3b0c442..."}
    }
    ev2["entry_hash"] = hash_bytes(canonicalize(ev2))
    
    audit_file = tmp_path / "events.jsonl"
    audit_file.write_text(json.dumps(ev1) + "\n" + json.dumps(ev2) + "\n", encoding='utf-8')
    builder.copy_audit_log(audit_file)

    meta = builder.build_and_sign(
        private_key_pem=keypair["priv_pem"],
        public_key_pem=keypair["pub_pem"],
        key_id="KEY-NTRO-PRIMARY"
    )
    return Path(meta["package_path"])


# ── Test 1: Untouched valid package ─────────────────────────────────────────────
def test_adversarial_1_valid_package(valid_package, keypair):
    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is True
    assert res.classification == EvidenceClassification.VERIFIED


# ── Test 2: Modified manifest field ─────────────────────────────────────────────
def test_adversarial_2_modified_manifest(valid_package, keypair):
    manifest_p = valid_package / "manifest.json"
    data = json.loads(manifest_p.read_text(encoding='utf-8'))
    data["case_id"] = "CASE-FORGED-99"
    manifest_p.write_bytes(canonicalize(data))

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert res.classification == EvidenceClassification.INVALID
    assert "Manifest tamper detected" in res.explanation


# ── Test 3: Modified file hash in manifest ──────────────────────────────────────
def test_adversarial_3_modified_file_hash(valid_package, keypair):
    manifest_p = valid_package / "manifest.json"
    data = json.loads(manifest_p.read_text(encoding='utf-8'))
    data["file_hashes"]["source/metadata.json"] = "0000000000000000000000000000000000000000000000000000000000000000"
    manifest_p.write_bytes(canonicalize(data))

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert res.classification == EvidenceClassification.INVALID


# ── Test 4: Modified signature ──────────────────────────────────────────────────
def test_adversarial_4_modified_signature(valid_package, keypair):
    sig_p = valid_package / "cryptography" / "signature.json"
    data = json.loads(sig_p.read_text(encoding='utf-8'))
    # Invert first two hex characters
    data["signature"] = ("00" if not data["signature"].startswith("00") else "ff") + data["signature"][2:]
    sig_p.write_bytes(canonicalize(data))

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert res.classification == EvidenceClassification.INVALID


# ── Test 5: Wrong / Rogue Public Key ────────────────────────────────────────────
def test_adversarial_5_rogue_public_key(valid_package):
    _, rogue_pub_raw = generate_keypair()
    valid, res = verify_evidence_package(valid_package, public_key_bytes=rogue_pub_raw)
    assert valid is False
    assert res.classification == EvidenceClassification.INVALID


# ── Test 6: Truncated package / missing artifact file ───────────────────────────
def test_adversarial_6_missing_file(valid_package, keypair):
    target = valid_package / "source" / "metadata.json"
    if target.exists():
        target.unlink()

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert "Missing evidence package file" in res.explanation


# ── Test 7: Deleted event in audit chain ────────────────────────────────────────
def test_adversarial_7_deleted_audit_event(valid_package, keypair):
    audit_p = valid_package / "audit" / "events.jsonl"
    lines = audit_p.read_text(encoding='utf-8').splitlines()
    # Keep only second event (breaking previous_hash genesis link)
    audit_p.write_text(lines[1] + "\n", encoding='utf-8')

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert "Audit chain broken" in res.explanation or "Tamper detected" in res.explanation


# ── Test 8: Reordered events in audit chain ─────────────────────────────────────
def test_adversarial_8_reordered_audit_events(valid_package, keypair):
    audit_p = valid_package / "audit" / "events.jsonl"
    lines = audit_p.read_text(encoding='utf-8').splitlines()
    # Swap order
    audit_p.write_text(lines[1] + "\n" + lines[0] + "\n", encoding='utf-8')

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert "Audit chain broken" in res.explanation or "Tamper detected" in res.explanation


# ── Test 9: Duplicate audit event ───────────────────────────────────────────────
def test_adversarial_9_duplicate_audit_event(valid_package, keypair):
    audit_p = valid_package / "audit" / "events.jsonl"
    lines = audit_p.read_text(encoding='utf-8').splitlines()
    # Duplicate first event
    audit_p.write_text(lines[0] + "\n" + lines[0] + "\n" + lines[1] + "\n", encoding='utf-8')

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert "Audit chain broken" in res.explanation or "Tamper detected" in res.explanation


# ── Test 10: Modified timestamp in envelope ─────────────────────────────────────
def test_adversarial_10_modified_timestamp(keypair):
    priv_pem = keypair["priv_pem"]
    pub_raw = keypair["pub_raw"]

    payload = {
        "evidence_id": "EVID-001",
        "case_id": "CASE-101",
        "operation_id": "OP-101",
        "evidence_type": "FORENSIC_RECOVERY",
        "created_at_utc": "2026-09-21T10:00:00Z",
        "input": {"path": "disk.img"},
        "operation": {"type": "CARVE"},
        "result": {"count": 1},
        "scope": "CASE_INTERNAL",
        "signing": {"algorithm": "Ed25519", "key_id": "KEY-1"},
    }
    canon_bytes = canonicalize(payload)
    ev_hash = hash_bytes(canon_bytes)
    sig = sign_evidence(priv_pem, canon_bytes)

    envelope = dict(payload)
    envelope["evidence_hash"] = ev_hash
    envelope["signature"] = sig

    # Verify original
    valid, _ = verify_envelope_dict(envelope, public_key_bytes=pub_raw)
    assert valid is True

    # Mutate timestamp
    envelope["created_at_utc"] = "2026-09-21T10:05:00Z"
    valid_mut, res_mut = verify_envelope_dict(envelope, public_key_bytes=pub_raw)
    assert valid_mut is False
    assert res_mut.classification == EvidenceClassification.INVALID


# ── Test 11: Modified artifact content bytes ────────────────────────────────────
def test_adversarial_11_modified_artifact_bytes(valid_package, keypair):
    target = valid_package / "source" / "metadata.json"
    target.write_bytes(b'{"tampered_data": true}')

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert "Tamper detected in artifact file" in res.explanation


# ── Test 12: Deleted manifest file ──────────────────────────────────────────────
def test_adversarial_12_deleted_manifest(valid_package, keypair):
    manifest_p = valid_package / "manifest.json"
    manifest_p.unlink()

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert res.classification == EvidenceClassification.INVALID
    assert "Package missing manifest.json" in res.explanation


# ── Test 13: Deleted signature file ─────────────────────────────────────────────
def test_adversarial_13_deleted_signature(valid_package, keypair):
    sig_p = valid_package / "cryptography" / "signature.json"
    sig_p.unlink()

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert res.classification == EvidenceClassification.INVALID
    assert "Package missing cryptography/signature.json" in res.explanation


# ── Test 14: Substituted artifact file with different content ───────────────────
def test_adversarial_14_substituted_artifact_file(valid_package, keypair):
    # Overwrite recovery artifacts with malicious artifact
    art_p = valid_package / "recovery" / "artifacts.json"
    art_p.write_bytes(b'{"forged_recovery": true, "carved": []}')

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert res.classification == EvidenceClassification.INVALID
    assert "Tamper detected in artifact file" in res.explanation


# ── Test 15: Missing public key during directory verification ───────────────────
def test_adversarial_15_missing_public_key(valid_package):
    pub_p = valid_package / "cryptography" / "public_key.pem"
    if pub_p.exists():
        pub_p.unlink()

    valid, res = verify_evidence_package(valid_package, public_key_pem=None, public_key_bytes=None)
    assert valid is False
    assert "No public key available" in res.explanation


# ── Test 16: Path traversal attempt inside manifest file entries ────────────────
def test_adversarial_16_path_traversal_in_manifest(valid_package, keypair):
    manifest_p = valid_package / "manifest.json"
    data = json.loads(manifest_p.read_text(encoding='utf-8'))
    # Inject traversal path
    data["file_hashes"]["../../../../etc/shadow"] = "11112222333344445555666677778888"
    manifest_p.write_bytes(canonicalize(data))

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert res.classification == EvidenceClassification.INVALID


# ── Test 17: Modified scope in sanitization result ──────────────────────────────
def test_adversarial_17_modified_scope_in_sanitization(valid_package, keypair):
    san_p = valid_package / "sanitization" / "result.json"
    san_data = json.loads(san_p.read_text(encoding='utf-8'))
    san_data["target"] = "/dev/sda_ESCAPED_SCOPE"
    san_p.write_bytes(canonicalize(san_data))

    valid, res = verify_evidence_package(valid_package, public_key_pem=keypair["pub_pem"])
    assert valid is False
    assert "Tamper detected in artifact file" in res.explanation

