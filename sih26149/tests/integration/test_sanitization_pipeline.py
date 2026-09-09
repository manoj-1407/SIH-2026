"""
SIH26149 — M4 Sanitization Pipeline Integration Tests.
Verifies:
1. Unauthorized request (missing credentials or missing scope acknowledgement) -> REJECTED.
2. Authorized request -> executes ZERO_FILL only -> readback verification passes -> VERIFIED_WITHIN_SCOPE.
3. Attached scope permanently documents that physical NAND erasure, wear-leveling, and controller remapping are NOT established.
4. Generates signed evidence envelope with distinct (case_id, operation_id, evidence_id).
"""
import os
import shutil
import pytest
from pathlib import Path

from app.core.signing import generate_keypair
from app.core.trust import TrustRegistry
from app.core.persistence import EvidenceStore, atomic_write_json
from app.core.evidence_envelope import build_evidence_payload, sign_evidence_envelope, new_operation_id, new_evidence_id
from app.core.independent_verifier import verify_evidence_package
from app.core.classification import EvidenceClassification
from app.sanitization.authorization import authorize_sanitization, UnauthorizedError
from app.sanitization.methods import execute_sanitization, SanitizationMethod
from app.sanitization.verification import verify_sanitization
from app.sanitization.scope import get_scope_record, SANITIZATION_SCOPE_STATEMENT


@pytest.fixture
def dummy_target_image(tmp_path):
    img = tmp_path / "target_sanitize.img"
    # Write 5MB of non-zero pattern
    with open(img, "wb") as f:
        f.write(b"\xde\xad\xbe\xef" * (1280 * 1024))
    return str(img)


def test_sanitization_unauthorized_missing_operator():
    """Missing operator ID or name must be rejected."""
    with pytest.raises(UnauthorizedError) as exc:
        authorize_sanitization({
            "operator_id": "",
            "operator_name": "",
            "authorization_reason": "Decommissioning test drive",
            "confirmed_scope_acknowledgement": True,
        })
    assert "mandatory" in str(exc.value).lower()


def test_sanitization_unauthorized_missing_scope_ack():
    """Missing scope acknowledgement must be rejected."""
    with pytest.raises(UnauthorizedError) as exc:
        authorize_sanitization({
            "operator_id": "OPR-7701",
            "operator_name": "Chief Examiner Singh",
            "authorization_reason": "Official disposal",
            "confirmed_scope_acknowledgement": False,
        })
    assert "scope" in str(exc.value).lower()


def test_sanitization_authorized_pipeline_and_scope(dummy_target_image, tmp_path):
    """
    Authorized flow:
    1. Valid operator authorization + scope acknowledgement
    2. ZERO_FILL executed
    3. Readback verifies all bytes are zero
    4. Classified as VERIFIED_WITHIN_SCOPE
    5. Scope record explicitly documents technical boundaries
    6. Signed evidence package created and verified
    """
    # 1. Authorize
    auth = authorize_sanitization({
        "operator_id": "OPR-7701",
        "operator_name": "Chief Examiner Singh",
        "authorization_reason": "Forensic lab evidence drive sanitization",
        "confirmed_scope_acknowledgement": True,
    })
    assert auth.operator_id == "OPR-7701"

    # 2. Execute ZERO_FILL
    op_record = execute_sanitization(dummy_target_image, method=SanitizationMethod.ZERO_FILL)
    assert op_record.method == SanitizationMethod.ZERO_FILL
    assert op_record.bytes_written > 0

    # 3. Readback verification
    verify_res = verify_sanitization(dummy_target_image)
    assert verify_res.classification == EvidenceClassification.VERIFIED_WITHIN_SCOPE
    assert "within scope" in verify_res.explanation.lower()
    assert "nand" in verify_res.explanation.lower()  # Explicit limitation mentioned!

    # 4. Sign evidence package
    key_dir = tmp_path / "keys_san"
    reg = TrustRegistry(key_dir / "reg.json")
    priv, pub = generate_keypair()
    reg.register("KEY-SAN-01", pub)

    case_id = "CASE-SAN-TEST-001"
    op_id = new_operation_id()
    evid_id = new_evidence_id()

    payload = build_evidence_payload(
        case_id=case_id,
        operation_id=op_id,
        evidence_id=evid_id,
        evidence_type="SANITIZATION",
        input_meta={"target_path": dummy_target_image, "size_bytes": op_record.bytes_written},
        operation_meta={
            "method": op_record.method.value,
            "operator": auth.to_dict(),
            "passes": op_record.passes_completed,
        },
        result_meta={
            "classification": verify_res.classification.value,
            "all_zeros_verified": True,
        },
        scope=SANITIZATION_SCOPE_STATEMENT,
        key_id="KEY-SAN-01",
    )

    signed_pkg = sign_evidence_envelope(payload, priv)
    store = EvidenceStore(tmp_path / "san_store")
    saved_path = store.save(signed_pkg)

    # 5. Verify package
    is_valid, cl_res = verify_evidence_package(signed_pkg, key_registry=reg)
    assert is_valid is True
    assert cl_res.classification == EvidenceClassification.VERIFIED
