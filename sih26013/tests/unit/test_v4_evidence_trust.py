import pytest
import copy
from app.core.hashing import sha256_canonical
from app.core.signing import get_signing_key, get_registry
from app.core.evidence_envelope import build_evidence_payload, sign_evidence, verify_envelope

def test_canonical_hash_deterministic():
    obj1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
    obj2 = {"a": 1, "c": [3, 2, 1], "b": 2}
    h1 = sha256_canonical(obj1)
    h2 = sha256_canonical(obj2)
    assert h1 == h2

def test_sign_and_verify_valid():
    key = get_signing_key()
    registry = get_registry()
    payload = build_evidence_payload(
        comparison_id="CMP-001",
        case_id="CASE-001",
        record_ids=["REC-A", "REC-B"],
        geo_classification="GEOMETRIC_CONFLICT",
        geo_measurements={"conflict": True, "iou": 0.4},
        temporal_result={"gap_days": 2.0, "qualified": False},
        crs_result={"ok": True},
        provenance_result={"independent_lineages": 1, "is_independent": False},
        independent_lineages=1,
        explanation="Test explanation"
    )
    env = sign_evidence(payload, key)
    assert env["signature"] is not None
    assert env["signing"]["algorithm"] == "Ed25519"

    is_valid, msg = verify_envelope(env, registry)
    assert is_valid is True
    assert "verified" in msg.lower()

def test_tamper_detection_on_lineage_count():
    key = get_signing_key()
    registry = get_registry()
    payload = build_evidence_payload(
        comparison_id="CMP-001",
        case_id="CASE-001",
        record_ids=["REC-A", "REC-B"],
        geo_classification="GEOMETRIC_CONFLICT",
        geo_measurements={"conflict": True, "iou": 0.4},
        temporal_result={"gap_days": 2.0, "qualified": False},
        crs_result={"ok": True},
        provenance_result={"independent_lineages": 1, "is_independent": False},
        independent_lineages=1,
        explanation="Test explanation"
    )
    env = sign_evidence(payload, key)

    # Attack: forge independent_lineages from 1 to 3
    tampered = copy.deepcopy(env)
    tampered["result"]["independent_lineages"] = 3

    is_valid, msg = verify_envelope(tampered, registry)
    assert is_valid is False
    assert "tamper" in msg.lower() or "mismatch" in msg.lower()

def test_unknown_key_id_rejected():
    key = get_signing_key()
    registry = get_registry()
    payload = build_evidence_payload(
        comparison_id="CMP-002",
        case_id="CASE-002",
        record_ids=["REC-1"],
        geo_classification="NO_CONFLICT",
        geo_measurements={},
        temporal_result={},
        crs_result={},
        provenance_result={},
        independent_lineages=0,
        explanation=""
    )
    env = sign_evidence(payload, key)

    # Tamper with key_id
    env["signing"]["key_id"] = "ROGUE-KEY-999"
    is_valid, msg = verify_envelope(env, registry)
    assert is_valid is False
    assert "untrusted" in msg.lower() or "unknown" in msg.lower() or "not registered" in msg.lower()

def test_unknown_result_signed_and_verifiable():
    key = get_signing_key()
    registry = get_registry()
    payload = build_evidence_payload(
        comparison_id="CMP-UNK",
        case_id="CASE-UNKNOWN",
        record_ids=["REC-U1", "REC-U2"],
        geo_classification="UNKNOWN",
        geo_measurements={"conflict": False, "iou": 1.0},
        temporal_result={"valid": True, "qualified": False},
        crs_result={"ok": True},
        provenance_result={"independent_lineages": 0, "unknown": True},
        independent_lineages=0,
        explanation="Provenance missing - cannot establish truth"
    )
    env = sign_evidence(payload, key)
    is_valid, msg = verify_envelope(env, registry)
    assert is_valid is True
    assert env["result"]["provenance"]["unknown"] is True
