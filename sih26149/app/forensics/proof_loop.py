"""
SIH26149 — Forensic Proof Loop & Validation Probe Engine.

Sequential Proof Loop Architecture:
  1. KNOWN TEST EVIDENCE (Seed synthetic media with known artifacts)
  2. PRE-SANITIZATION RECOVERY (Perform initial carving scan)
  3. SANITIZATION (Apply selected wipe method: Clear/Purge/Destroy)
  4. POST-SANITIZATION RECOVERY PROBE (Perform secondary carving scan on sanitized stream)
  5. COMPARISON & DIFFERENTIAL ANALYSIS
  6. VERIFICATION (Confirms operation executed successfully) vs. VALIDATION (Confirms required assurance level achieved)
  7. SIGNED ASSURANCE REPORT
"""
import time
import hashlib
from typing import Dict, Any, List
from app.forensics.carving import carve_image_summary
from app.core.evidence_envelope import build_evidence_payload, sign_evidence_envelope, new_operation_id, new_evidence_id
from app.api.deps import get_or_create_primary_key


def execute_forensic_proof_loop(
    raw_bytes: bytes,
    method: str = "CLEAR",
    case_id: str = "PROOF-LOOP-CASE",
    data_sensitivity: str = "CONFIDENTIAL",
) -> Dict[str, Any]:
    """
    Executes the closed-loop forensic assurance workflow on a provided or synthetic disk stream.
    Returns complete sequential proof metrics, differential findings, verification/validation results,
    and a signed evidence payload.
    """
    t0 = time.time()

    # 1. KNOWN TEST EVIDENCE INITIALIZATION
    media_size = len(raw_bytes)
    initial_hash = hashlib.sha256(raw_bytes).hexdigest()

    # 2. PRE-SANITIZATION RECOVERY (STAGE 1)
    t_pre_start = time.time()
    pre_carve_summary = carve_image_summary(raw_bytes, target_types=None, max_results=100)
    pre_carve_time_ms = round((time.time() - t_pre_start) * 1000, 2)
    pre_artifacts_found = pre_carve_summary.get("total_carved", 0)

    # 3. SANITIZATION EXECUTION (STAGE 2)
    t_san_start = time.time()
    san_method = method.upper() if method.upper() in ["CLEAR", "PURGE", "DESTROY"] else "CLEAR"
    
    if san_method == "PURGE" or san_method == "DESTROY":
        # Crypto erase or block overwrite simulation: replace stream with crypto pseudo-random bytes
        import secrets
        sanitized_bytes = secrets.token_bytes(media_size)
    else:
        # Clear: overwrite stream with zero bytes
        sanitized_bytes = b'\x00' * media_size

    san_time_ms = round((time.time() - t_san_start) * 1000, 2)
    post_hash = hashlib.sha256(sanitized_bytes).hexdigest()

    # 4. POST-SANITIZATION RECOVERY PROBE (STAGE 3)
    t_post_start = time.time()
    post_carve_summary = carve_image_summary(sanitized_bytes, target_types=None, max_results=100)
    post_carve_time_ms = round((time.time() - t_post_start) * 1000, 2)
    post_artifacts_found = post_carve_summary.get("total_carved", 0)

    # 5. BEFORE / AFTER COMPARISON & DIFFERENTIAL ANALYSIS
    eliminated_artifacts = max(0, pre_artifacts_found - post_artifacts_found)
    erasure_rate = 1.0 if pre_artifacts_found == 0 else (eliminated_artifacts / pre_artifacts_found)

    # 6. VERIFICATION vs VALIDATION DISTINCTION
    # Verification: Did the sanitization function run without exception and alter the media?
    verification_passed = (initial_hash != post_hash) or (media_size == 0)
    verification_notes = (
        "Sanitization process executed cleanly; hash shift confirmed."
        if verification_passed else
        "Verification failed: post-sanitization hash identical to pre-sanitization."
    )

    # Validation: Is post-sanitization recovery count 0 for the selected sensitivity level?
    validation_passed = (post_artifacts_found == 0)
    if validation_passed:
        validation_status = "VALIDATED_ZERO_RECOVERABLE"
        validation_notes = (
            f"Validation Probe Confirmed: 0 / {pre_artifacts_found} pre-existing artifacts recoverable "
            f"under {san_method} method for {data_sensitivity} sensitivity."
        )
    else:
        validation_status = "VALIDATION_FAILED_RESIDUAL_ARTIFACTS"
        validation_notes = (
            f"Validation Warning: {post_artifacts_found} residual artifact(s) detected after {san_method} execution. "
            "Higher sanitization level (PURGE/DESTROY) required."
        )

    total_duration_ms = round((time.time() - t0) * 1000, 2)

    # 7. SIGNED ASSURANCE PACKAGE
    op_id = new_operation_id()
    ev_id = new_evidence_id()
    
    proof_result = {
        "proof_loop_status": "SUCCESS" if (verification_passed and validation_passed) else "WARNING",
        "case_id": case_id,
        "method_requested": san_method,
        "data_sensitivity": data_sensitivity,
        "media_size_bytes": media_size,
        "pre_sanitization": {
            "sha256": initial_hash,
            "artifacts_found": pre_artifacts_found,
            "by_type": pre_carve_summary.get("by_type", {}),
            "scan_time_ms": pre_carve_time_ms,
        },
        "sanitization_execution": {
            "method_applied": san_method,
            "post_sha256": post_hash,
            "passes_completed": 1,
            "execution_time_ms": san_time_ms,
        },
        "post_sanitization_probe": {
            "artifacts_recovered": post_artifacts_found,
            "probe_time_ms": post_carve_time_ms,
            "by_type": post_carve_summary.get("by_type", {}),
        },
        "differential": {
            "artifacts_eliminated": eliminated_artifacts,
            "erasure_percentage": round(erasure_rate * 100, 1),
        },
        "assurance": {
            "verification": {
                "passed": verification_passed,
                "detail": verification_notes,
            },
            "validation": {
                "status": validation_status,
                "passed": validation_passed,
                "detail": validation_notes,
            },
            "decision_logic_reference": "Decision logic informed by NIST SP 800-88 Rev. 2 and IEEE 2883-2022 standards.",
        },
        "execution_duration_total_ms": total_duration_ms,
    }

    # Build signed Ed25519 payload
    payload = build_evidence_payload(
        case_id=case_id,
        operation_id=op_id,
        evidence_type="SANITIZATION_PROOF_LOOP",
        input_meta={
            "initial_hash": initial_hash,
            "sanitization_method": san_method,
            "media_size_bytes": media_size,
        },
        operation_meta={
            "operation_type": "PROOF_LOOP_VALIDATION",
            "passes": 1,
        },
        result_meta=proof_result,
        scope=f"Controlled Validation Probe ({data_sensitivity})",
        key_id="PRIMARY-ED25519",
        evidence_id=ev_id,
    )
    
    key_id, priv_key = get_or_create_primary_key()
    signed_pkg = sign_evidence_envelope(payload, priv_key)

    return {
        "proof_result": proof_result,
        "signed_evidence": signed_pkg,
    }


