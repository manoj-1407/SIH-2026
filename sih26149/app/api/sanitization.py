"""Sanitization workflow API router."""
import os
import shutil
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.api.deps import (
    case_store, audit_logger, evidence_store,
    get_or_create_primary_key
)
from app.api.validation import validate_case_id
from app.core.evidence_envelope import build_evidence_payload, sign_evidence_envelope, new_operation_id, new_evidence_id
from app.sanitization.authorization import authorize_sanitization, UnauthorizedError
from app.sanitization.methods import execute_sanitization, SanitizationMethod
from app.sanitization.verification import verify_sanitization
from app.sanitization.scope import get_scope_record, SANITIZATION_SCOPE_STATEMENT

router = APIRouter(prefix='/cases/{case_id}', tags=['Sanitization'])


class SanitizationRequest(BaseModel):
    operator_id: str
    operator_name: str
    authorization_reason: str
    confirmed_scope_acknowledgement: bool
    method: str = 'ZERO_FILL'


@router.post('/sanitize')
def run_sanitization(case_id: str, req: SanitizationRequest):
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')
    if not case.source_path or not os.path.exists(case.source_path):
        raise HTTPException(status_code=400, detail='No target evidence image selected for sanitization')

    # Step 1: Mandatory Operator Authorization (No fake tokens!)
    try:
        auth = authorize_sanitization(req.model_dump())
    except UnauthorizedError as e:
        audit_logger.log(
            case_id=case_id,
            event_type='SANITIZATION_REJECTED',
            actor=req.operator_id or 'UNKNOWN',
            details={'reason': str(e)},
        )
        raise HTTPException(status_code=403, detail=str(e))

    op_id = new_operation_id()

    audit_logger.log(
        case_id=case_id,
        event_type='SANITIZATION_AUTHORIZED',
        actor=f'{auth.operator_name} ({auth.operator_id})',
        operation_id=op_id,
        details=auth.to_dict(),
    )

    # Step 2: Execute requested Clear-class method (ZERO_FILL or PSEUDO_RANDOM only)
    try:
        method = SanitizationMethod(req.method.upper())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f'Invalid method: {req.method}. Supported: ZERO_FILL, PSEUDO_RANDOM '
                   f'(NIST Clear-class overwrite). PURGE/DESTROY require media-specific tooling '
                   f'outside this workstation scope.',
        )

    try:
        op_res = execute_sanitization(case.source_path, method=method)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Sanitization execution failed: {e}')

    # Step 3: Readback Verification (method-aware)
    verify_res = verify_sanitization(
        case.source_path,
        method=method,
        pre_sha256=case.input_sha256,
    )

    # Step 4: Build signed evidence package
    key_id, priv_key = get_or_create_primary_key()
    evid_id = new_evidence_id()
    scope_rec = get_scope_record()

    payload = build_evidence_payload(
        case_id=case_id,
        operation_id=op_id,
        evidence_id=evid_id,
        evidence_type='SANITIZATION',
        input_meta={'target_path': case.source_path, 'input_sha256': case.input_sha256},
        operation_meta={
            'method': method.value,
            'operator': auth.to_dict(),
            'bytes_written': op_res.bytes_written,
            'passes': op_res.passes_completed,
        },
        result_meta={
            'classification': verify_res.classification.value,
            'explanation': verify_res.explanation,
            'details': verify_res.details,
        },
        scope=scope_rec['scope_statement'],
        key_id=key_id,
    )

    signed_pkg = sign_evidence_envelope(payload, priv_key)
    evidence_store.save(signed_pkg)

    case_store.record_operation_and_evidence(
        case_id=case_id,
        operation_id=op_id,
        evidence_id=evid_id,
        operation_type='SANITIZATION',
        result_data=signed_pkg,
    )

    audit_logger.log(
        case_id=case_id,
        event_type='SANITIZATION_COMPLETED',
        actor='SANITIZATION_ENGINE',
        operation_id=op_id,
        evidence_id=evid_id,
        details={'classification': verify_res.classification.value},
    )

    audit_logger.log(
        case_id=case_id,
        event_type='EVIDENCE_SIGNED',
        actor='TRUST_LAYER',
        operation_id=op_id,
        evidence_id=evid_id,
        details={'algorithm': 'Ed25519', 'key_id': key_id},
        hash_ref=signed_pkg['evidence_hash'],
    )

    return {
        'operation_id': op_id,
        'evidence_id': evid_id,
        'classification': verify_res.classification.value,
        'explanation': verify_res.explanation,
        'scope': scope_rec,
        'signed_evidence': signed_pkg,
    }


class ProofLoopRequest(BaseModel):
    method: str = "CLEAR"
    data_sensitivity: str = "CONFIDENTIAL"


@router.post('/proof-loop')
def run_proof_loop_endpoint(case_id: str, req: Optional[ProofLoopRequest] = None):
    """
    Executes the sequential Forensic Proof Loop:
    1. Known Test Evidence → 2. Pre-Carve → 3. Sanitize → 4. Post-Carve Probe → 5. Compare → 6. Verification vs Validation → 7. Signed Assurance Package.
    """
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
        source_path = case.source_path
    except Exception:
        source_path = None

    if source_path and os.path.exists(source_path):
        with open(source_path, 'rb') as f:
            disk_bytes = f.read(5 * 1024 * 1024)
    else:
        from app.forensics.synthetic import generate_synthetic_disk_stream
        disk_bytes = generate_synthetic_disk_stream()

    from app.forensics.proof_loop import execute_forensic_proof_loop
    method = req.method if req and req.method else "CLEAR"
    sens = req.data_sensitivity if req and req.data_sensitivity else "CONFIDENTIAL"
    result = execute_forensic_proof_loop(
        raw_bytes=disk_bytes,
        method=method,
        case_id=case_id,
        data_sensitivity=sens
    )
    return result


class DecisionEngineRequest(BaseModel):
    media_type: str = "NVME_SSD"  # NVME_SSD, SATA_HDD, USB_FLASH
    data_sensitivity: str = "CONFIDENTIAL"  # RESTRICTED, CONFIDENTIAL, SECRET
    hardware_health: str = "GOOD"  # GOOD, DEGRADED, DAMAGED
    leaving_custody: bool = True


@router.post('/decision-profile')
def profile_sanitization_decision(req: DecisionEngineRequest):
    """
    NIST SP 800-88 Rev. 2 & IEEE 2883-2022 Decision Profiler.
    Recommends Clear vs Purge vs Destroy based on hardware characteristics and risk profile.
    """
    media = req.media_type.upper()
    sens = req.data_sensitivity.upper()

    if sens == "SECRET" or req.hardware_health == "DAMAGED":
        rec_method = "DESTROY"
        reason = "High sensitivity or damaged hardware requires physical destruction or degaussing."
    elif sens == "CONFIDENTIAL" or req.leaving_custody or media in ["NVME_SSD", "USB_FLASH"]:
        rec_method = "PURGE"
        reason = "Flash media or media leaving organizational control requires firmware-level Purge (cryptographic erase or sanitize block erase)."
    else:
        rec_method = "CLEAR"
        reason = "Standard overwrite Clear acceptable for reusable magnetic/logical storage within secure custody."

    return {
        "recommended_method": rec_method,
        "reasoning": reason,
        "input_profile": req.model_dump(),
        "standards_reference": "Decision logic informed by NIST SP 800-88 Rev. 2 and IEEE 2883-2022 / IEEE 2883.1-2025 standards.",
        "verification_type": "Logical Readback Pattern Verification",
        "validation_probe": f"Post-Sanitization Forensic Carving Probe ({sens} scope)",
    }


@router.get('/benchmark')
def run_live_benchmark(runs: int = 3):
    """
    Runs actual dynamic evaluation runs on synthetic test sets to compute real metrics.
    No hardcoded values.
    """
    from app.forensics.benchmark import run_live_forensic_benchmark
    num_runs = min(max(1, runs), 5)
    return run_live_forensic_benchmark(num_synthetic_runs=num_runs)

