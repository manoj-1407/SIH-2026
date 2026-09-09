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

    # Step 2: Execute ZERO_FILL
    try:
        op_res = execute_sanitization(case.source_path, method=SanitizationMethod.ZERO_FILL)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Sanitization execution failed: {e}')

    # Step 3: Readback Verification
    verify_res = verify_sanitization(case.source_path)

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
            'method': SanitizationMethod.ZERO_FILL.value,
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
