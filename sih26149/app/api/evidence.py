"""Evidence Vault and Independent Verification API router."""
import os
import re
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Dict, Any, Optional

from app.api.deps import evidence_store, trust_registry, audit_logger
from app.core.independent_verifier import verify_evidence_package
from app.core.classification import EvidenceClassification

router = APIRouter(prefix='/evidence', tags=['Evidence Vault'])

EVIDENCE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]+$')

def validate_evidence_id(evidence_id: str):
    if not evidence_id or not EVIDENCE_ID_PATTERN.match(evidence_id):
        raise HTTPException(status_code=400, detail='Invalid evidence_id format')


@router.get('/{evidence_id}')
def get_evidence(evidence_id: str):
    validate_evidence_id(evidence_id)
    try:
        return evidence_store.get(evidence_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f'Evidence package {evidence_id} not found')


@router.get('')
def list_evidence(case_id: Optional[str] = None):
    return evidence_store.list_all(case_id=case_id)


@router.post('/{evidence_id}/verify')
def verify_stored_evidence(evidence_id: str):
    validate_evidence_id(evidence_id)
    try:
        pkg = evidence_store.get(evidence_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Evidence package not found')

    is_valid, cl_result = verify_evidence_package(pkg, key_registry=trust_registry)

    case_id = pkg.get('case_id')
    if case_id:
        audit_logger.log(
            case_id=case_id,
            event_type='EVIDENCE_VERIFIED' if is_valid else 'VERIFICATION_FAILED',
            actor='INDEPENDENT_VERIFIER',
            evidence_id=evidence_id,
            details=cl_result.details,
        )

    return {
        'evidence_id': evidence_id,
        'is_valid': is_valid,
        'classification': cl_result.classification.value,
        'explanation': cl_result.explanation,
        'details': cl_result.details,
    }


@router.post('/verify-package')
def verify_external_package(package: Dict[str, Any]):
    """Independent verification for exported evidence JSON packages."""
    try:
        is_valid, cl_result = verify_evidence_package(package, key_registry=trust_registry)
        return {
            'is_valid': is_valid,
            'classification': cl_result.classification.value,
            'explanation': cl_result.explanation,
            'details': cl_result.details,
        }
    except Exception as e:
        return {
            'is_valid': False,
            'classification': EvidenceClassification.INVALID.value,
            'explanation': f'Malformed evidence package: {e}',
            'details': {'error': str(e)},
        }


@router.post('/{evidence_id}/demo-tamper')
def demo_tamper_test(evidence_id: str, x_demo_mode: Optional[str] = Header(None)):
    """
    [DEMO / VERIFICATION TEST ONLY]
    Simulates adversarial evidence modification by altering a signed field.
    Requires DEMO_MODE=1 in environment OR X-Demo-Mode: 1 header.
    """
    if os.environ.get('DEMO_MODE') != '1' and x_demo_mode != '1':
        raise HTTPException(
            status_code=403,
            detail='Tamper endpoint is disabled. Requires authorized DEMO_MODE.'
        )

    validate_evidence_id(evidence_id)
    try:
        pkg = evidence_store.get(evidence_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Evidence package not found')

    tampered = dict(pkg)
    orig_val = tampered.get('result', {}).get('classification', 'UNKNOWN')
    tampered['result'] = dict(tampered.get('result', {}))
    tampered['result']['classification'] = 'TAMPERED_VERIFIED_FAKE'

    is_valid, cl_result = verify_evidence_package(tampered, key_registry=trust_registry)

    return {
        'evidence_id': evidence_id,
        'tampered_field': 'result.classification',
        'tamper_description': f"Altered signed result field: {orig_val} -> 'TAMPERED_VERIFIED_FAKE'",
        'is_valid': is_valid,
        'classification': cl_result.classification.value,
        'explanation': cl_result.explanation,
        'tamper_detected': cl_result.details.get('tamper_detected', False),
        'verification': {
            'valid': is_valid,
            'reason': cl_result.explanation,
        },
    }
