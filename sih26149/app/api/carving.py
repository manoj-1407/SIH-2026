"""Advanced File Carving API router — SIH26149."""
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List

from app.api.deps import case_store, audit_logger, evidence_store, get_or_create_primary_key
from app.api.validation import validate_case_id
from app.forensics.carving import carve_image_summary
from app.core.evidence_envelope import build_evidence_payload, sign_evidence_envelope, new_operation_id, new_evidence_id

router = APIRouter(prefix='/cases/{case_id}', tags=['Advanced Carving'])


class CarvingRequest(BaseModel):
    target_types: Optional[List[str]] = None   # e.g. ["JPEG","PDF"] or None for all
    max_results: int = 200


@router.post('/carve')
def run_carving(case_id: str, req: CarvingRequest):
    """
    Advanced raw file carving on the case's acquired evidence image.
    Supports: JPEG, PNG, PDF, ZIP, DOCX, XLSX, MP4.
    Performs structural validation + confidence scoring — no false positives promoted.
    """
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    if not case.source_path or not os.path.exists(case.source_path):
        raise HTTPException(status_code=400, detail='No evidence image acquired for this case')

    try:
        summary = carve_image_summary(
            case.source_path,
            max_results=req.max_results,
            target_types=req.target_types,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Carving failed: {e}')

    # Build signed evidence package for this carving run
    key_id, priv_key = get_or_create_primary_key()
    op_id   = new_operation_id()
    evid_id = new_evidence_id()

    payload = build_evidence_payload(
        case_id=case_id,
        operation_id=op_id,
        evidence_id=evid_id,
        evidence_type='CARVING',
        input_meta={'source_path': case.source_path},
        operation_meta={
            'target_types': req.target_types or 'ALL',
            'max_results': req.max_results,
        },
        result_meta={
            'total_carved': summary['total_carved'],
            'intact': summary['intact'],
            'high_confidence': summary['high_confidence'],
            'partial': summary['partial'],
            'bifragmented': summary['bifragmented'],
            'by_type': summary['by_type'],
            'classification': 'VERIFIED' if summary['total_carved'] > 0 else 'VERIFIED_WITHIN_SCOPE',
        },
        scope=(
            'Advanced raw file carving using structural signature analysis. '
            'Confidence is evidence-derived from structural depth, CRC verification, '
            'and marker completeness. No external tools required.'
        ),
        key_id=key_id,
    )

    signed_pkg = sign_evidence_envelope(payload, priv_key)
    evidence_store.save(signed_pkg)

    case_store.record_operation_and_evidence(
        case_id=case_id,
        operation_id=op_id,
        evidence_id=evid_id,
        operation_type='CARVING',
        result_data=signed_pkg,
    )

    audit_logger.log(
        case_id=case_id,
        event_type='CARVING_COMPLETED',
        actor='CARVING_ENGINE',
        operation_id=op_id,
        evidence_id=evid_id,
        details={
            'total_carved': summary['total_carved'],
            'by_type': summary['by_type'],
        },
    )

    return {
        'operation_id': op_id,
        'evidence_id': evid_id,
        'carved': summary,
        'summary': summary,
        'signed_evidence': signed_pkg,
    }
