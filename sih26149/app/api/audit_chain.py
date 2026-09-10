"""Audit Chain verification API router — SIH26149."""
import os
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional

from app.api.deps import audit_logger
from app.api.validation import validate_case_id

router = APIRouter(prefix='/cases/{case_id}/timeline', tags=['Audit Chain'])


@router.get('')
def get_timeline(case_id: str):
    """Get the full chain-of-custody timeline for a case."""
    validate_case_id(case_id)
    return audit_logger.get_timeline(case_id)


@router.get('/verify')
def verify_audit_chain(case_id: str):
    """
    Verify the cryptographic integrity of the entire audit chain.
    Returns whether the chain is intact and details of any violations.
    """
    validate_case_id(case_id)
    is_valid, violations = audit_logger.verify_chain(case_id)
    return {
        'case_id': case_id,
        'chain_valid': is_valid,
        'violation_count': len(violations),
        'violations': violations,
        'explanation': (
            'All audit entries are cryptographically linked and unmodified.'
            if is_valid else
            f'{len(violations)} chain violation(s) detected — audit log may have been tampered.'
        )
    }


class TamperDemoRequest(BaseModel):
    entry_index: int = 0
    field: str = 'actor'
    new_value: str = 'INJECTED_ACTOR'


@router.post('/demo-tamper')
def demo_tamper_audit_chain(
    case_id: str,
    req: TamperDemoRequest,
    x_demo_mode: Optional[str] = Header(None),
):
    """
    [DEMO ONLY] Demonstrate cryptographic tamper detection in the audit chain.
    Modifies a field in one entry, verifies the chain breaks, then restores.
    """
    if os.environ.get("DEMO_MODE", "").strip() != "1" and x_demo_mode != "1":
        raise HTTPException(
            status_code=403,
            detail="Audit chain tamper demo is only available when DEMO_MODE=1 (or X-Demo-Mode: 1).",
        )
    validate_case_id(case_id)
    timeline = audit_logger.get_timeline(case_id)
    if not timeline:
        raise HTTPException(status_code=400, detail='No audit events for this case. Run some operations first.')

    result = audit_logger.demo_tamper_chain(
        case_id=case_id,
        entry_index=req.entry_index,
        field=req.field,
        new_value=req.new_value,
    )
    if 'error' in result:
        raise HTTPException(status_code=400, detail=result['error'])
    return result
