"""Cases management API router."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from app.cases.models import WorkflowType
from app.api.deps import case_store, audit_logger
from app.api.validation import validate_case_id

router = APIRouter(prefix='/cases', tags=['Cases'])


class CaseCreateRequest(BaseModel):
    workflow: str = 'FORENSIC'
    title: str = ''
    description: str = ''


@router.post('')
def create_case(req: CaseCreateRequest):
    try:
        wf = WorkflowType(req.workflow.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f'Invalid workflow: {req.workflow}. Use FORENSIC or SANITIZATION')

    case = case_store.create(workflow=wf, title=req.title, description=req.description)
    audit_logger.log(
        case_id=case.case_id,
        event_type='CASE_CREATED',
        actor='OPERATOR',
        details={'workflow': wf.value, 'title': case.title},
    )
    return case.to_dict()


@router.get('')
def list_cases():
    return [c.to_dict() for c in case_store.list_all()]


@router.get('/{case_id}')
def get_case(case_id: str):
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
        return case.to_dict()
    except Exception:
        raise HTTPException(status_code=404, detail=f'Case {case_id} not found')


@router.get('/{case_id}/timeline')
def get_timeline(case_id: str):
    validate_case_id(case_id)
    return audit_logger.get_timeline(case_id)


@router.post('/seed-demo')
def seed_demo_case():
    """Seeds an official demonstration case ready for full forensic analysis."""
    from app.api.forensics import seed_synthetic_evidence
    demo_id = 'CASE-DEMO-2026'
    try:
        case = case_store.get(demo_id)
    except Exception:
        case = case_store.create(
            workflow=WorkflowType.FORENSIC,
            title="Forensic Evidence Recovery Demo (SIH26149)",
            description="Official demonstration case containing synthetic disk image with embedded JPEG, PNG, and PDF artifacts."
        )
        # override case_id for consistency
        case.case_id = demo_id
        case_store.save(case)

    # Seed the synthetic evidence
    acq = seed_synthetic_evidence(demo_id)

    audit_logger.log(
        case_id=demo_id,
        event_type='CASE_SEEDED',
        actor='SYSTEM_DEMO_SEEDER',
        details={'workflow': 'FORENSIC', 'title': case.title},
    )

    return {
        'status': 'seeded',
        'case': case.to_dict(),
        'acquisition': acq,
        'message': 'Successfully seeded official forensic demo case.',
    }

