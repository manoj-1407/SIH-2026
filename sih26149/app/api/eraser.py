"""Selective File & Folder Eraser API router — SIH26149."""
import os
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List

from app.api.deps import (
    case_store, audit_logger, evidence_store,
    get_or_create_primary_key, UPLOADS_DIR,
)
from app.api.validation import validate_case_id
from app.sanitization.file_eraser import (
    preview_scope, erase_paths, EraserMethod,
)
from app.sanitization.device_detector import detect_media_type
from app.core.evidence_envelope import build_evidence_payload, sign_evidence_envelope, new_operation_id, new_evidence_id

# Erasure is only permitted within the case uploads directory.
# Path.resolve() dereferences symlinks before the containment check so that
# a symlink pointing outside the root cannot bypass the guard.
_ERASURE_ROOT = UPLOADS_DIR.resolve()


def _validate_erasure_paths(paths: List[str]) -> List[str]:
    """Validate and resolve paths within the authorised erasure root. Returns list of resolved string paths."""
    resolved_paths = []
    for raw in paths:
        try:
            p = Path(raw)
            resolved = (_ERASURE_ROOT / p).resolve() if not p.is_absolute() else p.resolve()
        except Exception:
            raise HTTPException(
                status_code=400,
                detail=f"Malformed path: {raw!r}",
            )
        if not resolved.is_relative_to(_ERASURE_ROOT):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Path outside authorized erasure scope: {raw!r}. "
                    f"Only paths within the case uploads directory ({_ERASURE_ROOT}) "
                    "are permitted."
                ),
            )
        resolved_paths.append(str(resolved))
    return resolved_paths

router = APIRouter(prefix='/cases/{case_id}', tags=['File Eraser'])


class PreviewRequest(BaseModel):
    target_paths: List[str]


class FileEraseRequest(BaseModel):
    target_paths: List[str]
    operator_id: str
    operator_name: str
    authorization_reason: str
    confirmed_scope_acknowledgement: bool
    method: str = 'ZERO_FILL'
    scrub_metadata: bool = True
    scramble_names: bool = True


class DeviceDetectRequest(BaseModel):
    target_path: str


@router.post('/erase-preview')
def preview_erase_scope(case_id: str, req: PreviewRequest):
    """Preview files/folders in erasure scope without erasing."""
    validate_case_id(case_id)
    try:
        case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    resolved = _validate_erasure_paths(req.target_paths)
    items = preview_scope(resolved)
    return {
        'case_id': case_id,
        'scope_items': [
            {
                'path': item.path,
                'size_bytes': item.size_bytes,
                'is_dir': item.is_dir,
                'child_count': item.child_count,
            }
            for item in items
        ],
        'total_files': sum(1 for i in items if not i.is_dir) + sum(i.child_count for i in items if i.is_dir),
        'total_size_bytes': sum(i.size_bytes for i in items),
        'warning': 'Review scope carefully. File erasure is irreversible.',
    }


@router.post('/erase-files')
def run_file_eraser(case_id: str, req: FileEraseRequest):
    """
    Selective file & folder erasure with metadata scrubbing.
    NIST SP 800-88 Rev. 2 §2.3 Clear — single-pass overwrite.
    Requires explicit operator authorization and scope acknowledgement.
    """
    validate_case_id(case_id)
    try:
        case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    if not req.confirmed_scope_acknowledgement:
        raise HTTPException(
            status_code=400,
            detail='Scope acknowledgement required. Set confirmed_scope_acknowledgement=true.'
        )
    if not req.operator_id or not req.operator_name:
        raise HTTPException(status_code=400, detail='Operator ID and name required.')
    if not req.authorization_reason:
        raise HTTPException(status_code=400, detail='Authorization reason required.')

    try:
        method = EraserMethod(req.method.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f'Invalid method: {req.method}. Use ZERO_FILL or RANDOM_FILL')

    op_id = new_operation_id()
    audit_logger.log(
        case_id=case_id,
        event_type='FILE_ERASURE_AUTHORIZED',
        actor=f'{req.operator_name} ({req.operator_id})',
        operation_id=op_id,
        details={
            'reason': req.authorization_reason,
            'target_paths': req.target_paths,
            'method': method.value,
        },
    )

    resolved = _validate_erasure_paths(req.target_paths)

    try:
        result = erase_paths(
            resolved,
            method=method,
            scrub_metadata=req.scrub_metadata,
            scramble_names=req.scramble_names,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'File erasure failed: {e}')

    # Sign evidence
    key_id, priv_key = get_or_create_primary_key()
    evid_id = new_evidence_id()

    payload = build_evidence_payload(
        case_id=case_id,
        operation_id=op_id,
        evidence_id=evid_id,
        evidence_type='FILE_ERASURE',
        input_meta={'target_paths': req.target_paths},
        operation_meta={
            'method': method.value,
            'operator': {'id': req.operator_id, 'name': req.operator_name},
            'scrub_metadata': req.scrub_metadata,
            'scramble_names': req.scramble_names,
        },
        result_meta=result.to_dict(),
        scope=(
            f'Selective file/folder erasure — NIST SP 800-88 Rev. 2 §2.3 Clear. '
            f'Method: {method.value}. Metadata scrubbed: {req.scrub_metadata}. '
            f'Filename scrambled before unlink: {req.scramble_names}.'
        ),
        key_id=key_id,
    )

    signed_pkg = sign_evidence_envelope(payload, priv_key)
    evidence_store.save(signed_pkg)

    case_store.record_operation_and_evidence(
        case_id=case_id,
        operation_id=op_id,
        evidence_id=evid_id,
        operation_type='FILE_ERASURE',
        result_data=signed_pkg,
    )

    audit_logger.log(
        case_id=case_id,
        event_type='FILE_ERASURE_COMPLETED',
        actor='ERASER_ENGINE',
        operation_id=op_id,
        evidence_id=evid_id,
        details={
            'classification': result.to_dict()['classification'],
            'total_files': result.total_files,
            'total_bytes': result.total_bytes,
        },
    )

    return {
        'operation_id': op_id,
        'evidence_id': evid_id,
        'result': result.to_dict(),
        'signed_evidence': signed_pkg,
    }


@router.post('/detect-device')
def detect_device(case_id: str, req: DeviceDetectRequest):
    """
    NIST SP 800-88 Rev. 2 device capability detection.
    Classifies storage media and returns scope-limited sanitization guidance.
    """
    validate_case_id(case_id)
    try:
        case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    capability = detect_media_type(req.target_path)
    return capability.to_dict()
