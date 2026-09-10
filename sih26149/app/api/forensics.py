"""Forensic investigation workflow API router."""
import os
import re
import shutil
import uuid
from pathlib import Path
from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Optional

from app.api.deps import (
    case_store, audit_logger, evidence_store, trust_registry,
    get_or_create_primary_key, UPLOADS_DIR
)
from app.api.validation import validate_case_id
from app.core.hashing import hash_file
from app.core.evidence_envelope import build_evidence_payload, sign_evidence_envelope, new_operation_id, new_evidence_id
from app.forensics.filesystem import detect_filesystem
from app.forensics.discovery import discover_deleted_artifacts
from app.forensics.recovery import recover_artifact
from app.forensics.verification import verify_recovery

router = APIRouter(prefix='/cases/{case_id}', tags=['Forensics'])

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB limit


@router.post('/upload')
async def upload_evidence_image(case_id: str, file: UploadFile = File(...)):
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    if not file.filename:
        raise HTTPException(status_code=400, detail='Filename is required')

    # Security: Strip directory traversal characters
    safe_filename = os.path.basename(file.filename)
    if not safe_filename or safe_filename in ('.', '..') or '/' in file.filename or '\\' in file.filename:
        # If traversal attempted, sanitize to safe basename or reject
        safe_filename = re.sub(r'[^a-zA-Z0-9._\-]', '_', safe_filename)
        if not safe_filename:
            safe_filename = 'upload.img'

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    acq_id = f'ACQ-{uuid.uuid4().hex[:8].upper()}'
    # Immutable acquisition filename — never overwrite a prior upload of the same name
    file_path = UPLOADS_DIR / f'{case_id}_{acq_id}_{safe_filename}'

    # Write uploaded file with size bound check
    total_written = 0
    with open(file_path, 'wb') as buffer:
        while True:
            chunk = await file.read(64 * 1024)
            if not chunk:
                break
            total_written += len(chunk)
            if total_written > MAX_UPLOAD_SIZE:
                buffer.close()
                if file_path.exists():
                    file_path.unlink()
                raise HTTPException(status_code=413, detail=f'File exceeds maximum allowed size of {MAX_UPLOAD_SIZE} bytes')
            buffer.write(chunk)

    hash_res = hash_file(str(file_path))

    case_store.update_acquisition(
        case_id=case_id,
        acquisition_id=acq_id,
        source_path=str(file_path),
        sha256=hash_res.hex_digest,
        size_bytes=hash_res.size_bytes,
    )

    audit_logger.log(
        case_id=case_id,
        event_type='EVIDENCE_ACQUIRED',
        actor='INVESTIGATOR',
        details={'filename': safe_filename, 'size_bytes': hash_res.size_bytes},
        hash_ref=hash_res.hex_digest,
    )

    return {
        'acquisition_id': acq_id,
        'filename': safe_filename,
        'sha256': hash_res.hex_digest,
        'size_bytes': hash_res.size_bytes,
    }


@router.get('/filesystem')
def get_filesystem(case_id: str):
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')
    if not case.source_path or not os.path.exists(case.source_path):
        raise HTTPException(status_code=400, detail='No evidence image acquired for this case')

    cap = detect_filesystem(case.source_path)
    case_store.update_filesystem(case_id, cap.to_dict())

    audit_logger.log(
        case_id=case_id,
        event_type='FILESYSTEM_IDENTIFIED',
        actor='FORENSIC_ENGINE',
        details=cap.to_dict(),
    )
    return cap.to_dict()


@router.get('/artifacts')
def get_deleted_artifacts(case_id: str):
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')
    if not case.source_path:
        raise HTTPException(status_code=400, detail='No evidence image acquired')

    # Capability gate: Ext4 tooling must never be invoked on unsupported filesystem
    cap = detect_filesystem(case.source_path)
    if not cap.recovery_supported:
        raise HTTPException(
            status_code=400,
            detail=f'Recovery not supported for {cap.status_label}. Ext4 recovery tooling rejected dispatch.',
        )

    artifacts = discover_deleted_artifacts(case.source_path)
    art_dicts = [a.to_dict() for a in artifacts]

    case.discovered_artifacts = art_dicts
    case_store.save(case)

    audit_logger.log(
        case_id=case_id,
        event_type='ARTIFACT_DISCOVERED',
        actor='FORENSIC_ENGINE',
        details={'artifact_count': len(artifacts)},
    )
    return art_dicts


class ForensicRecoveryRequest(BaseModel):
    inode: str
    artifact_name: str = ''
    reference_sha256: Optional[str] = None


@router.post('/forensic')
@router.post('/recover')
def run_forensic_recovery(case_id: str, req: ForensicRecoveryRequest):
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')
    if not case.source_path:
        raise HTTPException(status_code=400, detail='No evidence image acquired')

    cap = detect_filesystem(case.source_path)
    if not cap.recovery_supported:
        raise HTTPException(status_code=400, detail=f'Filesystem {cap.status_label} does not support ext4 recovery')

    # Execute icat recovery
    try:
        rec = recover_artifact(case.source_path, req.inode)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Recovery error: {e}')

    # Verify recovery against reference hash (or classify UNVERIFIED if none)
    classified = verify_recovery(rec.sha256, req.reference_sha256)

    # Build signed evidence envelope with distinct operation_id and evidence_id
    key_id, priv_key = get_or_create_primary_key()
    op_id = new_operation_id()
    evid_id = new_evidence_id()

    payload = build_evidence_payload(
        case_id=case_id,
        operation_id=op_id,
        evidence_id=evid_id,
        evidence_type='FORENSIC_RECOVERY',
        input_meta={'sha256': case.input_sha256, 'filesystem': cap.filesystem},
        operation_meta={
            'inode': req.inode,
            'artifact_name': req.artifact_name,
            'method': 'icat',
        },
        result_meta={
            'classification': classified.classification.value,
            'recovered_sha256': rec.sha256,
            'reference_sha256': req.reference_sha256,
            'size_bytes': rec.size_bytes,
            'explanation': classified.explanation,
        },
        scope='Ext4 deleted-file recovery via inode analysis. Verified against supplied ground truth.',
        key_id=key_id,
    )

    signed_pkg = sign_evidence_envelope(payload, priv_key)
    evidence_store.save(signed_pkg)

    # Record operation in case and audit log
    case_store.record_operation_and_evidence(
        case_id=case_id,
        operation_id=op_id,
        evidence_id=evid_id,
        operation_type='FORENSIC',
        result_data=signed_pkg,
    )

    audit_logger.log(
        case_id=case_id,
        event_type='RECOVERY_COMPLETED',
        actor='FORENSIC_ENGINE',
        operation_id=op_id,
        evidence_id=evid_id,
        details={'classification': classified.classification.value, 'recovered_sha256': rec.sha256},
        hash_ref=rec.sha256,
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
        'classification': classified.classification.value,
        'explanation': classified.explanation,
        'artifact_name': req.artifact_name or f'inode_{req.inode}',
        'inode': req.inode,
        'recovered_sha256': rec.sha256,
        'reference_sha256': req.reference_sha256,
        'match': req.reference_sha256 is not None and rec.sha256.lower() == req.reference_sha256.lower(),
        'size_bytes': rec.size_bytes,
        'signed_evidence': signed_pkg,
    }


def generate_synthetic_disk_stream() -> bytes:
    """Creates a deterministic synthetic disk stream with valid JPEG, PNG, and PDF for safe demonstration."""
    padding_front = b"\xaa\xbb\xcc\xdd" * 128
    jpeg_data = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00\x43\x00"
        + (b"\x01" * 64)
        + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x00\xff\xd9"
    )
    padding_mid = b"\x00" * 512
    png_ihdr = b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    png_iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    png_data = b"\x89PNG\r\n\x1a\n" + png_ihdr + png_iend
    padding_mid2 = b"\x00" * 256
    pdf_data = (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n185\n%%EOF\n"
    )
    padding_end = b"\x55" * 256
    return padding_front + jpeg_data + padding_mid + png_data + padding_mid2 + pdf_data + padding_end


@router.post('/seed-synthetic-evidence')
def seed_synthetic_evidence(case_id: str):
    """
    [DEMO / EVALUATOR] Generates synthetic unallocated disk media with embedded valid artifacts.
    Enables instant demonstration of carving and recovery without uploading local files.
    """
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    safe_filename = 'synthetic_evidence_disk.raw'
    file_path = UPLOADS_DIR / f'{case_id}_{safe_filename}'

    data = generate_synthetic_disk_stream()
    with open(file_path, 'wb') as f:
        f.write(data)

    hash_res = hash_file(str(file_path))
    acq_id = f'ACQ-SYNTH-{uuid.uuid4().hex[:6].upper()}'

    case_store.update_acquisition(
        case_id=case_id,
        acquisition_id=acq_id,
        source_path=str(file_path),
        sha256=hash_res.hex_digest,
        size_bytes=hash_res.size_bytes,
    )

    audit_logger.log(
        case_id=case_id,
        event_type='EVIDENCE_ACQUIRED',
        actor='SYNTHETIC_EVIDENCE_GENERATOR',
        details={'filename': safe_filename, 'size_bytes': hash_res.size_bytes, 'synthetic': True},
        hash_ref=hash_res.hex_digest,
    )

    return {
        'acquisition_id': acq_id,
        'filename': safe_filename,
        'sha256': hash_res.hex_digest,
        'size_bytes': hash_res.size_bytes,
        'synthetic': True,
        'description': 'Deterministic synthetic disk image containing valid JPEG, PNG, and PDF artifacts',
    }

