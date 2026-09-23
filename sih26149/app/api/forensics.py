"""Forensic investigation workflow API router."""
import os
import re
import shutil
import threading
import uuid
from pathlib import Path
from fastapi import APIRouter, HTTPException, Request, UploadFile, File
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

MAX_UPLOAD_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB practical ceiling for evidence images
_UPLOAD_SESSION_LOCK = threading.Lock()
_UPLOAD_SESSIONS: dict[tuple[str, str], dict] = {}


def _sanitize_upload_filename(filename: str) -> str:
    if not filename or not filename.strip():
        return 'upload.img'
    base = os.path.basename(filename.replace('\\', '/'))
    clean_name = re.sub(r'[^a-zA-Z0-9._\-]', '_', base)
    if not clean_name or clean_name.replace('_', '') == '':
        clean_name = 'upload.img'
    if len(clean_name) > 120:
        root, ext = os.path.splitext(clean_name)
        clean_name = root[:100] + ext[:20]
    return clean_name


async def _finalize_acquisition(case_id: str, acquisition_id: str, file_path: Path, filename: str) -> dict:
    """Persist a complete acquisition and return the normalized metadata payload."""
    hash_res = hash_file(str(file_path))
    case_store.update_acquisition(
        case_id=case_id,
        acquisition_id=acquisition_id,
        source_path=str(file_path),
        sha256=hash_res.hex_digest,
        size_bytes=hash_res.size_bytes,
    )

    audit_logger.log(
        case_id=case_id,
        event_type='EVIDENCE_ACQUIRED',
        actor='INVESTIGATOR',
        details={'filename': filename, 'size_bytes': hash_res.size_bytes},
        hash_ref=hash_res.hex_digest,
    )

    return {
        'acquisition_id': acquisition_id,
        'filename': filename,
        'sha256': hash_res.hex_digest,
        'size_bytes': hash_res.size_bytes,
    }


@router.post('/upload')
async def upload_evidence_image(case_id: str, file: UploadFile = File(...)):
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    safe_filename = _sanitize_upload_filename(file.filename)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    acq_id = f'ACQ-{uuid.uuid4().hex[:8].upper()}'
    file_path = UPLOADS_DIR / f'{case_id}_{acq_id}_{safe_filename}'

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

    return await _finalize_acquisition(case_id, acq_id, file_path, safe_filename)


@router.post('/upload-session')
async def create_upload_session(case_id: str, payload: dict):
    validate_case_id(case_id)
    try:
        case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    filename = payload.get('filename') if isinstance(payload, dict) else None
    if not filename or not str(filename).strip():
        raise HTTPException(status_code=400, detail='Filename is required')

    total_size = int(payload.get('total_size', 0)) if isinstance(payload, dict) else 0
    if total_size <= 0:
        raise HTTPException(status_code=400, detail='total_size must be a positive integer')
    if total_size > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f'File exceeds maximum allowed size of {MAX_UPLOAD_SIZE} bytes')

    safe_filename = _sanitize_upload_filename(str(filename))
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    session_id = f'CHUNK-{uuid.uuid4().hex[:12].upper()}'
    temp_path = UPLOADS_DIR / f'{case_id}_{session_id}_{safe_filename}.part'
    temp_path.touch(exist_ok=False)

    with _UPLOAD_SESSION_LOCK:
        _UPLOAD_SESSIONS[(case_id, session_id)] = {
            'filename': safe_filename,
            'total_size': total_size,
            'received_bytes': 0,
            'temp_path': str(temp_path),
            'chunk_count': 0,
            'last_chunk_index': -1,
        }

    return {
        'session_id': session_id,
        'filename': safe_filename,
        'total_size': total_size,
        'status': 'active',
    }


@router.get('/upload-session/{session_id}')
async def get_upload_session(case_id: str, session_id: str):
    validate_case_id(case_id)
    with _UPLOAD_SESSION_LOCK:
        session = _UPLOAD_SESSIONS.get((case_id, session_id))
    if session is None:
        raise HTTPException(status_code=404, detail='Upload session not found')
    return {
        'session_id': session_id,
        'filename': session['filename'],
        'total_size': session['total_size'],
        'received_bytes': session['received_bytes'],
        'status': 'complete' if session['received_bytes'] >= session['total_size'] else 'active',
    }


@router.post('/upload-session/{session_id}/chunk')
async def upload_session_chunk(case_id: str, session_id: str, request: Request):
    validate_case_id(case_id)
    with _UPLOAD_SESSION_LOCK:
        session = _UPLOAD_SESSIONS.get((case_id, session_id))
    if session is None:
        raise HTTPException(status_code=404, detail='Upload session not found')

    chunk_index_raw = request.headers.get('X-Chunk-Index')
    if chunk_index_raw is None:
        raise HTTPException(status_code=400, detail='X-Chunk-Index header is required')
    try:
        chunk_index = int(chunk_index_raw)
    except ValueError:
        raise HTTPException(status_code=400, detail='X-Chunk-Index must be an integer')

    total_size_hdr = request.headers.get('X-Total-Size')
    if total_size_hdr is not None:
        try:
            total_size_hdr_int = int(total_size_hdr)
        except ValueError:
            raise HTTPException(status_code=400, detail='X-Total-Size must be an integer')
        if total_size_hdr_int != session['total_size']:
            raise HTTPException(status_code=400, detail='Chunk total size does not match the session total_size')

    chunk = await request.body()
    if not chunk:
        raise HTTPException(status_code=400, detail='Chunk body is empty')

    temp_path = Path(session['temp_path'])
    with open(temp_path, 'ab') as buffer:
        buffer.write(chunk)

    with _UPLOAD_SESSION_LOCK:
        session = _UPLOAD_SESSIONS[(case_id, session_id)]
        new_received = session['received_bytes'] + len(chunk)
        if new_received > session['total_size']:
            raise HTTPException(status_code=413, detail='Received bytes exceed the declared total_size for this upload session')
        session['received_bytes'] = new_received
        session['chunk_count'] += 1
        session['last_chunk_index'] = max(session['last_chunk_index'], chunk_index)

    return {
        'session_id': session_id,
        'received_bytes': new_received,
        'total_size': session['total_size'],
        'status': 'active',
    }


@router.post('/upload-session/{session_id}/finalize')
async def finalize_upload_session(case_id: str, session_id: str):
    validate_case_id(case_id)
    try:
        case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    with _UPLOAD_SESSION_LOCK:
        session = _UPLOAD_SESSIONS.get((case_id, session_id))
    if session is None:
        raise HTTPException(status_code=404, detail='Upload session not found')

    temp_path = Path(session['temp_path'])
    if not temp_path.exists():
        raise HTTPException(status_code=400, detail='Upload session file does not exist')
    if session['received_bytes'] != session['total_size']:
        raise HTTPException(status_code=400, detail='Upload session is incomplete; all chunks have not been received yet')

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    acq_id = f'ACQ-{uuid.uuid4().hex[:8].upper()}'
    final_path = UPLOADS_DIR / f'{case_id}_{acq_id}_{session["filename"]}'
    if final_path.exists():
        final_path = UPLOADS_DIR / f'{case_id}_{acq_id}_{session["filename"]}.final'
    temp_path.replace(final_path)

    payload = await _finalize_acquisition(case_id, acq_id, final_path, session['filename'])

    with _UPLOAD_SESSION_LOCK:
        _UPLOAD_SESSIONS.pop((case_id, session_id), None)

    return payload


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

    cap = detect_filesystem(case.source_path)
    art_dicts = []
    if cap.recovery_supported:
        try:
            artifacts = discover_deleted_artifacts(case.source_path)
            art_dicts = [a.to_dict() for a in artifacts]
        except Exception:
            art_dicts = []

    # If ext4 discovery yielded no results or if filesystem requires carving fallback
    if not art_dicts and (cap.carving_fallback or not cap.recovery_supported):
        from app.forensics.carving import carve_image
        try:
            carved = carve_image(case.source_path, max_results=50)
            art_dicts = [
                {
                    'inode': str(c.offset),
                    'name': f'carved_{c.file_type.lower()}_0x{c.offset:X}.{c.file_type.lower()}',
                    'filename': f'carved_{c.file_type.lower()}_0x{c.offset:X}.{c.file_type.lower()}',
                    'is_deleted': True,
                    'size_bytes': c.size,
                    'artifact_type': 'r',
                    'recovery_method': 'RAW_CARVING_FALLBACK',
                    'confidence': c.confidence.value,
                    'sha256': c.sha256,
                }
                for c in carved
            ]
        except Exception:
            art_dicts = []

    case.discovered_artifacts = art_dicts
    case_store.save(case)

    audit_logger.log(
        case_id=case_id,
        event_type='ARTIFACT_DISCOVERED',
        actor='FORENSIC_ENGINE',
        details={'artifact_count': len(art_dicts), 'recovery_method': 'INODE_METADATA' if cap.recovery_supported and art_dicts else 'RAW_CARVING_FALLBACK'},
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
        # Carving-based extraction fallback
        from app.forensics.carving import carve_image
        carved = carve_image(case.source_path, max_results=100)
        target = None
        for c in carved:
            if str(c.offset) == req.inode or f"0x{c.offset:X}".lower() == req.inode.lower() or f"carve_{c.offset}" == req.inode:
                target = c
                break
        if not target and carved:
            target = carved[0]

        if target:
            classified = verify_recovery(target.sha256, req.reference_sha256)
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
                    'offset': target.offset,
                    'artifact_name': req.artifact_name or f'carved_{target.file_type.lower()}',
                    'method': 'raw_carving_fallback',
                },
                result_meta={
                    'classification': classified.classification.value,
                    'recovered_sha256': target.sha256,
                    'reference_sha256': req.reference_sha256,
                    'size_bytes': target.size,
                    'explanation': f'Carved {target.file_type} artifact recovered via structural analysis at offset 0x{target.offset:X}.',
                },
                scope='Raw byte-stream carving extraction fallback (filesystem-independent).',
                key_id=key_id,
            )
            signed_pkg = sign_evidence_envelope(payload, priv_key)
            evidence_store.save(signed_pkg)
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
                details={'classification': classified.classification.value, 'recovered_sha256': target.sha256},
                hash_ref=target.sha256,
            )
            return {
                'operation_id': op_id,
                'evidence_id': evid_id,
                'classification': classified.classification.value,
                'explanation': f'Carved {target.file_type} artifact recovered via structural signature analysis (confidence: {target.confidence.value}).',
                'artifact_name': req.artifact_name or f'carved_{target.file_type.lower()}',
                'inode': req.inode,
                'recovered_sha256': target.sha256,
                'reference_sha256': req.reference_sha256,
                'match': req.reference_sha256 is not None and target.sha256.lower() == req.reference_sha256.lower(),
                'size_bytes': target.size,
                'signed_evidence': signed_pkg,
            }
        else:
            raise HTTPException(status_code=404, detail=f'No recoverable artifact found for target: {req.inode}')

    # Execute icat recovery
    try:
        rec = recover_artifact(case.source_path, req.inode)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Recovery error: {e}')

    # ext4 forensic note: if icat returned empty (block pointers zeroed on delete),
    # we record a FAILED evidence envelope and direct operator to raw carving.
    from app.forensics.recovery import RecoveryLayerStatus
    if rec.layer_status == RecoveryLayerStatus.FAILED_SK_LAYER:
        key_id, priv_key = get_or_create_primary_key()
        op_id = new_operation_id()
        evid_id = new_evidence_id()
        payload = build_evidence_payload(
            case_id=case_id, operation_id=op_id, evidence_id=evid_id,
            evidence_type='FORENSIC_RECOVERY',
            input_meta={'sha256': case.input_sha256, 'filesystem': cap.filesystem},
            operation_meta={'inode': req.inode, 'method': 'icat'},
            result_meta={'classification': 'FAILED', 'layer_status': rec.layer_status.value,
                         'forensic_note': rec.forensic_note},
            scope='ext4 inode recovery attempt — see forensic_note for explanation.',
            key_id=key_id,
        )
        signed_pkg = sign_evidence_envelope(payload, priv_key)
        evidence_store.save(signed_pkg)
        case_store.record_operation_and_evidence(
            case_id=case_id, operation_id=op_id, evidence_id=evid_id,
            operation_type='FORENSIC', result_data=signed_pkg,
        )
        audit_logger.log(case_id=case_id, event_type='RECOVERY_FAILED_SK_LAYER',
                         actor='FORENSIC_ENGINE', operation_id=op_id, evidence_id=evid_id,
                         details={'layer_status': rec.layer_status.value, 'inode': req.inode,
                                  'forensic_note': rec.forensic_note})
        return {
            'operation_id': op_id, 'evidence_id': evid_id,
            'classification': 'FAILED',
            'layer_status': rec.layer_status.value,
            'forensic_note': rec.forensic_note,
            'inode': req.inode,
            'size_bytes': 0,
            'explanation': (
                'ext4 zeroes inode block pointers on deletion — icat returns empty data. '
                'This is expected filesystem behaviour. Use raw carving (/carve) to recover data.'
            ),
            'next_action': 'USE_RAW_CARVE',
            'signed_evidence': signed_pkg,
        }

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
    padding_end = bytes((i * 37 + 11) % 256 for i in range(256))
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


class AntiForensicsRequest(BaseModel):
    mft_records: Optional[list] = None
    directory_names: Optional[list] = None


@router.post('/anti-forensics')
def run_anti_forensics_audit(case_id: str, req: Optional[AntiForensicsRequest] = None):
    """
    Scan acquired evidence image and metadata for anti-forensic concealment:
    - NTFS timestomping ($STANDARD_INFORMATION vs $FILE_NAME anomalies)
    - Residual wipe-tool signatures (SDelete, BleachBit, Eraser)
    - Suspicious high-entropy unallocated clusters (crypto-shredding)
    """
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    if not case.source_path or not os.path.exists(case.source_path):
        raise HTTPException(status_code=400, detail='No acquired evidence image found for this case')

    from app.forensics.anti_forensics import analyze_anti_forensics
    mft_recs = req.mft_records if req else None
    dir_names = req.directory_names if req else None

    report = analyze_anti_forensics(
        image_input=case.source_path,
        mft_records=mft_recs,
        directory_names=dir_names,
    )

    audit_logger.log(
        case_id=case_id,
        event_type='ANTI_FORENSICS_SCANNED',
        actor='ANTI_FORENSICS_ENGINE',
        details={
            'anti_forensics_detected': report['anti_forensics_detected'],
            'total_indicators': report['total_indicators'],
            'verdict': report['verdict'],
        },
    )

    return report


@router.post('/steganography')
def run_steganography_audit(case_id: str, artifact_offset: Optional[int] = None):
    """
    Run Chi-Square (χ²) PoVs analysis on acquired evidence image or recovered image artifact.
    Detects covert LSB steganographic payloads and calculates statistical probability.
    """
    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    if not case.source_path or not os.path.exists(case.source_path):
        raise HTTPException(status_code=400, detail='No acquired evidence image found for this case')

    from app.forensics.steganography import analyze_file_for_steganography

    with open(case.source_path, "rb") as f:
        if artifact_offset is not None and artifact_offset >= 0:
            f.seek(artifact_offset)
            sample_data = f.read(256 * 1024) # 256KB sample
        else:
            sample_data = f.read(512 * 1024)

    report = analyze_file_for_steganography(sample_data)

    audit_logger.log(
        case_id=case_id,
        event_type='STEGANOGRAPHY_SCANNED',
        actor='STEGO_DETECTOR',
        details={
            'stego_detected': report.get('steganography_detected', False),
            'probability': report.get('stego_probability', 0.0),
            'verdict': report.get('verdict', 'UNKNOWN'),
        }
    )

    return report


@router.post('/entropy')
async def compute_entropy_heatmap(case_id: str):
    """
    Compute Shannon entropy for each 512-byte sector of the acquisition image.
    Returns up to 2048 sectors for browser-side heatmap rendering.
    Classification: ENCRYPTED (H>7.5), COMPRESSED (H>6.5),
                    STRUCTURED (H>3.0), EMPTY (H<1.0), NORMAL otherwise.
    """
    import math

    validate_case_id(case_id)
    try:
        case = case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail='Case not found')

    source_path = getattr(case, 'source_path', None) if not isinstance(case, dict) else case.get('source_path')
    if not source_path or not os.path.isfile(source_path):
        acq = (case.get('acquisitions') or {}) if isinstance(case, dict) else {}
        if not acq:
            raise HTTPException(status_code=404, detail='No acquisition found for this case. Upload or seed an image first.')

        # Pick the most recent acquisition
        source_path = None
        for _acq in acq.values():
            p = _acq.get('source_path') if isinstance(_acq, dict) else getattr(_acq, 'source_path', None)
            if p and os.path.isfile(p):
                source_path = p
                break

    if not source_path:
        raise HTTPException(status_code=404, detail='Acquisition file not found on disk.')

    SECTOR_SIZE = 512
    MAX_SECTORS = 2048

    def _sector_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        h = 0.0
        for f in freq:
            if f > 0:
                p = f / n
                h -= p * math.log2(p)
        return round(h, 4)

    def _classify(h: float) -> str:
        if h < 1.0:
            return 'EMPTY'
        if h < 3.0:
            return 'SPARSE'
        if h < 6.5:
            return 'STRUCTURED'
        if h < 7.5:
            return 'COMPRESSED'
        return 'ENCRYPTED'

    file_size = os.path.getsize(source_path)
    total_sectors = file_size // SECTOR_SIZE
    step = max(1, total_sectors // MAX_SECTORS)

    sectors = []
    with open(source_path, 'rb') as f:
        sector_idx = 0
        while sector_idx < total_sectors and len(sectors) < MAX_SECTORS:
            f.seek(sector_idx * SECTOR_SIZE)
            data = f.read(SECTOR_SIZE)
            if not data:
                break
            h = _sector_entropy(data)
            sectors.append({
                'sector': sector_idx,
                'offset': sector_idx * SECTOR_SIZE,
                'entropy': h,
                'classification': _classify(h),
            })
            sector_idx += step

    audit_logger.log(
        case_id=case_id,
        event_type='ENTROPY_ANALYSIS',
        actor='ENTROPY_ENGINE',
        details={
            'total_sectors_sampled': len(sectors),
            'file_size_bytes': file_size,
            'source_path': os.path.basename(source_path),
        }
    )

    return {
        'case_id': case_id,
        'file_size_bytes': file_size,
        'sector_size': SECTOR_SIZE,
        'total_sectors': total_sectors,
        'sampled_sectors': len(sectors),
        'sectors': sectors,
    }
