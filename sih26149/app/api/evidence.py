"""Evidence Vault and Independent Verification API router."""
import os
import re
import io
import json
import zipfile
import datetime
from fastapi import APIRouter, HTTPException, Header, Response
from pydantic import BaseModel
from typing import Dict, Any, Optional

from app.api.deps import evidence_store, trust_registry, audit_logger, case_store, demo_snapshot
from app.api.validation import validate_case_id
from app.core.independent_verifier import verify_evidence_package
from app.core.classification import EvidenceClassification
from app.core.hashing import hash_bytes
from app.core.signing import generate_keypair, sign_evidence
from app.core.canonical import canonicalize
from app.core.persistence import atomic_write_json, PersistenceError

router = APIRouter(prefix='/evidence', tags=['Evidence Vault'])
verifier_demo_router = APIRouter(prefix='/cases/{case_id}/verifier-demo', tags=['Verifier Demo'])

EVIDENCE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]+$')

def validate_evidence_id(evidence_id: str):
    if not evidence_id or not EVIDENCE_ID_PATTERN.match(evidence_id):
        raise HTTPException(status_code=400, detail='Invalid evidence_id format')


def _demo_gate(x_demo_mode: Optional[str]) -> None:
    if os.environ.get('DEMO_MODE', '').strip() != '1' and x_demo_mode != '1':
        raise HTTPException(
            status_code=403,
            detail='Verifier demo endpoints are disabled. Requires DEMO_MODE=1 env var or X-Demo-Mode: 1 header.'
        )


def _ensure_snapshot(case_id: str) -> None:
    if not demo_snapshot.has_snapshot(case_id):
        demo_snapshot.create_snapshot(case_id)


def _ensure_case_exists(case_id: str) -> None:
    try:
        case_store.get(case_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f'Case {case_id} not found')


def _generate_demo_artifact_bytes(evidence_id: str, artifact_id: str, size: int = 512) -> bytes:
    seed = f'{evidence_id}::{artifact_id}'.encode('utf-8')
    out = bytearray()
    i = 0
    while len(out) < size:
        out.extend(hash_bytes(seed + bytes([i % 256])).encode('ascii'))
        i += 1
    return bytes(out[:size])


def _get_or_create_artifact_bytes(pkg: Dict[str, Any], evidence_id: str, artifact_id: str) -> bytes:
    result = pkg.get('result') or {}
    demo_artifacts = result.get('_demo_artifacts')
    if not isinstance(demo_artifacts, dict):
        demo_artifacts = {}
    artifact_record = demo_artifacts.get(artifact_id)
    if isinstance(artifact_record, dict) and isinstance(artifact_record.get('bytes_hex'), str):
        try:
            return bytes.fromhex(artifact_record['bytes_hex'])
        except ValueError:
            pass
    new_bytes = _generate_demo_artifact_bytes(evidence_id, artifact_id)
    return new_bytes


def _store_artifact_bytes(pkg: Dict[str, Any], artifact_id: str, artifact_bytes: bytes) -> None:
    result = pkg.get('result') or {}
    demo_artifacts = result.get('_demo_artifacts')
    if not isinstance(demo_artifacts, dict):
        demo_artifacts = {}
    demo_artifacts[artifact_id] = {'bytes_hex': artifact_bytes.hex()}
    result['_demo_artifacts'] = demo_artifacts
    pkg['result'] = result


class TamperArtifactRequest(BaseModel):
    evidence_id: str
    artifact_id: str
    byte_offset: int = 42


class TamperAuditRequest(BaseModel):
    pass


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
        'valid': is_valid,
        'signature_valid': is_valid,
        'verification_result': 'VERIFIED' if is_valid else 'INVALID',
        'classification': cl_result.classification.value,
        'explanation': cl_result.explanation,
        'details': cl_result.details,
    }


@router.post('/verify-package')
def verify_external_package(package: Dict[str, Any]):
    """Independent verification for exported evidence JSON packages."""
    if 'package' in package and isinstance(package.get('package'), dict):
        package = package['package']
    try:
        is_valid, cl_result = verify_evidence_package(package, key_registry=trust_registry)
        return {
            'is_valid': is_valid,
            'valid': is_valid,
            'signature_valid': is_valid,
            'verification_result': 'VERIFIED' if is_valid else 'INVALID',
            'classification': cl_result.classification.value,
            'explanation': cl_result.explanation,
            'details': cl_result.details,
        }
    except Exception as e:
        return {
            'is_valid': False,
            'valid': False,
            'signature_valid': False,
            'verification_result': 'INVALID',
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


@router.get('/{evidence_id}/download')
def download_evidence_package(evidence_id: str):
    validate_evidence_id(evidence_id)
    try:
        envelope = evidence_store.get(evidence_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f'Evidence package {evidence_id} not found')

    case_id = envelope.get('case_id', 'UNKNOWN')

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        manifest_json = json.dumps(envelope, indent=2)
        zf.writestr('manifest.json', manifest_json)

        signing_info = envelope.get('signing', {})
        sig_record = {
            'key_id': signing_info.get('key_id', ''),
            'algorithm': signing_info.get('algorithm', 'Ed25519'),
            'evidence_hash': envelope.get('evidence_hash', ''),
            'signature': envelope.get('signature', ''),
            'signed_at_utc': envelope.get('created_at_utc', ''),
        }
        zf.writestr('cryptography/signature.json', json.dumps(sig_record, indent=2))

        pem_candidates = [
            envelope.get('public_key_pem'),
            signing_info.get('public_key_pem'),
            envelope.get('public_key'),
            signing_info.get('public_key'),
        ]
        pem_content = None
        for candidate in pem_candidates:
            if isinstance(candidate, str) and 'PUBLIC KEY' in candidate:
                pem_content = candidate
                break
        if pem_content is None:
            pem_content = (
                '-----BEGIN PUBLIC KEY-----\n'
                '[Public key not embedded in evidence envelope. '
                'Retrieve from trusted key registry using key_id.]\n'
                '-----END PUBLIC KEY-----\n'
            )
        zf.writestr('cryptography/public_key.pem', pem_content)

        if case_id and case_id != 'UNKNOWN':
            try:
                timeline = audit_logger.get_timeline(case_id)
                if timeline:
                    jsonl_lines = []
                    for entry in timeline:
                        jsonl_lines.append(json.dumps(entry))
                    zf.writestr('audit/events.jsonl', '\n'.join(jsonl_lines) + '\n')
                else:
                    zf.writestr('audit/events.jsonl', '')
            except Exception as exc:
                raise HTTPException(
                    status_code=500,
                    detail='Unable to retrieve the chain-of-custody timeline for export',
                ) from exc
        else:
            zf.writestr('audit/events.jsonl', '')

        classification = envelope.get('result', {}).get('classification', 'UNKNOWN')
        evidence_hash = envelope.get('evidence_hash', 'N/A')
        signature = envelope.get('signature', 'N/A')
        hashes_lines = []
        for section_name in ('input', 'operation', 'result'):
            section = envelope.get(section_name, {})
            if isinstance(section, dict):
                for k, v in section.items():
                    k_lower = k.lower()
                    if 'hash' in k_lower or 'sha' in k_lower or 'md5' in k_lower:
                        hashes_lines.append(f'  {section_name}.{k}: {v}')
        hashes_block = '\n'.join(hashes_lines) if hashes_lines else '  (no additional hashes embedded)'
        summary = (
            f'Evidence Package Summary\n'
            f'========================\n'
            f'Evidence ID: {evidence_id}\n'
            f'Case ID: {case_id}\n'
            f'Classification: {classification}\n'
            f'Created (UTC): {envelope.get("created_at_utc", "N/A")}\n'
            f'Evidence Type: {envelope.get("evidence_type", "N/A")}\n'
            f'Operation ID: {envelope.get("operation_id", "N/A")}\n'
            f'Signing Key ID: {signing_info.get("key_id", "N/A")}\n'
            f'\n'
            f'Cryptographic Hashes\n'
            f'--------------------\n'
            f'  evidence_hash (SHA-256): {evidence_hash}\n'
            f'  signature (Ed25519 hex): {signature[:16]}...{signature[-16:] if len(signature) > 32 else signature}\n'
            f'{hashes_block}\n'
            f'\n'
            f'Payload limitation: this export includes only bytes already embedded in the evidence envelope; it does not retrieve recovered files from the source image.\n'
            f'\n'
            f'Scope: {envelope.get("scope", "N/A")}\n'
        )
        zf.writestr('reports/evidence_summary.txt', summary)

    buf.seek(0)
    zip_bytes = buf.getvalue()
    ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')
    filename = f'evidence_{case_id}_{evidence_id}_{ts}.zip'

    return Response(
        content=zip_bytes,
        media_type='application/zip',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@verifier_demo_router.post('/tamper-artifact')
def demo_tamper_artifact(
    case_id: str,
    req: TamperArtifactRequest,
    x_demo_mode: Optional[str] = Header(None),
):
    _demo_gate(x_demo_mode)
    validate_case_id(case_id)
    _ensure_case_exists(case_id)
    validate_evidence_id(req.evidence_id)

    try:
        pkg = evidence_store.get(req.evidence_id)
    except Exception:
        raise HTTPException(status_code=404, detail=f'Evidence package {req.evidence_id} not found')

    if pkg.get('case_id') != case_id:
        raise HTTPException(status_code=400, detail=f'Evidence {req.evidence_id} does not belong to case {case_id}')

    _ensure_snapshot(case_id)

    artifact_bytes = _get_or_create_artifact_bytes(pkg, req.evidence_id, req.artifact_id)

    offset = req.byte_offset
    if offset < 0 or offset >= len(artifact_bytes):
        raise HTTPException(
            status_code=400,
            detail=f'byte_offset {offset} out of range for artifact of size {len(artifact_bytes)} bytes'
        )

    old_sha256 = hash_bytes(artifact_bytes)

    modified = bytearray(artifact_bytes)
    modified[offset] = modified[offset] ^ 0x01
    modified_bytes = bytes(modified)

    new_sha256 = hash_bytes(modified_bytes)

    _store_artifact_bytes(pkg, req.artifact_id, modified_bytes)

    try:
        atomic_write_json(evidence_store._path(req.evidence_id), pkg)
    except PersistenceError as e:
        raise HTTPException(status_code=500, detail=f'Failed to write tampered evidence: {e}')

    return {
        'tampered': True,
        'evidence_id': req.evidence_id,
        'artifact_id': req.artifact_id,
        'byte_offset': offset,
        'old_sha256': old_sha256,
        'new_sha256': new_sha256,
        'description': (
            f'Flipped bit-0 of byte at offset {offset} in artifact {req.artifact_id}. '
            f'Manifest.sha256 for this artifact no longer matches on-disk bytes.'
        ),
    }


@verifier_demo_router.post('/key-substitution')
def demo_key_substitution(
    case_id: str,
    x_demo_mode: Optional[str] = Header(None),
):
    _demo_gate(x_demo_mode)
    validate_case_id(case_id)
    _ensure_case_exists(case_id)

    evidence_packages = evidence_store.list_all(case_id=case_id)
    if not evidence_packages:
        raise HTTPException(status_code=400, detail=f'No evidence packages found for case {case_id}')

    _ensure_snapshot(case_id)

    attack_private_pem, attack_public_raw = generate_keypair()
    attack_key_id = f'ATTACK-KEY-{hash_bytes(attack_public_raw)[:10].upper()}'

    target_pkg = evidence_packages[0]
    evidence_id = target_pkg.get('evidence_id')
    original_key_id = (target_pkg.get('signing') or {}).get('key_id', 'UNKNOWN')

    payload_to_sign = {k: v for k, v in target_pkg.items() if k not in ('evidence_hash', 'signature')}
    signing_info = payload_to_sign.get('signing') or {}
    signing_info['key_id'] = attack_key_id
    signing_info['_attack_public_key_hex'] = attack_public_raw.hex()
    payload_to_sign['signing'] = signing_info

    canon_bytes = canonicalize(payload_to_sign)
    new_evidence_hash = hash_bytes(canon_bytes)
    try:
        new_signature = sign_evidence(attack_private_pem, canon_bytes)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Attack signing failed: {e}')

    modified_pkg = dict(payload_to_sign)
    modified_pkg['evidence_hash'] = new_evidence_hash
    modified_pkg['signature'] = new_signature
    modified_pkg['_attack_substitution'] = {
        'attack_key_id': attack_key_id,
        'original_key_id': original_key_id,
    }

    try:
        atomic_write_json(evidence_store._path(evidence_id), modified_pkg)
    except PersistenceError as e:
        raise HTTPException(status_code=500, detail=f'Failed to write attack-signed evidence: {e}')

    return {
        'tampered': True,
        'evidence_id': evidence_id,
        'original_key_id': original_key_id,
        'attack_key_id': attack_key_id,
        'description': (
            'Signed manifest with attacker key B and shipped attacker pubkey B in cryptography dir '
            'alongside original. Trusted key registry still expects key A — verifier MUST reject per DEF-003.'
        ),
    }


@verifier_demo_router.post('/tamper-audit-chain')
def demo_tamper_audit_chain_verifier(
    case_id: str,
    x_demo_mode: Optional[str] = Header(None),
):
    _demo_gate(x_demo_mode)
    validate_case_id(case_id)
    _ensure_case_exists(case_id)

    timeline = audit_logger.get_timeline(case_id)
    if not timeline:
        raise HTTPException(status_code=400, detail='No audit events for this case. Run some operations first.')

    _ensure_snapshot(case_id)

    result = audit_logger.apply_permanent_audit_tamper(case_id)
    if 'error' in result:
        raise HTTPException(status_code=400, detail=result['error'])

    return {
        'tampered': True,
        'event_id': result.get('event_id', f'{case_id}-{result.get("entry_index", 0)}'),
        'entry_index': result.get('entry_index'),
        'field': result.get('field'),
        'original_value': result.get('original_value'),
        'tampered_value': result.get('tampered_value'),
        'description': 'Modified operation_result field of last event; next_event.previous_hash no longer matches',
        'violations': result.get('violations', []),
    }


@verifier_demo_router.post('/reset')
def demo_reset_case(
    case_id: str,
    x_demo_mode: Optional[str] = Header(None),
):
    _demo_gate(x_demo_mode)
    validate_case_id(case_id)
    _ensure_case_exists(case_id)

    restored = demo_snapshot.restore_snapshot(case_id)
    if not restored:
        return {
            'restored': False,
            'case_id': case_id,
            'description': 'No pre-tamper snapshot exists for this case. Nothing to restore.',
        }

    return {
        'restored': True,
        'case_id': case_id,
        'description': (
            'Restored pre-tamper backup snapshot of case evidence directory. '
            'Case data, audit chain, and all evidence envelopes reverted to their pre-attack state.'
        ),
    }
