"""
Cryptographic Evidence Envelope.
Implements distinct case_id, operation_id, and evidence_id identities.
Every important forensic or sanitization conclusion becomes a signed,
canonically serialized, Ed25519-signed envelope.
"""
import uuid
import datetime
from typing import Any, Optional
from app.core.canonical import canonicalize
from app.core.hashing import hash_bytes
from app.core.signing import sign_evidence, verify_evidence
from app.core.trust import KeyRegistry, KeyNotFoundError


def new_evidence_id() -> str:
    return f'EVID-{uuid.uuid4().hex[:10].upper()}'


def new_operation_id() -> str:
    return f'OP-{uuid.uuid4().hex[:8].upper()}'


def build_evidence_payload(
    case_id: str,
    operation_id: str,
    evidence_type: str,
    input_meta: dict,
    operation_meta: dict,
    result_meta: dict,
    scope: str,
    key_id: str,
    evidence_id: Optional[str] = None,
    created_at_utc: Optional[str] = None,
) -> dict:
    """
    Build the canonical payload to be signed.
    Notice: Does NOT include signature or evidence_hash yet.
    """
    if evidence_id is None:
        evidence_id = new_evidence_id()
    if created_at_utc is None:
        created_at_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return {
        'evidence_id': evidence_id,
        'case_id': case_id,
        'operation_id': operation_id,
        'evidence_type': evidence_type,
        'created_at_utc': created_at_utc,
        'input': input_meta,
        'operation': operation_meta,
        'result': result_meta,
        'scope': scope,
        'signing': {
            'algorithm': 'Ed25519',
            'key_id': key_id,
        }
    }


def sign_evidence_envelope(
    payload: dict,
    private_key_bytes: bytes,
) -> dict:
    """
    Sign an evidence payload.
    1. Canonicalize the payload.
    2. Compute SHA-256 of canonical bytes.
    3. Sign canonical bytes with Ed25519 private key.
    4. Return full package with evidence_hash and signature.
    """
    canon_bytes = canonicalize(payload)
    evidence_hash = hash_bytes(canon_bytes)
    signature_hex = sign_evidence(private_key_bytes, canon_bytes)

    package = dict(payload)
    package['evidence_hash'] = evidence_hash
    package['signature'] = signature_hex
    return package
