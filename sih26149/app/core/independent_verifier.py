"""
Portable Independent Evidence Verifier.
Verifies an evidence package JSON independently of any case database.
Resolves signing key from the trusted key registry via key_id.
Never trusts an attacker-supplied public key inside the evidence package.
"""
from typing import Tuple, Dict, Any, Optional
from app.core.canonical import canonicalize
from app.core.hashing import hash_bytes
from app.core.signing import verify_evidence
from app.core.trust import KeyRegistry, KeyNotFoundError
from app.core.classification import EvidenceClassification, ClassifiedResult


def verify_evidence_package(
    package: dict,
    key_registry: Optional[KeyRegistry] = None,
    public_key_bytes: Optional[bytes] = None,
) -> Tuple[bool, ClassifiedResult]:
    """
    Verify a signed evidence package.

    Returns:
        (is_valid: bool, classified_result: ClassifiedResult)
    """
    # Check essential fields
    required_fields = ['evidence_id', 'case_id', 'evidence_type', 'created_at_utc',
                       'input', 'operation', 'result', 'scope', 'signing',
                       'evidence_hash', 'signature']
    for field in required_fields:
        if field not in package:
            return False, ClassifiedResult(
                classification=EvidenceClassification.INVALID,
                explanation=f'Evidence package missing required field: {field}',
                details={'missing_field': field},
            )

    signing_info = package.get('signing', {})
    key_id = signing_info.get('key_id')
    algorithm = signing_info.get('algorithm')

    if algorithm != 'Ed25519':
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation=f'Unsupported signing algorithm: {algorithm}',
            details={'algorithm': algorithm},
        )

    # Resolve public key from trusted registry
    trusted_pubkey = public_key_bytes
    if trusted_pubkey is None:
        if key_registry is None:
            return False, ClassifiedResult(
                classification=EvidenceClassification.INVALID,
                explanation='No trusted key registry or public key provided for verification',
                details={'key_id': key_id},
            )
        try:
            trusted_pubkey = key_registry.get_public_key(key_id)
        except KeyNotFoundError:
            return False, ClassifiedResult(
                classification=EvidenceClassification.INVALID,
                explanation=f'Signer key {key_id} is not registered in the trusted key registry',
                details={'key_id': key_id, 'untrusted_key': True},
            )

    # Reconstruct the signed payload by omitting evidence_hash and signature
    payload_to_verify = {k: v for k, v in package.items() if k not in ('evidence_hash', 'signature')}
    canonical_bytes = canonicalize(payload_to_verify)

    # 1. Verify computed evidence hash matches the stored evidence hash
    computed_hash = hash_bytes(canonical_bytes)
    stored_hash = package.get('evidence_hash', '')

    if computed_hash.lower() != stored_hash.lower():
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation='Evidence hash mismatch — signed fields have been tampered with or altered',
            details={
                'computed_hash': computed_hash,
                'stored_hash': stored_hash,
                'tamper_detected': True,
            },
        )

    # 2. Verify asymmetric Ed25519 signature
    stored_sig = package.get('signature', '')
    sig_valid = verify_evidence(trusted_pubkey, canonical_bytes, stored_sig)

    if not sig_valid:
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation='Cryptographic signature verification failed — invalid Ed25519 signature',
            details={
                'key_id': key_id,
                'signature_valid': False,
            },
        )

    return True, ClassifiedResult(
        classification=EvidenceClassification.VERIFIED,
        explanation=f'Evidence package cryptographically verified using trusted key {key_id}',
        details={
            'evidence_id': package['evidence_id'],
            'key_id': key_id,
            'algorithm': algorithm,
            'evidence_hash': computed_hash,
            'signature_valid': True,
            'hash_matches': True,
        },
    )
