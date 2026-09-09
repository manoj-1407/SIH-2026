"""Evidence envelope construction and independent verification.

Protocol (same as 26149 trust foundation, independently implemented):
  canonical evidence dict → SHA-256 → Ed25519 sign → store with key_id

Verification is stateless: given envelope + trust registry → valid/invalid.
The verifier holds no write access to any store.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any

from app.core.hashing import sha256_canonical, sha256_bytes, canonical_json
from app.core.signing import SigningKey, TrustRegistry, get_signing_key, get_registry
from app.core.classification import GeoClassification, ProvenanceClassification


def build_evidence_payload(
    comparison_id: str,
    case_id: str,
    record_ids: list[str],
    geo_classification: str,
    geo_measurements: dict,
    temporal_result: dict,
    crs_result: dict,
    provenance_result: dict,
    independent_lineages: int,
    explanation: str,
) -> dict:
    """Assemble the canonical evidence dict for signing."""
    return {
        "comparison_id": comparison_id,
        "case_id": case_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "record_ids": sorted(record_ids),
        "result": {
            "geo_classification": geo_classification,
            "geo_measurements": geo_measurements,
            "temporal": temporal_result,
            "crs": crs_result,
            "provenance": provenance_result,
            "independent_lineages": independent_lineages,
            "explanation": explanation,
        },
    }


def sign_evidence(payload: dict, signing_key: SigningKey = None) -> dict:
    """
    Sign a payload. Returns the full evidence envelope:
    {payload fields} + evidence_hash + signature + signing metadata.
    """
    if signing_key is None:
        signing_key = get_signing_key()

    # Canonicalize once and reuse for both the hash and the signature —
    # sha256_canonical() and .sign() each independently called
    # canonical_json() on the same dict before, serializing it twice for
    # one signing operation.
    raw = canonical_json(payload)
    evidence_hash = sha256_bytes(raw).hex_digest
    sig_hex = signing_key.sign_bytes(raw)

    return {
        **payload,
        "evidence_hash": evidence_hash,
        "signature": sig_hex,
        "signing": {
            "algorithm": "Ed25519",
            "key_id": signing_key.key_id,
        },
    }


# Alias for compatibility across modules
sign_evidence_envelope = sign_evidence


def verify_envelope(envelope: dict, registry: TrustRegistry = None) -> tuple[bool, str]:
    """
    Independently verify a signed evidence envelope.
    Returns (is_valid, explanation).
    Does NOT access any persistence store.
    """
    if registry is None:
        registry = get_registry()

    key_id = envelope.get("signing", {}).get("key_id")
    sig_hex = envelope.get("signature")
    stored_hash = envelope.get("evidence_hash")

    if not key_id:
        return False, "missing signing.key_id"
    if not sig_hex:
        return False, "missing signature"
    if not stored_hash:
        return False, "missing evidence_hash"

    # Reconstruct payload (everything except envelope-level fields)
    payload = {k: v for k, v in envelope.items()
               if k not in ("evidence_hash", "signature", "signing")}

    # 1. Verify content hash
    computed_hash = sha256_canonical(payload).hex_digest
    if computed_hash != stored_hash:
        return False, f"evidence_hash mismatch — payload has been tampered with"

    # 2. Verify Ed25519 signature
    try:
        valid = registry.verify(key_id, payload, sig_hex)
    except KeyError:
        return False, f"key {key_id!r} not registered in trust registry"

    if not valid:
        return False, "Ed25519 signature verification failed"

    return True, f"Evidence package cryptographically verified using trusted key {key_id}"
