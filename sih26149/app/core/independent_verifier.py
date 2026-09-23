"""
Portable Independent Forensic Evidence Verifier — SIH26149.

Consumes only:
  - Evidence Package (JSON file or Directory)
  - Public Key (PEM file, raw bytes, or trusted key registry)

Guarantees complete independence:
  - No database connection required.
  - No web UI or running FastAPI server required.
  - No producer internal state or ORM required.

Verification pipeline:
  1. Manifest & Schema validation
  2. RFC 8785 canonicalization & file SHA-256 integrity verification
  3. Ed25519 digital signature verification
  4. Audit event-chain hash continuity verification
  5. Outcome: VERIFIED (Valid) or INVALID (Tamper Detected) with exact violation trace
"""
import os
import json
from pathlib import Path
from typing import Tuple, Dict, Any, Optional

from app.core.canonical import canonicalize
from app.core.hashing import hash_bytes, hash_file
from app.core.signing import verify_evidence, load_public_key_raw
from app.core.trust import KeyRegistry, KeyNotFoundError
from app.core.classification import EvidenceClassification, ClassifiedResult
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_evidence_package(
    package_or_path: dict | str | Path,
    key_registry: Optional[KeyRegistry] = None,
    public_key_bytes: Optional[bytes] = None,
    public_key_pem: Optional[bytes | str] = None,
) -> Tuple[bool, ClassifiedResult]:
    """
    Verify either a single envelope JSON or a complete directory package.
    """
    if isinstance(package_or_path, (str, Path)):
        p = Path(package_or_path)
        if p.is_dir():
            return verify_directory_package(
                p,
                key_registry=key_registry,
                public_key_pem=public_key_pem,
                public_key_bytes=public_key_bytes,
            )
        else:
            with open(p, 'r', encoding='utf-8') as f:
                package = json.load(f)
            return verify_envelope_dict(package, key_registry=key_registry, public_key_bytes=public_key_bytes, public_key_pem=public_key_pem)
    elif isinstance(package_or_path, dict):
        return verify_envelope_dict(package_or_path, key_registry=key_registry, public_key_bytes=public_key_bytes, public_key_pem=public_key_pem)
    else:
        raise ValueError(f"Unsupported package type: {type(package_or_path)}")


def verify_envelope_dict(
    package: dict,
    key_registry: Optional[KeyRegistry] = None,
    public_key_bytes: Optional[bytes] = None,
    public_key_pem: Optional[bytes | str] = None,
) -> Tuple[bool, ClassifiedResult]:
    """Verify a single JSON evidence envelope."""
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

    # Resolve public key
    trusted_raw = None
    if public_key_bytes:
        trusted_raw = public_key_bytes
    elif public_key_pem:
        if isinstance(public_key_pem, str):
            public_key_pem = public_key_pem.encode('utf-8')
        pub_obj = serialization.load_pem_public_key(public_key_pem)
        if isinstance(pub_obj, Ed25519PublicKey):
            trusted_raw = pub_obj.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
    elif key_registry:
        try:
            trusted_raw = key_registry.get_public_key(key_id)
        except KeyNotFoundError:
            return False, ClassifiedResult(
                classification=EvidenceClassification.INVALID,
                explanation=f'Signer key {key_id} is not registered in the trusted key registry',
                details={'key_id': key_id, 'untrusted_key': True},
            )
    else:
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation='No trusted key registry or public key provided for verification',
            details={'key_id': key_id},
        )

    # Reconstruct the signed payload by omitting evidence_hash and signature
    payload_to_verify = {k: v for k, v in package.items() if k not in ('evidence_hash', 'signature')}
    canonical_bytes = canonicalize(payload_to_verify)

    # 1. Verify computed evidence hash matches stored evidence hash
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
    sig_valid = verify_evidence(trusted_raw, canonical_bytes, stored_sig)

    if not sig_valid:
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation='Cryptographic signature verification failed — invalid Ed25519 signature',
            details={'key_id': key_id, 'signature_valid': False},
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


def verify_directory_package(
    package_dir: str | Path,
    key_registry: Optional[KeyRegistry] = None,
    public_key_pem: Optional[bytes | str] = None,
    public_key_bytes: Optional[bytes] = None,
) -> Tuple[bool, ClassifiedResult]:
    """
    Verify a complete portable evidence package directory.
    Checks manifest, all file hashes, signature, and audit chain.

    Security rule: directory packages must be anchored to a trusted registry,
    not silently accepted with an embedded public key. Explicit public keys are
    allowed only as an out-of-band trust source; the embedded key is never used
    as the sole trust anchor.
    """
    root = Path(package_dir)
    manifest_p = root / "manifest.json"
    sig_p = root / "cryptography" / "signature.json"
    pub_p = root / "cryptography" / "public_key.pem"
    audit_p = root / "audit" / "events.jsonl"

    if not manifest_p.exists():
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation="Package missing manifest.json",
            details={"missing_file": "manifest.json"}
        )
    if not sig_p.exists():
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation="Package missing cryptography/signature.json",
            details={"missing_file": "cryptography/signature.json"}
        )

    try:
        manifest = json.loads(manifest_p.read_text(encoding='utf-8'))
        sig_data = json.loads(sig_p.read_text(encoding='utf-8'))
    except Exception as e:
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation=f"Corrupted JSON in package manifest/signature: {e}",
            details={"error": str(e)}
        )

    # 1. Verify all file hashes listed in manifest
    file_hashes = manifest.get("file_hashes", {})
    for rel_path, expected_hash in file_hashes.items():
        file_target = root / rel_path
        if not file_target.exists():
            return False, ClassifiedResult(
                classification=EvidenceClassification.INVALID,
                explanation=f"Missing evidence package file: {rel_path}",
                details={"missing_file": rel_path}
            )
        computed_file_hash = hash_file(str(file_target)).hex_digest
        if computed_file_hash.lower() != expected_hash.lower():
            return False, ClassifiedResult(
                classification=EvidenceClassification.INVALID,
                explanation=f"Tamper detected in artifact file '{rel_path}': hash mismatch",
                details={
                    "file": rel_path,
                    "expected_hash": expected_hash,
                    "computed_hash": computed_file_hash,
                    "tamper_detected": True,
                }
            )

    # 1b. Reverse check: detect files injected AFTER signing.
    # Any file that exists in the package directory but is NOT listed in the
    # manifest (and is not one of the three by-design excluded files) must
    # cause INVALID — the manifest is the authoritative file inventory.
    _EXCLUDED_FROM_MANIFEST = {
        "manifest.json",
        "cryptography/signature.json",
        "cryptography/public_key.pem",
    }
    for walk_root, _, walk_files in os.walk(root):
        for wf in walk_files:
            full_wf = Path(walk_root) / wf
            rel_wf = str(full_wf.relative_to(root)).replace("\\", "/")
            if rel_wf in _EXCLUDED_FROM_MANIFEST:
                continue
            if rel_wf not in file_hashes:
                return False, ClassifiedResult(
                    classification=EvidenceClassification.INVALID,
                    explanation=(
                        f"Unexpected file '{rel_wf}' found in evidence package "
                        "— file was not present when the package was signed"
                    ),
                    details={"unexpected_file": rel_wf, "tamper_detected": True},
                )

    # 2. Verify manifest raw on-disk hash, canonical structure, and signature
    raw_manifest_bytes = manifest_p.read_bytes()
    raw_manifest_hash = hash_bytes(raw_manifest_bytes)
    stored_manifest_hash = sig_data.get("manifest_hash", "")

    # Strict on-disk raw hash check: manifest on disk must match the exact signed hash
    if raw_manifest_hash.lower() != stored_manifest_hash.lower():
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation="Manifest tamper detected — manifest on-disk hash does not match signature record",
            details={"computed_hash": raw_manifest_hash, "stored_hash": stored_manifest_hash}
        )

    # Manifest canonical re-serialization check
    manifest_canonical_bytes = canonicalize(manifest)
    if hash_bytes(manifest_canonical_bytes).lower() != stored_manifest_hash.lower():
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation="Manifest canonicalization mismatch — manifest is not in strict RFC 8785 canonical form",
            details={"stored_hash": stored_manifest_hash}
        )

    # 3. Resolve public key via trusted registry or explicit out-of-band key only.
    trusted_raw = None
    if public_key_bytes:
        trusted_raw = public_key_bytes
    elif public_key_pem:
        if isinstance(public_key_pem, str):
            public_key_pem = public_key_pem.encode('utf-8')
        pub_obj = serialization.load_pem_public_key(public_key_pem)
        if isinstance(pub_obj, Ed25519PublicKey):
            trusted_raw = pub_obj.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
    elif key_registry:
        try:
            trusted_raw = key_registry.get_public_key(sig_data.get("key_id"))
        except KeyNotFoundError:
            return False, ClassifiedResult(
                classification=EvidenceClassification.INVALID,
                explanation="Package signature cannot be verified with the trusted key registry",
                details={"key_id": sig_data.get("key_id"), "trusted_key_registry": True}
            )

    # If the package embeds a public key, use it only as a comparison anchor when
    # an external trust source was already provided; embedded keys are never trusted
    # as the sole trust root for directory verification.
    if pub_p.exists():
        embedded_pem = pub_p.read_bytes()
        try:
            embedded_obj = serialization.load_pem_public_key(embedded_pem)
            if isinstance(embedded_obj, Ed25519PublicKey):
                embedded_raw = embedded_obj.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                if trusted_raw is not None and embedded_raw != trusted_raw:
                    return False, ClassifiedResult(
                        classification=EvidenceClassification.INVALID,
                        explanation="Public key substitution detected: package public key does not match trusted key authority",
                        details={"key_id": sig_data.get("key_id"), "tamper_detected": True}
                    )
        except Exception as e:
            return False, ClassifiedResult(
                classification=EvidenceClassification.INVALID,
                explanation=f"Corrupted public key in evidence package: {e}",
                details={"error": str(e)}
            )

    if trusted_raw is None:
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation="No public key available for directory verification; no trusted key registry or explicit public key supplied for directory verification; embedded public keys are never trusted as the sole anchor",
            details={"key_id": sig_data.get("key_id")}
        )

    sig_hex = sig_data.get("signature", "")
    sig_valid = verify_evidence(trusted_raw, manifest_canonical_bytes, sig_hex)
    if not sig_valid:
        return False, ClassifiedResult(
            classification=EvidenceClassification.INVALID,
            explanation="Cryptographic signature verification failed on package manifest",
            details={"key_id": sig_data.get("key_id"), "signature_valid": False}
        )

    # 4. Verify audit events hash chain if present
    if audit_p.exists() and audit_p.stat().st_size > 0:
        lines = audit_p.read_text(encoding='utf-8').splitlines()
        expected_prev = "GENESIS"
        for idx, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                return False, ClassifiedResult(
                    classification=EvidenceClassification.INVALID,
                    explanation=f"Malformed audit event JSON at line {idx}",
                    details={"line": idx}
                )
            stored_prev = event.get("previous_hash", "GENESIS")
            if stored_prev != expected_prev:
                return False, ClassifiedResult(
                    classification=EvidenceClassification.INVALID,
                    explanation=f"Audit chain broken at event {idx}: previous hash mismatch",
                    details={"event_index": idx, "expected_prev": expected_prev, "stored_prev": stored_prev}
                )
            sanitized = {k: v for k, v in event.items() if k != "entry_hash"}
            computed_ev_hash = hash_bytes(canonicalize(sanitized))
            if event.get("entry_hash") != computed_ev_hash:
                return False, ClassifiedResult(
                    classification=EvidenceClassification.INVALID,
                    explanation=f"Tamper detected in audit event {idx}: entry hash mismatch",
                    details={"event_index": idx, "tamper_detected": True}
                )
            expected_prev = event.get("entry_hash")

    return True, ClassifiedResult(
        classification=EvidenceClassification.VERIFIED,
        explanation=f"Portable evidence package '{root.name}' fully verified (manifest, file hashes, signature, audit chain)",
        details={
            "case_id": manifest.get("case_id"),
            "manifest_hash": raw_manifest_hash,
            "signature_valid": True,
            "files_verified": len(file_hashes),
        }
    )
