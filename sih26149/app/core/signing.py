"""
Ed25519 evidence signing and verification.

Actual asymmetric signatures — not hash pretending to be signature.

Sign:   private_key -> sign(canonical_bytes) -> signature_hex
Verify: key_id -> trust_registry -> public_key -> verify(canonical_bytes, sig_hex)

Verifier NEVER trusts public key embedded in evidence package.
Key resolution always goes through the trusted key registry.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class SigningError(Exception):
    pass


class VerificationError(Exception):
    pass


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate Ed25519 keypair.
    Returns: (private_key_pem_bytes, public_key_raw_32_bytes)
    """
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_pem, public_raw


def load_private_key(private_pem: bytes) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(private_pem, password=None)


def load_public_key_raw(public_raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(public_raw)


def sign(private_pem: bytes, canonical_bytes: bytes) -> str:
    """Sign canonical evidence bytes. Returns hex-encoded signature."""
    try:
        key = load_private_key(private_pem)
        sig = key.sign(canonical_bytes)
        return sig.hex()
    except Exception as e:
        raise SigningError(f'Signing failed: {e}') from e


def verify(public_raw: bytes, canonical_bytes: bytes, signature_hex: str) -> bool:
    """
    Verify signature against canonical bytes using raw public key.
    Returns True if valid, False if invalid/tampered.
    NEVER raises on invalid signature — always returns bool.
    """
    try:
        pub = load_public_key_raw(public_raw)
        sig = bytes.fromhex(signature_hex)
        pub.verify(sig, canonical_bytes)
        return True
    except (InvalidSignature, ValueError):
        return False
    except Exception:
        return False

# Aliases for envelope compatibility
sign_evidence = sign
verify_evidence = verify
