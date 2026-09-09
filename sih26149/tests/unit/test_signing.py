"""
Unit tests for Ed25519 signing.
Includes 12 adversarial cases per the engineering spec.
"""
import pytest
from app.core.signing import generate_keypair, sign, verify, SigningError


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def keypair2():
    return generate_keypair()


def test_generate_keypair_returns_bytes(keypair):
    priv, pub = keypair
    assert isinstance(priv, bytes)
    assert isinstance(pub, bytes)


def test_public_key_is_32_bytes(keypair):
    _, pub = keypair
    assert len(pub) == 32


def test_sign_returns_hex_string(keypair):
    priv, _ = keypair
    sig = sign(priv, b'test message')
    assert isinstance(sig, str)
    assert all(c in '0123456789abcdef' for c in sig)


def test_sign_and_verify_valid(keypair):
    """Adversarial 1: baseline — valid signature verifies correctly."""
    priv, pub = keypair
    data = b'canonical evidence bytes'
    sig = sign(priv, data)
    assert verify(pub, data, sig) is True


def test_modified_evidence_fails(keypair):
    """Adversarial 2: modified evidence content -> signature fails."""
    priv, pub = keypair
    data = b'classification=VERIFIED'
    sig = sign(priv, data)
    tampered = b'classification=INVALID'
    assert verify(pub, tampered, sig) is False


def test_modified_hash_fails(keypair):
    """Adversarial 3: modified evidence hash -> signature fails."""
    priv, pub = keypair
    import hashlib, json
    from app.core.canonical import canonicalize
    evidence = {'classification': 'VERIFIED', 'hash': 'deadbeef'}
    data = canonicalize(evidence)
    sig = sign(priv, data)
    tampered_evidence = {'classification': 'VERIFIED', 'hash': 'cafebabe'}
    tampered_data = canonicalize(tampered_evidence)
    assert verify(pub, tampered_data, sig) is False


def test_substituted_public_key_fails(keypair, keypair2):
    """Adversarial 4: substituted public key -> signature fails."""
    priv, pub = keypair
    _, attacker_pub = keypair2
    data = b'signed content'
    sig = sign(priv, data)
    # Attacker substitutes their own public key
    assert verify(attacker_pub, data, sig) is False


def test_forged_evidence_fails(keypair):
    """Adversarial 5: forged evidence (no valid private key) -> fails."""
    _, pub = keypair
    data = b'legitimate evidence'
    forged_sig = 'a' * 128  # 64 bytes of hex zeros
    assert verify(pub, data, forged_sig) is False


def test_invalid_signature_format_fails(keypair):
    """Adversarial 6: invalid signature hex -> returns False, not exception."""
    _, pub = keypair
    data = b'evidence'
    assert verify(pub, data, 'not-valid-hex!!') is False


def test_empty_signature_fails(keypair):
    """Adversarial 7: empty signature -> False."""
    _, pub = keypair
    assert verify(pub, b'data', '') is False


def test_truncated_signature_fails(keypair):
    """Adversarial 8: truncated signature -> False."""
    priv, pub = keypair
    data = b'evidence'
    sig = sign(priv, data)
    truncated = sig[:32]  # half the signature
    assert verify(pub, data, truncated) is False


def test_wrong_data_fails(keypair):
    """Adversarial 9: correct signature but wrong data."""
    priv, pub = keypair
    data_a = b'evidence A'
    data_b = b'evidence B'
    sig_a = sign(priv, data_a)
    assert verify(pub, data_b, sig_a) is False


def test_different_keypairs_dont_cross_verify(keypair, keypair2):
    """Adversarial 10: key from pair 1 does not verify sig from pair 2."""
    priv1, pub1 = keypair
    priv2, pub2 = keypair2
    data = b'evidence'
    sig2 = sign(priv2, data)
    assert verify(pub1, data, sig2) is False


def test_signature_is_deterministic_to_data(keypair):
    """Adversarial 11: same data always produces verifiable signature."""
    priv, pub = keypair
    data = b'canonical evidence'
    sig1 = sign(priv, data)
    sig2 = sign(priv, data)
    # Both should verify (Ed25519 is deterministic)
    assert verify(pub, data, sig1) is True
    assert verify(pub, data, sig2) is True


def test_verify_never_raises_on_invalid_input(keypair):
    """Adversarial 12: verify() must not raise — always returns bool."""
    _, pub = keypair
    # Various garbage inputs
    assert verify(pub, b'', '') is False
    assert verify(pub, b'x', 'xyz') is False
    assert verify(b'\x00' * 32, b'data', 'aa' * 32) is False
