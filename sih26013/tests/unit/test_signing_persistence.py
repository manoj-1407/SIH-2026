"""
test_signing_persistence.py — verifies that Ed25519 key survives process restart.

Gate: sign payload in scope A → clear module singletons → reload key from disk
      in scope B → verify old signature → MUST succeed.
"""
import importlib
import json
import sys
import tempfile
from pathlib import Path

import pytest


def _reload_signing():
    """Force a true fresh import of the signing module (simulate new process).

    Must purge both 'app.core.signing' AND 'app.core' so that
    'from app.core import signing' actually re-executes the module rather than
    returning the cached attribute from the app.core package namespace.
    """
    to_remove = [m for m in sys.modules if 'signing' in m or m == 'app.core']
    for mod in to_remove:
        del sys.modules[mod]
    from app.core import signing
    return signing


def test_signing_key_persists_across_simulated_restart():
    """Key loaded in a fresh module context must verify evidence signed earlier."""
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir)

        # ── Process A: sign some evidence ──────────────────────────────────────
        signing_a = _reload_signing()
        signing_a.init_signing(data_dir)
        key_a = signing_a.get_signing_key()
        pubkey_hex_a = key_a.public_bytes.hex()

        payload = {"case_id": "TEST-001", "lat": 12.34, "lon": 56.78}
        signature = key_a.sign(payload)

        print(f"\nProcess A key: {pubkey_hex_a[:16]}...")
        print(f"Signature    : {signature[:16]}...")

        # ── Process B: fresh module load, same data_dir ────────────────────────
        signing_b = _reload_signing()
        signing_b.init_signing(data_dir)
        key_b = signing_b.get_signing_key()
        pubkey_hex_b = key_b.public_bytes.hex()
        registry_b = signing_b.get_registry()

        print(f"Process B key: {pubkey_hex_b[:16]}...")

        # Keys must be identical
        assert pubkey_hex_a == pubkey_hex_b, (
            f"Key mismatch after reload!\n"
            f"  A: {pubkey_hex_a}\n"
            f"  B: {pubkey_hex_b}"
        )

        # Old signature must verify under new process's registry
        is_valid = registry_b.verify(
            signing_b.EXAMINER_KEY_ID, payload, signature
        )
        assert is_valid, "Fresh-process verification FAILED — cross-process signing is broken"
        print("✓ VERIFIED: signature from process A verified in process B")


def test_trust_registry_json_written():
    """init_signing must write a trust_registry.json for independent verifiers."""
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir)
        signing = _reload_signing()
        signing.init_signing(data_dir)

        reg_path = data_dir / "keys" / "trust_registry.json"
        assert reg_path.exists(), "trust_registry.json not written"

        reg = json.loads(reg_path.read_text())
        key = signing.get_signing_key()
        assert signing.EXAMINER_KEY_ID in reg
        assert reg[signing.EXAMINER_KEY_ID] == key.public_bytes.hex()
        print(f"\n✓ trust_registry.json present with key {signing.EXAMINER_KEY_ID}")


def test_private_key_file_mode():
    """Private key file must have 0o600 permissions (owner-read only)."""
    import stat
    import os
    if os.name == "nt":
        pytest.skip("POSIX file permission bits (0o600) not supported on Windows NTFS")
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir)
        signing = _reload_signing()
        signing.init_signing(data_dir)

        key_path = data_dir / "keys" / "geo_examiner.priv"
        assert key_path.exists(), "geo_examiner.priv not created"

        mode = oct(stat.S_IMODE(key_path.stat().st_mode))
        assert key_path.stat().st_mode & 0o777 == 0o600, (
            f"Private key permissions are {mode}, expected 0o600"
        )
        print(f"\n✓ Key file permissions: {mode}")


def test_second_init_is_noop():
    """Calling init_signing twice must not raise (idempotent)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir)
        signing = _reload_signing()
        signing.init_signing(data_dir)
        key1 = signing.get_signing_key().public_bytes.hex()

        # Second call — must not re-register and not raise ValueError
        signing.init_signing(data_dir)
        key2 = signing.get_signing_key().public_bytes.hex()

        assert key1 == key2, "Key changed after second init_signing call"
        print("\n✓ Second init_signing is idempotent")
