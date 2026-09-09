"""Ed25519 signing for geospatial evidence envelopes.
Independently implemented from 26149 — same cryptographic protocol.
Keys are persisted to disk so signatures survive process restarts.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from app.core.hashing import canonical_json


class SigningKey:
    def __init__(self, key_id: str, private_key: Ed25519PrivateKey):
        self.key_id = key_id
        self._private = private_key
        self.public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    @classmethod
    def generate(cls, key_id: str) -> "SigningKey":
        return cls(key_id, Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, key_id: str, key_bytes: bytes) -> "SigningKey":
        """Load a private key from bytes, auto-detecting PEM vs raw.

        Standardized on PEM going forward (matches sih26149 and the
        `cryptography` library's own native load/save convention — raw
        32-byte encoding was a format only this project used, which meant
        a key from one project could never be used in the other's context).
        Raw-bytes loading is kept only so a key persisted by an older
        version of this code still loads instead of breaking outright.
        """
        if b"BEGIN" in key_bytes:
            private_key = serialization.load_pem_private_key(key_bytes, password=None)
        else:
            private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        return cls(key_id, private_key)

    def private_raw_bytes(self) -> bytes:
        return self._private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def private_pem_bytes(self) -> bytes:
        """PEM/PKCS8 encoding — the format new keys are persisted in."""
        return self._private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def sign(self, payload: dict) -> str:
        """Sign canonical JSON of payload. Returns hex signature."""
        raw = canonical_json(payload)
        return self.sign_bytes(raw)

    def sign_bytes(self, raw: bytes) -> str:
        """Sign already-canonicalized bytes directly.

        Exists so callers that already have the canonical bytes (e.g.
        sign_evidence, which also hashes them) don't have to serialize the
        same dict to JSON twice for one signing operation.
        """
        sig_bytes = self._private.sign(raw)
        return sig_bytes.hex()


class TrustRegistry:
    """Maps key_id -> public key bytes. Immutable after registration."""

    def __init__(self):
        self._keys: dict[str, bytes] = {}

    def register(self, key_id: str, public_bytes: bytes) -> None:
        if key_id in self._keys:
            raise ValueError(f"Key {key_id!r} already registered")
        self._keys[key_id] = public_bytes

    def verify(self, key_id: str, payload: dict, signature_hex: str) -> bool:
        """Returns True iff signature is valid under the registered key for key_id."""
        if key_id not in self._keys:
            raise KeyError(f"Key {key_id!r} not registered in trust registry")
        raw = canonical_json(payload)
        pub_bytes = self._keys[key_id]
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _PK
            pub = _PK.from_public_bytes(pub_bytes)
            pub.verify(bytes.fromhex(signature_hex), raw)
            return True
        except (InvalidSignature, ValueError):
            return False


import threading

# Module-level singletons — populated by init_signing()
_key_init_lock = threading.Lock()
_registry = TrustRegistry()
_signing_key: SigningKey | None = None
_data_dir: Path | None = None   # tracks the data_dir used at init time

EXAMINER_KEY_ID = "KEY-GEO-EXAMINER-26013-PRIMARY"


def _default_data_dir() -> Path:
    env_dir = os.environ.get("SIH26013_DATA_DIR")
    if env_dir:
        return Path(env_dir)
    project_data = Path(__file__).resolve().parents[2] / "data"
    try:
        project_data.mkdir(parents=True, exist_ok=True)
        return project_data
    except (PermissionError, OSError):
        pass
    app_data = Path("/app/data")
    try:
        app_data.mkdir(parents=True, exist_ok=True)
        return app_data
    except (PermissionError, OSError):
        pass
    import tempfile
    fallback = Path(tempfile.gettempdir()) / "sih26013_data"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def init_signing(data_dir: Path) -> None:
    """Load Ed25519 key from disk or generate+persist on first run.

    Must be called once at application startup before any signing/verification.
    Subsequent calls with the same data_dir are no-ops (idempotent).
    """
    global _signing_key, _data_dir
    with _key_init_lock:
        if _signing_key is not None:
            return  # already initialised — idempotent

        _data_dir = data_dir
        key_dir = data_dir / "keys"
        key_dir.mkdir(parents=True, exist_ok=True)
        key_path = key_dir / "geo_examiner.priv"
        reg_path = key_dir / "trust_registry.json"

        if key_path.exists():
            # Load existing persistent key — auto-detects PEM (current format)
            # vs. raw bytes (format written by older versions of this file).
            raw = key_path.read_bytes()
            _signing_key = SigningKey.load(EXAMINER_KEY_ID, raw)
        else:
            # First run: generate and persist in PEM (see private_pem_bytes()
            # docstring for why — standardizes on the same format sih26149 uses).
            _signing_key = SigningKey.generate(EXAMINER_KEY_ID)
            key_path.write_bytes(_signing_key.private_pem_bytes())
            try:
                key_path.chmod(0o600)
            except OSError:
                pass

        if EXAMINER_KEY_ID not in _registry._keys:
            _registry.register(EXAMINER_KEY_ID, _signing_key.public_bytes)

        # Persist public trust registry for independent verification
        reg_path.write_text(
            json.dumps({EXAMINER_KEY_ID: _signing_key.public_bytes.hex()}, indent=2),
            encoding="utf-8",
        )


def _ensure_key() -> tuple:
    """Fallback for code paths that call before explicit init (e.g. tests)."""
    global _signing_key
    if _signing_key is None:
        init_signing(_default_data_dir())
    return _signing_key, _registry


def get_registry() -> TrustRegistry:
    _ensure_key()
    return _registry


def get_signing_key() -> SigningKey:
    _ensure_key()
    return _signing_key
