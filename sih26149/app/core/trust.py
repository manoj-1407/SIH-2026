"""
Persistent trust anchor / key registry.

Maps: key_id -> { public_key_hex, status, created_at }

Verifier resolves keys from this registry ONLY.
Does NOT trust a public key supplied inside an evidence package.
"""
import threading
import time
from enum import Enum
from pathlib import Path
from dataclasses import dataclass

from app.core.persistence import atomic_write_json, load_json, PersistenceError


class KeyStatus(str, Enum):
    ACTIVE = 'ACTIVE'
    REVOKED = 'REVOKED'


@dataclass
class KeyRecord:
    key_id: str
    public_key_hex: str
    status: KeyStatus
    created_at: float
    revoked_at: float | None = None


class TrustRegistryError(Exception):
    pass


class KeyNotFoundError(TrustRegistryError):
    pass


class TrustRegistry:
    def __init__(self, registry_path: str | Path):
        self.registry_path = Path(registry_path)
        self._keys: dict[str, KeyRecord] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if self.registry_path.exists():
            try:
                raw = load_json(self.registry_path)
                self._keys = {
                    k: KeyRecord(
                        key_id=v['key_id'],
                        public_key_hex=v['public_key_hex'],
                        status=KeyStatus(v['status']),
                        created_at=v['created_at'],
                        revoked_at=v.get('revoked_at'),
                    )
                    for k, v in raw.items()
                }
            except (PersistenceError, KeyError, ValueError):
                self._keys = {}

    def _save(self):
        data = {
            k: {
                'key_id': r.key_id,
                'public_key_hex': r.public_key_hex,
                'status': r.status.value,
                'created_at': r.created_at,
                'revoked_at': r.revoked_at,
            }
            for k, r in self._keys.items()
        }
        atomic_write_json(self.registry_path, data)

    def register(self, key_id: str, public_raw: bytes) -> KeyRecord:
        """Register a new public key. Raises if key_id already exists."""
        with self._lock:
            if key_id in self._keys:
                raise TrustRegistryError(f'Key {key_id!r} already registered')
            record = KeyRecord(
                key_id=key_id,
                public_key_hex=public_raw.hex(),
                status=KeyStatus.ACTIVE,
                created_at=time.time(),
            )
            self._keys[key_id] = record
            self._save()
            return record

    def upsert(self, key_id: str, public_raw: bytes) -> KeyRecord:
        """Register or overwrite a key's public bytes, always ACTIVE.

        Used when the signer's on-disk private key has changed (e.g. a
        first-run migration) and the registry needs to track the new
        public key under the same key_id. register() intentionally raises
        on an existing key_id — reaching into `registry._keys[key_id] = ...`
        and calling the private `_save()` directly (as deps.py used to do)
        bypasses the class's own invariants for no reason. This does the
        same update, but as part of the public API and under the lock.
        """
        with self._lock:
            record = KeyRecord(
                key_id=key_id,
                public_key_hex=public_raw.hex(),
                status=KeyStatus.ACTIVE,
                created_at=time.time(),
            )
            self._keys[key_id] = record
            self._save()
            return record

    def get_public_key(self, key_id: str) -> bytes:
        """Resolve key from registry. Raises KeyNotFoundError if absent or revoked."""
        record = self._keys.get(key_id)
        if record is None:
            raise KeyNotFoundError(f'Key {key_id!r} not in registry')
        if record.status == KeyStatus.REVOKED:
            raise KeyNotFoundError(f'Key {key_id!r} is revoked')
        return bytes.fromhex(record.public_key_hex)

    def revoke(self, key_id: str) -> None:
        with self._lock:
            record = self._keys.get(key_id)
            if record is None:
                raise KeyNotFoundError(f'Key {key_id!r} not in registry')
            record.status = KeyStatus.REVOKED
            record.revoked_at = time.time()
            self._save()

    def list_keys(self) -> list[dict]:
        return [
            {
                'key_id': r.key_id,
                'status': r.status.value,
                'created_at': r.created_at,
            }
            for r in self._keys.values()
        ]

# Compatibility alias
KeyRegistry = TrustRegistry
