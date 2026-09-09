"""Canonical SHA-256 evidence hashing.
Same protocol as 26149 trust foundation, independently implemented.
"""
import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class HashResult:
    hex_digest: str
    size_bytes: int


def canonical_json(obj) -> bytes:
    """Deterministic JSON serialization: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> HashResult:
    h = hashlib.sha256(data)
    return HashResult(hex_digest=h.hexdigest(), size_bytes=len(data))


def sha256_canonical(obj) -> HashResult:
    """Hash an arbitrary dict/list via canonical JSON representation."""
    raw = canonical_json(obj)
    return sha256_bytes(raw)
