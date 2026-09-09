"""SHA-256 hashing with streaming reads."""
import hashlib
from pathlib import Path
from dataclasses import dataclass


@dataclass
class HashResult:
    hex_digest: str
    size_bytes: int


def hash_file(path) -> HashResult:
    """Stream-hash a file. Returns hex digest and byte count."""
    h = hashlib.sha256()
    size = 0
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
            size += len(chunk)
    return HashResult(hex_digest=h.hexdigest(), size_bytes=size)


def hash_bytes(data: bytes) -> str:
    """Hash raw bytes, return hex digest."""
    return hashlib.sha256(data).hexdigest()


def hash_string(s: str) -> str:
    """Hash UTF-8 string, return hex digest."""
    return hashlib.sha256(s.encode('utf-8')).hexdigest()
