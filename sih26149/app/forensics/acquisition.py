"""
Forensic Source Acquisition & Immutable Preservation Engine — SIH26149.

Guarantees source preservation:
1. Records source path, size, pre-acquisition SHA-256, and metadata.
2. Read-only verification: sets read-only permissions on working evidence copies.
3. Post-operation integrity verification: verifies source SHA-256 remains byte-identical.
4. If a recovery workflow mutates the source: BLOCKS execution and raises SourceMutationError.
"""
import os
import stat
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from contextlib import contextmanager
from typing import Generator

from app.core.hashing import hash_file


class SourceMutationError(Exception):
    """Raised when an operation mutates or alters immutable forensic source data."""
    pass


class SourcePreservationError(Exception):
    """Raised when source preservation constraints cannot be established."""
    pass


@dataclass
class AcquisitionRecord:
    acquisition_id: str
    source_path: str
    working_copy_path: str
    timestamp: float
    sha256: str
    size_bytes: int
    read_only_locked: bool = True

    def to_dict(self) -> dict:
        return {
            'acquisition_id': self.acquisition_id,
            'source_path': self.source_path,
            'working_copy_path': self.working_copy_path,
            'timestamp': self.timestamp,
            'sha256': self.sha256,
            'size_bytes': self.size_bytes,
            'read_only_locked': self.read_only_locked,
        }


def set_file_read_only(file_path: str | Path) -> None:
    """Set read-only permissions on evidence file."""
    p = Path(file_path)
    if p.exists():
        mode = p.stat().st_mode
        # Remove write bits for owner, group, other
        p.chmod(mode & ~stat.S_IWRITE & ~stat.S_IWGRP & ~stat.S_IWOTH)


def acquire_image(source_path: str, case_dir: str) -> AcquisitionRecord:
    """
    Acquire a forensic image into the case directory under strict read-only lock.
    Hashes the source before copying, copies, sets read-only permissions on destination,
    and returns an AcquisitionRecord.
    """
    source = Path(source_path)
    if not source.exists():
        raise FileNotFoundError(f'Evidence image not found: {source_path}')
    if not source.is_file():
        raise ValueError(f'Evidence source must be a file: {source_path}')

    acq_id = f'ACQ-{uuid.uuid4().hex[:8].upper()}'
    dest_dir = Path(case_dir) / 'evidence'
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f'{acq_id}_{source.name}'

    # Hash BEFORE copying
    pre_hash_res = hash_file(str(source))

    # Copy to case directory
    shutil.copy2(str(source), str(dest))

    # Lock destination to read-only
    try:
        set_file_read_only(dest)
        locked = True
    except OSError:
        locked = False

    return AcquisitionRecord(
        acquisition_id=acq_id,
        source_path=str(source),
        working_copy_path=str(dest),
        timestamp=time.time(),
        sha256=pre_hash_res.hex_digest,
        size_bytes=pre_hash_res.size_bytes,
        read_only_locked=locked,
    )


@contextmanager
def preserve_source(image_path: str) -> Generator[str, None, None]:
    """
    Context manager that monitors a forensic image across an operation.
    Verifies that the SHA-256 after the operation is byte-identical to the SHA-256 before.
    """
    p = Path(image_path)
    if not p.exists():
        raise FileNotFoundError(f"Forensic source not found: {image_path}")

    pre_hash = hash_file(str(p)).hex_digest
    try:
        yield str(p)
    finally:
        post_hash = hash_file(str(p)).hex_digest
        if pre_hash != post_hash:
            raise SourceMutationError(
                f"CRITICAL FORENSIC INTEGRITY VIOLATION: Source image '{image_path}' "
                f"was modified during operation. Pre-hash: {pre_hash}, Post-hash: {post_hash}"
            )
