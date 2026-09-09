"""
Forensic acquisition.

Records source, timestamp, SHA-256, and size.
Does NOT modify the original evidence.
Works on a copy placed in the case working directory.
"""
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.core.hashing import hash_file


@dataclass
class AcquisitionRecord:
    acquisition_id: str
    source_path: str
    working_copy_path: str
    timestamp: float
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict:
        return {
            'acquisition_id': self.acquisition_id,
            'source_path': self.source_path,
            'working_copy_path': self.working_copy_path,
            'timestamp': self.timestamp,
            'sha256': self.sha256,
            'size_bytes': self.size_bytes,
        }


def acquire_image(source_path: str, case_dir: str) -> AcquisitionRecord:
    """
    Acquire a forensic image into the case directory.
    Hashes the source before copying (acquisition hash).
    Does not modify the source.
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

    # Hash BEFORE copying (acquisition hash = hash of source)
    hash_result = hash_file(str(source))

    # Copy to case directory
    shutil.copy2(str(source), str(dest))

    return AcquisitionRecord(
        acquisition_id=acq_id,
        source_path=str(source),
        working_copy_path=str(dest),
        timestamp=time.time(),
        sha256=hash_result.hex_digest,
        size_bytes=hash_result.size_bytes,
    )
