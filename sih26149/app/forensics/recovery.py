"""
Forensic artifact recovery using Sleuth Kit (icat).

Recovers raw bytes from a specific inode.
Returns bytes — NEVER executes recovered content.
Recovered data is always treated as UNTRUSTED.

FORENSIC NOTE (ext4):
  ext4 zeroes inode block pointers immediately on deletion.
  icat will return empty data for deleted inodes on ext4 — this is
  expected filesystem behaviour, NOT a tool failure.
  When icat returns empty, the API returns a FAILED_SK_LAYER status
  with a clear explanation so the operator can use raw carving instead.
"""
import subprocess
import shutil
from dataclasses import dataclass
from enum import Enum

from app.core.hashing import hash_bytes


class RecoveryLayerStatus(str, Enum):
    RECOVERED       = "RECOVERED"
    FAILED_SK_LAYER = "FAILED_SK_LAYER"   # icat empty — expected on ext4
    ERROR           = "ERROR"


@dataclass
class RecoveryResult:
    inode: str
    image_path: str
    recovered_bytes: bytes
    sha256: str
    size_bytes: int
    layer_status: RecoveryLayerStatus = RecoveryLayerStatus.RECOVERED
    forensic_note: str = ""

    def to_dict(self) -> dict:
        return {
            'inode': self.inode,
            'image_path': self.image_path,
            'sha256': self.sha256,
            'size_bytes': self.size_bytes,
            'layer_status': self.layer_status.value,
            'forensic_note': self.forensic_note,
            # NOTE: recovered_bytes NOT included — caller decides disposition
        }


class RecoveryError(Exception):
    pass


def recover_artifact(image_path: str, inode: str, timeout: int = 60) -> RecoveryResult:
    """
    Recover a deleted artifact using icat.

    On ext4, icat will return empty data for deleted inodes because ext4
    zeroes block pointers on deletion. This is not an error — it is the
    correct filesystem behaviour. The caller receives a FAILED_SK_LAYER
    result with a forensic note directing them to use raw carving.

    Returns:
        RecoveryResult — always returns, never raises on empty icat output.

    Raises:
        RecoveryError only on tool errors (icat not found, timeout, non-zero exit).
    """
    if not shutil.which('icat'):
        raise RecoveryError('icat (Sleuth Kit) not found in PATH')

    try:
        inode_int = int(inode)
        if inode_int < 0:
            raise ValueError()
    except (ValueError, TypeError):
        raise RecoveryError(f'Invalid inode: {inode!r}')

    try:
        result = subprocess.run(
            ['icat', image_path, str(inode_int)],
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RecoveryError(f'icat timed out for inode {inode}')
    except Exception as e:
        raise RecoveryError(f'icat failed: {e}')

    if result.returncode != 0:
        stderr_msg = result.stderr.decode('utf-8', errors='replace')[:500]
        raise RecoveryError(f'icat returned {result.returncode}: {stderr_msg}')

    recovered = result.stdout

    if not recovered:
        # ext4 expected behaviour — document it, don't crash
        note = (
            "icat returned empty data for inode. "
            "This is expected on ext4: the filesystem zeroes inode block pointers "
            "immediately on deletion, making inode-level recovery impossible. "
            "Use raw signature carving (/carve endpoint) to recover data from this image."
        )
        return RecoveryResult(
            inode=str(inode_int),
            image_path=image_path,
            recovered_bytes=b'',
            sha256=hash_bytes(b''),
            size_bytes=0,
            layer_status=RecoveryLayerStatus.FAILED_SK_LAYER,
            forensic_note=note,
        )

    return RecoveryResult(
        inode=str(inode_int),
        image_path=image_path,
        recovered_bytes=recovered,
        sha256=hash_bytes(recovered),
        size_bytes=len(recovered),
        layer_status=RecoveryLayerStatus.RECOVERED,
        forensic_note="",
    )
