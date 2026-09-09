"""
Forensic artifact recovery using Sleuth Kit (icat).

Recovers raw bytes from a specific inode.
Returns bytes — NEVER executes recovered content.
Recovered data is always treated as UNTRUSTED.
"""
import subprocess
import shutil
from dataclasses import dataclass

from app.core.hashing import hash_bytes


@dataclass
class RecoveryResult:
    inode: str
    image_path: str
    recovered_bytes: bytes
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict:
        return {
            'inode': self.inode,
            'image_path': self.image_path,
            'sha256': self.sha256,
            'size_bytes': self.size_bytes,
            # NOTE: recovered_bytes NOT included — caller decides disposition
        }


class RecoveryError(Exception):
    pass


def recover_artifact(image_path: str, inode: str, timeout: int = 60) -> RecoveryResult:
    """
    Recover a deleted artifact using icat.

    Args:
        image_path: Path to the forensic image
        inode: Inode number as string
        timeout: Max seconds to allow icat to run

    Returns:
        RecoveryResult with recovered bytes and SHA-256

    Raises:
        RecoveryError on failure

    IMPORTANT: The returned bytes are UNTRUSTED data.
    Do not execute, parse without resource limits, or auto-open recovered content.
    """
    if not shutil.which('icat'):
        raise RecoveryError('icat (Sleuth Kit) not found in PATH')

    # Input validation: inode must be a valid number
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
        raise RecoveryError(f'icat returned empty content for inode {inode}')

    return RecoveryResult(
        inode=str(inode_int),
        image_path=image_path,
        recovered_bytes=recovered,
        sha256=hash_bytes(recovered),
        size_bytes=len(recovered),
    )
