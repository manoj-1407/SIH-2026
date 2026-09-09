"""
Deleted artifact discovery using Sleuth Kit (fls).

Uses actual filesystem analysis — not simulated.
"""
import logging
import subprocess
import shutil
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Artifact:
    inode: str
    name: str
    is_deleted: bool
    size_bytes: int | None
    artifact_type: str  # 'r' regular, 'd' directory, etc.

    def to_dict(self) -> dict:
        return {
            'inode': self.inode,
            'name': self.name,
            'is_deleted': self.is_deleted,
            'size_bytes': self.size_bytes,
            'artifact_type': self.artifact_type,
        }


class DiscoveryError(Exception):
    pass


def discover_deleted_artifacts(image_path: str, timeout: int = 60) -> list[Artifact]:
    """
    Use fls to discover deleted artifacts in an ext4 image.

    Returns list of deleted inodes.
    Raises DiscoveryError on fls failure or tool unavailability.
    """
    if not shutil.which('fls'):
        raise DiscoveryError('fls (Sleuth Kit) not found in PATH')

    try:
        result = subprocess.run(
            ['fls', '-r', '-d', '-p', image_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise DiscoveryError('fls timed out')
    except Exception as e:
        raise DiscoveryError(f'fls failed: {e}')

    if result.returncode != 0 and not result.stdout:
        raise DiscoveryError(f'fls error: {result.stderr[:500]}')

    return _parse_fls_output(result.stdout)


def _parse_fls_output(output: str) -> list[Artifact]:
    """
    Parse fls output into Artifact list.

    fls -r -d -p output format:
      r/r * inode:  path/name
      d/d * inode:  path/name

    The '*' indicates deleted.
    """
    artifacts = []
    skipped = 0
    for line in output.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        try:
            artifact = _parse_fls_line(line)
            if artifact:
                artifacts.append(artifact)
        except Exception as e:
            # A damaged/corrupt image can legitimately produce malformed
            # fls lines — but silently dropping them (as this used to do)
            # means missing artifacts with zero indication, which is worse
            # than an error in a forensic context: an investigator has no
            # way to know evidence was skipped. Log the line and the reason
            # so it's visible, without failing the whole scan over one bad
            # line.
            skipped += 1
            logger.warning("Skipping unparseable fls line: %r (%s: %s)", line, type(e).__name__, e)
    if skipped:
        logger.warning("%d fls output line(s) could not be parsed and were skipped", skipped)
    return artifacts


def _parse_fls_line(line: str) -> Artifact | None:
    """
    Parse a single fls output line.
    Example: r/r * 12:   secret.txt
    Example: d/d * 13:   dir/
    """
    parts = line.split(None, 3)
    if len(parts) < 3:
        return None

    type_str = parts[0]  # e.g. 'r/r'
    deleted_marker = parts[1]  # '*' or inode if not deleted
    
    # With -d flag, all returned entries should be deleted
    # Format: type * inode: name
    if deleted_marker == '*' and len(parts) >= 4:
        inode_part = parts[2].rstrip(':')
        name = parts[3].strip()
        artifact_type = type_str.split('/')[0] if '/' in type_str else type_str
        return Artifact(
            inode=inode_part,
            name=name,
            is_deleted=True,
            size_bytes=None,  # fls -d doesn't include size; use istat for details
            artifact_type=artifact_type,
        )
    elif ':' in deleted_marker:
        # No '*' — format: type inode: name (when not using -d but parsing anyway)
        inode_part = deleted_marker.rstrip(':')
        name = parts[2].strip() if len(parts) > 2 else ''
        artifact_type = type_str.split('/')[0] if '/' in type_str else type_str
        return Artifact(
            inode=inode_part,
            name=name,
            is_deleted=False,
            size_bytes=None,
            artifact_type=artifact_type,
        )
    return None
