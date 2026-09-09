"""
Filesystem detection and capability model.
Distinguishes detected filesystems from supported recovery/sanitization backends.
Never dispatches ext4 recovery tooling to incompatible or corrupt inputs.
"""
import subprocess
import shutil
from dataclasses import dataclass, asdict
from typing import Dict, Any


@dataclass
class FilesystemCapability:
    filesystem: str            # 'ext4', 'fat32', 'ntfs', 'unknown', 'corrupt'
    detected: bool             # Was a filesystem structure identified?
    recovery_supported: bool   # Does the engine support deleted-file recovery for this fs?
    sanitization_supported: bool # Does the engine support bounded sanitization for this target?
    status_label: str          # 'EXT4_SUPPORTED', 'UNSUPPORTED_FAT32', 'NOT_A_FILESYSTEM', 'CORRUPT_INVALID'
    details: Dict[str, Any]

    def to_dict(self) -> dict:
        return asdict(self)


def detect_filesystem(image_path: str) -> FilesystemCapability:
    """
    Detect filesystem type and evaluate operational capability.
    Uses 'file -s' and 'fsstat' (when applicable) to inspect filesystem headers.
    """
    try:
        file_cmd = shutil.which('file')
        if not file_cmd:
            return FilesystemCapability(
                filesystem='unknown',
                detected=False,
                recovery_supported=False,
                sanitization_supported=False,
                status_label='NOT_A_FILESYSTEM',
                details={'error': 'file command unavailable'},
            )

        res = subprocess.run(
            ['file', '-b', image_path],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = res.stdout.strip().lower()

        # Check for ext4
        if 'ext4' in output or 'ext3' in output or 'ext2' in output:
            fsstat_details = _inspect_ext4(image_path)
            return FilesystemCapability(
                filesystem='ext4',
                detected=True,
                recovery_supported=True,
                sanitization_supported=True,
                status_label='EXT4_SUPPORTED',
                details=fsstat_details,
            )

        # Check for FAT
        if 'fat' in output or 'ms-dos' in output:
            return FilesystemCapability(
                filesystem='fat32',
                detected=True,
                recovery_supported=False,
                sanitization_supported=False,
                status_label='UNSUPPORTED_FAT32',
                details={'description': output, 'reason': 'FAT32 recovery backend not implemented in current version'},
            )

        # Check for NTFS
        if 'ntfs' in output:
            return FilesystemCapability(
                filesystem='ntfs',
                detected=True,
                recovery_supported=False,
                sanitization_supported=False,
                status_label='UNSUPPORTED_NTFS',
                details={'description': output, 'reason': 'NTFS recovery backend not implemented in current version'},
            )

        # Non-filesystem data
        if 'data' == output or len(output) == 0:
            return FilesystemCapability(
                filesystem='non_fs',
                detected=False,
                recovery_supported=False,
                sanitization_supported=False,
                status_label='NOT_A_FILESYSTEM',
                details={'description': output or 'raw data / no filesystem signature'},
            )

        return FilesystemCapability(
            filesystem='unknown',
            detected=False,
            recovery_supported=False,
            sanitization_supported=False,
            status_label='CORRUPT_INVALID',
            details={'description': output},
        )

    except Exception as e:
        return FilesystemCapability(
            filesystem='corrupt',
            detected=False,
            recovery_supported=False,
            sanitization_supported=False,
            status_label='CORRUPT_INVALID',
            details={'error': str(e)},
        )


def _inspect_ext4(image_path: str) -> dict:
    details = {'raw_type': 'Linux ext4'}
    fsstat_cmd = shutil.which('fsstat')
    if fsstat_cmd:
        try:
            r = subprocess.run(['fsstat', image_path], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                for line in r.stdout.splitlines()[:20]:
                    if ':' in line:
                        k, v = line.split(':', 1)
                        details[k.strip().lower().replace(' ', '_')] = v.strip()
        except Exception:
            pass
    return details
