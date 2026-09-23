"""System health and forensic tool capability API router."""
import shutil
import subprocess
from fastapi import APIRouter

router = APIRouter(tags=['Health'])


@router.get('/health')
def health():
    fls_ok = shutil.which('fls') is not None
    icat_ok = shutil.which('icat') is not None
    fsstat_ok = shutil.which('fsstat') is not None
    mkfs_ok = shutil.which('mkfs.ext4') is not None

    has_tsk = fls_ok and icat_ok and fsstat_ok

    return {
        'status': 'OPERATIONAL',
        'version': '2.0.0',
        'engine_mode': 'HYBRID_NATIVE_AND_TSK' if has_tsk else 'AUTONOMOUS_NATIVE_FORENSICS',
        'subsystems': {
            'native_raw_carver': True,
            'native_ntfs_mft_parser': True,
            'native_anti_forensics': True,
            'cryptography': 'RFC 8032 Ed25519 + RFC 8785 JCS',
            'persistence': 'Atomic fsync rename',
            'sleuthkit_ext4_layer': has_tsk,
            'ext4_tools': mkfs_ok,
        },
        'tools': {
            'fls': fls_ok,
            'icat': icat_ok,
            'fsstat': fsstat_ok,
            'mkfs.ext4': mkfs_ok,
            'native_ntfs_parser': True,
            'native_carver': True,
        },
        'advisory': (
            'Full dual-mode forensic capability active (Native Carvers + SleuthKit ext4 layer).'
            if has_tsk else
            'Autonomous Native Forensics active. Deleted file recovery and raw carving operate without external binary dependencies.'
        )
    }
