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

    return {
        'status': 'OPERATIONAL',
        'version': '1.0.0',
        'subsystems': {
            'sleuthkit': fls_ok and icat_ok and fsstat_ok,
            'ext4_tools': mkfs_ok,
            'cryptography': 'Ed25519',
            'persistence': 'Atomic fsync rename',
        },
        'tools': {
            'fls': fls_ok,
            'icat': icat_ok,
            'fsstat': fsstat_ok,
            'mkfs.ext4': mkfs_ok,
        }
    }
