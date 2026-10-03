"""System capability detection API router."""
import os
import shutil
import platform
from fastapi import APIRouter
from app.sanitization.purge_commands import get_hardware_capability_matrix

router = APIRouter(tags=['System'])


@router.get('/system/capabilities')
def get_system_capabilities():
    fls_available = shutil.which('fls') is not None
    icat_available = shutil.which('icat') is not None
    fsstat_available = shutil.which('fsstat') is not None
    mkfs_ext4_available = shutil.which('mkfs.ext4') is not None
    debugfs_available = shutil.which('debugfs') is not None
    hdparm_available = shutil.which('hdparm') is not None
    nvme_available = shutil.which('nvme') is not None
    smartctl_available = shutil.which('smartctl') is not None

    platform_name = platform.system()

    is_admin = False
    if platform_name == 'Windows':
        try:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin = False
    else:
        try:
            is_admin = hasattr(os, 'geteuid') and os.geteuid() == 0
        except Exception:
            is_admin = False

    return {
        'fls_available': fls_available,
        'icat_available': icat_available,
        'fsstat_available': fsstat_available,
        'mkfs_ext4_available': mkfs_ext4_available,
        'debugfs_available': debugfs_available,
        'hdparm_available': hdparm_available,
        'nvme_available': nvme_available,
        'smartctl_available': smartctl_available,
        'platform': platform_name,
        'is_admin': is_admin,
        'sanitization_capability_matrix': get_hardware_capability_matrix(),
    }
