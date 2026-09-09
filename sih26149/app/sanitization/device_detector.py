"""
NIST SP 800-88 Rev. 2 Device Capability Detector — SIH26149

Classifies storage media type and maps legally defensible sanitization
operations per NIST SP 800-88 Rev. 2 (finalized September 2025).

Key design decisions:
  - No ATA/NVMe kernel ioctl calls on Windows (no raw disk access available
    in most evaluation environments). Detection is best-effort from path
    heuristics + OS APIs, with honest scope limitation statements.
  - Flash-based media (USB, SD, SSD) never claim full PURGE unless the
    backend can actually issue ATA Secure Erase or NVMe Sanitize commands.
  - VIRTUAL_DISK_IMAGE is the correct classification for .img/.dd files
    operated on in this workstation (a forensic image file ≠ a physical drive).
"""
import os
import re
import platform
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


class MediaType(str, Enum):
    ROTATIONAL_HDD    = "ROTATIONAL_HDD"
    NVME_SSD          = "NVME_SSD"
    SATA_SSD          = "SATA_SSD"
    USB_FLASH         = "USB_FLASH"
    SD_CARD           = "SD_CARD"
    VIRTUAL_DISK_IMAGE = "VIRTUAL_DISK_IMAGE"
    UNKNOWN           = "UNKNOWN"


class SanitizationLevel(str, Enum):
    """NIST 800-88 Rev. 2 sanitization levels."""
    CLEAR   = "CLEAR"    # Logical overwrite — applies to all addressable storage locations
    PURGE   = "PURGE"    # Cryptographic erase or hardware sanitize command
    DESTROY = "DESTROY"  # Physical destruction

    @property
    def nist_reference(self) -> str:
        return {
            self.CLEAR:   "NIST SP 800-88 Rev. 2 §2.3 Clear",
            self.PURGE:   "NIST SP 800-88 Rev. 2 §2.4 Purge",
            self.DESTROY: "NIST SP 800-88 Rev. 2 §2.5 Destroy",
        }[self]


@dataclass
class DeviceCapability:
    media_type: MediaType
    clear_supported: bool
    purge_supported: bool
    purge_command: Optional[str]           # ATA Secure Erase / NVMe Sanitize / etc.
    destroy_recommendation: Optional[str]
    scope_statement: str
    classification_basis: list             # Evidence for the media type determination
    warnings: list = field(default_factory=list)

    @property
    def recommended_level(self) -> SanitizationLevel:
        if self.purge_supported:
            return SanitizationLevel.PURGE
        if self.clear_supported:
            return SanitizationLevel.CLEAR
        return SanitizationLevel.DESTROY

    def to_dict(self) -> dict:
        return {
            "media_type": self.media_type.value,
            "recommended_level": self.recommended_level.value,
            "nist_reference": self.recommended_level.nist_reference,
            "clear_supported": self.clear_supported,
            "purge_supported": self.purge_supported,
            "purge_command": self.purge_command,
            "destroy_recommendation": self.destroy_recommendation,
            "scope_statement": self.scope_statement,
            "classification_basis": self.classification_basis,
            "warnings": self.warnings,
        }


# ── Media detection helpers ─────────────────────────────────────────────────────

_IMAGE_EXTENSIONS = {'.img', '.dd', '.raw', '.iso', '.bin', '.dmg', '.e01', '.ex01'}
_USB_PATH_PATTERNS = [r'usb', r'removable', r'usbstor']
_SD_PATH_PATTERNS  = [r'mmc', r'sdcard', r'sd\d', r'mmcblk\d']
_NVME_PATTERNS     = [r'nvme', r'nvm', r'/dev/nvme']
_SSD_PATTERNS      = [r'ssd', r'solid.state']
_HDD_PATTERNS      = [r'hdd', r'rotational', r'ata', r'sata']


def _match_any(text: str, patterns: list) -> bool:
    text_lower = text.lower()
    return any(re.search(p, text_lower) for p in patterns)


def detect_media_type(target_path: str) -> DeviceCapability:
    """
    Classify media type for NIST 800-88 Rev. 2 compliance.

    For disk image files (.img, .dd, .raw, etc.) the correct classification
    is VIRTUAL_DISK_IMAGE — this workstation operates on image files, not
    physical block devices, and it cannot issue hardware sanitize commands
    to the underlying physical device.

    Physical device detection is best-effort on Windows (no /proc/block or
    smartmontools available in most evaluation environments).
    """
    path = Path(target_path)
    basis = []
    warnings = []

    # 1. File extension detection (primary for this workstation context)
    ext = path.suffix.lower()
    if ext in _IMAGE_EXTENSIONS:
        basis.append(f"File extension '{ext}' matches forensic disk image format")
        return DeviceCapability(
            media_type=MediaType.VIRTUAL_DISK_IMAGE,
            clear_supported=True,
            purge_supported=False,
            purge_command=None,
            destroy_recommendation=(
                "Delete the image file and overwrite the host filesystem allocation. "
                "Physical media hosting this image file should undergo PURGE separately."
            ),
            scope_statement=(
                "CLEAR (logical overwrite) applies to all sectors within this disk image file. "
                "This operation DOES NOT sanitize the physical storage device containing this file. "
                "NIST SP 800-88 Rev. 2 §2.3 Clear — Scope: Disk image file sectors only."
            ),
            classification_basis=basis,
            warnings=[
                "Virtual disk image: hardware PURGE (ATA Secure Erase / NVMe Sanitize) cannot "
                "be issued to the image file. Only CLEAR (logical overwrite) is applicable.",
                "This workstation operates on forensic image files. To sanitize the physical "
                "source drive, use a dedicated hardware sanitization tool or eraser appliance."
            ],
        )

    # 2. Path-based heuristics (matches USB, SD, NVMe, SSD, HDD markers regardless of OS)
    path_str = str(target_path)
    if _match_any(path_str, _NVME_PATTERNS):
        basis.append("Path matches NVMe pattern")
        return _nvme_capability(basis, warnings)
    if _match_any(path_str, _USB_PATH_PATTERNS):
        basis.append("Path matches USB storage pattern")
        return _usb_capability(basis, warnings)
    if _match_any(path_str, _SD_PATH_PATTERNS):
        basis.append("Path matches SD/MMC card pattern")
        return _sd_capability(basis, warnings)
    if _match_any(path_str, _SSD_PATTERNS):
        basis.append("Path matches SSD pattern")
        return _ssd_capability(basis, warnings)
    if _match_any(path_str, _HDD_PATTERNS):
        basis.append("Path matches HDD pattern")
        return _hdd_capability(basis, warnings)

    # 3. Linux sysfs inspection (if on Linux and block device exists)
    if platform.system() == 'Linux':
        basis.append("Linux system detected — attempting sysfs inspection")
        dev_res = _detect_linux(target_path, basis, warnings)
        if dev_res.media_type != MediaType.VIRTUAL_DISK_IMAGE:
            return dev_res

    basis.append("No definitive media type markers found — defaulting to UNKNOWN")
    warnings.append(
        "Media type could not be determined from path. "
        "Only CLEAR (verified overwrite) is authorized. "
        "Do not claim PURGE without confirming hardware sanitize command support."
    )
    return DeviceCapability(
        media_type=MediaType.UNKNOWN,
        clear_supported=True,
        purge_supported=False,
        purge_command=None,
        destroy_recommendation="Consult manufacturer documentation for physical destruction guidance.",
        scope_statement=(
            "CLEAR only. Media type unknown — hardware PURGE not authorized without "
            "explicit device capability verification. "
            "NIST SP 800-88 Rev. 2 §2.3 Clear — Scope: Logical overwrite, all addressable sectors."
        ),
        classification_basis=basis,
        warnings=warnings,
    )


def _detect_linux(target_path: str, basis: list, warnings: list) -> DeviceCapability:
    """Best-effort Linux sysfs detection."""
    try:
        # Try to resolve block device name from path
        device_name = Path(target_path).resolve().name
        rotational_path = f"/sys/block/{device_name}/queue/rotational"
        if os.path.exists(rotational_path):
            with open(rotational_path) as f:
                rot = f.read().strip()
            if rot == '1':
                basis.append(f"sysfs rotational=1 for {device_name}")
                return _hdd_capability(basis, warnings)
            else:
                basis.append(f"sysfs rotational=0 for {device_name}")
                # Check if NVMe
                if 'nvme' in device_name.lower():
                    return _nvme_capability(basis, warnings)
                return _ssd_capability(basis, warnings)
    except Exception:
        pass

    basis.append("sysfs inspection failed — using VIRTUAL_DISK_IMAGE default")
    return DeviceCapability(
        media_type=MediaType.VIRTUAL_DISK_IMAGE,
        clear_supported=True, purge_supported=False, purge_command=None,
        destroy_recommendation="Physical destruction per NIST 800-88 Rev.2 §2.5",
        scope_statement=(
            "CLEAR (logical overwrite) — media type could not be determined from sysfs. "
            "NIST SP 800-88 Rev. 2 §2.3 Clear."
        ),
        classification_basis=basis, warnings=warnings,
    )


def _hdd_capability(basis: list, warnings: list) -> DeviceCapability:
    warnings.append(
        "Rotational HDD: single-pass zero overwrite (CLEAR) is effective per NIST 800-88 Rev. 2. "
        "ATA Secure Erase (PURGE) is recommended where available — this workstation issues logical "
        "overwrite only. Use hdparm for ATA Secure Erase on physical drives."
    )
    return DeviceCapability(
        media_type=MediaType.ROTATIONAL_HDD,
        clear_supported=True, purge_supported=False,
        purge_command="ATA Secure Erase (hdparm --security-erase) — not issued by this tool",
        destroy_recommendation="Degaussing + physical shredding per NSA/CSS EPL.",
        scope_statement=(
            "CLEAR: Single-pass logical overwrite per NIST SP 800-88 Rev. 2 §2.3. "
            "Effective for modern HDDs (≥2001 per NIST guidance). "
            "PURGE via ATA Secure Erase requires hdparm — not performed by this workstation tool."
        ),
        classification_basis=basis, warnings=warnings,
    )


def _ssd_capability(basis: list, warnings: list) -> DeviceCapability:
    warnings.append(
        "SATA SSD: Logical overwrite (CLEAR) may not reach worn-out NAND blocks due to "
        "wear-leveling and over-provisioning. PURGE (ATA Secure Erase Enhanced) is required "
        "per NIST 800-88 Rev. 2 for complete sanitization. This workstation performs CLEAR only."
    )
    return DeviceCapability(
        media_type=MediaType.SATA_SSD,
        clear_supported=True, purge_supported=False,
        purge_command="ATA Secure Erase Enhanced (hdparm --security-erase-enhanced)",
        destroy_recommendation="Disintegration/shredding to particles ≤2mm.",
        scope_statement=(
            "CLEAR only (NIST SP 800-88 Rev. 2 §2.3). "
            "⚠ SSD wear-leveling means logical overwrite leaves data in unaddressable NAND blocks. "
            "PURGE (ATA Secure Erase Enhanced) is required for full sanitization — "
            "NOT performed by this image-level tool. Report as VERIFIED_WITHIN_SCOPE."
        ),
        classification_basis=basis, warnings=warnings,
    )


def _nvme_capability(basis: list, warnings: list) -> DeviceCapability:
    warnings.append(
        "NVMe SSD: Logical CLEAR is insufficient. NVMe Sanitize (Block Erase or Crypto Erase) "
        "is required for PURGE. This workstation operates on image files and cannot issue "
        "NVMe Admin commands. Use nvme-cli for hardware sanitization."
    )
    return DeviceCapability(
        media_type=MediaType.NVME_SSD,
        clear_supported=True, purge_supported=False,
        purge_command="NVMe Sanitize (nvme sanitize --sanact=block-erase or --sanact=crypto-erase)",
        destroy_recommendation="Disintegration/shredding to particles ≤2mm.",
        scope_statement=(
            "CLEAR only (NIST SP 800-88 Rev. 2 §2.3). "
            "⚠ NVMe over-provisioning and wear-leveling make logical CLEAR insufficient. "
            "NVMe Sanitize Admin Command required for PURGE — "
            "NOT performed by this tool. Report as VERIFIED_WITHIN_SCOPE."
        ),
        classification_basis=basis, warnings=warnings,
    )


def _usb_capability(basis: list, warnings: list) -> DeviceCapability:
    warnings.append(
        "USB Flash: Logical overwrite is severely limited by wear-leveling, "
        "over-provisioning, and remapped sectors. Data in remapped blocks cannot be overwritten "
        "via the standard USB mass storage protocol. NIST 800-88 Rev. 2 recommends DESTROY "
        "for USB flash containing sensitive data."
    )
    return DeviceCapability(
        media_type=MediaType.USB_FLASH,
        clear_supported=True, purge_supported=False, purge_command=None,
        destroy_recommendation=(
            "Physical destruction recommended for sensitive data: shredding/disintegration "
            "to particles ≤2mm. USB controllers do not expose hardware sanitize commands "
            "via standard USB Mass Storage protocol."
        ),
        scope_statement=(
            "⚠ CLEAR ONLY — scope is severely limited on USB Flash. "
            "Wear-leveling means overwritten data may persist in remapped NAND blocks "
            "inaccessible via USB mass storage interface. "
            "NIST SP 800-88 Rev. 2 §2.5 recommends physical DESTROY for sensitive USB flash data."
        ),
        classification_basis=basis, warnings=warnings,
    )


def _sd_capability(basis: list, warnings: list) -> DeviceCapability:
    warnings.append(
        "SD/MMC Card: Same wear-leveling limitations as USB Flash. "
        "NIST 800-88 Rev. 2 recommends DESTROY for sensitive SD card data."
    )
    return DeviceCapability(
        media_type=MediaType.SD_CARD,
        clear_supported=True, purge_supported=False, purge_command=None,
        destroy_recommendation=(
            "Physical destruction: shredding/disintegration to particles ≤2mm. "
            "SD controllers do not expose hardware sanitize commands."
        ),
        scope_statement=(
            "⚠ CLEAR ONLY — scope is severely limited on SD/MMC cards. "
            "Wear-leveling means overwritten data may persist in remapped NAND blocks. "
            "NIST SP 800-88 Rev. 2 §2.5 recommends physical DESTROY."
        ),
        classification_basis=basis, warnings=warnings,
    )
