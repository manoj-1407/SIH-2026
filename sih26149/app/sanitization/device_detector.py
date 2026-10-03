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
from typing import Optional, Dict, Any


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
    hpa_dco_warning: str = ""              # Host Protected Area / Device Config Overlay advisory
    write_protection_note: str = ""        # Write-blocker / read-only enforcement status
    is_sed_opal_capable: bool = False      # TCG Opal / Enterprise SSC Self-Encrypting Drive
    opal_ssc_version: Optional[str] = None # e.g. "TCG Opal 2.0"
    crypto_erase_recommended: bool = False # Prefer Cryptographic Erase over 4-hour overwrite
    crypto_erase_rationale: str = ""       # Legal & operational rationale per NIST 800-88 §2.4
    ieee_2883_reference: Optional[str] = None  # IEEE 2883-2022 cross-reference per H02
    hpa_checked: bool = False              # H03: actual HPA probe attempted
    hpa_detected: Optional[bool] = None    # H03: True/False if checked, None if unknown
    dco_checked: bool = False              # H03: actual DCO probe attempted
    dco_detected: Optional[bool] = None    # H03: True/False if checked, None if unknown

    @property
    def recommended_level(self) -> SanitizationLevel:
        if self.purge_supported or self.crypto_erase_recommended:
            return SanitizationLevel.PURGE
        if self.clear_supported:
            return SanitizationLevel.CLEAR
        return SanitizationLevel.DESTROY

    def to_dict(self) -> dict:
        return {
            "media_type": self.media_type.value,
            "recommended_level": self.recommended_level.value,
            "nist_reference": self.recommended_level.nist_reference,
            "ieee_2883_reference": self.ieee_2883_reference,
            "clear_supported": self.clear_supported,
            "purge_supported": self.purge_supported or self.crypto_erase_recommended,
            "purge_command": self.purge_command or ("TCG OPAL CRYPTOGRAPHIC ERASE (MEK Invalidation)" if self.crypto_erase_recommended else None),
            "destroy_recommendation": self.destroy_recommendation,
            "scope_statement": self.scope_statement,
            "classification_basis": self.classification_basis,
            "warnings": self.warnings,
            "hpa_dco_warning": self.hpa_dco_warning,
            "hpa_checked": self.hpa_checked,
            "hpa_detected": self.hpa_detected,
            "dco_checked": self.dco_checked,
            "dco_detected": self.dco_detected,
            "write_protection_note": self.write_protection_note,
            "is_sed_opal_capable": self.is_sed_opal_capable,
            "opal_ssc_version": self.opal_ssc_version,
            "crypto_erase_recommended": self.crypto_erase_recommended,
            "crypto_erase_rationale": self.crypto_erase_rationale,
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


def probe_hpa_dco(device_path: str) -> Dict[str, Any]:
    """
    Advisory-only Host Protected Area (HPA) / Device Configuration Overlay
    (DCO) probe. Returns honest ``checked=False`` + advisory command strings
    when the executing environment cannot run hdparm (non-POSIX, non-root,
    binary absent). Never raises — always returns a valid dict.

    On POSIX systems as root with hdparm on PATH, a best-effort subprocess
    attempt is made and string-matched against hdparm's known output format.
    """
    import shutil
    import subprocess

    advisory_commands = {
        "hpa_check": (
            "/usr/sbin/hdparm -N /dev/sdX  "
            "# Max Address field. If non-default (max sectors differs from drive-native), HPA is active."
        ),
        "dco_check": (
            "/usr/sbin/hdparm --dco-identify /dev/sdX  "
            "# Compare 'Real max sectors' vs 'current max sectors'. Different values = DCO hiding data."
        ),
    }
    result: Dict[str, Any] = {
        "hpa_checked": False,
        "hpa_detected": None,
        "dco_checked": False,
        "dco_detected": None,
        "commands": advisory_commands,
        "probe_environment": {
            "os": os.name,
            "platform": platform.system(),
            "is_posix": os.name == "posix",
            "is_root": (os.geteuid() == 0) if os.name == "posix" else False,
            "hdparm_available": bool(shutil.which("hdparm")),
        },
    }

    if os.name != "posix":
        result["gating_reason"] = (
            "Non-POSIX host: hdparm ioctls require Linux /sys/block + block-device fd. "
            "Run the advisory commands above on a Linux forensic workstation with direct block access."
        )
        return result

    is_root = os.geteuid() == 0 if os.name == "posix" else False
    has_hdparm = bool(shutil.which("hdparm"))
    hdparm = shutil.which("hdparm") or "/usr/sbin/hdparm"

    if not (is_root and has_hdparm):
        missing = []
        if not is_root:
            missing.append("not root (UID 0)")
        if not has_hdparm:
            missing.append("hdparm binary not on PATH")
        result["gating_reason"] = (
            f"HPA/DCO probe skipped on POSIX: {', '.join(missing)}. "
            f"Execute advisory commands with sudo on a forensic live-boot environment."
        )
        return result

    try:
        hpa_raw = subprocess.run(
            [hdparm, "-N", device_path],
            capture_output=True, text=True, timeout=8, check=False,
        )
        hpa_out = (hpa_raw.stdout or "") + (hpa_raw.stderr or "")
        result["hpa_checked"] = True
        if re.search(r"max sectors\s*=\s*\d+[^\n]*?\(native\s+\d+\)", hpa_out, re.I):
            m = re.search(r"max sectors\s*=\s*(\d+)[^\n]*?\(native\s+(\d+)\)", hpa_out, re.I)
            if m and int(m.group(1)) < int(m.group(2)):
                result["hpa_detected"] = True
            else:
                result["hpa_detected"] = False
        else:
            result["hpa_detected"] = None
        result["hpa_raw_output_snippet"] = hpa_out[:400]
    except Exception as e:
        result["hpa_error"] = f"{type(e).__name__}: {e}"

    try:
        dco_raw = subprocess.run(
            [hdparm, "--dco-identify", device_path],
            capture_output=True, text=True, timeout=10, check=False,
        )
        dco_out = (dco_raw.stdout or "") + (dco_raw.stderr or "")
        result["dco_checked"] = True
        real_max_match = re.search(r"Real\s+max\s+sectors\s*:\s*(\d+)", dco_out, re.I)
        cur_max_match = re.search(r"current\s+max\s+sectors\s*:\s*(\d+)", dco_out, re.I)
        if real_max_match and cur_max_match:
            result["dco_detected"] = int(cur_max_match.group(1)) < int(real_max_match.group(1))
        else:
            result["dco_detected"] = None
        result["dco_raw_output_snippet"] = dco_out[:400]
    except Exception as e:
        result["dco_error"] = f"{type(e).__name__}: {e}"

    return result


def _apply_hpa_dco_probe(cap: DeviceCapability, device_path: str) -> DeviceCapability:
    """Run probe_hpa_dco and stamp results onto an existing DeviceCapability.
    Safe for any media type — returns cap unchanged for virtual images."""
    if cap.media_type == MediaType.VIRTUAL_DISK_IMAGE:
        cap.hpa_checked = False
        cap.hpa_detected = None
        cap.dco_checked = False
        cap.dco_detected = None
        return cap
    hpa = probe_hpa_dco(device_path)
    cap.hpa_checked = hpa["hpa_checked"]
    cap.hpa_detected = hpa["hpa_detected"]
    cap.dco_checked = hpa["dco_checked"]
    cap.dco_detected = hpa["dco_detected"]
    return cap


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
            hpa_dco_warning="N/A — disk image file does not have HPA/DCO regions.",
            write_protection_note=(
                "Recovery mode operates read-only on source evidence. Carving engine reads "
                "bytes from the image without writing. Source image integrity is preserved."
            ),
            ieee_2883_reference="N/A — virtual image; IEEE 2883 does not apply to logical container files.",
        )

    # 2. Path-based heuristics (matches USB, SD, NVMe, SSD, HDD markers regardless of OS)
    path_str = str(target_path)
    if _match_any(path_str, _NVME_PATTERNS):
        basis.append("Path matches NVMe pattern")
        return _apply_hpa_dco_probe(_nvme_capability(basis, warnings), target_path)
    if _match_any(path_str, _USB_PATH_PATTERNS):
        basis.append("Path matches USB storage pattern")
        return _apply_hpa_dco_probe(_usb_capability(basis, warnings), target_path)
    if _match_any(path_str, _SD_PATH_PATTERNS):
        basis.append("Path matches SD/MMC card pattern")
        return _apply_hpa_dco_probe(_sd_capability(basis, warnings), target_path)
    if _match_any(path_str, _SSD_PATTERNS):
        basis.append("Path matches SSD pattern")
        return _apply_hpa_dco_probe(_ssd_capability(basis, warnings), target_path)
    if _match_any(path_str, _HDD_PATTERNS):
        basis.append("Path matches HDD pattern")
        return _apply_hpa_dco_probe(_hdd_capability(basis, warnings), target_path)

    # 3. Linux sysfs inspection (if on Linux and block device exists)
    if platform.system() == 'Linux':
        basis.append("Linux system detected — attempting sysfs inspection")
        dev_res = _detect_linux(target_path, basis, warnings)
        if dev_res.media_type != MediaType.VIRTUAL_DISK_IMAGE:
            return _apply_hpa_dco_probe(dev_res, target_path)

    basis.append("No definitive media type markers found — defaulting to UNKNOWN")
    warnings.append(
        "Media type could not be determined from path. "
        "Only CLEAR (verified overwrite) is authorized. "
        "Do not claim PURGE without confirming hardware sanitize command support."
    )
    cap = DeviceCapability(
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
        ieee_2883_reference=(
            "Unknown media type — IEEE 2883 cross-reference not assignable. "
            "Confirm bus/controller type before applying IEEE 2883-2022 §5.x guidance."
        ),
    )
    return _apply_hpa_dco_probe(cap, target_path)


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
                return _apply_hpa_dco_probe(_hdd_capability(basis, warnings), target_path)
            else:
                basis.append(f"sysfs rotational=0 for {device_name}")
                # Check if NVMe
                if 'nvme' in device_name.lower():
                    return _apply_hpa_dco_probe(_nvme_capability(basis, warnings), target_path)
                return _apply_hpa_dco_probe(_ssd_capability(basis, warnings), target_path)
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
        ieee_2883_reference="N/A — virtual image; IEEE 2883 does not apply.",
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
        hpa_dco_warning=(
            "⚠ HPA/DCO CHECK REQUIRED: ATA HDDs may have a Host Protected Area (HPA) or "
            "Device Configuration Overlay (DCO) hiding sectors from the OS. Use `hdparm -N` "
            "to detect HPA and `hdparm --dco-identify` for DCO. Sectors hidden by HPA/DCO "
            "are NOT overwritten by logical CLEAR and may retain residual data."
        ),
        write_protection_note=(
            "Recovery mode: source media should be accessed through a hardware write-blocker "
            "or mounted read-only (mount -o ro) to prevent accidental modification of evidence."
        ),
        ieee_2883_reference=None,
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
        hpa_dco_warning=(
            "⚠ SSD over-provisioning: SATA SSDs reserve 7-28% of NAND capacity for wear-leveling "
            "and bad-block management. These over-provisioned blocks are NOT addressable via "
            "logical I/O and may retain data after CLEAR. ATA Secure Erase Enhanced or "
            "vendor crypto-erase is required to reach these blocks."
        ),
        write_protection_note=(
            "Recovery mode: source media should be accessed through a hardware write-blocker. "
            "SSD TRIM commands can destroy evidence if write access is allowed."
        ),
        ieee_2883_reference=(
            "IEEE 2883-2022 §5.2 — ATA Sanitize Device command (SANITIZE with CRYPTO SCRAMBLE "
            "or BLOCK ERASE operation)."
        ),
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
        hpa_dco_warning=(
            "⚠ NVMe namespaces: NVMe drives may have multiple namespaces or hidden controller "
            "regions. Use `nvme id-ctrl` and `nvme list-ns` to enumerate all namespaces. "
            "Logical CLEAR only reaches the active namespace visible to the OS."
        ),
        write_protection_note=(
            "Recovery mode: NVMe evidence should be accessed through a forensic NVMe bridge "
            "with write-blocking capability (e.g., Tableau T356789). Direct NVMe attachment "
            "may trigger controller-initiated garbage collection or TRIM."
        ),
        ieee_2883_reference=(
            "IEEE 2883-2022 §5.3 — NVMe Sanitize command (Sanitize Action field: 0x01 Block "
            "Erase, 0x02 Crypto Erase, 0x03 Overwrite, 0x04 Secure Erase if controller supports)."
        ),
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
        ieee_2883_reference=(
            "IEEE 2883-2022 §5.5 — Removable flash storage: Block Erase recommended by IEEE "
            "2883 but not uniformly supported by USB flash controllers (most do not expose "
            "ATA/NVMe passthrough); Cryptographic Erase supported only on TCG Opal USB drives "
            "with PSID. NIST recommends physical DESTROY for sensitive data "
            "(NIST SP 800-88 Rev. 2 §2.5)."
        ),
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
        ieee_2883_reference=(
            "IEEE 2883-2022 §5.5 (same as USB Flash) — additionally: SD CCCMD ERASE_WR "
            "command exists but performs only logical erase; NAND over-provisioned regions "
            "are inaccessible to the host and remain unerased unless physical DESTROY is performed."
        ),
    )


# ── TCG Opal Self-Encrypting Drive (SED) Discovery Parser ──────────────────────

def parse_tcg_level0_discovery(discovery_bytes: bytes) -> Dict[str, Any]:
    """
    Parses a TCG Storage Architecture Level 0 Discovery Response.
    Standardized by Trusted Computing Group (TCG) Storage Core Specification.

    Feature Codes:
      0x0001: TPer Feature
      0x0002: Locking Feature
      0x0200: Opal SSC V1.00
      0x0203: Opal SSC V2.00
      0x0301: Enterprise SSC
      0x0402: Ruby SSC
    """
    if len(discovery_bytes) < 48:
        return {"is_sed": False, "reason": "Discovery payload smaller than 48 bytes"}

    import struct
    param_data_len = struct.unpack_from(">I", discovery_bytes, 0)[0]
    major_ver, minor_ver = struct.unpack_from(">HH", discovery_bytes, 4)

    features = {}
    is_opal = False
    opal_ver = None
    locking_supported = False

    offset = 48  # Feature descriptors start at offset 0x30
    limit = min(len(discovery_bytes), param_data_len + 4)

    while offset + 4 <= limit:
        code, ver_res, length = struct.unpack_from(">HBB", discovery_bytes, offset)
        feat_data = discovery_bytes[offset + 4:offset + 4 + length]

        features[f"0x{code:04X}"] = {
            "version": ver_res >> 4,
            "length": length
        }

        if code == 0x0002:
            locking_supported = True
        elif code == 0x0200:
            is_opal = True
            opal_ver = "TCG Opal SSC V1.0"
        elif code == 0x0203:
            is_opal = True
            opal_ver = "TCG Opal SSC V2.0"
        elif code == 0x0301:
            is_opal = True
            opal_ver = "TCG Enterprise SSC"
        elif code == 0x0402:
            is_opal = True
            opal_ver = "TCG Ruby SSC"

        offset += 4 + length

    return {
        "is_sed": is_opal or locking_supported,
        "opal_capable": is_opal,
        "opal_version": opal_ver,
        "locking_supported": locking_supported,
        "feature_count": len(features),
        "features": features,
    }


def evaluate_opal_capability(target_path: str, raw_discovery_bytes: Optional[bytes] = None) -> DeviceCapability:
    """
    Evaluates storage device for TCG Opal Self-Encrypting Drive capability.
    When Opal SED is detected, promotes sanitization recommendation to instant
    Cryptographic Erase per NIST SP 800-88 Rev. 2 §2.4 Purge.
    """
    cap = detect_media_type(target_path)
    if raw_discovery_bytes:
        parsed = parse_tcg_level0_discovery(raw_discovery_bytes)
        if parsed.get("opal_capable"):
            cap.is_sed_opal_capable = True
            cap.opal_ssc_version = parsed.get("opal_version")
            cap.crypto_erase_recommended = True
            cap.crypto_erase_rationale = (
                f"TCG Opal Self-Encrypting Drive confirmed ({parsed.get('opal_version')}). "
                "Hardware Media Encryption Key (MEK) cryptographic destruction fulfills "
                "NIST SP 800-88 Rev. 2 §2.4 Purge instantly with zero wear-leveling endurance loss."
            )
            cap.purge_supported = True
            cap.purge_command = "TCG OPAL CRYPTOGRAPHIC ERASE (PSID Revert / MEK Invalidation)"
            cap.classification_basis.append(f"TCG Level 0 Discovery verified: {parsed.get('opal_version')}")
    return cap

