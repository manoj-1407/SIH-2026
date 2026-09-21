# Real Media Validation Protocol & Hardware Test Plan — SIH26149

**Standard**: NIST SP 800-88 Rev. 2 (Media Sanitization) & NIST CFTT  
**Purpose**: Protocols for validating forensic recovery and sanitization on physical disposable storage media.

---

## 1. Safety Protocols for Real Hardware Validation

> [!CAUTION]
> **Host Safety Safeguard**: Real device testing must NEVER be executed against active OS disks, boot loaders, system partitions, swap volumes, or mounted critical filesystems.

The software implements safety checks to verify:
1. Target is NOT `/dev/sda` or `C:` if active OS partition is mounted.
2. Operator must supply explicit JSON authorization scope with exact serial number and device identifier.
3. Media under test must be authorized, dedicated test hardware.

---

## 2. Hardware Test Protocol Matrix

| Media Class | Test Interface | Target Mechanisms | Expected Capability | Verification Method |
| :--- | :--- | :--- | :--- | :--- |
| **Rotational HDD** | SATA (3.5" / 2.5") | Single-pass zero / pattern overwrite | `CLEAR: SUPPORTED`<br>`PURGE: ATA SECURE ERASE (hdparm)` | 100% full-capacity LBA read-back verification against expected pattern. |
| **SATA SSD** | SATA III | ATA Secure Erase / Logical Overwrite | `CLEAR: SUPPORTED`<br>`PURGE: ATA ENHANCED SECURE ERASE` | Read-back verification; explicit notation that unmapped NAND blocks are out-of-scope for software Clear. |
| **NVMe SSD** | PCIe / M.2 | NVMe Sanitize (Block Erase / Crypto Erase) | `CLEAR: SUPPORTED`<br>`PURGE: NVMe SANITIZE (nvme-cli)` | Read-back verification; verify controller log page 0x81. |
| **USB Flash** | USB 3.0 Mass Storage | Single/Multi-pass overwrite | `CLEAR: SUPPORTED`<br>`PURGE: UNSUPPORTED` | Sector-by-sector readback verification. |
| **SD / microSD** | SDIO / USB Adapter | Logical overwrite / SD Erase Command | `CLEAR: SUPPORTED`<br>`PURGE: UNSUPPORTED` | Read-back verification. |

---

## 3. Hardware Test Execution Log Format

When real hardware validation experiments are conducted on authorized media, records are captured in the following schema:

```json
{
  "test_id": "HW-VAL-2026-001",
  "timestamp_utc": "2026-09-21T00:00:00Z",
  "media": {
    "manufacturer": "SampleVendor",
    "model": "SampleModel-128G",
    "serial": "SN-XXXX-YYYY",
    "capacity_bytes": 128035676160,
    "interface": "USB3 / Mass Storage",
    "firmware_version": "v1.0.4"
  },
  "environment": {
    "os_kernel": "Linux 6.6.13-lts",
    "driver": "uas / usb-storage",
    "tool_version": "2.0.0"
  },
  "operation": {
    "method_requested": "CLEAR_ZERO_FILL",
    "capability_detected": "CLEAR_SUPPORTED_PURGE_UNSUPPORTED",
    "duration_seconds": 142.5,
    "status": "VERIFIED_SUCCESS"
  },
  "verification": {
    "sectors_verified": 250069680,
    "pattern_expected": "0x00",
    "mismatch_count": 0,
    "assurance_level": "NIST_SP_800_88_REV2_CLEAR"
  }
}
```
