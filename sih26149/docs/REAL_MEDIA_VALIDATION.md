# Real Media Validation Protocol & Hardware Test Plan — SIH26149

**Standard**: NIST SP 800-88 Rev. 2 (Media Sanitization) & NIST CFTT  
**Purpose**: Protocols for validating forensic recovery and sanitization on physical disposable storage media.

**Execution status**: Protocol only. No physical HDD, SATA SSD, NVMe SSD, USB
flash, or SD sanitization test has been performed. There is no hardware
execution backend in the current workstation; command previews are non-executing.

---

## 1. Safety Protocols for Real Hardware Validation

> [!CAUTION]
> **Host Safety Safeguard**: Real device testing must NEVER be executed against active OS disks, boot loaders, system partitions, swap volumes, or mounted critical filesystems.

These are mandatory requirements for a future hardware backend, not checks
implemented by the current preview-only software:
1. Resolve the exact target by stable device identity and refuse active OS, boot, swap, and mounted system media.
2. Require explicit authorization bound to the exact serial number and device identifier.
3. Require dedicated disposable test hardware and operator confirmation immediately before execution.

---

## 2. Hardware Test Protocol Matrix

| Media Class | Test Interface | Candidate Mechanisms (Unvalidated) | Capability Status | Verification Method If Lab-Tested |
| :--- | :--- | :--- | :--- | :--- |
| **Rotational HDD** | SATA (3.5" / 2.5") | Single-pass zero / pattern overwrite; ATA Secure Erase | `UNVERIFIED_NOT_PROBED` | Full-capacity LBA read-back plus independent command completion evidence. |
| **SATA SSD** | SATA III | ATA Secure Erase / enhanced erase; logical overwrite | `UNVERIFIED_NOT_PROBED` | Controller completion/status plus bounded logical read-back; unmapped NAND remains outside software observation. |
| **NVMe SSD** | PCIe / M.2 | NVMe Sanitize (Block Erase / Crypto Erase) | `UNVERIFIED_NOT_PROBED` | Controller completion/status, sanitize log page, and a separately scoped forensic probe. |
| **USB Flash** | USB Mass Storage | Logical overwrite | `PURGE_NOT_SUPPORTED_BY_STANDARD_HOST_METHOD` | Read-back only; no NAND-level assertion. |
| **SD / microSD** | SDIO / USB Adapter | Logical overwrite | `PURGE_NOT_SUPPORTED_BY_STANDARD_HOST_METHOD` | Read-back only; no NAND-level assertion. |

The table describes laboratory candidates, not results or verified target
capabilities. Physical execution requires a dedicated disposable test device,
explicit serial-number-bound authorization, and a separately reviewed safety
implementation. No command in this repository currently performs that execution.

---

## 3. Hardware Test Execution Log Format

When authorized hardware validation experiments are conducted in a future lab,
records can use a schema like the following. This is fictional example data,
not a performed test:

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
