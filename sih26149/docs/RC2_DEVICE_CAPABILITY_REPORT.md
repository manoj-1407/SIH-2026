# RC2 Storage Device Capability & Sanitization Matrix

## NIST SP 800-88 Rev. 2 Media Classification
The SIH26149 capability detection engine interrogates device interfaces and paths to map the exact standard sanitization level and block unsupported destructive operations.

---

## 1. Storage Device Profile Matrix

| Device Profile | Detected Media Type | NIST Recommended Level | Clear Overwrite | Hardware Purge | Fail-Closed Enforcement |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **SATA HDD** | `UNKNOWN` | **CLEAR** | `SUPPORTED` | `BLOCKED` | **Fail-closed: No unsupported ATA/NVMe commands simulated** |
| **NVMe SSD** | `NVME_SSD` | **CLEAR** | `SUPPORTED` | `BLOCKED` | **Fail-closed: No unsupported ATA/NVMe commands simulated** |
| **USB Drive** | `UNKNOWN` | **CLEAR** | `SUPPORTED` | `BLOCKED` | **Fail-closed: No unsupported ATA/NVMe commands simulated** |
| **SD Card** | `SD_CARD` | **CLEAR** | `SUPPORTED` | `BLOCKED` | **Fail-closed: No unsupported ATA/NVMe commands simulated** |
| **Virtual Image (.raw)** | `VIRTUAL_DISK_IMAGE` | **CLEAR** | `SUPPORTED` | `BLOCKED` | **Fail-closed: No unsupported ATA/NVMe commands simulated** |
| **Virtual Image (.img)** | `VIRTUAL_DISK_IMAGE` | **CLEAR** | `SUPPORTED` | `BLOCKED` | **Fail-closed: No unsupported ATA/NVMe commands simulated** |

---

## 2. Capability Invariants & Laboratory Boundaries
1. **Virtual Container Scope**: For disk images (`.raw`, `.img`, `.vmdk`), sanitization operates exclusively at the logical file/container level (Clear).
2. **Hardware Purge Boundary**: ATA Secure Erase and NVMe Sanitize hardware primitives require unmediated direct kernel block device access and are fail-closed when executing in virtualized or non-raw environments.
3. **NAND Flash Wear-Leveling Disclaimer**: Software overwrite on SSD/USB/SD targets is explicitly noted as logical clear, acknowledging that wear-leveling spare blocks require hardware controller purge or physical destruction for total sanitization.
