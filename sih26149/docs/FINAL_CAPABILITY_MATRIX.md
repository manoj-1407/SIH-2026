# Final Capability Matrix & Reconciliation — SIH26149

**Audit Date**: 2026-09-21  
**Software Version**: `2.0.0`

---

## 1. Capability Status & Ground Truth Evidence

| Feature / Capability | Operational Status | Ground Truth Evidence | Known Limitations | Automated Test Count | Real Hardware Validated? |
| :--- | :---: | :--- | :--- | :---: | :---: |
| **Case Management & Store** | **IMPLEMENTED** | `app/cases/models.py`, `app/cases/store.py` | JSON filesystem storage | 8 unit / 4 integration | PARTIAL (OS disk) |
| **Source Preservation** | **PROVEN** | `app/forensics/acquisition.py` | Pre/Post SHA-256 hash invariant | 4 unit | YES (Image files) |
| **Source SHA-256 Hashing** | **PROVEN** | `app/core/hashing.py` | Chunked hashing | 6 unit | YES |
| **ext4 Deleted Inode Recovery**| **DEMONSTRATED** | `app/forensics/recovery.py` | `icat`/`fls` recovery | SleuthKit required | YES (Ext4 images) |
| **NTFS / FAT32 Recovery** | **RAW_CARVING_FALLBACK** | `app/forensics/filesystem.py` | Raw carving fallback | Inode/MFT timestamps not extracted | 4 integration | YES (Raw stream) |
| **Raw Carving (JPEG/PNG/PDF/ZIP/MP4)** | **PROVEN** | `app/forensics/carving.py` | 24-case recovery matrix | Structural markers required | 24 matrix tests | YES |
| **Multi-Layer File Validation** | **PROVEN** | `app/forensics/validation.py` | In-memory structural & decoder tests | Safe in-memory decoding | 12 unit / 24 matrix | YES |
| **Bounded Fragment Recovery** | **IMPLEMENTED** | `app/forensics/carving.py` | Forward gap scan (up to 2MB) | Bounded reconstruction; does not solve arbitrary n-way interleaving | 3 matrix tests | YES (Synthetic images) |
| **NIST 800-88 Rev. 2 Capability Gating** | **PROVEN** | `app/sanitization/device_detector.py` | Fail-closed blocking of unsupported purge | Hardware ATA/NVMe sanitize requires kernel ioctl | 8 unit / 4 integration | YES |
| **Selective File Erasure** | **PROVEN** | `app/sanitization/file_eraser.py` | Multi-pass overwrite, filename scrambling & readback check | Host filesystem dependent | 6 integration | YES |
| **Logical Overwrite (Clear)** | **PROVEN** | `app/sanitization/methods.py` | 100% byte read-back verified | Addressable logical sectors only | 6 integration | YES |
| **Hardware Purge Execution** | **UNSUPPORTED / BLOCKED**| `app/sanitization/device_detector.py` | Fail-closed `ACTION BLOCKED` | Requires privileged host & storage appliance | 4 integration | NO (Virtual disk only) |
| **Physical NAND Block Erasure**| **UNSUPPORTED** | `app/sanitization/device_detector.py` | Certified as `LOGICAL_OBSERVATION_ONLY` | Physical NAND wear-leveling is out-of-scope for software | 2 unit | NO (Physical lab only) |
| **Ed25519 Signing** | **PROVEN** | `app/core/signing.py` | RFC 8032 test vectors | None | 8 unit | YES |
| **RFC 8785 JCS Canonicalization**| **PROVEN** | `app/core/canonical.py` | Lexicographical UTF-16 sorting & ECMAScript numbers | None | 6 unit | YES |
| **Audit Hash Chain (`events.jsonl`)** | **PROVEN** | `app/cases/audit.py` | SHA-256 chain; tamper detection tested | None | 8 unit / 3 adversarial | YES |
| **Portable Evidence Package** | **PROVEN** | `app/core/package.py` | Self-contained package generator | None | 4 adversarial | YES |
| **Standalone Independent Verifier**| **PROVEN** | `app/core/independent_verifier.py` | Zero application DB dependency | Consumes package + raw PEM | 11 adversarial tests | YES |
| **Workstation UI** | **IMPLEMENTED** | `app/static/` | Vanilla HTML5/CSS3/JS | Manual browser testing | YES |
| **Unified Forensic CLI** | **PROVEN** | `app/cli/forensic.py` | `recover`, `sanitize`, `verify` | None | 3 integration | YES |
| **ReportLab PDF & HTML Reports**| **PROVEN** | `app/core/certificate.py` | Offline PDF/HTML generator | ReportLab library | 4 unit | YES |
| **Adversarial Tamper Detection**| **PROVEN** | `tests/adversarial/` | 11 attack vectors tested | None | 11 adversarial tests | YES |
| **Security Fuzzing Robustness** | **PROVEN** | `tests/fuzz/` | Bit-flips, random noise, large ints | None | 19 fuzz tests | YES |
