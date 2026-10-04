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

## 2. H01–H09 National-Readiness Audit Reconciliation

The following records implementation and automated-test coverage, not physical-media validation or legal certification.

| Audit item | Current status | Evidence and boundary |
| :--- | :--- | :--- |
| **H01 — ATA/NVMe sanitize profiles** | **PREVIEW ONLY** | Media-specific command profiles and safety gates are available; this application does not execute ATA Secure Erase or NVMe Sanitize commands. No physical-drive execution was performed. |
| **H02 — IEEE 2883 references** | **REFERENCED** | Purge/sanitization profiles and technical records expose IEEE 2883 references; the project does not claim standards conformance. |
| **H03 — HPA/DCO honesty** | **ADVISORY / ENVIRONMENT-DEPENDENT** | Capability results report whether HPA/DCO probes ran and expose advisory commands when they did not. No physical-device probe was performed in this validation. |
| **H04 — Legacy Office and EML/MSG** | **IMPLEMENTED / SYNTHETICALLY TESTED** | OLE-based DOC/XLS/PPT/MSG subtype identification and EML carving have focused positive/negative tests. These are heuristic recovery results, not a guarantee of complete document reconstruction. |
| **H05 — Indian evidence-law propagation** | **TECHNICAL RECORDS ONLY** | Generated notes identify BSA references without claiming certification, admissibility, or compliance. §65B is not described as a provision of the Information Technology Act. Legal applicability must be assessed by qualified counsel and the responsible certifying person. |
| **H06 — Three adversarial tamper demonstrations** | **IMPLEMENTED / INTEGRATION-TESTED** | Audit-chain, artifact-byte, and signing-key substitution attacks are exposed in the verifier demo UI and checked for detection/reset behavior. |
| **H07 — One-click evidence ZIP** | **IMPLEMENTED / INTEGRATION-TESTED** | The UI exports the signed envelope, signature record, available audit timeline, key material or a trusted-registry placeholder, and summary. It does not retrieve recovered payload files from the source image unless payload bytes are already embedded in the envelope. Timeline retrieval failures are surfaced rather than exported as empty evidence. |
| **H08 — Python/Node verifier parity** | **AUTOMATED-TESTED** | Cross-verifier integration tests cover valid envelopes and tamper/key-substitution rejection. Passing these tests does not certify every runtime or external trust-store configuration. |
| **H09 — Corpus, USB profile, and Destroy manifest** | **SYNTHETIC / PREVIEW BOUNDARY** | The 40-case matrix and USB/destroy decision-support code are present. Corpus tests use synthetic fixtures; Linux/Sleuth Kit-dependent cases skip on Windows, and no live USB device or physical destruction process was validated. |

Hardware sanitization execution, live USB validation, and legal determinations remain explicit external-validation items; they must not be inferred from passing software tests.
