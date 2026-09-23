# Claims Matrix & Engineering Defense — SIH26149

**Purpose**: Defines the exact defensibility status of all claims in documentation, presentations, and technical evaluations.  
**Allowed States**: `PROVEN` | `DEMONSTRATED` | `IMPLEMENTED` | `PARTIAL` | `UNSUPPORTED` | `PLANNED`

---

| Claim / Capability | Status | Implementation Reference | Test / Verification Evidence | Boundary / Known Limitation |
| :--- | :---: | :--- | :--- | :--- |
| **Source Preservation** | **PROVEN** | `app/forensics/acquisition.py` | `preserve_source` pre/post SHA-256 invariant check | Applies to file-based images and working copies. |
| **SHA-256 Hashing** | **PROVEN** | `app/core/hashing.py` | `tests/unit/test_hashing.py` against FIPS test vectors | None. |
| **Ed25519 Signatures** | **PROVEN** | `app/core/signing.py` | `tests/unit/test_signing.py` against RFC 8032 vectors | None. |
| **RFC 8785 JCS Canonicalization** | **PROVEN** | `app/core/canonical.py` | `tests/unit/test_rfc8785.py` and `tests/unit/test_canonical.py` | NaN and Infinity explicitly rejected per standard. |
| **Audit Event Hash Chaining** | **PROVEN** | `app/cases/audit.py` | `tests/adversarial/test_evidence_tamper.py` (Tests 7, 8, 9) | Detects deletion, reordering, and duplicate records. |
| **Portable Evidence Package** | **PROVEN** | `app/core/package.py` | `demo/run_demo.py`, `test_adversarial_1_valid_package` | Directory layout with self-contained manifest & raw PEM. |
| **Independent Verifier** | **PROVEN** | `app/core/independent_verifier.py` | Standalone execution; tested without application DB | Independent of database and producer runtime. |
| **ext4 Deleted Inode Recovery** | **DEMONSTRATED** | `app/forensics/recovery.py` | `tests/integration/test_forensic_pipeline.py` via `icat`/`fls` | Requires The Sleuth Kit binaries installed. |
| **NTFS Recovery (native MFT parser)** | **PARTIAL** | `app/forensics/ntfs_mft.py`, `app/forensics/recovery.py` | Native parser scans $MFT records and reconstructs resident/non-resident payloads in controlled cases | Not a full filesystem-wide NTFS recovery engine; still falls back to raw carving for unsupported or fragmented cases. |
| **Raw Carving (JPEG, PNG, PDF, ZIP, MP4)** | **PROVEN** | `app/forensics/carving.py` | `tests/corpus/test_24_case_matrix.py` (24 cases) | Signature & structural marker dependent. |
| **Multi-Layer File Validation** | **PROVEN** | `app/forensics/validation.py` | `validate_carved_file` with in-memory decoder tests | Safe in-memory decoding; never executes native code. |
| **Bounded Fragment Reconstruction**| **IMPLEMENTED** | `app/forensics/carving.py` | `test_case_08_two_fragments_gap` (Bifragment scan) | Bounded to 4 cluster hops (2MB); does not solve arbitrary n-way interleaving. |
| **Selective File Erasure** | **PROVEN** | `app/sanitization/file_eraser.py` | `tests/integration/test_sanitization_pipeline.py` | Multi-pass overwrite, filename scrambling & readback check. |
| **Logical Overwrite (Clear)** | **PROVEN** | `app/sanitization/methods.py` | `test_sanitization_pipeline.py` (100% read-back verified) | Certified for logical addressable sectors only. |
| **NIST SP 800-88 Rev. 2 Capability Gating** | **PROVEN** | `app/sanitization/device_detector.py` | `app/cli/forensic.py`, `demo/run_demo.py` | Evaluates media class and blocks unsupported commands. |
| **Hardware Purge Execution** | **UNSUPPORTED** | `app/sanitization/device_detector.py` | Blocks requested PURGE on virtual disks / unprivileged hosts | Requires root kernel ATA/NVMe sanitize ioctl support. |
| **Physical NAND Block Erasure**| **UNSUPPORTED** | `app/sanitization/device_detector.py` | Documented in scope statements & logs | Software cannot overwrite retired/overprovisioned NAND. |
| **Real Media Hardware Testing** | **PLANNED** | `docs/REAL_MEDIA_VALIDATION.md` | Testing protocol and disposable media test procedure | Awaiting controlled laboratory hardware execution. |
