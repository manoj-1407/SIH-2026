# Implementation Audit & Ground Truth Baseline — SIH26149

## Audit Execution Date: 2026-09-21
**Repository**: `manoj-1407/SIH-2026` / Subproject: `sih26149`  
**Problem Statement**: SIH26149 — Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization  
**Organization**: National Technical Research Organisation (NTRO)  
**Standard References**: NIST SP 800-88 Rev. 2, NIST CFTT, RFC 8032 (Ed25519), RFC 8785 (JCS)

---

## 1. Component Ground Truth Matrix

| Component | Exists | Implemented | Tested (Unit) | Integration-tested | Real-world validated | Evidence / Repository Location |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Case management** | YES | YES | YES | YES | PARTIAL | `app/cases/models.py`, `app/cases/store.py`, `app/api/cases.py`, `tests/unit/test_persistence.py` |
| **Source preservation** | YES | PARTIAL | YES | PARTIAL | NO | Read-only input validation in `app/forensics/acquisition.py`, immutable hashing on upload in `app/api/forensics.py`. Missing explicit source write-lock verification adapter. |
| **Source hashing** | YES | YES | YES | YES | YES | `app/core/hashing.py`, `tests/unit/test_hashing.py` (SHA-256 chunked hashing verified against standard vectors). |
| **Filesystem profiling** | YES | YES | YES | YES | PARTIAL | `app/forensics/filesystem.py` (Detects ext4/NTFS/FAT32/raw via `file`/`fsstat`; maps capabilities honestly). |
| **Deleted-file recovery** | YES | YES | YES | YES (Linux/SleuthKit) | PARTIAL | `app/forensics/discovery.py`, `app/forensics/recovery.py`, `tests/integration/test_forensic_pipeline.py` (icat/fls). |
| **Raw carving** | YES | YES | YES | YES | PARTIAL | `app/forensics/carving.py` (JPEG, PNG, PDF, ZIP, DOCX, XLSX, MP4 scanners). |
| **Fragment reconstruction** | YES | PARTIAL | YES | PARTIAL | NO | Forward bounded gap-scan in `app/forensics/carving.py` (`MAX_FRAGMENT_SCAN`). Lacks multi-hypothesis compatibility scoring. |
| **File validation** | YES | PARTIAL | YES | PARTIAL | NO | Basic marker/chunk checks (JPEG SOI/EOI, PNG IHDR/CRC/IEND, PDF %PDF/%%EOF, ZIP EOCD, MP4 ftyp/moov/mdat). Needs deep parser decode layer. |
| **Recovery provenance** | YES | YES | YES | YES | PARTIAL | `evidence_factors`, `reconstruction_strategy`, offset recording in `CarvedFile` (`app/forensics/carving.py`). |
| **Capability detection** | YES | YES | YES | YES | PARTIAL | `app/sanitization/device_detector.py` (NIST SP 800-88 Rev. 2 classification: HDD, NVMe, SATA SSD, USB, SD, Virtual Image). |
| **File/folder erasure** | YES | YES | YES | YES | YES (Logical) | `app/sanitization/file_eraser.py` (Multi-pass zero/random fill, metadata scrubbing, filename scrambling). |
| **Drive sanitization** | YES | PARTIAL | YES | YES (Virtual Image) | NO (Raw HW) | `app/sanitization/methods.py` (Logical zero-fill for image files; blocks unsupported hardware purge safely). |
| **Post-operation verification** | YES | YES | YES | YES | YES (Logical) | `app/sanitization/verification.py` (Byte-by-byte readback verification for zero/pattern fill). |
| **SHA-256 evidence** | YES | YES | YES | YES | YES | `app/core/hashing.py`, `app/core/evidence_envelope.py`. |
| **Ed25519 signing** | YES | YES | YES | YES | YES | `app/core/signing.py` using `cryptography` lib; RFC 8032 test vectors in `tests/unit/test_signing.py`. |
| **Event chain** | YES | YES | YES | YES | PARTIAL | `app/cases/audit.py` (JSONL SHA-256 hash-chained timeline with tampering detection and demo tamper endpoint). |
| **Canonicalization** | YES | YES | YES | YES | YES | `app/core/canonical.py` (Strict RFC 8785 JSON Canonicalization Scheme; verified against RFC test vectors in `tests/unit/test_rfc8785.py`). |
| **Independent verifier** | YES | YES | YES | YES | YES | `app/core/independent_verifier.py`, `app/cli/verify.py` (Verifies single envelope and portable directory packages; detects tampered hashes, invalid signatures, and injected unmanifested files). |
| **PDF/HTML reporting** | YES | YES | YES | YES | PARTIAL | `app/core/certificate.py` (Generates ReportLab PDF and HTML sanitization/recovery certificates). |
| **UI** | YES | YES | NO (Manual) | NO (Manual) | PARTIAL | Single-page vanilla HTML/CSS/JS in `app/static/` (Case creation, Forensics, Carving, Eraser, Audit Timeline, Verifier). |
| **CLI** | YES | YES | YES | YES | YES | Unified CLI in `app/cli/forensic.py` with `recover`, `sanitize`, `verify` subcommands, human/machine JSON output, tested in `tests/integration/test_cli.py`. |
| **Docker** | YES | YES | YES (Container) | YES | PARTIAL | `Dockerfile` (Debian with SleuthKit, Python 3.12/3.13), `docker-compose.yml`, tested in `scripts/test_container_live.py`. |
| **Security controls** | YES | YES | YES | YES | YES | Path traversal guards, upload limits, filename sanitization, rate limiter with test bypass, API key auth, private key leak prevention. |

---

## 2. Test Execution & Operational Baseline

- **Automated Regression Suite**: 227 test items collected across 18 test modules.
- **Results**: 220 executed tests passed, 7 platform-dependent tests skipped (Linux kernel ext4 tools on Windows host), 0 failed.
- **Operational RC1 Gate**: 20 / 20 checks passed (`scripts/verify_rc1_gate.py`).
- **Recovery Accuracy (Evaluated Corpus)**: 100.0% Precision (0 false positives), 83.3% Recall, 0.9091 F1 Score.
- **Measured Cryptographic & Ingest Baseline** (*Windows 11 • Python 3.13.3 • Intel64*):
  - Ed25519 Signing Latency: **0.21 ms** (Median) / **0.399 ms** (P95)
  - Directory Package Verification: **13.87 ms** (Median) / **22.24 ms** (P95)
  - SHA-256 Streaming Ingest: **141 – 228 MB/s**
  - NIST SP 800-88 Clear Overwrite + Read-back: **7.0 – 10.4 MB/s**

- **Test Categories in Repo**:
  - `tests/unit/`: 9 test suites (`test_canonical.py`, `test_classification.py`, `test_hashing.py`, `test_persistence.py`, `test_proof_loop_benchmark.py`, `test_rfc8785.py`, `test_signing.py`, `test_trust.py`, `test_v2_features.py`).
  - `tests/integration/`: 7 test suites (`test_api.py`, `test_api_failures.py`, `test_cli.py`, `test_forensic_pipeline.py`, `test_sanitization_pipeline.py`, `test_security_attacks.py`, `test_storage_abuse.py`, `test_upload_edge_cases.py`).
  - `tests/corpus/`: 1 test suite (`test_24_case_matrix.py` — 24 distinct file formats & edge cases).
  - `tests/fuzz/`: 1 test suite (`test_parser_fuzz.py` — 22 mutated & truncated stream scenarios).
  - `tests/adversarial/`: 1 test suite (`test_evidence_tamper.py` — 17 cryptographic & envelope tampering attacks).

---

## 3. Discrepancies & Defensible Boundaries

1. **Hardware Sanitization Claims**:
   - Software performs *logical overwrite (Clear)* and *read-back verification*.
   - ATA Secure Erase and NVMe Sanitize commands cannot be executed on Windows or on virtual image files.
   - **Ground Truth**: System strictly reports `CLEAR` or `UNSUPPORTED` and blocks simulated `PURGE` claims on real block devices.
   - **Demonstrated**: NIST SP 800-88 Rev. 2 §2.3 Clear single-pass overwrite with 100% byte-level read-back verification on tested logical files and virtual disk images.
2. **Recovery Accuracy & Bounds**:
   - **Demonstrated**: 100.0% precision and 83.3% recall on the evaluated ground-truth corpus (0 false positives; fragmented streams bounded to `PARTIAL`).
3. **Source Preservation**:
   - Software-enforced read-only binary file handles (`rb`) and SHA-256 pre/post-operation hash invariance.
   - Physical hardware write-blocking explicitly noted as `PENDING LABORATORY HARDWARE BRIDGES`.
4. **Filesystem Recovery vs Raw Carving**:
   - `ext4`: Inode metadata recovery supported via SleuthKit (`icat`, `fls`).
   - `NTFS` / `FAT32`: Inode/directory recovery falls back to raw signature carving without claiming MFT timestamp reconstruction.
3. **Canonicalization & Trust Integrity**:
   - Strict RFC 8785 (JCS) canonical serialization active on all evidence hashes and signature generation.
   - Independent verifier strictly checks directory package contents against manifest, rejecting injected extra files (DEF-005).
   - In-memory rate limiting supports `SIH26149_DISABLE_RATE_LIMIT=1` for isolated automated test runs without rate-exhaustion collisions.
