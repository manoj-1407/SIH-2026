# Repository Ground-Truth Audit & Production Gap Analysis — SIH26149

**Audit Execution Date**: 2026-09-21  
**Target Standard**: Forensic Assurance & Media Sanitization Workstation  
**Repository**: `manoj-1407/SIH-2026` (`sih26149`)  
**Core Baseline**: 148 Passed / 7 Skipped (Windows environment-dependent SleuthKit tests) / 0 Failed

---

## 1. Traceable Ground-Truth Component Matrix

Every entry below is verified from **Source Code → Caller/API → Automated Test → Observable Output**.

| Component | Exists | Implemented | Unit Tested | Integration Tested | Production / Hardware Gap | Evidence / Traceability Path |
| :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| **Acquisition** | YES | YES | YES | YES | Hardware write-blocker bridging not tested on physical SATA/NVMe bridges. | `app/forensics/acquisition.py` → `preserve_source` → `tests/unit/test_persistence.py` → SHA-256 pre/post match. |
| **Profiling** | YES | YES | YES | YES | Linux `file`/`fsstat` required for full ext4 metadata profile; Windows uses pure Python fallback. | `app/forensics/filesystem.py` → `detect_filesystem` → `tests/integration/test_forensic_pipeline.py` → `FilesystemCapability`. |
| **Recovery** | YES | YES | YES | YES | NTFS/FAT32 metadata parser not implemented; fallback to raw carving. | `app/forensics/recovery.py` (`icat`) + `carving.py` → `carve_bytes` → `tests/corpus/test_24_case_matrix.py` (24 cases). |
| **Validation** | YES | YES | YES | YES | Pure Python in-memory parser only; third-party binary decoders (e.g. libjpeg-turbo) not embedded. | `app/forensics/validation.py` → `validate_carved_file` → `tests/corpus/test_24_case_matrix.py` → `ValidationOutcome`. |
| **Sanitization** | YES | YES | YES | YES | Hardware ATA Secure Erase & NVMe Sanitize commands cannot be issued from Windows/unprivileged users. | `app/sanitization/methods.py` + `file_eraser.py` → `tests/integration/test_sanitization_pipeline.py` → `CLEAR` verified. |
| **Capability Detection** | YES | YES | YES | YES | Linux sysfs rotational check supported; Windows uses path/drive-letter heuristics. | `app/sanitization/device_detector.py` → `detect_media_type` → `tests/unit/test_v2_features.py` → `DeviceCapability`. |
| **Evidence Packaging** | YES | YES | YES | YES | None; directory package layout is fully portable and self-contained. | `app/core/package.py` → `EvidencePackageBuilder` → `tests/adversarial/test_evidence_tamper.py` → `manifest.json`. |
| **Signing** | YES | YES | YES | YES | None; PyCA `cryptography` Ed25519 implementation. | `app/core/signing.py` → `sign_evidence` → `tests/unit/test_signing.py` → RFC 8032 test vectors. |
| **Independent Verifier** | YES | YES | YES | YES | None; operates with zero application DB/backend state using raw PEM. | `app/core/independent_verifier.py` → `verify_evidence_package` → `tests/adversarial/test_evidence_tamper.py` → `VALID/INVALID`. |
| **CLI** | YES | YES | YES | YES | Interactive prompting disabled for automated non-interactive pipelines. | `app/cli/forensic.py` & `app/cli/verify.py` → `main()` → Subprocess/CLI execution tests → Structured stdout. |
| **UI** | YES | YES | MANUAL | MANUAL | End-to-end Selenium/Playwright browser automation suite pending. | `app/static/index.html` + `app.js` + `app.css` → Single-page interface connecting to `/api/*` endpoints. |

---

## 2. Deep Architectural & Code Quality Findings

### A. Coupling & Layering Verification
- **Presentation Layer**: Static UI in `app/static/` communicates strictly over HTTP/REST JSON endpoints with no backend domain bleeding.
- **Application Layer**: API routers in `app/api/` wrap domain services and enforce authentication (`X-API-Key`) and sliding-window rate limiting (`rate_limit.py`).
- **Domain Engine Layer**:
  - `app/forensics/`: Independent recovery and validation logic. Does not import FastAPI or UI.
  - `app/sanitization/`: Capability-aware sanitization engine. Enforces fail-closed blocking for unsupported `PURGE` commands.
  - `app/core/`: Cryptographic hashing, RFC 8785 canonicalization, Ed25519 signing, and portable package packaging. Zero circular dependencies.
- **Verifier Separation**: `app/core/independent_verifier.py` has a strict zero-dependency trust boundary. It consumes only the file package and raw public key PEM, without referencing any database or active server state.

### B. Security & Safety Controls
1. **Subprocess Execution**: All subprocess calls (`icat`, `fls`, `fsstat`, `file`) use `shell=False` and explicit argument lists with strict path and numerical validation (e.g. integer inode validation in `recovery.py`).
2. **Path Traversal Defense**: All file upload endpoints and package extractors sanitize paths against `../`, absolute paths, null bytes, and Windows device names.
3. **Resource Bounds**: File carvers enforce `MAX_SCAN_SIZE` (500MB) and bounds on candidate lists (`max_results=500`).

---

## 3. Ground Truth Execution Summary

- **Automated Test Results**:
  - `tests/unit/`: 8 test suites passing (Canonical, RFC 8785, Signing, Hashing, Persistence, Proof Loop, Trust, V2 Features).
  - `tests/integration/`: 4 test suites passing (API, Forensic Pipeline, Sanitization Pipeline, Security Attacks).
  - `tests/adversarial/`: 11 adversarial tamper mutation tests passing.
  - `tests/corpus/`: 24-case recovery test matrix passing.
  - `tests/fuzz/`: 19 security parser fuzzing tests passing.
  - **Total**: 148 passed, 7 skipped, 0 failed.
- **Live Demo Verification**: `demo/run_demo.py` executes all 8 proof steps deterministically in < 2 seconds.
