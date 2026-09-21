# Standards Mapping Specification — SIH26149

**Project**: Integrated Secure Data Erasure and Advanced File Recovery Tool  
**Organization**: National Technical Research Organisation (NTRO)  
**Standard References**: NIST SP 800-88 Rev. 2, NIST CFTT, RFC 8032, RFC 8785

---

## 1. NIST SP 800-88 Rev. 2 (Media Sanitization Guidance)

*Reference*: NIST SP 800-88 Rev. 2, Finalized September 26, 2025. Supersedes Rev. 1.

| NIST Level | Section | Requirement | SIH26149 Implementation | Operational Status |
| :--- | :--- | :--- | :--- | :--- |
| **Clear** | §2.3 | Logical overwrite of user-accessible storage locations using logical interface | Single-pass zero/random fill with 100% byte read-back verification. | **IMPLEMENTED + TESTED** |
| **Purge** | §2.4 | Hardware-level execution (ATA Secure Erase, NVMe Sanitize, Cryptographic Erase) rendering recovery infeasible against laboratory techniques | Capability detection evaluates target. If operating on virtual disk images or without kernel ATA/NVMe sanitize privileges, operation is **BLOCKED**. | **CAPABILITY GATED / FAIL-CLOSED** |
| **Destroy** | §2.5 | Physical destruction (shredding, incineration, degaussing) | Guidance and advisory emission for obsolete/failing media. | **ADVISORY SPECIFIED** |

### Critical NAND / Flash Boundary
Per NIST SP 800-88 Rev. 2 §2.4, software logical overwrites on SSDs/Flash do not overwrite retired or over-provisioned NAND blocks. **SIH26149 explicitly records all sanitization results as `LOGICAL_OBSERVATION_ONLY` and never falsely certifies physical NAND erasure from software write-backs.**

---

## 2. NIST CFTT (Computer Forensic Tool Testing Program)

*Reference*: NIST CFTT Methodology for Forensic Recovery Tools.

| CFTT Metric | Description | SIH26149 Implementation |
| :--- | :--- | :--- |
| **Source Preservation** | Forensic source must not be altered during examination | Read-only input lock + Pre/Post SHA-256 hash invariants in `app/forensics/acquisition.py`. |
| **Functionality-Driven Testing** | Structured evaluation based on specifications, criteria, and controlled test sets | 24-case recovery matrix (`tests/corpus/test_24_case_matrix.py`) testing contiguous, fragmented, corrupted, and truncated files. |
| **Outcome Transparency** | Clearly report what was recovered vs unrecoverable | Discrete states: `VALIDATED`, `PARTIAL`, `FRAGMENTED`, `UNVERIFIED`, `INVALID`. |

---

## 3. Cryptographic Standards

| Standard | Subject | SIH26149 Implementation |
| :--- | :--- | :--- |
| **FIPS 180-4** | SHA-256 Hash Standard | Chunked SHA-256 hashing for source, artifacts, and event chains (`app/core/hashing.py`). |
| **RFC 8032** | Edwards-Curve Digital Signature Algorithm (Ed25519) | Asymmetric Ed25519 signing using PyCA `cryptography` (`app/core/signing.py`). |
| **RFC 8785** | JSON Canonicalization Scheme (JCS) | Invariant UTF-8 JSON serialization with lexicographical UTF-16 key sorting and ECMAScript number rules (`app/core/canonical.py`). |
