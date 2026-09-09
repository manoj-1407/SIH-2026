# SIH26149 System Architecture

```text
                     Browser Workstation UI (HTML/CSS/JS)
                                    │
                                    ▼
                         FastAPI Application (REST)
                        ┌───────────┴───────────┐
                        ▼                       ▼
               Forensics Service       Sanitization Service
                        │                       │
                        ▼                       ▼
            Sleuth Kit Engine (fls, icat)   Zero-Fill Engine (dd, verify)
                        └───────────┬───────────┘
                                    ▼
                          Evidence Core Layer
                     ┌──────────────┼──────────────┐
                     ▼              ▼              ▼
               Canonicalizer     SHA-256        Ed25519
                                                   │
                                                   ▼
                                         Trust Key Registry
                                                   │
                                                   ▼
                                            Evidence Store
                                         (Atomic fsync rename)
```

## Layer Responsibilities
1. **Presentation Layer (`app/static/`)**:
   - Operator interface for Case management, Forensic Stepper, Sanitization Authorization, Evidence Vault, and Independent Verifier.
2. **API Layer (`app/api/`)**:
   - Exposes RESTful endpoints for cases, uploads, filesystem capability queries, recovery, sanitization, and evidence verification.
3. **Forensic Core (`app/forensics/`)**:
   - `filesystem.py`: Detects filesystem structures, separates detection from recovery capability.
   - `discovery.py`: Discovers deleted inodes via `fls`.
   - `recovery.py`: Extracts raw file bytes via `icat`.
   - `verification.py`: Computes SHA-256 and compares against ground truth.
4. **Sanitization Core (`app/sanitization/`)**:
   - `authorization.py`: Validates authentic operator identity and scope acknowledgement.
   - `methods.py`: Executes single-pass zero overwrite (`ZERO_FILL`).
   - `verification.py`: Readback byte-by-byte zero verification.
   - `scope.py`: Attaches technical boundaries permanently to records.
5. **Trust & Evidence Layer (`app/core/`)**:
   - `canonical.py`: Deterministic canonical JSON (sorted keys, no whitespace), aligned with the principles of RFC 8785 but not certified/tested against the full RFC 8785 conformance suite.
   - `signing.py`: Ed25519 keypair generation, signing, and verification.
   - `trust.py`: Trusted public key registry. Never trusts keys inside untrusted packages.
   - `persistence.py`: Atomic write primitives with fsync guarantees.
   - `independent_verifier.py`: Standalone evidence envelope verifier.
