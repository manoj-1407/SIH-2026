# SIH26149 — Module Inventory

**Generated**: 2026-09-23  
**Baseline**: 285 passed / 7 skipped

---

## 1. Python Modules

### `app/` — Application Root
| Module | Purpose |
|--------|---------|
| `app/__init__.py` | Package marker |
| `app/main.py` | FastAPI application, lifespan, middleware, router mounting, /api sub-app, static mount |

### `app/api/` — HTTP API Layer
| Module | Purpose |
|--------|---------|
| `app/api/health.py` | `GET /health` — system status and tool availability |
| `app/api/cases.py` | `GET/POST /cases`, `GET /cases/{id}`, `GET /cases/{id}/timeline`, `POST /cases/seed-demo` |
| `app/api/forensics.py` | Upload, filesystem, artifacts, recover, forensic, seed-synthetic-evidence, entropy, stego |
| `app/api/sanitization.py` | Sanitize, proof-loop, decision-profile, benchmark |
| `app/api/evidence.py` | Evidence list, get, verify, verify-package, demo-tamper |
| `app/api/carving.py` | `POST /cases/{id}/carve` — raw file carving |
| `app/api/eraser.py` | erase-preview, erase-files, detect-device |
| `app/api/audit_chain.py` | timeline GET, timeline/verify GET, timeline/demo-tamper POST |
| `app/api/certificates.py` | certificate.html, certificate.pdf, legal-affidavit |
| `app/api/auth.py` | `require_api_key` dependency — X-API-Key header enforcement |
| `app/api/deps.py` | Shared singletons: case_store, audit_logger, evidence_store, trust_registry, UPLOADS_DIR, get_or_create_primary_key |
| `app/api/rate_limit.py` | Sliding-window rate limiter (in-memory) |
| `app/api/validation.py` | `validate_case_id()` — case ID format guard |

### `app/cases/` — Case Management Domain
| Module | Purpose |
|--------|---------|
| `app/cases/models.py` | `Case`, `WorkflowType`, `CaseStatus` dataclasses |
| `app/cases/store.py` | `CaseStore` — atomic JSON persistence for cases |
| `app/cases/audit.py` | `AuditLogger` — hash-chained JSONL audit timeline |

### `app/core/` — Cryptography and Evidence Core
| Module | Purpose |
|--------|---------|
| `app/core/canonical.py` | RFC 8785 JSON Canonicalization Scheme (JCS) |
| `app/core/signing.py` | Ed25519 (RFC 8032) keypair generation, sign, verify |
| `app/core/hashing.py` | SHA-256 file and bytes hashing |
| `app/core/evidence_envelope.py` | Evidence payload builder, operation/evidence ID generators |
| `app/core/package.py` | `EvidencePackageBuilder` — self-contained evidence directory |
| `app/core/independent_verifier.py` | Standalone package verifier (zero DB dependency) |
| `app/core/legal_reliability.py` | BSA 2023 §63(4) / Daubert legal affidavit & chain of custody generator |
| `app/core/classification.py` | Forensic classification enums (VERIFIED, PARTIAL, FAILED, BLOCKED, …) |
| `app/core/certificate.py` | HTML/PDF evidence certificate generator |
| `app/core/persistence.py` | Atomic fsync-rename JSON persistence primitives |
| `app/core/trust.py` | Trust registry for public key storage |

### `app/forensics/` — Recovery Engine
| Module | Purpose |
|--------|---------|
| `app/forensics/carving.py` | File carver: JPEG, PNG, PDF, ZIP, DOCX, XLSX, MP4 |
| `app/forensics/validation.py` | Multi-layer structural + decoder validation per file type |
| `app/forensics/acquisition.py` | Read-only source lock + pre/post hash invariant |
| `app/forensics/filesystem.py` | Filesystem detection (ext4/NTFS/FAT32/raw) |
| `app/forensics/discovery.py` | Deleted artifact discovery (SleuthKit or fallback) |
| `app/forensics/recovery.py` | Single-artifact recovery coordinator |
| `app/forensics/verification.py` | Recovery result verification |
| `app/forensics/proof_loop.py` | Pre-carve → sanitize → post-probe assurance loop |
| `app/forensics/benchmark.py` | In-process recovery benchmark runner |
| `app/forensics/synthetic.py` | Synthetic disk image generator for testing |
| `app/forensics/steganography.py` | Chi-square LSB steganography detection with composite scoring & LSB entropy |

### `app/sanitization/` — Sanitization Engine
| Module | Purpose |
|--------|---------|
| `app/sanitization/device_detector.py` | NIST SP 800-88 Rev. 2 media classification & TCG Opal / SED detection |
| `app/sanitization/smart_telemetry.py` | NVMe/SATA SMART health telemetry & SSD wear indicators |
| `app/sanitization/authorization.py` | Operator authorization model |
| `app/sanitization/methods.py` | CLEAR/ZERO_FILL/RANDOM_FILL execution |
| `app/sanitization/file_eraser.py` | Selective file/folder eraser with metadata scrubbing |
| `app/sanitization/scope.py` | Scope statement and scope record utilities |
| `app/sanitization/verification.py` | Post-sanitization read-back verification |

### `app/cli/` — Command-Line Interface
| Module | Purpose |
|--------|---------|
| `app/cli/forensic.py` | `forensic recover`, `forensic sanitize`, `forensic verify` CLI |
| `app/cli/verify.py` | Standalone evidence package verifier CLI |

---

## 2. API Routes (28 routes, verified from live OpenAPI spec 2026-09-21)

| Method | Path | Module | Auth |
|--------|------|--------|------|
| GET | `/health` | `health` | None |
| GET, POST | `/cases` | `cases` | API Key |
| GET | `/cases/{case_id}` | `cases` | API Key |
| GET | `/cases/{case_id}/timeline` | `cases` + `audit_chain` ⚠️ | API Key |
| POST | `/cases/seed-demo` | `cases` | API Key |
| POST | `/cases/{case_id}/upload` | `forensics` | API Key |
| GET | `/cases/{case_id}/filesystem` | `forensics` | API Key |
| GET | `/cases/{case_id}/artifacts` | `forensics` | API Key |
| POST | `/cases/{case_id}/recover` | `forensics` | API Key |
| POST | `/cases/{case_id}/forensic` | `forensics` | API Key |
| POST | `/cases/{case_id}/seed-synthetic-evidence` | `forensics` | API Key |
| POST | `/cases/{case_id}/entropy` | `forensics` | API Key |
| POST | `/cases/{case_id}/stego` | `forensics` | API Key |
| POST | `/cases/{case_id}/sanitize` | `sanitization` | API Key |
| POST | `/cases/{case_id}/proof-loop` | `sanitization` | API Key |
| POST | `/cases/{case_id}/decision-profile` | `sanitization` | API Key |
| GET | `/cases/{case_id}/benchmark` | `sanitization` | API Key |
| GET | `/evidence` | `evidence` | API Key |
| GET | `/evidence/{evidence_id}` | `evidence` | API Key |
| POST | `/evidence/{evidence_id}/verify` | `evidence` | API Key |
| POST | `/evidence/verify-package` | `evidence` | API Key |
| POST | `/evidence/{evidence_id}/demo-tamper` | `evidence` | API Key |
| POST | `/cases/{case_id}/carve` | `carving` | API Key |
| POST | `/cases/{case_id}/erase-preview` | `eraser` | API Key |
| POST | `/cases/{case_id}/erase-files` | `eraser` | API Key |
| POST | `/cases/{case_id}/detect-device` | `eraser` | API Key |
| GET | `/cases/{case_id}/timeline/verify` | `audit_chain` | API Key |
| POST | `/cases/{case_id}/timeline/demo-tamper` | `audit_chain` | API Key |
| GET | `/evidence/{evidence_id}/certificate.html` | `certificates` | API Key |
| GET | `/evidence/{evidence_id}/certificate.pdf` | `certificates` | API Key |
| GET | `/evidence/{evidence_id}/legal-affidavit` | `certificates` | API Key |

---

## 3. Frontend JavaScript Functions (51 in `app/static/app.js`)

### Navigation & Layout
`switchTab`, `toggleMobileDrawer`, `toggleThemeMenu`, `setTheme`, `initTheme`, `initAmbientCanvas`

### Case Management
`loadCases`, `createCase`, `selectCase`, `setActiveCase`, `showNewCaseForm`, `hideNewCaseForm`, `seedOfficialDemoCase`, `seedSyntheticEvidenceForActiveCase`

### Forensic Recovery
`onImageSelect`, `runRecovery`, `detectFilesystem`, `discoverDeleted`, `prefillRecovery`

### File Carving
`runCarving`

### Sanitization & Eraser
`setSanMode`, `executeDriveSanitization`, `promptDriveSanitization`, `runDeviceDetect`, `previewEraseScope`, `promptFileErasure`, `executeFileErasure`

### Audit Chain
`loadAuditChain`, `verifyAuditChain`, `runTamper`, `setTamperPreset`

### Evidence & Verification
`loadVault`, `runVerify`

### Showcase Tab
`triggerShowcaseProofLoop`, `fetchLiveBenchmarkMetrics`, `updateDecisionProfile`, `simulateTamperDemo`

### Judge Demo
`runJudgeDemoSequence`, `toggleJudgeDemoModal`, `closeJudgeDemoModal`, `startColdStartCountdown`

### Diagnostics & API Config
`pingHealth`, `openConnDiagnostics`, `closeConnDiagnostics`, `saveApiKey`, `saveApiOverride`, `resetApiOverride`, `refreshCurrentView`

### Utilities
`promptConfirm`, `onConfirmModalConfirmed`, `closeConfirmModal`

---

## 4. Environment Variables

| Variable | Type | Default | Effect |
|----------|------|---------|--------|
| `SIH26149_DATA_DIR` | string | `./data` | Override data directory |
| `SIH26149_API_KEY` | string | None | Require X-API-Key header on all API requests |
| `DEMO_MODE` | string | None | `"1"` bypasses API key checks and enables demo tamper endpoints |
| `SIH26149_CORS_ORIGINS` | string | `"*"` | Comma-separated allowed CORS origins |

---

## 5. Persistent Files and Directories (runtime-generated)

| Path | Created by | Contents |
|------|-----------|---------|
| `data/` | `deps.py` | Root data directory |
| `data/cases/` | `CaseStore` | One JSON file per case |
| `data/uploads/` | `forensics.py` upload handler | Uploaded evidence images |
| `data/evidence/` | `evidence_store` | Signed evidence envelopes |
| `data/keys/` | `get_or_create_primary_key()` | `primary.pem` Ed25519 private key |
| `data/audit/<case_id>.jsonl` | `AuditLogger` | Hash-chained audit timeline |

---

## 6. Test Files

| File | Type | Covers |
|------|------|--------|
| `tests/unit/test_canonical.py` | Unit | RFC 8785 JCS |
| `tests/unit/test_rfc8785.py` | Unit | RFC 8785 official vectors |
| `tests/unit/test_hashing.py` | Unit | SHA-256 hashing |
| `tests/unit/test_signing.py` | Unit | Ed25519 sign/verify |
| `tests/unit/test_classification.py` | Unit | NIST device classification |
| `tests/unit/test_persistence.py` | Unit | Atomic JSON persistence |
| `tests/unit/test_trust.py` | Unit | Trust registry |
| `tests/unit/test_v2_features.py` | Unit | Package, verifier |
| `tests/unit/test_proof_loop_benchmark.py` | Unit | Proof loop timing |
| `tests/integration/test_api.py` | Integration | API happy paths |
| `tests/integration/test_forensic_pipeline.py` | Integration | Full forensic workflow |
| `tests/integration/test_sanitization_pipeline.py` | Integration | Sanitization pipeline |
| `tests/integration/test_security_attacks.py` | Integration | Security attack vectors |
| `tests/adversarial/test_evidence_tamper.py` | Adversarial | 17 evidence tamper vectors |
| `tests/corpus/test_24_case_matrix.py` | Corpus | 24 recovery cases |
| `tests/corpus/generator.py` | Fixture | Synthetic corpus generator |
| `tests/fuzz/test_parser_fuzz.py` | Fuzz | 22 parser fuzz cases |

---

## 7. Known Defects (Discovered During Phase A Audit)

| ID | Severity | Location | Description | Phase Fixed |
|----|---------|---------|-------------|-------------|
| DEF-001 | Low | `cases.py:50` + `audit_chain.py:13` | Duplicate `GET /cases/{case_id}/timeline` → OpenAPI duplicate operation ID warning | Phase A |
| DEF-002 | Info | `rate_limit.py` | In-memory rate limiter resets on restart | Document as limitation |
| DEF-003 | Medium | `core/package.py` | Evidence package write is not atomic (.tmp → rename missing) | Phase M |
| DEF-004 | Medium | `cases/audit.py` | No truncation detection on audit chain load | Phase M |
