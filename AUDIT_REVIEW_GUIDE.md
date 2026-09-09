# SIH Final v5 — Comprehensive Audit & Review Guide

**Problem Statements**:
1. **SIH26149** (NTRO): Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization
2. **SIH26013** (MoRD / DoLR): Automated Integration and Intelligent Harmonization of Multi-source Geospatial Data for Urban Land Record Management

---

## Live Production Deployments (Render)
- **SIH26149 Forensic Assurance Platform**: `https://sih26149.onrender.com`
- **SIH26013 Geospatial Harmonization Platform**: `https://sih26013.onrender.com`

---

## Package Structure

```
d:/SIH_FINAL_v5/
│
├── AUDIT_REVIEW_GUIDE.md                         # This comprehensive audit manual
├── DEPLOYMENT.md                                 # Production deployment & environment specification
├── README.md                                     # System overview & quickstart
├── SECURITY.md                                   # Security policy & cryptographic threat model
│
├── sih26149/                                     # Forensic Assurance & Sanitization Platform
│   ├── app/
│   │   ├── api/
│   │   │   ├── audit_chain.py                    # Append-only SHA-256 hash chain & live tamper demo API
│   │   │   ├── auth.py                           # API key middleware (exact canonical public showcase routes)
│   │   │   ├── carving.py                        # Raw file carving API endpoint
│   │   │   ├── cases.py                          # Case management & chain-of-custody tracking
│   │   │   ├── certificates.py                   # Court evidence certificate (HTML + QR & PDF) API
│   │   │   ├── deps.py                           # Dependency injection & keystore providers
│   │   │   ├── eraser.py                         # Selective file/folder eraser & NIST detector API
│   │   │   ├── evidence.py                       # Signed evidence envelope retrieval & independent verification
│   │   │   ├── forensics.py                      # Filesystem acquisition & artifact recovery
│   │   │   ├── health.py                         # Subsystem liveness & tool status
│   │   │   ├── rate_limit.py                     # Sliding-window IP rate limiter
│   │   │   ├── sanitization.py                   # Whole-drive / virtual image zero-fill overwrite & decision profiler
│   │   │   └── validation.py                     # Input sanitization & path traversal barriers
│   │   ├── cases/
│   │   │   └── audit.py                          # Cryptographically hash-chained append-only audit logger
│   │   ├── core/
│   │   │   ├── certificate.py                    # Printable HTML certificate & ReportLab PDF generator with QR
│   │   │   ├── evidence_envelope.py              # Ed25519 canonical envelope signing & stateless verification
│   │   │   ├── hashing.py                        # SHA-256 streaming file hasher & canonical JSON serialization
│   │   │   └── persistence.py                    # Atomic write-replace with retry backoff for Windows NTFS
│   │   ├── forensics/
│   │   │   ├── proof_loop.py                     # 5-Stage Closed-Loop Forensic Proof Loop Engine
│   │   │   ├── benchmark.py                      # Live Dynamic Synthetic Benchmark Suite
│   │   │   ├── carving.py                        # Pure-Python raw stream carving (JPEG, PNG, PDF, ZIP, MP4)
│   │   │   ├── discovery.py                      # Unallocated inode & metadata scanner
│   │   │   ├── filesystem.py                     # Ext4, FAT32, NTFS detection
│   │   │   ├── recovery.py                       # Block-level artifact extraction
│   │   │   └── verification.py                   # Readback hash verification against reference
│   │   ├── sanitization/
│   │   │   ├── device_detector.py                # Storage media classifier informed by NIST SP 800-88 Rev. 2
│   │   │   ├── file_eraser.py                    # Selective file/folder eraser (zero-fill, metadata scrub, name scramble)
│   │   │   └── methods.py                        # Cross-platform chunked zero-fill overwrite
│   │   ├── static/
│   │   │   ├── app.js                            # Modular UI controller with dual-mount API routing
│   │   │   ├── app.css                           # Professional dark-mode design system
│   │   │   └── index.html                        # 3-Layer Experience: Cinematic Showcase, Cases, Workstation
│   │   └── main.py                               # FastAPI application entrypoint (dual-mounts / and /api)
│   ├── tests/
│   │   └── unit/
│   │       ├── test_proof_loop_benchmark.py      # Unit tests for Proof Loop, benchmark & decision profiler
│   │       └── test_v2_features.py               # Unit tests for carving, eraser, audit chain, certificates
│   ├── Dockerfile, docker-compose.yml, requirements.txt
│   └── README.md
│
└── sih26013/                                     # Geospatial Harmonization Platform
    ├── app/
    │   ├── api/
    │   │   ├── auth.py                           # API key middleware (exact canonical public showcase routes)
    │   │   └── server.py                         # Core FastAPI server with Tri-Reality, Entity matching, topology, drone
    │   ├── core/
    │   │   ├── reconciliation.py                 # Tri-Reality Reconciliation & Counterfactual Simulation Engine
    │   │   ├── benchmark.py                      # Live Dynamic Geospatial Benchmark Evaluator
    │   │   ├── ai_matcher.py                     # Hybrid Geospatial Entity Matcher (IoU, centroid, token similarity)
    │   │   ├── attribute_harmonizer.py           # Cross-agency schema mapper, unit normalizer (acres/gunthas), discrepancy grader
    │   │   ├── canonical_model.py                # Unified CanonicalParcel model across Revenue, Municipal, Cadastral, Drone
    │   │   ├── classification.py                 # Multi-axis classification taxonomy
    │   │   ├── crs_check.py                      # CRS plausibility, axis-inversion & bounding-box validator
    │   │   ├── evidence_envelope.py              # Canonical JSON evidence envelopes & verification
    │   │   ├── geometry.py                       # Shapely polygon validation, IoU & Hausdorff distance (meters)
    │   │   ├── hashing.py                        # Cryptographic canonical hash utilities
    │   │   ├── imagery_features.py               # Photogrammetric building footprint encroachment CV
    │   │   ├── persistence.py                    # Atomic JSON persistence & append-only audit logger
    │   │   ├── pipeline.py                       # 4-axis comparison engine (Geometry, Temporal, CRS, Provenance)
    │   │   ├── provenance.py                     # Directed Acyclic Graph (DAG) lineage & shared-origin collapse
    │   │   ├── rate_limit.py                     # Sliding-window rate limiter
    │   │   ├── signing.py                        # Ed25519 private key management & TrustRegistry
    │   │   ├── spatial_index.py                  # Shapely STRtree spatial indexing for candidate windowing
    │   │   ├── temporal.py                       # Temporal gap analysis & era-qualification
    │   │   └── topology_repair.py                # Cadastral boundary overlap elimination & shared-edge snapping
    │   ├── static/
    │   │   ├── app.js                            # Modular UI controller with dual-mount API routing
    │   │   ├── style.css                         # Dark-mode styling for geospatial workstation
    │   │   └── index.html                        # 3-Layer Experience: Tri-Reality Showcase, Cases, Workstation
    │   └── main.py
    ├── tests/
    │   ├── unit/
    │   │   ├── test_tri_reality_benchmark.py     # Unit tests for Tri-Reality, uncertainty models & benchmark
    │   │   └── test_v0_geometry.py, ...          # Unit tests for geometry, CRS, provenance, temporal, pipelines
    │   └── test_v2_features.py                   # Integration tests for entity matcher, topology, drone, proposals
    ├── Dockerfile, docker-compose.yml, requirements.txt
    └── README.md
```

---

## Automated Verification & Test Results

### 148 Automated Tests · 0 Failures

### SIH26149 (Forensic Assurance Platform)
- **89 passed, 7 skipped, 0 failures** in `pytest tests/`
- Command to run:
  ```powershell
  cd sih26149
  py -m pytest tests/ -v
  ```
- Key Test Highlights:
  - `test_proof_loop_flow`: Verifies full 5-stage sequential proof loop execution.
  - `test_proof_loop_tamper_detection`: Verifies tamper barrier and post-probe validation.
  - `test_live_benchmark_metrics`: Verifies dynamic precision, recall, and erasure calculations.
  - `test_decision_engine_mappings`: Verifies NIST SP 800-88 & IEEE 2883 guidance rules.
  - `test_carving_jpeg_and_png`: Verifies structural integrity of carved JPEG/PNG files from raw byte streams.
  - `test_audit_chain_and_tamper`: Validates SHA-256 hash chaining and proves tamper detection triggers immediately.

### SIH26013 (Geospatial Harmonization Platform)
- **59 passed, 1 skipped, 0 failures on Windows (60 passed on Linux)** in `pytest tests/`
- Command to run:
  ```powershell
  cd sih26013
  py -m pytest tests/ -v
  ```
- Key Test Highlights:
  - `test_tri_reality_reconciliation_bangalore_demo`: Validates RSS uncertainty propagation ($\sqrt{\sigma_1^2 + \sigma_2^2}$) and 4 Evidence-Weighted Hypotheses generation.
  - `test_counterfactual_simulation`: Validates downstream topology and area impact analysis across hypotheses.
  - `test_live_geospatial_benchmark`: Validates live synthetic benchmark metrics evaluation with ground-truth TP/FP/TN/FN.
  - `test_provenance_independence`: Validates shared upstream ancestry detection in DAG lineage graphs.
  - `test_topology_repair`: Validates automated cadastral overlap elimination and edge snapping.

---

## Canonical Showcase API Endpoints

### SIH26149
- `POST /api/cases/CASE-DEMO-2026/proof-loop` — Executes 5-stage sequential Forensic Proof Loop.
- `GET  /api/cases/CASE-DEMO-2026/benchmark?runs=3` — Executes live synthetic carving & sanitization benchmark.
- `POST /api/cases/CASE-DEMO-2026/decision-profile` — Evaluates media parameters against NIST SP 800-88 / IEEE 2883.

### SIH26013
- `POST /api/cases/DEMO-ALIGN/reconcile/tri-reality` — Reconciles Legal, Surveyed, and Observed realities with error envelopes.
- `GET  /api/cases/DEMO-ALIGN/benchmark?runs=3` — Executes live multi-source geospatial matching benchmark.

---

## Local Launch Instructions

### 1. Launch SIH26149 (Forensic Assurance Platform)
```powershell
cd sih26149
py -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
- Open in browser: `http://127.0.0.1:8000`

### 2. Launch SIH26013 (Geospatial Harmonization Platform)
```powershell
cd sih26013
py -m uvicorn app.api.server:app --host 127.0.0.1 --port 8001
```
- Open in browser: `http://127.0.0.1:8001`
