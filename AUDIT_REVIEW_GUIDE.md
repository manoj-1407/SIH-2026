# SIH Final v5 — Comprehensive Audit & Review Guide
**Problem Statements**:
1. **SIH26149** (NTRO): Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization
2. **SIH26013** (MoRD): Automated Integration and Intelligent Harmonization of Multi-source Geospatial Data for Urban Land Record Management

---

## Package Structure

```
d:/SIH_FINAL_v5/
│
├── AUDIT_REVIEW_GUIDE.md                         # This comprehensive audit manual
│
├── sih26149/                                     # Track B: Forensic & Sanitization Workstation v2
│   ├── app/
│   │   ├── api/
│   │   │   ├── audit_chain.py                    # Append-only SHA-256 hash chain & live tamper demo API
│   │   │   ├── auth.py                           # API key middleware & security headers
│   │   │   ├── carving.py                        # Raw file carving API endpoint
│   │   │   ├── cases.py                          # Case management & chain-of-custody tracking
│   │   │   ├── certificates.py                   # Court evidence certificate (HTML + QR & PDF) API
│   │   │   ├── deps.py                           # Dependency injection & keystore providers
│   │   │   ├── eraser.py                         # Selective file/folder eraser & NIST detector API
│   │   │   ├── evidence.py                       # Signed evidence envelope retrieval & independent verification
│   │   │   ├── forensics.py                      # Filesystem acquisition & artifact recovery
│   │   │   ├── health.py                         # Subsystem liveness & tool status
│   │   │   ├── rate_limit.py                     # Sliding-window IP rate limiter
│   │   │   ├── sanitization.py                   # Whole-drive / virtual image zero-fill overwrite
│   │   │   └── validation.py                     # Input sanitization & path traversal barriers
│   │   ├── cases/
│   │   │   └── audit.py                          # Cryptographically hash-chained append-only audit logger
│   │   ├── core/
│   │   │   ├── certificate.py                    # Printable HTML certificate & ReportLab PDF generator with QR
│   │   │   ├── evidence_envelope.py              # Ed25519 canonical envelope signing & stateless verification
│   │   │   ├── hashing.py                        # SHA-256 streaming file hasher & canonical JSON serialization
│   │   │   └── persistence.py                    # Atomic write-replace with retry backoff for Windows NTFS
│   │   ├── forensics/
│   │   │   ├── carving.py                        # Pure-Python raw stream carving (JPEG, PNG, PDF, ZIP, MP4)
│   │   │   ├── discovery.py                      # Unallocated inode & metadata scanner
│   │   │   ├── filesystem.py                     # Ext4, FAT32, NTFS detection
│   │   │   ├── recovery.py                       # Block-level artifact extraction
│   │   │   └── verification.py                   # Readback hash verification against reference
│   │   ├── sanitization/
│   │   │   ├── device_detector.py                # NIST SP 800-88 Rev. 2 media classifier (HDD, SSD, USB, SD)
│   │   │   ├── file_eraser.py                    # Selective file/folder eraser (zero-fill, metadata scrub, name scramble)
│   │   │   └── methods.py                        # Cross-platform chunked zero-fill overwrite
│   │   ├── static/
│   │   │   ├── app.js                            # Modular UI controller with dual-mount API routing
│   │   │   ├── app.css                           # Professional dark-mode design system
│   │   │   └── index.html                        # Workstation UI with Carving, Eraser, and Audit Chain tabs
│   │   └── main.py                               # FastAPI application entrypoint (dual-mounts / and /api)
│   ├── tests/
│   │   └── unit/
│   │       └── test_v2_features.py               # Unit tests for carving, eraser, audit chain, certificates
│   ├── Dockerfile, docker-compose.yml, requirements.txt
│   └── README.md
│
└── sih26013/                                     # Track A: Geospatial Harmonization Platform v2
    ├── app/
    │   ├── api/
    │   │   ├── auth.py                           # API key check middleware
    │   │   └── server.py                         # Core FastAPI server with AI matching, topology, drone analysis
    │   ├── core/
    │   │   ├── ai_matcher.py                     # Hybrid AI+GIS matching engine (IoU, centroid, Levenshtein tokens)
    │   │   ├── attribute_harmonizer.py           # Cross-agency schema mapper, unit normalizer (acres/gunthas), discrepancy grader
    │   │   ├── canonical_model.py                # Unified CanonicalParcel model across Revenue, Municipal, Cadastral, Drone
    │   │   ├── classification.py                 # Multi-axis classification taxonomy
    │   │   ├── crs_check.py                      # CRS plausibility, axis-inversion & bounding-box validator
    │   │   ├── evidence_envelope.py              # Canonical JSON evidence envelopes & verification
    │   │   ├── geometry.py                       # Shapely polygon validation, IoU & Hausdorff distance (meters)
    │   │   ├── hashing.py                        # Cryptographic canonical hash utilities
    │   │   ├── imagery_features.py               # Photogrammetric building footprint encroachment & unrecorded construction CV
    │   │   ├── persistence.py                    # Atomic JSON persistence & append-only audit logger
    │   │   ├── pipeline.py                       # 4-axis comparison engine (Geometry, Temporal, CRS, Provenance)
    │   │   ├── provenance.py                     # Directed Acyclic Graph (DAG) lineage & shared-origin collapse
    │   │   ├── rate_limit.py                     # Sliding-window rate limiter
    │   │   ├── signing.py                        # Ed25519 private key management & TrustRegistry
    │   │   ├── spatial_index.py                  # Shapely STRtree spatial indexing for candidate windowing
    │   │   ├── temporal.py                       # Temporal gap analysis & era-qualification
    │   │   └── topology_repair.py                # Cadastral boundary overlap elimination & shared-edge snapping
    │   ├── static/
    │   │   ├── app.js                            # UI controller with map integration and 4 demo presets
    │   │   ├── style.css                         # Dark-mode styling for geospatial workstation
    │   │   └── index.html                        # Workstation UI with AI Match, Topology, Drone, Proposal tabs
    │   └── main.py
    ├── tests/
    │   └── test_v2_features.py                   # Unit tests for canonical model, AI matcher, topology, drone, proposals
    ├── Dockerfile, docker-compose.yml, requirements.txt
    └── README.md
```

---

## Automated Verification & Test Results

### SIH26149 (Forensics & Sanitization Workstation)
- **70 passed, 0 failed** in `pytest tests/unit/`
- Command to run:
  ```powershell
  cd sih26149
  python -m pytest tests/unit/ -v
  ```
- Highlights:
  - `test_carving_jpeg_and_png`: Verifies structural integrity of carved JPEG/PNG files from raw byte streams.
  - `test_carving_pdf`: Verifies xref and trailer parsing on raw unallocated streams.
  - `test_device_detector`: Validates NIST SP 800-88 Rev. 2 media classification.
  - `test_file_eraser`: Validates atomic multi-pass zero-fill overwrite and metadata scrubbing.
  - `test_audit_chain_and_tamper`: Validates SHA-256 hash chaining and proves tamper detection triggers immediately when an entry is modified.
  - `test_html_certificate`: Validates interactive HTML court certificate generation with verification QR code.

### SIH26013 (Geospatial Harmonization Platform)
- **56 passed, 0 failed, 1 skipped (Windows NTFS permission bits)** in `pytest tests/`
- Command to run:
  ```powershell
  cd sih26013
  python -m pytest tests/ -v
  ```
- Highlights:
  - `test_canonical_parcel`: Verifies multi-source cross-agency parcel model serialization.
  - `test_ai_matcher`: Validates hybrid AI matching, centroid distance decay, and Levenshtein token similarity.
  - `test_attribute_harmonizer`: Validates Indian regional unit conversions (Acres, Gunthas, Bighas to m²) and statutory conflict grading.
  - `test_imagery_encroachment`: Validates photogrammetric rooftop footprint encroachment detection outside legal boundaries.
  - `test_topology_repair`: Validates automated cadastral overlap elimination and edge snapping.
  - `test_harmonization_proposals`: Validates official proposal synthesis, review decision workflow, and Ed25519 cryptographic signing.

---

## Live Running Instructions

### 1. Launch SIH26149 (Forensics & Sanitization Workstation)
```powershell
cd sih26149
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
- Open in browser: `http://127.0.0.1:8000`
- Live interactive features:
  1. **Raw Carving Tab**: Click "Run Deep Stream Carving" to carve files from unallocated clusters.
  2. **Sanitization Tab**: Click "Detect Capability" on any target file/drive to see NIST SP 800-88 Rev. 2 Clear/Purge/Destroy mapping; preview file scope and authorize selective erasure.
  3. **Audit Chain Tab**: Click "Verify Cryptographic Chain" (100% intact); click "Simulate Unauthorized Modification & Detect" to test live tamper detection.
  4. **Evidence Vault Tab**: Click "📜 Court Certificate (HTML + QR)" to view printable certificate with offline verification QR code.

### 2. Launch SIH26013 (Geospatial Harmonization Platform)
```powershell
cd sih26013
python -m uvicorn app.api.server:app --host 127.0.0.1 --port 8001
```
- Open in browser: `http://127.0.0.1:8001`
- Live interactive features:
  1. Click **"⚡ Seed 4 Official Cases"** in the sidebar to populate the 4 official problem statement test scenarios.
  2. Switch to **"1. Alignment (Urban)"** -> **AI Parcel Match** tab -> click "Run AI Matching" to view IoU, Centroid distance, and Levenshtein score.
  3. Switch to **"2. Drone Encroachment"** -> **Drone Footprints** tab -> click "Run Encroachment CV Engine" to view building footprints crossing legal boundaries.
  4. Switch to **"3. Topology Overlap"** -> **Topology Repair** tab -> click "Snap & Repair Topology" to see boundary overlaps eliminated to 0.0 m².
  5. Switch to **"4. Land-Use Conflict"** -> **Harmonization** tab -> click "✓ Approve & Cryptographically Sign" to issue an Ed25519 sealed record.

---

## Cryptographic Security & Defensibility

1. **Independent Verification**:
   - Every forensic recovery, sanitization, and geospatial harmonization output is wrapped in a deterministic canonical JSON envelope and signed with an Ed25519 keypair.
   - Verification is stateless: `verify_envelope(envelope, registry)` verifies the SHA-256 hash and Ed25519 signature without write access to any database.
2. **Audit Trail Integrity**:
   - Audit entries are linked in an append-only hash chain where `current_hash = SHA-256(prev_hash + entry_bytes)`.
   - Any retrospective alteration breaks subsequent hashes, making unauthorized tampering immediately detectable.
3. **Standards Compliance**:
   - Media sanitization aligns strictly with **NIST SP 800-88 Rev. 2** (§2.3 Clear, §2.4 Purge, §2.5 Destroy).
   - Geospatial boundaries conform to **WGS84 (EPSG:4326)** with metric re-projection checks and topological invariants enforced via Shapely/GEOS.
