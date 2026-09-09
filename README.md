# Smart India Hackathon (SIH) 2026 — Unified Repository

This repository contains two production-grade, containerized digital forensic and geospatial workstations developed for Smart India Hackathon 2026:

```
SIH_FINAL_v5/
├── sih26013/       # Cadastral Boundary AI Harmonization & Multi-Source Geospatial Conflict Detection
├── sih26149/       # Integrated Forensic File Recovery & NIST SP 800-88 Rev.2 Data Sanitization Workstation
├── DEPLOYMENT.md   # Complete Docker & Render Deployment Guide
├── SECURITY.md     # Cryptographic Security Architecture & Threat Model
└── .gitignore      # Comprehensive exclusion rules (0 keys, 0 payloads, 0 caches)
```

---

## Solutions Overview

### 1. SIH26013 — Multi-Source Geospatial Data Harmonization
- **Organization**: Ministry of Rural Development
- **Problem Statement**: SIH26013
- **Features**:
  - IoU and Hausdorff geometric conflict detection.
  - DAG-based provenance lineage collapse (identifies whether 3 datasets are independent confirmations or 1 observation in 3 containers).
  - India CRS coordinate heuristic validation (guards against axis swaps and degrees/meters confusion).
  - Pure Shapely `STRtree` spatial indexing engine (zero external C library dependencies).
  - Ed25519 cryptographic evidence generation with honest `UNKNOWN` handling.

### 2. SIH26149 — Forensic Recovery & Secure Data Sanitization
- **Organization**: National Technical Research Organisation (NTRO)
- **Problem Statement**: SIH26149
- **Features**:
  - Raw byte file carving for JPEG, PNG, PDF, ZIP, and MP4 structures with confidence scoring.
  - NIST SP 800-88 Rev. 2 compliant storage device capability classification (USB flash, SD card, virtual disk images).
  - Scope-confined selective file eraser with metadata scrubbing and pseudorandom directory renaming.
  - Tamper-evident SHA-256 hash-chained audit trails.
  - Cryptographic HTML/PDF evidence certificates with QR verification.

---

## Quick Start (Docker)

### Run SIH26013:
```bash
cd sih26013
docker-compose up --build -d
# UI accessible at http://localhost:8001
```

### Run SIH26149:
```bash
cd sih26149
docker-compose up --build -d
# UI accessible at http://localhost:8000
```

---

## Test Suites & Validation

Both applications contain automated test suites:

```bash
# Test SIH26013 (57 tests)
cd sih26013 && python -m pytest tests/ -v

# Test SIH26149 (87 tests)
cd sih26149 && python -m pytest tests/ -v
```

See [DEPLOYMENT.md](file:///d:/SIH_FINAL_v5/DEPLOYMENT.md) for full cloud and Render deployment steps.
See [SECURITY.md](file:///d:/SIH_FINAL_v5/SECURITY.md) for cryptographic signing and defense details.
