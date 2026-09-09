# Smart India Hackathon (SIH) 2026 — Unified Repository

This repository contains two production-grade, containerized digital forensic and geospatial workstations developed for Smart India Hackathon 2026:

```
SIH_FINAL_v5/
├── sih26013/             # Geospatial Harmonization Platform (Tri-Reality & Provenance DAG)
├── sih26149/             # Integrated Forensic File Recovery & NIST/IEEE Sanitization Workstation
├── AUDIT_REVIEW_GUIDE.md # Complete Evaluation & Audit Verification Manual
├── DEPLOYMENT.md         # Complete Docker & Render Deployment Guide
├── SECURITY.md           # Cryptographic Security Architecture & Threat Model
└── .gitignore            # Clean repository rules (0 keys, 0 payloads, 0 runtime caches)
```

---

## Solutions Overview

### 1. SIH26013 — Multi-Source Geospatial Data Harmonization
- **Organization**: Ministry of Rural Development / Department of Land Resources (DoLR)
- **Problem Statement**: SIH26013
- **Core Innovations**:
  - **Tri-Reality Boundary Reconciliation**: Reconciles Legal (Cadastral), Surveyed (GNSS), and Observed (Drone ORI) boundaries with dynamic RSS error-propagation envelopes.
  - **Explainable Conflict Hypotheses**: Evaluates centroid displacements and generates Evidence-Weighted Hypotheses for official field-verification.
  - **DAG Lineage Provenance**: Traverses cross-departmental ancestry graphs to identify shared-origin dependencies ("3 records from 1 source = 1 independent origin").
  - **Deterministic Hybrid Entity Matcher**: IoU geometric overlap, Hausdorff metric distance, and token similarity.
  - **Automated Topology Repair**: Resolves cadastral overlaps and micro-slivers while preserving spatial invariants.
  - **Ed25519 Cryptographic Assurance**: Generates tamper-evident signed proposal envelopes (*The system recommends · The authority decides*).

### 2. SIH26149 — Forensic Recovery & Secure Data Sanitization
- **Organization**: National Technical Research Organisation (NTRO)
- **Problem Statement**: SIH26149
- **Core Innovations**:
  - **Sequential Forensic Proof Loop**: Closed-loop assurance (Known Evidence → Pre-Sanitization Recovery Scan → Sanitization Execution → Post-Sanitization Recovery Probe → Signed Assurance Package).
  - **Raw Byte Stream Carving**: Pure-Python reconstruction of JPEG, PNG, PDF, ZIP, and MP4 structures with bounded gap-scan fragment assembly.
  - **Standards-Informed Sanitization**: Storage-device capability classification informed by NIST SP 800-88 Rev. 2 and IEEE 2883-2022.
  - **Scope-Confined Selective Eraser**: Multi-pass zero-fill with filesystem metadata scrubbing and directory name scrambling.
  - **Tamper-Evident SHA-256 Audit Trail**: Cryptographic append-only hash chain with real-time mutation detection.
  - **Independent Verification**: Ed25519 digital signature verification without database dependencies.

---

## Quick Start — Windows (No Docker Required)

The fastest way to run on any Windows machine:

### SIH26149 — Forensic Workstation (Port 8000)
```bat
cd sih26149
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
→ Open **http://localhost:8000** in your browser

Or just double-click **`sih26149\run_windows.bat`** — it installs dependencies and starts the server automatically.

### SIH26013 — Geospatial Workstation (Port 8001)
```bat
cd sih26013
pip install -r requirements.txt
python -m uvicorn app.api.server:app --host 127.0.0.1 --port 8001
```
→ Open **http://localhost:8001** in your browser

Or just double-click **`sih26013\run_windows.bat`**.

> **No API key needed on localhost:** Both systems run in `DEMO_MODE=1` by default locally — the connection indicator will show 🟢 **API Online** immediately. If you see **Auth Required** (amber), click the connection pill (top-right) → enter your API key in the modal → **Save Key**.

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

Both applications contain automated unit, integration, and security test suites:

```bash
# Test SIH26013 (59 passed / 1 skipped on Windows, 60 passed on Linux)
cd sih26013 && python -m pytest tests/ -v

# Test SIH26149 (89 passed, 7 skipped)
cd sih26149 && python -m pytest tests/ -v
```

Total verification: **148 automated tests passed** (0 failures).

Cross-system integration test (21 audit criteria):
```bash
python scratch_test_everything.py
```

See [AUDIT_REVIEW_GUIDE.md](AUDIT_REVIEW_GUIDE.md) for full step-by-step evaluator instructions.  
See [DEPLOYMENT.md](DEPLOYMENT.md) for cloud and Render deployment steps.  
See [SECURITY.md](SECURITY.md) for cryptographic signing and defense details.
