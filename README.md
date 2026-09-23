# SIH 2026 — Problem Statement 149

This repository is the NTRO-focused forensic workstation for Smart India Hackathon 2026, problem statement 149.

The implementation is centered on one mission: proving what happened to digital evidence and what was actually removed during secure sanitization.

## What is included

- Forensic intake, case management, and evidence capture
- Recovery workflows for deleted and hidden data
- Raw-byte carving for common file types and media patterns
- Secure sanitization validation with explicit scope limits
- Hash-chain audit trail and signed evidence packages
- Independent verification workflow for judges, investigators, and reviewers
- Production-ready Python FastAPI backend with an interactive web UI

## Repository layout

```
.
├── README.md                 # Project overview and quick start
├── DEPLOYMENT.md             # Deployment and runtime guidance
├── SECURITY.md               # Security controls and threat model
├── AUDIT_REVIEW_GUIDE.md     # Demo and evaluation checklist
├── sih26149/                 # Main NTRO forensic workstation
├── make_zip.py               # Packaging helper for final submission
├── make_zip.ps1              # Windows packaging helper
└── .gitignore                # Repository hygiene rules
```

## Why this project matters

Problem statement 149 requires a trustworthy forensic system that can both recover useful evidence and prove the sanitization outcome without overstating claims. The platform therefore combines:

- evidence-preserving acquisition
- explicit classification of outcomes
- cryptographic signing and audit-chain integrity
- bounded claims for sanitization and recovery
- secure, rate-limited API access and local-first operation

## Fast start

### Windows
```bat
cd sih26149
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://localhost:8000

### Linux / WSL2
```bash
cd sih26149
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Verification

```bash
cd sih26149
python -m pytest -q
```

The project includes automated tests for validation, forensics, sanitization, and security flows.

See [DEPLOYMENT.md](DEPLOYMENT.md), [SECURITY.md](SECURITY.md), and [AUDIT_REVIEW_GUIDE.md](AUDIT_REVIEW_GUIDE.md) for production and evaluation guidance.

