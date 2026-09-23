# SIH 2026 Problem 149 — NTRO Forensic Assurance Workstation

This project implements the NTRO problem statement for Smart India Hackathon 2026: secure evidence recovery and verifiable sanitization.

## Purpose

The goal is to provide a forensic workstation that can:

- recover relevant digital evidence from imaging sources
- classify outcomes with clear, explicit evidence semantics
- preserve a chain-of-custody trail with cryptographic integrity
- validate sanitization actions with a bounded and honest claim model
- provide a judge-friendly interface and a verifiable API workflow

## Core capabilities

- Forensic case and evidence management
- Recovery and triage workflows for digital artefacts
- Raw-byte carving and integrity checking
- Signed evidence packages using cryptographic validation
- Sanitization enforcement with scope-aware audit comments
- Rate limiting and API protection for production-like operation
- Live web UI for investigators, administrators, and judges

## Quick start

### Linux / WSL2
```bash
cd sih26149
./setup.sh
./run.sh
```

### Windows
```bat
cd sih26149
run_windows.bat
```

### Docker
```bash
cd sih26149
docker-compose up --build -d
```

Open the UI at http://localhost:8000

## Environment notes

- `DEMO_MODE=1` enables local demo behavior without a hard API key.
- `SIH26149_API_KEY` enforces authenticated access in production mode.
- `SIH26149_RATE_LIMIT_GENERAL` and `SIH26149_RATE_LIMIT_UPLOAD` tune API protection.

## Verification

```bash
cd sih26149
python -m pytest -q
```

This project includes automated checks for core workflows, security assumptions, API behavior, and evidence verification.

## Security posture

The system keeps its claims within a verifiable scope, avoids false universal assertions, and records outcomes in a signed, restart-safe way. The implementation emphasizes transparent evidence handling and operational honesty over overstated claims.
