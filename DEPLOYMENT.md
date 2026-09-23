# SIH 2026 — Problem 149 Deployment Guide

This deployment guide covers the NTRO forensic workstation for Smart India Hackathon 2026, problem statement 149.

## 1. Deployment model

The solution is designed as a single self-contained FastAPI application with:

- a secure web-based operator interface
- forensic case and evidence workflows
- signed evidence packages and audit trails
- optional API-key enforcement and request throttling
- support for local, Docker, and cloud-style deployment

## 2. Recommended runtime

### Local run
```bash
cd sih26149
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Docker run
```bash
cd sih26149
docker-compose up --build -d
```

Open the application at http://localhost:8000

## 3. Environment variables

```env
DEMO_MODE=1
SIH26149_DATA_DIR=/app/data
SIH26149_API_KEY=your_secure_key_here
SIH26149_CORS_ORIGINS=http://localhost:8000
SIH26149_RATE_LIMIT_GENERAL=120
SIH26149_RATE_LIMIT_UPLOAD=10
```

## 4. Production notes

- Store evidence and signed material under a persistent volume.
- Keep the API key in the deployment environment, not in source control.
- Use `DEMO_MODE=0` in production-style deployments where authenticated access is required.
- Use rate limits and request validation to protect upload and forensic endpoints.

## 5. Health and verification checks

After deployment, validate:

- `GET /health`
- `GET /docs`
- `GET /api/health`
- `GET /cases/CASE-DEMO-2026` or relevant seeded demo case

## 6. Security checklist

- no secrets committed to git
- all evidence writes use safe persistence patterns
- key material kept outside the repo
- API requests protected with header validation
- rate limiting enabled for general and upload traffic
- clear scope statements attached to sanitization outcomes

This keeps the system audit-friendly and suitable for judges, reviewers, and operational teams.
