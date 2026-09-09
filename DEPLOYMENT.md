# SIH 2026 — Production & Render Deployment Guide

This guide details deploying both **SIH26013** and **SIH26149** on **Render** (or any Docker-compliant host) using containerized FastAPI services with optional persistent disks.

---

## 1. Architecture Overview

Both applications are self-contained Dockerized workstations:
- **SIH26013**: Cadastral Boundary AI Harmonization & Multi-Source Geospatial Conflict Detection (Ministry of Rural Development).
- **SIH26149**: Integrated Forensic File Recovery & NIST SP 800-88 Rev. 2 Data Sanitization Workstation (National Technical Research Organisation).

```
                      GitHub Private Repo (main branch)
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
                    ▼                                 ▼
         Render Web Service 1              Render Web Service 2
             (SIH26013)                         (SIH26149)
        Dockerfile: sih26013/Dockerfile    Dockerfile: sih26149/Dockerfile
                    │                                 │
                    ▼                                 ▼
             Persistent Disk                   Persistent Disk
             Mount: /app/data                  Mount: /app/data
```

---

## 2. Deploying on Render (Step-by-Step)

### Step 1: Connect Repository
1. Log into your [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** → **Web Service**.
3. Select **Build and deploy from a Git repository** and connect `manoj-1407/SIH-2026`.

---

### Step 2: Configure Service 1 — SIH26013 (Geospatial Harmonization)

| Setting | Value |
|---|---|
| **Name** | `sih26013-cadastral` |
| **Region** | Singapore / Frankfurt / Oregon |
| **Branch** | `main` |
| **Root Directory** | `sih26013` |
| **Runtime** | `Docker` |
| **Dockerfile Path** | `Dockerfile` (relative to `sih26013`) |
| **Plan** | Free (for live demo) or Starter (for persistent disk) |

#### Environment Variables (SIH26013):
```env
SIH26013_DATA_DIR=/app/data
SIH26013_API_KEY=your_secure_api_key_here
DEMO_MODE=0
PORT=8000
```
*(Note: In demo/judging evaluation sessions, set `DEMO_MODE=1` to allow interactive tamper tests from the UI).*

#### Persistent Disk (Recommended for Production / Starter plan):
- **Mount Path**: `/app/data`
- **Size**: 1 GB

---

### Step 3: Configure Service 2 — SIH26149 (Digital Forensics & Sanitization)

| Setting | Value |
|---|---|
| **Name** | `sih26149-forensics` |
| **Region** | Same region as Service 1 |
| **Branch** | `main` |
| **Root Directory** | `sih26149` |
| **Runtime** | `Docker` |
| **Dockerfile Path** | `Dockerfile` (relative to `sih26149`) |
| **Plan** | Free (for live demo) or Starter (for persistent disk) |

#### Environment Variables (SIH26149):
```env
SIH26149_DATA_DIR=/app/data
SIH26149_API_KEY=your_secure_api_key_here
SIH26149_CORS_ORIGINS=https://your-frontend-domain.onrender.com
DEMO_MODE=0
PORT=8000
```

#### Persistent Disk (Recommended for Production / Starter plan):
- **Mount Path**: `/app/data`
- **Size**: 2 GB (holds uploaded test images, audit logs, signed envelopes, and cryptographic certificates)

---

## 3. Persistent Storage vs. Free Tier Behavior

- **Render Free Tier**:
  - Ephemeral disk: `/app/data` resets on container restart/spindown.
  - Signing keys and evidence generated during a single session remain fully valid during that session.
  - Best for: Interactive live hackathon demonstration presentations.
- **Render Starter (Paid) with Persistent Disk**:
  - Durably retains Ed25519 signing identity (`primary_examiner.priv` / `geo_examiner.priv`), trust registries, case histories, and audit timelines across all redeployments.

---

## 4. Health & Verification Endpoints

Once deployed, verify your instances:

- **SIH26013**:
  - Health check: `GET https://<your-sih26013-app>.onrender.com/health`
  - Interactive UI: `GET https://<your-sih26013-app>.onrender.com/`
  - OpenAPI Docs: `GET https://<your-sih26013-app>.onrender.com/docs`
- **SIH26149**:
  - Health check: `GET https://<your-sih26149-app>.onrender.com/health`
  - Interactive UI: `GET https://<your-sih26149-app>.onrender.com/`
  - OpenAPI Docs: `GET https://<your-sih26149-app>.onrender.com/docs`
