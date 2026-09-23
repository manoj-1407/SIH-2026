# SIH 2026 — Problem 149 Audit Review Guide

This guide is for the NTRO forensic assurance implementation behind Smart India Hackathon 2026, problem statement 149.

## 1. Objective

The platform must demonstrate that it can:

- preserve and analyze the integrity of digital evidence
- identify recoverable artifacts and their reliability
- validate sanitization outcomes with clear and honest scope boundaries
- produce a trustworthy trail for investigators, judges, and reviewers

## 2. Product scope

This repository focuses on the 149 implementation only. The system is centered on:

- case intake and evidence handling
- forensic recovery and file carving
- audit-trail integrity
- sanitization verification
- signed evidence and review workflows
- secure API access and operational guardrails

## 3. Local validation steps

```bash
cd sih26149
python -m pytest -q
```

Optional manual startup:

```bash
cd sih26149
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Then open http://localhost:8000

## 4. Evaluation checklist

- UI loads with the forensic workflow and security narrative
- Cases can be created and inspected
- Forensic endpoints respond with structured payloads
- Sanitization and evidence outcomes are clearly classified
- API protection is active via rate limiting and auth settings
- Audit and verification flows remain transparent and reproducible

## 5. Quality expectations

The project should impress both technical evaluators and non-technical stakeholders by showing:

- professionalism in the UI and message framing
- evidence-first decision-making
- clear operational honesty about what was and was not proven
- secure-by-default API design
- a strong demonstration of realistic forensic investigation workflows

This is the correct center of gravity for the 149 prototype and its evaluation narrative.

