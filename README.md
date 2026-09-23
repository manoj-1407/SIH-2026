# SIH 2026 Repository Overview

This repository is the workspace for Smart India Hackathon 2026. It contains multiple problem-set explorations and the active implementation for Problem Statement 149, which is the project being developed and refined under the `sih26149/` directory.

The root repository is intentionally a portfolio-style workspace. It bundles project assets, packaging helpers, and the current flagship implementation together so the team can manage evaluation, documentation, and deployment from one place without losing the actual product context.

## Why there are two README files

There are two main documentation entry points because this repo is structured as a multi-project workspace, but the live product is a single active subproject.

- The root `README.md` explains the repository-level organization, the role of the active project folder, and the project context for the hackathon.
- The project README in `sih26149/README.md` is the product-level technical document for the actual solution being shipped.

This separation helps in three ways:

1. Repository-level readability: the root README explains why the repo name is `SIH 2026` while the work is under `sih26149`.
2. Product clarity: the project README documents architecture, workflows, setup, benchmarking, and demo steps for the actual solution.
3. Safe portfolio management: the workspace can include historical or unrelated explorations without cluttering the main product narrative.

## Active project

The current focus of this repository is:

- `sih26149/` — NTRO forensic assurance workstation for Problem Statement 149

This is the product under development. All active engineering, validation, deployment, and product documentation are centered here.

## Problem Statement 149

Problem 149 asks for an integrated secure data erasure and advanced file recovery tool for digital forensics and data sanitization.

The product is designed to address a practical gap in the industry: recovery and sanitization are often treated as separate tools or separate narratives, yet a trustworthy forensic workflow must preserve evidence integrity, document scope, and avoid overstating conclusions.

## Team Aikta

The project is built by Team Aikta:

- Nitisha
- Manoj
- Abhiram
- Varsha
- Rishitha
- Sanjana

## Repository structure

```text
.
├── README.md                     # Repository-level overview and context
├── DEPLOYMENT.md                 # Deployment and operating guidance
├── SECURITY.md                   # Security posture and controls
├── AUDIT_REVIEW_GUIDE.md         # Demo and review checklist
├── make_zip.py                   # Packaging helper for final submission
├── make_zip.ps1                  # Windows packaging helper
├── audit_zip.py                  # Audit packaging utility
├── scratch_test_everything.py    # Local validation scratch area
├── sih26149/                     # Active SIH 2026 Problem 149 implementation
│   ├── README.md                 # Product-focused technical README
│   ├── requirements.txt          # Python pinned dependencies
│   ├── pytest.ini                # Test configuration
│   ├── Dockerfile                # Container build
│   ├── docker-compose.yml        # Local orchestration
│   ├── run.sh / run_windows.bat  # Runtime helpers
│   ├── app/                      # Backend and frontend app code
│   ├── benchmarks/               # Benchmark scripts
│   ├── data/                     # Cases, evidence, and key data
│   ├── docs/                     # Architecture, benchmarks, and product docs
│   ├── scripts/                  # Verification and deployment helpers
│   └── tests/                    # Unit, integration, corpus, and adversarial tests
├── ...
└── .gitignore
```

## Why the project is organized this way

The repo is intentionally not a monolithic single-project stand-alone repository because this workspace was created as a hackathon environment with multiple explorations and active artifacts. The important point is that the relevant deliverable is not the whole folder collection; it is the active product under `sih26149/`.

This makes the project easier to:

- isolate the active solution
- understand the working product from a clean entry point
- preserve related artifacts without confusing them with the live solution
- present the final engineering story clearly to judges and reviewers

## Product focus

The implemented system is designed to provide:

- forensic evidence intake and case tracking
- deleted data / fragmented artifact recovery
- raw-byte carving and structural validation
- evidence hashing and canonicalization
- cryptographic signing of forensic results
- independent evidence verification
- scope-aware sanitization with controlled operator authorization
- safe fail-closed enforcement when capability is unsupported
- a judge-friendly web interface plus API endpoints

## Quick links

- Product README: [sih26149/README.md](sih26149/README.md)
- Architecture: [sih26149/docs/ARCHITECTURE.md](sih26149/docs/ARCHITECTURE.md)
- Benchmark report: [sih26149/docs/BENCHMARK_REPORT.md](sih26149/docs/BENCHMARK_REPORT.md)
- Recovery accuracy: [sih26149/docs/RECOVERY_ACCURACY.md](sih26149/docs/RECOVERY_ACCURACY.md)
- Implementation audit: [sih26149/docs/IMPLEMENTATION_AUDIT.md](sih26149/docs/IMPLEMENTATION_AUDIT.md)
- Security posture: [SECURITY.md](SECURITY.md)
- Deployment guide: [DEPLOYMENT.md](DEPLOYMENT.md)

## Product status

This repository is positioned as a working prototype and next-step product for a forensic assurance platform. The engineering direction is deliberate: the system aims to remain evidence-driven, clear about uncertainty, and verifiable rather than overclaiming.

## Summary

The repo name `SIH 2026` is the broader competition workspace. The actual product being developed is the `sih26149` subproject. This layout is intentional and should be explained clearly in any GitHub/project documentation to avoid confusion about the naming and folder structure.

