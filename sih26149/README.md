# SIH 2026 Problem 149 — NTRO Forensic Assurance Workstation

This repository contains the implementation for Smart India Hackathon 2026 Problem Statement 149: a secure forensic evidence recovery and verifiable sanitization platform.

The product is built to solve a practical and legally sensitive problem: when evidence is recovered and media is sanitized, the system must not merely report success; it must preserve truth, bound claims, and make the final state independently verifiable.

## Why this project exists

Most forensic workflows are fragmented. Recovery tools, sanitization tools, and evidence reports often exist as separate pipelines with little guarantee that the final conclusions are tied to the same source, hash, and scope.

This project creates a single evidence-first workflow that:

- preserves the original source identity
- recovers deleted or fragmented artefacts only when justified by structure and validation
- records audit evidence in a hash-linked, append-only chain
- signs all important conclusions with Ed25519
- verifies these conclusions independently from the producing UI
- enforces a fail-closed model when sanitization or recovery exceeds supported capability

## Product vision

We are building a forensic assurance platform for investigators, auditors, lab supervisors, and governance stakeholders. The system is designed to answer the following question with integrity:

> What really happened to the evidence, what was recovered, what was sanitized, and what claims are actually supported by the underlying data and controls?

## Team Aikta

Built by Team Aikta:

- Nitisha
- Manoj
- Abhiram
- Varsha
- Rishitha
- Sanjana

## Audience and use cases

The product is aimed at:

- forensic investigators and digital evidence teams
- lab supervisors and review officers
- compliance and audit stakeholders
- secure sanitization operators
- governance and legal review teams
- judges and evaluation reviewers who need clear, auditable evidence

## Project summary at a glance

- Domain: digital forensics and secure sanitization
- Goal: recover valid evidence and justify sanitization operations without overstating conclusions
- Architecture: Python + FastAPI + modular forensic engine + signed evidence envelope
- Deployment model: local-first, container-friendly, API-first, browser UI for operational flow
- Security model: rate limits, API-key enforcement, trusted key registry, strict path validation, fail-closed sanitization

## Core capabilities

- case creation and evidence acquisition workflow
- filesystem and media profiling
- deleted-file discovery and recovery
- raw byte carving for JPEG, PNG, PDF, ZIP, DOCX/XLSX, and MP4 patterns
- evidence classification and bounded confidence states
- signed evidence payloads and append-only audit ledger
- independent verifier for tamper detection and schema validation
- controlled sanitization workflow with explicit scope acknowledgement
- live browser-based UI for operational usage

## How the flow works

```mermaid
flowchart LR
    A[Acquire Evidence] --> B[Preserve Source Hash]
    B --> C[Recover / Carve Data]
    C --> D[Classify Validation State]
    D --> E[Authorize Scope]
    E --> F[Sanitize Media]
    F --> G[Read-back Verify]
    G --> H[Sign Evidence]
    H --> I[Independent Verification]
```

This is the project’s core design principle: preserve, recover, validate, authorize, sanitize, verify, and prove with traceable evidence rather than user-interface optimism.

## Repository structure

```text
sih26149/
├── README.md                     # Product overview and demo guide
├── requirements.txt              # Pinned dependency versions
├── pytest.ini                    # Test configuration
├── Dockerfile                    # Container build
├── docker-compose.yml            # Local composition for service orchestration
├── run.sh                        # Linux runtime helper
├── run_windows.bat               # Windows runtime helper
├── setup.sh                      # Setup and environment initialization
├── app/
│   ├── main.py                   # FastAPI application entry point
│   ├── api/                      # REST endpoints: cases, forensics, carving, erasure, audit, evidence
│   ├── core/                     # Canonicalization, hashing, signing, verifier, trust registry
│   ├── forensics/                # Recovery, carving, validation, benchmarking logic
│   ├── sanitization/             # Device detection, erasure, verification, scope enforcement
│   ├── cases/                    # Case tracking and state
│   ├── static/                   # Frontend UI (HTML/CSS/JS)
│   └── cli/                      # CLI workflow for forensic operations
├── benchmarks/                  # Benchmark execution and evaluation helpers
├── data/                        # Case/evidence output and persisted store
├── demo/                        # Demo and workdir assets
├── docs/                        # Product documentation, architecture, audits, metrics
├── scripts/                     # verification, deployment, and live validation helpers
├── tests/                       # Unit, integration, corpus, and adversarial tests
└── README.md
```

## Stack selection and architecture

### Why Python

Python was chosen as the primary product language because it offers the best balance between:

- developer speed in forensic workflow prototyping
- mature ecosystem for cryptography, hashing, JSON, and API tooling
- strong FastAPI support for secure web services
- easy integration with evidence workflows and testing frameworks
- clear maintainability for a team prototype that must be easy to explain and demo

### Why not C++ or Rust as the first choice

C++ and Rust are strong languages for extremely low-level imaging or kernel-level tooling, but they introduce trade-offs for this project:

- slower iteration speed for a hackathon-grade multi-feature product
- more effort in building secure, testable API layers and evidence workflows
- less immediate web-service integration compared with Python’s FastAPI ecosystem
- more complexity in cross-platform demo reliability for judges and reviewers

That said, the project remains intentionally designed in a modular way. The core logic can be extended or reimplemented in lower-level languages if the project later needs hardware-accelerated processing or a deeper kernel-level block device interface.

### Why FastAPI

FastAPI was a strong choice because it provides:

- clear REST API design
- automatic validation and schema checking
- easily testable endpoints
- solid compatibility with Python security and cryptography libraries
- a stable single-product backend for the web UI and service APIs

### Why HTML/CSS/JS for the UI

A lightweight browser interface is appropriate because this project is not primarily a large enterprise UI platform; it is a forensic assurance workstation where operational speed and clear evidence flow matter more than a full React ecosystem. The current stack keeps the frontend transparent, maintainable, and easy to run locally or in a containerized demo environment.

## Fast start

### Local Python setup

```bash
cd sih26149
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Then open:

- http://localhost:8000
- Swagger docs at http://localhost:8000/docs

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

## Demo workflow

For a demonstration, the expected product flow is:

1. Create a case.
2. Acquire or upload an image.
3. Preserve the source hash and metadata.
4. Run forensic recovery or carving.
5. Inspect the classification states and evidence factors.
6. Review the audit trail and evidence envelope.
7. Authorize sanitization scope if the operation is supported.
8. Perform the sanitization or read-back verification.
9. Review the signed evidence and independent verification output.

## Product demo checklist

- create case
- upload evidence image
- validate acquisition metadata
- run recovery and carving
- inspect artifact details and confidence
- review audit chain
- verify evidence signing
- execute supported sanitization workflow
- confirm fail-closed behavior for unsupported operations

## Feature status and realism

The project is strongest in the following areas:

- forensic evidence and audit flow
- cryptographic evidence signing and verification
- secure scope-aware sanitization
- case and workflow orchestration
- explainable forensic reporting and bounded claims

The project is realistic about the boundaries:

- logical read-back verification is not the same as physical NAND-level proof
- unsupported hardware-level erase operations are blocked rather than falsely claimed
- uncertain or fragmented artifacts remain marked as partial or unverified

This is intentional and is central to the project’s evidence-first design.

## Product measurements and claims

The repository includes real benchmark and evaluation artifacts in the `docs/` directory. The project claims only what it can defend within measured operational scope.

Current documented evidence includes:

- cryptographic signing latency baselines
- evidence package verification times
- throughput measurements for hashing and read-back workflows
- recovery precision/recall measured against validation corpora
- adversarial tamper and invariant tests

These values are documented in:

- [docs/IMPLEMENTATION_AUDIT.md](docs/IMPLEMENTATION_AUDIT.md)
- [docs/BENCHMARK_REPORT.md](docs/BENCHMARK_REPORT.md)
- [docs/RECOVERY_ACCURACY.md](docs/RECOVERY_ACCURACY.md)
- [docs/RC2_REAL_WORLD_CORPUS.md](docs/RC2_REAL_WORLD_CORPUS.md)

## Security posture

The system includes:

- upload and path validation
- API key enforcement in protected modes
- rate limiting
- trusted key registry usage
- secure file handling practices
- scope-aware sanitization checks
- fail-closed operation for unsupported capabilities

## Future enhancements

The current codebase is a strong prototype foundation. The following enhancements are realistic next steps:

### Near-term improvements

- deeper forensic parsers for more file families and fragmented structures
- richer evidence classification for edge-case recovery states
- extended device capability profiles for more hardware classes
- stronger UI analytics and case dashboards
- more robust export formats for legal and lab review

### Medium-term improvements

- better integration with real write-block hardware and acquisition tooling
- more formal evidence package export standards and signing policies
- richer cross-case correlation and timeline analytics
- enhanced forensic corpus generation for continuous benchmarking

### Long-term roadmap

- build a hardened production deployment model
- introduce stronger multi-user role separation
- expand legal and governance reporting features
- add a formal investigation workflow spanning multiple devices and cases

## Documentation map

- Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Benchmark report: [docs/BENCHMARK_REPORT.md](docs/BENCHMARK_REPORT.md)
- Implementation audit: [docs/IMPLEMENTATION_AUDIT.md](docs/IMPLEMENTATION_AUDIT.md)
- Recovery accuracy: [docs/RECOVERY_ACCURACY.md](docs/RECOVERY_ACCURACY.md)
- Real-world corpus: [docs/RC2_REAL_WORLD_CORPUS.md](docs/RC2_REAL_WORLD_CORPUS.md)

## Testing

```bash
cd sih26149
python -m pytest -q
```

This project includes unit tests, integration tests, corpus validation, and adversarial checks to validate the reliability of the forensic pipeline and evidence model.

## Final note

This project is not just a UI demo or a toy workflow. It is a structured attempt to solve a real forensic assurance problem with credible evidence chain integrity, clear boundaries, and operational honesty.

The system is intentionally careful about what it claims. That is a strength, not a weakness, because in digital forensics, a correct bounded conclusion is more valuable than an overconfident one.
