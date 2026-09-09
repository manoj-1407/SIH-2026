# SIH26149 — Integrated Secure Data Erasure & Advanced File Recovery Tool

**Organisation:** National Technical Research Organisation (NTRO)  
**Problem Statement:** SIH26149  
**Team:** Session B

---

## What this system does

Digital forensic investigators need to recover evidence from storage media. Sanitization teams need to establish that data was actually erased. These are opposite operations that share a common problem: **how do you prove what happened?**

This system does not just perform recovery or erasure. It:
- **Establishes what actually occurred** — using real filesystem tooling, not simulation
- **Classifies outcomes explicitly** — `VERIFIED`, `UNVERIFIED`, `FAILED`, `VERIFIED_WITHIN_SCOPE`
- **Signs the result cryptographically** — Ed25519, tamper-detectable
- **Persists evidence atomically** — crash-safe, independently verifiable
- **Makes honest, bounded claims** — never claims universal SSD erasure it cannot prove

---

## Quick start

### Native Linux / WSL2
```bash
# 1. Install dependencies
./setup.sh

# 2. Start the workstation
./run.sh

# Access UI:       http://127.0.0.1:8000
# Access API docs: http://127.0.0.1:8000/docs
```

### Docker (recommended for demo)
```bash
docker-compose up --build -d
# UI at http://localhost:8000
```

### Run tests
```bash
python3 -m pytest tests/ -v
# Expected: 89 passed, 7 skipped (0 failures)
```

### Verify evidence from the CLI
```bash
# Any signed evidence package can be independently verified — no case DB needed.
python3 -m app.cli.verify path/to/evidence_package.json \
    --registry path/to/trust_registry.json
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SIH26149_DATA_DIR` | `/app/data` (container) or `<repo>/data` (local) | Root for all evidence, keys, cases |
| `SIH26149_API_KEY` | *(unset = open)* | When set, all API requests must supply `X-API-Key` header |
| `DEMO_MODE` | `0` | Set to `1` to enable tamper-demo endpoint and bypass API key |

### Running the tamper demonstration
```bash
# Start with demo mode enabled
DEMO_MODE=1 ./run.sh

# The tamper endpoint is now accessible — shown in the Evidence Vault tab.
# It modifies one field of a signed package and demonstrates that
# verification rejects the tampered result.
```

---

## Architecture

```
Browser Workstation UI (HTML / CSS / JS)
              │
              ▼
  FastAPI Application (REST, /api/*)
 ┌────────────┴────────────┐
 ▼                         ▼
Forensics               Sanitization
 │                         │
 ├─ fls  (inode discover)  ├─ Authorization gate (mandatory)
 ├─ icat (block extract)   ├─ dd ZERO_FILL
 └─ sha256 verify          └─ Readback verify
              │
              ▼
       Evidence Core Layer
  ┌──────┬────────┬────────┐
  │Canon.│SHA-256 │Ed25519 │
  └──────┴────────┴────────┘
              │
       TrustRegistry (persistent JSON)
              │
       EvidenceStore (atomic fsync rename)
```

### Layer responsibilities

**Presentation (`app/static/`)** — Five-tab operator interface: Cases, Forensic Recovery, Sanitization, Evidence Vault, Independent Verifier. All data from live API, never hardcoded.

**API (`app/api/`)** — RESTful routes. Optional API-key middleware. Separate routers per domain (cases, forensics, sanitization, evidence, health). No business logic in handlers.

**Forensics (`app/forensics/`)** — Real Sleuth Kit integration. `filesystem.py` identifies structure before dispatching tools. `discovery.py` scans deleted inodes via `fls`. `recovery.py` extracts blocks via `icat`. `verification.py` computes and compares SHA-256. Nothing is simulated.

**Sanitization (`app/sanitization/`)** — `authorization.py` enforces mandatory operator identity. `methods.py` executes `dd if=/dev/zero conv=notrunc`. `verification.py` reads back and confirms zero bytes. `scope.py` permanently attaches technical boundary statements to every record.

**Evidence core (`app/core/`)** — `canonical.py`: deterministic JSON (sorted keys, no whitespace). `signing.py`: Ed25519 keypair, persisted on disk, loaded on restart. `trust.py`: public key registry, never trusts keys embedded in packages. `persistence.py`: atomic write with fsync. `independent_verifier.py`: standalone verification with no dependency on case state.

---

## Security model

### What is cryptographically guaranteed
- A signed evidence package cannot have any field modified without breaking verification
- The signing key is resolved from a separate persistent registry, not from within the package
- An attacker who cannot access the private key file cannot produce a valid forged package
- Evidence persisted before a container restart remains independently verifiable after restart

### What is explicitly not claimed
- **Universal SSD erasure** — physical NAND wear-leveling, over-provisioning, and controller remapping are outside the observable scope of filesystem-level zeroing. The system reports `VERIFIED_WITHIN_SCOPE` with this limitation permanently attached.
- **Hardware-level sanitization** — ATA Secure Erase and NVMe crypto-erase require hardware cooperation and are outside the scope of this implementation
- **Private key compromise resilience** — if the private key file is stolen, an attacker can forge valid packages. This is a key-management problem, not a cryptographic one. The threat model documents this explicitly.

### Deployment security note
`security_opt: seccomp:unconfined` is required in Docker because Sleuth Kit forensic tools use low-level filesystem syscalls blocked by the default seccomp profile. This is a deliberate, documented tradeoff. The application itself makes no outbound calls and requires no external services — it processes only operator-supplied forensic images — but the current `docker-compose.yml` does not enforce network isolation at the container level (no `network_mode: none` or egress-blocking network). Operators who need a network-isolation guarantee, not just an application-level one, should add that at the compose/orchestration layer.

---

## Outcome classifications

| Classification | Meaning |
|---|---|
| `VERIFIED` | Recovered SHA-256 matches trusted reference hash. Content is byte-identical. |
| `UNVERIFIED` | Recovery succeeded, but no reference hash was provided. Cannot claim identity. |
| `FAILED` | Recovery failed or hash mismatch. Blocks may have been overwritten. |
| `VERIFIED_WITHIN_SCOPE` | Sanitization readback confirmed zeros, within the explicit filesystem-level scope. |
| `INVALID` | Cryptographic verification failed. Evidence was tampered with after signing. |
| `REJECTED` | Sanitization request lacked mandatory authorization. Operation did not proceed. |

---

## Threat model summary

| Threat | Defence |
|---|---|
| Forged evidence package | Ed25519 signature verification; outcome cannot be set by constructing a dict |
| Field tampering post-signing | Canonical hash recomputed and compared before signature check |
| Key substitution attack | Registry resolves key by `key_id`; embedded keys in packages are not trusted |
| Torn writes / power loss | Atomic `tempfile → fsync → os.replace()` |
| Non-filesystem image upload | `file -b` + `fsstat` gates before any Sleuth Kit dispatch |
| Malware in recovered content | Bytes never auto-executed; treated as untrusted data throughout |
| Unauthorized sanitization | `operator_id` + `operator_name` + `authorization_reason` + explicit acknowledgement required |
| Overstated erasure claims | `VERIFIED_WITHIN_SCOPE` with permanent scope attachment; NAND limitations explicitly documented |
| Private key in container image | Keys are **never** copied into image; generated at container startup into mounted volume |
| API access without authorization | Optional `X-API-Key` header enforcement via `SIH26149_API_KEY` env var |

See `docs/THREAT_MODEL.md` for full analysis.
