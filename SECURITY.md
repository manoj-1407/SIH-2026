# SIH 2026 — Security Model & Threat Mitigations

This document outlines the defense-in-depth architecture, cryptographic controls, and threat mitigations implemented across **SIH26013** and **SIH26149**.

---

## 1. Cryptographic Evidence & Trust Registry

Both platforms implement Ed25519 digital signatures and SHA-256 canonical envelopes for non-repudiation:

- **Private Key Isolation**: Private signing keys (`.priv`) are generated at first startup on the host/volume and are strictly excluded from source control (`.gitignore`). They are never exposed over any API endpoint.
- **Independent Trust Registry**: Public keys are indexed by `key_id` in `trust_registry.json`. Independent verification resolves keys exclusively from this registry, preventing untrusted key substitution attacks.
- **Hash-Chained Audit Logs (SIH26149)**: Every administrative and forensic operation is logged with SHA-256 block hashing (`previous_hash` → `entry_hash`), creating a tamper-evident chain of custody verified via `GET /cases/{id}/timeline/verify`.
- **Structured JSONL Audit Logs (SIH26013)**: Case operations are appended to per-case JSONL audit files with SHA-256 `entry_hash` linked via `previous_hash` for tamper evidence. SIH26013 does not expose a dedicated chain-verify API like SIH26149; treat the logs as structured, hash-linked custody records rather than a full verify UI surface.

---

## 2. Path Traversal & File Eraser Confinement

- **Dereferenced Symlink Containment**: In `sih26149`, `_validate_erasure_paths` invokes `Path(target).resolve()` before evaluating `is_relative_to(UPLOADS_DIR)`. Any target path resolving outside the case uploads root (including symlink escapes and `../` traversal) is strictly rejected with `HTTP 403 Forbidden`.
- **Evidence ID Sanitization**: All evidence retrieval and certificate routes validate `evidence_id` against the strict regex `^[a-zA-Z0-9_\-]+$`, preventing directory traversal when constructing persistence paths.

---

## 3. Production Authentication & RBAC

- **Header Authentication**: Production API requests require the `X-API-Key` header matched against `SIH26149_API_KEY` / `SIH26013_API_KEY`.
- **Demo Mode Isolation**: `DEMO_MODE=1` is reserved strictly for local/evaluation testing. When `DEMO_MODE=0` (production default), demo-tamper routes and unauthenticated requests are rejected with `HTTP 401 Unauthorized` / `HTTP 403 Forbidden`.
- **CORS Allowlist**: Configurable via `SIH26149_CORS_ORIGINS` to prevent cross-origin script execution.

---

## 4. Concurrency & Integrity Controls

- **Atomic File Replacement**: File persistence operations follow an atomic sequence (`write temp` -> `fsync` -> `atomic replace` with 30-attempt backoff retry) to prevent torn reads and partial writes under high thread contention.
- **Per-Case Isolation**: All evidence vault queries and timeline audits are scoped strictly to the authenticated `case_id`.
