# Dependency Audit & Security Evaluation — SIH26149

**Audit Date**: 2026-09-21  
**Target Environment**: Forensic Workstation (Offline-First, Zero Cloud Reliance)

---

## 1. Production Dependencies

| Package | Pinned Version | Purpose / Role | License | Security Considerations | Essential? |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **`fastapi`** | `0.141.1` | REST API framework for local UI & programmatic control | MIT | Fully offline; no telemetry or remote calls. | YES |
| **`uvicorn[standard]`** | `0.52.4` | ASGI server for local FastAPI instance | BSD-3-Clause | Bound to localhost (`127.0.0.1`) only. | YES |
| **`pydantic`** | `2.13.5` | Strict schema validation and typed models | MIT | Native validation; prevents type confusion. | YES |
| **`cryptography`** | `46.0.6` | Ed25519 digital signatures and secure key serialization | Apache 2.0 / BSD | Industry standard (PyCA); audited C/Rust bindings. | YES |
| **`python-multipart`**| `0.0.32` | Form-data and binary image upload parsing | Apache 2.0 | Memory/disk stream bounds enforced. | YES |
| **`reportlab`** | `4.2.5` | Forensic assurance PDF certificate generation | BSD | Offline PDF builder; no remote assets fetched. | YES |

---

## 2. Test & Development Dependencies

| Package | Pinned Version | Purpose | License | Essential? |
| :--- | :--- | :--- | :--- | :---: |
| **`pytest`** | `9.1.1` | Automated test runner | MIT | YES |
| **`httpx`** | `0.28.1` | In-process test client for API route integration tests | BSD-3-Clause | YES |

---

## 3. External System Tooling (Optional / Environment-Dependent)

| Tool | Role | Availability | Fallback Behavior |
| :--- | :--- | :--- | :--- |
| **The Sleuth Kit (`icat`, `fls`, `fsstat`)** | ext4 inode metadata recovery | Linux / Docker | Where missing, system falls back to pure Python signature carving without crashing. |
| **`file` command** | Filesystem magic probing | POSIX / Linux | Fallback to header heuristics in pure Python. |
