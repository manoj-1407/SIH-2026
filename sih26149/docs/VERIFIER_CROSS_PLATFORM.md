# Verifier Cross-Platform Parity — Script Changes

## scripts/verify_evidence.js — Updated 2026-10-03

**Change scope:** Minimal extension to match Python `verify_directory_package()` parity with the existing standalone envelope verifier. The original script verified only single standalone evidence envelope JSON files. It now also supports directory evidence packages.

### What changed

1. **Manifest/directory package detection** — When the input JSON has top-level keys `file_hashes` and `schema_version` (i.e. a package `manifest.json`), the verifier dispatches to `verifyDirectoryPackage()` instead of the envelope path.

2. **File hash integrity** — Every `rel_path → sha256` entry in `manifest.file_hashes` is re-computed on disk; any mismatch prints `INVALID / FAILED — Artifact tamper detected` and exits non-zero.

3. **Manifest double-hash check** — Both the raw on-disk bytes hash AND the RFC 8785 canonical re-serialization hash must equal `cryptography/signature.json → manifest_hash`; otherwise `INVALID` exit.

4. **Unexpected file injection check** — Filesystem walk finds files present in the package dir but absent from `file_hashes` (and not the three excluded entries `manifest.json`, `cryptography/signature.json`, `cryptography/public_key.pem`). Any such file → `INVALID` exit.

5. **Audit event chain verification** — If `audit/events.jsonl` exists and is non-empty, each event is validated:
   - `previous_hash` must match the preceding event's `entry_hash` (first event requires `GENESIS`).
   - The `entry_hash` must equal `sha256hex(canonicalize({everything except entry_hash}))`.
   - Any violation prints `AUDIT_CHAIN_TAMPER — ...` and exits non-zero. This matches the exact Python check wording family used by `verify_directory_package`.

6. **Public key resolution order** — Same as envelope path: explicit CLI PEM → trust_registry.json → `<keyId>.pub.pem` → `primary.pub.pem`. Falls back to package-embedded `cryptography/public_key.pem` only if the external resolution found nothing (mirroring Python's embedded-key comparison anchor).

### Backward compatibility

All prior usage (verifying a single envelope JSON) is preserved. The dispatch is purely structural — files without `file_hashes` + `schema_version` continue along the original `verifyEnvelope` code path with unchanged output.

### Parity target

The Node verifier's decision logic now maps 1:1 to `app/core/independent_verifier.py`:

| Attack vector | Python `verify_directory_package` | Node `verifyDirectoryPackage` |
|---|---|---|
| Artifact byte flip | INVALID (hash mismatch) | exit != 0, stdout contains `INVALID / FAILED` |
| Extra file injected | INVALID (unexpected_file) | exit != 0, stdout contains `Unexpected file` + `INVALID` |
| Manifest byte flip | INVALID (raw manifest hash) | exit != 0, stdout contains `INVALID` |
| Signature corrupted | INVALID (sig invalid) | exit != 0, stdout contains `signature INVALID` |
| Audit event prev_hash broken | INVALID (chain broken) | exit != 0, stdout contains `AUDIT_CHAIN_TAMPER` |
| Audit event entry_hash broken | INVALID (entry_hash mismatch) | exit != 0, stdout contains `AUDIT_CHAIN_TAMPER` |
