# Standalone evidence verifier

`scripts/verify_evidence.js` is an offline verifier implemented with Node.js
built-in modules; it does not start the FastAPI service or use application
dependencies. It checks the canonical evidence hash, Ed25519 signature against
an operator-supplied trust source, package file hashes, and an included audit
event chain.

## Verify an evidence envelope

```powershell
node scripts/verify_evidence.js path\to\evidence.json --trusted-key path\to\examiner.pub.pem
```

## Verify a portable package directory

```powershell
node scripts/verify_evidence.js path\to\case_evidence_package\manifest.json --registry path\to\trust_registry.json
```

The registry is JSON keyed by signer key ID; each active entry must contain
`public_key_hex`. The key or registry must come from an independently trusted
source. A package's embedded `public_key.pem` is only compared with the
independently trusted key and is never accepted as its own trust anchor.

Exit codes are `0` for cryptographic verification success, `1` for integrity,
signature, or audit-chain failure, and `2` when the trust source is missing or
untrusted. A missing signature check is never reported as success.

## Assurance checklist semantics

- **HASH** and **SIGNATURE** report cryptographic integrity and trust-anchor
  checks.
- **HASH CHAIN** is checked for portable directory packages. Single-envelope
  JSON has no audit-chain field, so the verifier reports it as not included.
- **SCOPE** and **OPERATION** indicate that the corresponding signed fields are
  present; they do not prove that physical hardware performed the operation.
- **POST-PROBE** reports the signed residual-artifact count when present. A
  non-zero residual count is a failed probe result even when its evidence
  signature is valid.
- Generic directory manifests do not normalize the scope, operation, or
  post-probe fields; those checks are shown as **NOT ATTESTED**, not inferred.

The Python implementation remains available as
`app/core/independent_verifier.py`. The cross-implementation tests compare both
implementations on valid packages and tampering cases.
