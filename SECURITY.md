# SIH 2026 — Problem 149 Security Model

This document captures the core security controls for the NTRO forensic assurance platform behind problem statement 149.

## 1. Security objectives

The platform is designed to protect both the evidence lifecycle and the integrity of the digital workflow:

- preserve evidence accurately and avoid silent mutation
- keep all cryptographic claims tamper-evident
- enforce bounded sanitization conclusions with clear scope statements
- restrict untrusted access to operator and evidence endpoints
- throttle API abuse and reject unsafe paths

## 2. Trust and integrity

- Evidence operations use persistent storage and atomic write patterns to reduce partial-write risks.
- Hash-chain and signed evidence patterns provide a tamper-evident trail for case operations.
- Independent verification is separated from runtime case state so a reviewer can validate the package without trusting the main database.
- Keys and trust registries are resolved from controlled storage rather than package-internal values.

## 3. API protection

- Requests may require an `X-API-Key` header in production-like operation.
- `DEMO_MODE` is reserved for local evaluation and should not be used for public deployments.
- Cross-origin exposure is controlled via explicit configuration.
- Rate limiting is enforced for general traffic and high-cost upload routes.

## 4. Path and file safety

- Upload and case paths are constrained to the allowed storage roots.
- Unsafe or traversal-like paths are rejected before write or read operations.
- Evidence IDs and file paths are validated before constructing persistent locations.

## 5. Sanitization safety

The platform avoids overstating the effect of erasure. It separates:

- proven in-scope zero-fill verification
- unsupported hardware-level claims
- preliminary recovery or classification results

This prevents false or misleading statements about storage media beyond the actual verified scope.

## 6. Operational hardening

Recommended deployment controls:

- run behind a reverse proxy with HTTPS termination
- keep secrets out of source control
- use environment-based configuration for all sensitive values
- restrict filesystem permissions for data and keys
- log and monitor failed auth and rate-limit events

This makes the system well-suited for evaluation, controlled deployment, and demonstration in front of judges and stakeholders.

