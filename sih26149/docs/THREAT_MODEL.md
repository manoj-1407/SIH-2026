# SIH26149 Security & Threat Model

## Threat Vectors & Defenses

| Threat Scenario | Attack Vector | System Defense | Defensible Boundary / Limitations |
|---|---|---|---|
| **Forged Evidence Envelope** | Attacker crafts a JSON claiming `VERIFIED` without executing recovery | Ed25519 asymmetric signature verification fails; outcome classified as `INVALID`. | Independent verifier does not require DB access; operates on RFC 8032 signature over RFC 8785 canonical bytes. |
| **Evidence Tampering** | Attacker modifies one field (e.g. SHA-256 or classification) in existing package | Canonical evidence hash differs from computed hash; signature verification fails; `tamper_detected: true`. | Any single-bit modification across manifest, certificates, or payload breaks signature. |
| **Key Substitution** | Attacker signs forged package with attacker's private key and embeds attacker's public key | Independent verifier queries persistent `TrustRegistry` by `key_id`; untrusted public keys rejected. | If attacker controls the external Trust Registry root, key substitution is possible; root of trust must be pinned out-of-band. |
| **Torn Reads / Half-Written Evidence** | Process interrupted or power lost during evidence persistence | Atomic write primitive writes to hidden temporary file, flushes, fsyncs, and performs atomic rename. | Protected against process termination; underlying OS/filesystem fsync integrity assumed. |
| **Incompatible / Malicious File Upload** | Attacker uploads corrupted or non-filesystem image to crash engine | Filesystem capability detector validates structure before dispatching; ext4 tools rejected for non-ext4 inputs. | Safe parser boundary: input is scanned for magic structures without invoking unsafe OS-level kernel mounts. |
| **Malicious Recovered Payload Execution** | Recovered deleted file contains malware or exploit | Workstation treats all recovered bytes as untrusted data; never auto-executes; provides safe downloads only. | Carving engine inspects byte structures in-memory; never executes or executes shell handlers on carved files. |
| **Injected Unmanifested Evidence Files** | Attacker injects rogue files into an exported evidence directory | Independent verifier performs full reverse directory walk; any unlisted file fails verification (DEF-005). | Directory packages must match manifest `file_hashes` 1-to-1. |
| **Source Media Modification During Examination** | Accidental or malicious write to acquired evidence image | Software opens all source files in `rb` (read-only binary) mode; records input SHA-256 at ingest; asserts post-operation hash invariance. | **Boundary Note**: Software-enforced read-only handling and hash invariance. Hardware write-blocking requires physical laboratory write-blocker bridges. |
| **Rate Limit Resource Exhaustion** | Flooding API with concurrent carving or upload requests | In-memory sliding-window rate limiter throttles excessive requests with 429 Too Many Requests. | Isolated test mode available via `SIH26149_DISABLE_RATE_LIMIT=1` without weakening default production enforcement. |

---

## Source Preservation Architecture

1. **Software-Level Preservation**:
   - Ingest computes SHA-256 digest immediately upon stream receipt.
   - File handles for carving, forensic discovery, and timeline analysis are opened exclusively in read-only binary (`rb`) mode.
   - Post-operation verification checks source hash against ingest hash to guarantee zero in-place mutation.
2. **Laboratory Hardware Write-Blocker Interface**:
   - Hardware write-blocking verification is marked: `PENDING LABORATORY HARDWARE BRIDGES`.
   - On commodity examination machines without hardware bridges, the software strictly identifies itself as software-level read-only protected.
| **Unauthorized Sanitization** | Rogue operator or automated request attempts to erase drive | API enforces mandatory operator identity credentials and affirmative scope acknowledgement; missing authorization triggers 403 Forbidden. |
| **Overstated Sanitization Claims** | Vendor claims physical destruction of flash media cells | System permanently binds all sanitization certificates to virtual container / filesystem scope, explicitly detailing NAND/wear-leveling limits. |
