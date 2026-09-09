# SIH26149 Security & Threat Model

## Threat Vectors & Defenses

| Threat Scenario | Attack Vector | System Defense |
|---|---|---|
| **Forged Evidence Envelope** | Attacker crafts a JSON claiming `VERIFIED` without executing recovery | Ed25519 asymmetric signature verification fails; outcome classified as `INVALID`. |
| **Evidence Tampering** | Attacker modifies one field (e.g. SHA-256 or classification) in existing package | Canonical evidence hash differs from computed hash; signature verification fails; `tamper_detected: true`. |
| **Key Substitution** | Attacker signs forged package with attacker's private key and embeds attacker's public key | Independent verifier queries persistent `TrustRegistry` by `key_id`; untrusted public keys rejected. |
| **Torn Reads / Half-Written Evidence** | Process interrupted or power lost during evidence persistence | Atomic write primitive writes to hidden temporary file, flushes, fsyncs, and performs atomic rename. |
| **Incompatible / Malicious File Upload** | Attacker uploads corrupted or non-filesystem image to crash engine | Filesystem capability detector validates structure before dispatching; ext4 tools rejected for non-ext4 inputs. |
| **Malicious Recovered Payload Execution** | Recovered deleted file contains malware or exploit | Workstation treats all recovered bytes as untrusted data; never auto-executes; provides safe downloads only. |
| **Unauthorized Sanitization** | Rogue operator or automated request attempts to erase drive | API enforces mandatory operator identity credentials and affirmative scope acknowledgement; missing authorization triggers 403 Forbidden. |
| **Overstated Sanitization Claims** | Vendor claims physical destruction of flash media cells | System permanently binds all sanitization certificates to virtual container / filesystem scope, explicitly detailing NAND/wear-leveling limits. |
