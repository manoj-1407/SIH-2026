# SIH26149 — Judge Demo Script (5 minutes)

## Setup (before judges arrive)
```bash
# DEMO_MODE=1 enables the tamper demo endpoint — required for Act 4.
DEMO_MODE=1 docker-compose up -d --build
# Wait for: "Application startup complete"
# Open http://localhost:8000
```

## Demo flow

### Act 1: Create case and upload image (45 seconds)
1. Click **New Case**. Name it "Device 14A — Recovery".
2. Go to **Forensic Recovery** tab.
3. Upload the demo ext4 image (provided in `scripts/demo_image.img` or create with `setup.sh --demo`).
4. Click **Detect Filesystem**.
   - Show: `EXT4 — SUPPORTED`

> "The system identifies the filesystem before dispatching any forensic tools.
> A FAT32 or corrupted image would be rejected here rather than producing garbage output."

### Act 2: Discover and recover (60 seconds)
5. Click **Discover Deleted Files**.
   - Show the inode list.
6. Select the target inode.
7. Optionally enter the known reference SHA-256 hash.
8. Click **Run Recovery**.
9. Show the result:
   - `VERIFIED` (if hash provided and matched)
   - `UNVERIFIED` (if no reference hash — correct: cannot claim identity without ground truth)

> "VERIFIED means the recovered bytes are byte-identical to the known original.
> UNVERIFIED means recovery succeeded but we have no reference to compare against —
> the system doesn't pretend certainty it doesn't have."

### Act 3: View signed evidence (45 seconds)
10. Click **Evidence Vault** tab.
11. Show the signed evidence package:
    - SHA-256 of the acquired image
    - SHA-256 of the evidence envelope
    - Ed25519 signature
    - Key ID, verification: ✓ VALID

> "Any court authority or second examiner can verify this package independently —
> without access to this workstation, without the case database, using only
> the evidence file and the public trust registry."

### Act 4: Tamper demonstration (60 seconds)
12. In Evidence Vault, find the **Tamper Demo** section.
13. Select preset: `outcome.status: VERIFIED → FAILED`
14. Click **Attempt Tamper**.
15. Show: `✗ Verification FAILED — tamper detected`

> "Changing even one field — the classification, the hash, a timestamp — invalidates
> the entire package. A forensic report cannot be quietly altered."

### Act 5: Sanitization with authorization (45 seconds)
16. Go to **Data Sanitization** tab.
17. Show that submitting without operator credentials returns `REJECTED`.
18. Fill in operator name, ID, reason, and check the scope acknowledgement.
19. Run sanitization.
20. Show `VERIFIED_WITHIN_SCOPE` with the scope statement.

> "We never say 'securely erased'. We say: zeroing completed, readback confirmed,
> within filesystem-level scope. SSD wear-leveling and NAND over-provisioning are
> outside what we can observe — that limitation is permanently attached to the certificate."

### Act 6: Unsupported filesystem (30 seconds)
21. Upload a non-ext4 file (any ZIP, PDF, or FAT32 image).
22. Click **Detect Filesystem**.
23. Show: `NOT_A_FILESYSTEM — UNSUPPORTED`

> "The system rejects unrecognised or incompatible images rather than running
> ext4 forensic tools against them and producing meaningless output."

## Likely judge questions

**Q: How is this different from Autopsy + dd?**
A: Autopsy recovers files. dd erases them. Neither produces cryptographically signed, court-verifiable evidence with explicit outcome classification and permanently attached scope statements. Our contribution is the evidence-integrity layer around those operations.

**Q: What if the private key is compromised?**
A: A compromised private key would allow an attacker to sign forged evidence. This is documented in the threat model as a key-management problem, not a cryptographic failure. The defence is physical security of the key file — the same defence used for any PKI system.

**Q: Can this handle NTFS or FAT32?**
A: Currently ext4 only. The architecture deliberately gates on filesystem type — adding NTFS or FAT32 backends requires implementing the appropriate recovery module, not changing the evidence or trust layer. The scope is documented.

**Q: How does DEMO_MODE work?**
A: Setting `DEMO_MODE=1` enables the `/api/evidence/{id}/tamper-demo` endpoint, which exists purely for demonstration. In a production deployment, `DEMO_MODE` is `0` and that endpoint is unavailable.
