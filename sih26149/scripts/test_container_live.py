import os
import subprocess
import tempfile
import hashlib
import httpx

BASE_URL = "http://localhost:8000"

def test_container_lifecycle():
    client = httpx.Client(base_url=BASE_URL, timeout=30.0)

    # ── 1. HEALTH ─────────────────────────────────────────────────────────
    print("[1] Checking container health (/health)...")
    r = client.get("/health")
    assert r.status_code == 200, f"Health check failed: {r.text}"
    health = r.json()
    assert health["status"] == "OPERATIONAL"
    assert health["subsystems"]["sleuthkit"] is True
    assert health["subsystems"]["ext4_tools"] is True
    assert health["subsystems"]["cryptography"] == "Ed25519"
    assert health["tools"]["fls"] is True
    assert health["tools"]["icat"] is True
    print("    Container health: OPERATIONAL, SleuthKit & ext4 tools verified.")

    # ── 2. CREATE CASE ────────────────────────────────────────────────────
    print("[2] Creating forensic case (/cases)...")
    r = client.post("/cases", json={
        "workflow": "FORENSIC",
        "title": "NTRO Live Docker Case",
        "description": "Live container forensic recovery & verification",
    })
    assert r.status_code == 200, f"Case creation failed: {r.text}"
    case_id = r.json()["case_id"]
    assert case_id.startswith("CASE-")
    print(f"    Created Case ID: {case_id}")

    with tempfile.TemporaryDirectory() as tmpdir:
        img_path = os.path.join(tmpdir, "live_ext4.img")

        # ── 3. BUILD EXT4 IMAGE ───────────────────────────────────────────
        print("[3] Creating real ext4 filesystem image with deleted artifact...")
        with open(img_path, "wb") as f:
            f.truncate(20 * 1024 * 1024)

        subprocess.run(["mkfs.ext4", "-F", "-b", "1024", img_path],
                       check=True, capture_output=True)

        secret_content = b"NTRO-TOP-SECRET-FORENSIC-PAYLOAD-2026"
        gt_sha256 = hashlib.sha256(secret_content).hexdigest()
        payload_file = os.path.join(tmpdir, "payload.dat")
        with open(payload_file, "wb") as f:
            f.write(secret_content)

        subprocess.run(["debugfs", "-w", "-R",
                        f"write {payload_file} payload.dat", img_path],
                       check=True, capture_output=True)
        subprocess.run(["debugfs", "-w", "-R", "rm payload.dat", img_path],
                       check=True, capture_output=True)

        with open(img_path, "rb") as f:
            disk_bytes = f.read()
        disk_hash = hashlib.sha256(disk_bytes).hexdigest()
        print(f"    Ext4 image built  — Image SHA256: {disk_hash[:16]}...")
        print(f"                        Payload SHA256: {gt_sha256[:16]}...")

        # ── 4. UPLOAD EVIDENCE ────────────────────────────────────────────
        print(f"[4] Uploading evidence image (/cases/{case_id}/upload)...")
        with open(img_path, "rb") as f:
            r = client.post(
                f"/cases/{case_id}/upload",
                files={"file": ("live_ext4.img", f, "application/octet-stream")},
            )
        assert r.status_code == 200, f"Upload failed: {r.text}"
        up_data = r.json()
        assert up_data["sha256"] == disk_hash, "SHA256 mismatch on upload!"
        print(f"    Uploaded. Acquisition ID: {up_data['acquisition_id']} (bit-exact SHA256 verified)")

        # ── 5. DETECT FILESYSTEM ──────────────────────────────────────────
        print(f"[5] Identifying filesystem (/cases/{case_id}/filesystem)...")
        r = client.get(f"/cases/{case_id}/filesystem")
        assert r.status_code == 200, f"Filesystem detection failed: {r.text}"
        fs_data = r.json()
        assert fs_data.get("filesystem") == "ext4"
        assert fs_data.get("recovery_supported") is True
        print(f"    Detected Filesystem: {fs_data['filesystem']} (Recovery supported: True)")

        # ── 6. DISCOVER DELETED ARTIFACTS (fls) ───────────────────────────
        print(f"[6] Discovering deleted artifacts via SleuthKit fls (/cases/{case_id}/artifacts)...")
        r = client.get(f"/cases/{case_id}/artifacts")
        assert r.status_code == 200, f"Artifact discovery failed: {r.text}"
        artifacts = r.json()
        assert len(artifacts) > 0, "No deleted artifacts found by fls!"
        target = [a for a in artifacts if "payload.dat" in a.get("name", "")][0]
        inode = target["inode"]
        print(f"    Discovered {len(artifacts)} artifact(s). Target: payload.dat @ inode {inode}")

        # ── 7. RECOVER & HASH-VERIFY (icat) ──────────────────────────────
        print(f"[7] Recovering artifact via SleuthKit icat (/cases/{case_id}/forensic)...")
        r = client.post(f"/cases/{case_id}/forensic", json={
            "inode": inode,
            "artifact_name": "payload.dat",
            "reference_sha256": gt_sha256,
        })
        assert r.status_code == 200, f"Forensic recovery failed: {r.text}"
        rec_data = r.json()
        assert rec_data["classification"] == "VERIFIED", \
            f"Expected VERIFIED, got {rec_data['classification']}"
        assert rec_data["match"] is True
        assert rec_data["recovered_sha256"] == gt_sha256
        evidence_id = rec_data["evidence_id"]
        assert evidence_id.startswith("EVID-")
        print(f"    ✓ RECOVERY GATE PASSED! VERIFIED, hash match, Evidence ID: {evidence_id}")

        # ── 8. RETRIEVE SIGNED ENVELOPE ───────────────────────────────────
        print(f"[8] Retrieving signed evidence envelope (/evidence/{evidence_id})...")
        r = client.get(f"/evidence/{evidence_id}")
        assert r.status_code == 200, f"Envelope fetch failed: {r.text}"
        ev_pkg = r.json()
        # "signature" is a hex string; "signing" is the dict
        assert isinstance(ev_pkg["signature"], str) and len(ev_pkg["signature"]) > 0
        assert ev_pkg["signing"]["algorithm"] == "Ed25519"
        assert ev_pkg["signing"]["key_id"].startswith("KEY-")
        print(f"    Envelope retrieved — algorithm: {ev_pkg['signing']['algorithm']}, "
              f"key_id: {ev_pkg['signing']['key_id']}")

        # ── 9. INDEPENDENT CRYPTOGRAPHIC VERIFICATION ─────────────────────
        print(f"[9] Independent cryptographic verification (/evidence/{evidence_id}/verify)...")
        r = client.post(f"/evidence/{evidence_id}/verify")
        assert r.status_code == 200, f"Verify failed: {r.text}"
        ver_data = r.json()
        assert ver_data["is_valid"] is True, f"Signature invalid: {ver_data}"
        assert ver_data["classification"] == "VERIFIED"
        assert ver_data["details"]["signature_valid"] is True
        assert ver_data["details"]["hash_matches"] is True
        print("    ✓ Cryptographic Verification: PASSED (Ed25519 sig + hash both valid)")

        # ── 10. SECURITY ATTACK: Unauthorized Tamper ──────────────────────
        print(f"[10] Security Attack: /demo-tamper without X-Demo-Mode header...")
        r = client.post(f"/evidence/{evidence_id}/demo-tamper")
        assert r.status_code == 403, f"Expected 403, got {r.status_code}"
        print("    ✓ Unauthorized tamper BLOCKED: HTTP 403 Forbidden")

        # ── 11. SECURITY ATTACK: Path Traversal ───────────────────────────
        print("[11] Security Attack: Path traversal in case_id...")
        r = client.get("/cases/../../etc/passwd/filesystem")
        assert r.status_code in [400, 404], f"Expected 400/404, got {r.status_code}"
        print(f"    ✓ Path traversal BLOCKED: HTTP {r.status_code}")

        # ── 12. AUTHORIZED TAMPER DEMO ────────────────────────────────────────
        # The demo-tamper endpoint is stateless: it tampers a copy in memory,
        # runs the verifier on that copy, and returns the detection result inline.
        # It does NOT corrupt the stored evidence (by design: immutability guarantee).
        print("[12] Demonstrating tamper detection via stateless demo (authorized header)...")
        r = client.post(
            f"/evidence/{evidence_id}/demo-tamper",
            headers={"X-Demo-Mode": "1"},
        )
        assert r.status_code == 200, f"Demo tamper failed: {r.text}"
        tamper_data = r.json()
        assert tamper_data["tamper_detected"] is True, "Tamper was not detected!"
        assert tamper_data["is_valid"] is False
        assert tamper_data["classification"] == "INVALID"
        print(f"    ✓ Tamper caught inline: classification={tamper_data['classification']}, "
              f"tamper_detected={tamper_data['tamper_detected']}")
        print(f"      Tamper description: {tamper_data['tamper_description']}")

        # ── 13. VAULT IMMUTABILITY: STORED EVIDENCE STILL VALID ───────────
        # The demo-tamper must NOT have mutated the stored evidence.
        # A fresh verify of the vault copy must still pass.
        print("[13] Confirming vault immutability — stored evidence still cryptographically valid...")
        r = client.post(f"/evidence/{evidence_id}/verify")
        assert r.status_code == 200
        post_ver = r.json()
        assert post_ver["is_valid"] is True, \
            f"Vault evidence was mutated by demo-tamper! is_valid={post_ver['is_valid']}"
        assert post_ver["classification"] == "VERIFIED"
        print("    ✓ Vault immutability CONFIRMED: original evidence still VERIFIED after demo-tamper.")

        # ── 14. CHAIN-OF-CUSTODY TIMELINE ─────────────────────────────────
        print(f"[14] Auditing chain-of-custody timeline (/cases/{case_id}/timeline)...")
        r = client.get(f"/cases/{case_id}/timeline")
        assert r.status_code == 200
        timeline = r.json()
        event_types = [e["event_type"] for e in timeline]
        required_events = [
            "CASE_CREATED", "EVIDENCE_ACQUIRED", "FILESYSTEM_IDENTIFIED",
            "ARTIFACT_DISCOVERED", "RECOVERY_COMPLETED", "EVIDENCE_SIGNED",
        ]
        for evt in required_events:
            assert evt in event_types, f"Missing audit event: {evt}"
        print(f"    ✓ All {len(required_events)} chain-of-custody audit events verified: {event_types}")

    print("\n" + "=" * 60)
    print("  ALL 14 LIVE CONTAINER FORENSIC & SECURITY GATES PASSED!")
    print("=" * 60)


if __name__ == "__main__":
    test_container_lifecycle()
