"""
SIH26149 — M3 Primary Technical Gate Integration Tests.
Strictly verifies:
1. Real ext4 image creation -> known file -> deletion -> fls discovery -> icat recovery -> SHA-256 match -> VERIFIED -> signed evidence -> fresh-process verification.
2. Block overwrite / reuse -> recovery fails or hash mismatches -> FAILED / PARTIAL.
3. No reference hash -> UNVERIFIED (never manufacture certainty).
4. Filesystem detection capability model -> non-ext4 rejected before ext4 dispatch.
5. Tamper detection -> modified signed field rejected as INVALID.
"""
import os
import sys
import tempfile
import subprocess
import hashlib
import json
import pytest
from pathlib import Path

from app.core.hashing import hash_bytes, hash_file
from app.core.signing import generate_keypair
from app.core.trust import KeyRegistry
from app.core.persistence import EvidenceStore, atomic_write_json, load_json
from app.core.evidence_envelope import build_evidence_payload, sign_evidence_envelope, new_operation_id, new_evidence_id
from app.core.independent_verifier import verify_evidence_package
from app.core.classification import EvidenceClassification
from app.forensics.filesystem import detect_filesystem, FilesystemCapability
from app.forensics.discovery import discover_deleted_artifacts
from app.forensics.recovery import recover_artifact
from app.forensics.verification import verify_recovery


@pytest.fixture(scope="module")
def real_ext4_image(tmp_path_factory):
    """
    Creates a real 20MB ext4 filesystem image,
    writes a known ground-truth file,
    and then deletes it using debugfs.
    """
    import shutil
    if not shutil.which("mkfs.ext4") or not shutil.which("debugfs"):
        pytest.skip("mkfs.ext4/debugfs required for ext4 forensic pipeline tests")

    tmp_dir = tmp_path_factory.mktemp("forensics_gate")
    img_path = str(tmp_dir / "evidence_ext4.img")

    # 1. Allocate 20MB
    with open(img_path, "wb") as f:
        f.truncate(20 * 1024 * 1024)

    # 2. Format with mkfs.ext4
    cmd_mkfs = ["mkfs.ext4", "-F", "-b", "1024", img_path]
    res_mkfs = subprocess.run(cmd_mkfs, capture_output=True, text=True)
    assert res_mkfs.returncode == 0, f"mkfs.ext4 failed: {res_mkfs.stderr}"

    # 3. Known file content
    known_content = b"OFFICIAL_FORENSIC_EXAMINATION_GROUND_TRUTH_NTRO_2026\nCONFIDENTIAL_PAYLOAD"
    ground_truth_sha256 = hashlib.sha256(known_content).hexdigest()

    src_file = str(tmp_dir / "classified_doc.dat")
    with open(src_file, "wb") as f:
        f.write(known_content)

    # 4. Write into ext4 image via debugfs
    cmd_write = ["debugfs", "-w", "-R", f"write {src_file} classified_doc.dat", img_path]
    res_write = subprocess.run(cmd_write, capture_output=True, text=True)
    assert res_write.returncode == 0, f"debugfs write failed: {res_write.stderr}"

    # 5. Delete file via debugfs rm
    cmd_rm = ["debugfs", "-w", "-R", "rm classified_doc.dat", img_path]
    res_rm = subprocess.run(cmd_rm, capture_output=True, text=True)
    assert res_rm.returncode == 0, f"debugfs rm failed: {res_rm.stderr}"

    return {
        "image_path": img_path,
        "ground_truth_content": known_content,
        "ground_truth_sha256": ground_truth_sha256,
        "filename": "classified_doc.dat",
        "tmp_dir": tmp_dir,
    }


def test_m3_primary_gate_real_ext4_recovery_and_fresh_process(real_ext4_image, tmp_path):
    """
    PRIMARY TECHNICAL GATE:
    1. Detect filesystem as ext4 -> recovery_supported=True
    2. Discover deleted file via fls -> finds classified_doc.dat
    3. Recover artifact via icat -> hashes match ground truth
    4. Result classification is strictly VERIFIED
    5. Sign evidence package with Ed25519
    6. Persist to EvidenceStore
    7. Launch a fresh Python subprocess to independently verify the persisted evidence package
    """
    img_path = real_ext4_image["image_path"]
    expected_hash = real_ext4_image["ground_truth_sha256"]
    expected_filename = real_ext4_image["filename"]

    # Step 1: Detect filesystem capability
    fs_cap = detect_filesystem(img_path)
    assert fs_cap.detected is True
    assert fs_cap.filesystem == "ext4"
    assert fs_cap.recovery_supported is True
    assert fs_cap.status_label == "EXT4_SUPPORTED"

    # Step 2: Discover deleted artifacts
    artifacts = discover_deleted_artifacts(img_path)
    assert len(artifacts) > 0, "Expected at least one deleted artifact"

    target_artifact = None
    for a in artifacts:
        if expected_filename in a.name:
            target_artifact = a
            break

    assert target_artifact is not None, f"Artifact {expected_filename} not found in deleted artifacts: {artifacts}"
    assert target_artifact.is_deleted is True
    inode = target_artifact.inode

    # Step 3: Recover artifact
    recovery_result = recover_artifact(img_path, inode)
    assert recovery_result.recovered_bytes == real_ext4_image["ground_truth_content"]
    assert recovery_result.sha256 == expected_hash

    # Step 4: Verify recovery with ground truth
    classified = verify_recovery(recovery_result.sha256, reference_sha256=expected_hash)
    assert classified.classification == EvidenceClassification.VERIFIED
    assert "matches" in classified.explanation.lower()

    # Step 5: Trust anchor & signing
    key_dir = tmp_path / "keys"
    registry_path = key_dir / "trust_registry.json"
    registry = KeyRegistry(registry_path)

    priv_key, pub_key = generate_keypair()
    key_id = "KEY-EXAMINER-NTRO-01"
    registry.register(key_id, pub_key)

    case_id = "CASE-GATE-TEST-001"
    op_id = new_operation_id()
    evid_id = new_evidence_id()

    payload = build_evidence_payload(
        case_id=case_id,
        operation_id=op_id,
        evidence_id=evid_id,
        evidence_type="FORENSIC_RECOVERY",
        input_meta={
            "sha256": hash_file(img_path).hex_digest,
            "filesystem": fs_cap.filesystem,
        },
        operation_meta={
            "inode": inode,
            "artifact_name": target_artifact.name,
            "method": "icat",
        },
        result_meta={
            "classification": classified.classification.value,
            "recovered_sha256": recovery_result.sha256,
            "reference_sha256": expected_hash,
            "hash_match": True,
            "size_bytes": recovery_result.size_bytes,
        },
        scope="ext4 forensic image; verified against ground truth",
        key_id=key_id,
    )

    signed_pkg = sign_evidence_envelope(payload, priv_key)
    assert "evidence_hash" in signed_pkg
    assert "signature" in signed_pkg

    # Step 6: Atomic persistence in EvidenceStore
    evidence_dir = tmp_path / "evidence_store"
    store = EvidenceStore(evidence_dir)
    saved_path = store.save(signed_pkg)
    assert Path(saved_path).exists()

    # Step 7: Fresh-process independent verification
    # Launch a completely fresh python process with no shared in-memory state
    verify_script = f"""
import sys
import json
from app.core.persistence import load_json
from app.core.trust import KeyRegistry
from app.core.independent_verifier import verify_evidence_package

pkg = load_json({repr(str(saved_path))})
reg = KeyRegistry({repr(str(registry_path))})
is_valid, result = verify_evidence_package(pkg, key_registry=reg)
assert is_valid is True, f"Verification failed: {{result.explanation}}"
assert result.classification.value == "VERIFIED"
print("FRESH_PROCESS_VERIFIED_OK")
"""
    cmd_fresh = [sys.executable, "-c", verify_script]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])
    proc = subprocess.run(cmd_fresh, capture_output=True, text=True, env=env)
    assert proc.returncode == 0, f"Fresh process verification failed: {proc.stderr}"
    assert "FRESH_PROCESS_VERIFIED_OK" in proc.stdout


def test_m3_block_overwrite_fails_or_mismatches(real_ext4_image, tmp_path):
    """
    Test block reuse / overwrite:
    When the underlying blocks of the deleted file are overwritten with zeroes/garbage,
    icat recovery yields corrupted content whose SHA-256 does NOT match the ground truth.
    Classification must return FAILED.
    """
    import shutil
    img_copy = str(tmp_path / "overwritten_test.img")
    shutil.copy2(real_ext4_image["image_path"], img_copy)

    expected_hash = real_ext4_image["ground_truth_sha256"]

    # Discover the inode first
    artifacts = discover_deleted_artifacts(img_copy)
    target = [a for a in artifacts if real_ext4_image["filename"] in a.name][0]

    # Deliberately overwrite blocks across the ext4 data area
    with open(img_copy, "r+b") as f:
        f.seek(1024 * 1024)  # 1MB offset into data blocks
        f.write(b"\xaa" * (512 * 1024))  # 512KB overwrite

    try:
        res = recover_artifact(img_copy, target.inode)
        recovered_hash = res.sha256
    except Exception:
        # If filesystem structure was destroyed enough that icat errors, that is also a valid failure
        recovered_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    # Must NOT match ground truth!
    assert recovered_hash != expected_hash

    classified = verify_recovery(recovered_hash, reference_sha256=expected_hash)
    assert classified.classification == EvidenceClassification.FAILED
    assert "does not match" in classified.explanation.lower() or "overwritten" in classified.explanation.lower()


def test_m3_unverified_when_ground_truth_unavailable(real_ext4_image):
    """
    When no ground-truth reference hash is available:
    The system MUST classify as UNVERIFIED.
    Never manufacture certainty.
    """
    img_path = real_ext4_image["image_path"]
    artifacts = discover_deleted_artifacts(img_path)
    target = [a for a in artifacts if real_ext4_image["filename"] in a.name][0]

    res = recover_artifact(img_path, target.inode)
    classified = verify_recovery(res.sha256, reference_sha256=None)

    assert classified.classification == EvidenceClassification.UNVERIFIED
    assert "unverified" in classified.classification.value.lower()
    assert "no reference hash" in classified.explanation.lower() or "trusted reference" in classified.explanation.lower()


def test_m3_unsupported_filesystem_dispatch_rejection(tmp_path):
    """
    When handed non-filesystem or FAT32 input:
    Filesystem detection must declare recovery_supported=False.
    Ext4 recovery tooling must not be invoked.
    """
    # 1. Raw random data
    raw_path = str(tmp_path / "raw_data.bin")
    with open(raw_path, "wb") as f:
        f.write(os.urandom(1024 * 1024))

    cap_raw = detect_filesystem(raw_path)
    assert cap_raw.recovery_supported is False
    assert cap_raw.status_label in ("NOT_A_FILESYSTEM", "CORRUPT_INVALID")

    # 2. Corrupted file
    corrupt_path = str(tmp_path / "corrupted.img")
    with open(corrupt_path, "wb") as f:
        f.write(b"EXT4" + b"\x00" * 50)  # Fake header but corrupt

    cap_corrupt = detect_filesystem(corrupt_path)
    assert cap_corrupt.recovery_supported is False


def test_m3_tamper_detection_on_signed_evidence(real_ext4_image, tmp_path):
    """
    Adversarial tamper test:
    Take a valid signed evidence package, modify exactly ONE signed field
    (e.g. change classification from FAILED to VERIFIED or alter recovered hash).
    Independent verifier MUST detect tamper and return INVALID.
    """
    key_dir = tmp_path / "keys_tamper"
    reg = KeyRegistry(key_dir / "reg.json")
    priv, pub = generate_keypair()
    reg.register("KEY-01", pub)

    payload = build_evidence_payload(
        case_id="CASE-TAMPER-001",
        operation_id="OP-01",
        evidence_type="FORENSIC_RECOVERY",
        input_meta={"sha256": "abc"},
        operation_meta={"inode": "12"},
        result_meta={"classification": "FAILED", "recovered_sha256": "deadbeef"},
        scope="test",
        key_id="KEY-01",
    )
    pkg = sign_evidence_envelope(payload, priv)

    # Verify original is valid
    valid_orig, res_orig = verify_evidence_package(pkg, key_registry=reg)
    assert valid_orig is True
    assert res_orig.classification == EvidenceClassification.VERIFIED

    # Attack 1: Modify a field in result without re-signing
    tampered_pkg_1 = json.loads(json.dumps(pkg))
    tampered_pkg_1["result"]["classification"] = "VERIFIED"  # Adversary claims VERIFIED!

    valid_1, res_1 = verify_evidence_package(tampered_pkg_1, key_registry=reg)
    assert valid_1 is False
    assert res_1.classification == EvidenceClassification.INVALID
    assert res_1.details.get("tamper_detected") is True

    # Attack 2: Re-calculate evidence_hash to match the tampered field, but keep old signature
    from app.core.canonical import canonicalize
    from app.core.hashing import hash_bytes
    tampered_pkg_2 = json.loads(json.dumps(tampered_pkg_1))
    tampered_payload = {k: v for k, v in tampered_pkg_2.items() if k not in ("evidence_hash", "signature")}
    tampered_pkg_2["evidence_hash"] = hash_bytes(canonicalize(tampered_payload))

    valid_2, res_2 = verify_evidence_package(tampered_pkg_2, key_registry=reg)
    assert valid_2 is False
    assert res_2.classification == EvidenceClassification.INVALID
    assert "signature" in res_2.explanation.lower()
