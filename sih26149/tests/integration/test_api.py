"""
SIH26149 — FastAPI REST API Integration Tests.
Tests full HTTP lifecycle:
1. Health check & forensic tool verification
2. Forensic investigation workflow (Case -> Upload -> Detect -> Discover -> Recover -> Sign -> Verify -> Tamper)
3. Sanitization workflow (Unauthorized rejected -> Authorized within scope)
4. Chain-of-custody timeline verification
"""
import os
import io
import subprocess
import hashlib
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@pytest.fixture(scope="module")
def sample_ext4_image(tmp_path_factory):
    import shutil
    if not shutil.which("mkfs.ext4") or not shutil.which("debugfs"):
        pytest.skip("mkfs.ext4/debugfs required for ext4 integration test")

    tmp_dir = tmp_path_factory.mktemp("api_forensic")
    img_path = str(tmp_dir / "api_ext4.img")

    # 1. 20MB image
    with open(img_path, "wb") as f:
        f.truncate(20 * 1024 * 1024)

    # 2. mkfs.ext4
    subprocess.run(["mkfs.ext4", "-F", "-b", "1024", img_path], check=True, capture_output=True)

    # 3. Known file
    content = b"EVIDENCE_API_VERIFICATION_PAYLOAD_2026"
    gt_sha256 = hashlib.sha256(content).hexdigest()

    src_file = str(tmp_dir / "payload.dat")
    with open(src_file, "wb") as f:
        f.write(content)

    # 4. write and delete via debugfs
    subprocess.run(["debugfs", "-w", "-R", f"write {src_file} payload.dat", img_path], check=True, capture_output=True)
    subprocess.run(["debugfs", "-w", "-R", "rm payload.dat", img_path], check=True, capture_output=True)

    return {
        "img_path": img_path,
        "gt_sha256": gt_sha256,
        "content": content,
    }


def test_api_health():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OPERATIONAL"
    assert "fls" in data["tools"]
    assert "icat" in data["tools"]


def test_api_forensic_lifecycle(sample_ext4_image):
    # 1. Create Case
    res_case = client.post("/cases", json={
        "workflow": "FORENSIC",
        "title": "Case 2026-NTRO-001",
        "description": "Examination of recovered storage volume",
    })
    assert res_case.status_code == 200
    case_data = res_case.json()
    case_id = case_data["case_id"]
    assert case_id.startswith("CASE-")

    # 2. Upload Evidence Image
    img_path = sample_ext4_image["img_path"]
    with open(img_path, "rb") as f:
        res_up = client.post(
            f"/cases/{case_id}/upload",
            files={"file": ("evidence.img", f, "application/octet-stream")},
        )
    assert res_up.status_code == 200
    up_data = res_up.json()
    assert "sha256" in up_data

    # 3. Detect Filesystem
    res_fs = client.get(f"/cases/{case_id}/filesystem")
    assert res_fs.status_code == 200
    fs_data = res_fs.json()
    assert fs_data["filesystem"] == "ext4"
    assert fs_data["recovery_supported"] is True

    # 4. Discover Deleted Artifacts
    res_art = client.get(f"/cases/{case_id}/artifacts")
    assert res_art.status_code == 200
    artifacts = res_art.json()
    assert len(artifacts) > 0
    target = [a for a in artifacts if "payload.dat" in a["name"]][0]
    inode = target["inode"]

    # 5. Run Forensic Recovery (with ground truth)
    res_rec = client.post(f"/cases/{case_id}/forensic", json={
        "inode": inode,
        "artifact_name": "payload.dat",
        "reference_sha256": sample_ext4_image["gt_sha256"],
    })
    assert res_rec.status_code == 200
    rec_data = res_rec.json()
    assert rec_data["classification"] == "VERIFIED"
    assert rec_data["match"] is True
    assert rec_data["recovered_sha256"] == sample_ext4_image["gt_sha256"]
    evidence_id = rec_data["evidence_id"]
    assert evidence_id.startswith("EVID-")

    # 6. Retrieve Evidence Package from Vault
    res_ev = client.get(f"/evidence/{evidence_id}")
    assert res_ev.status_code == 200
    ev_pkg = res_ev.json()
    assert ev_pkg["evidence_id"] == evidence_id
    assert "signature" in ev_pkg

    # 7. Verify Stored Evidence
    res_v = client.post(f"/evidence/{evidence_id}/verify")
    assert res_v.status_code == 200
    v_data = res_v.json()
    assert v_data["is_valid"] is True
    assert v_data["classification"] == "VERIFIED"

    # 8. Demo Tamper Test
    res_t = client.post(f"/evidence/{evidence_id}/demo-tamper", headers={"X-Demo-Mode": "1"})
    assert res_t.status_code == 200
    t_data = res_t.json()
    assert t_data["is_valid"] is False
    assert t_data["classification"] == "INVALID"
    assert t_data["tamper_detected"] is True

    # 9. Verify Chain-of-Custody Timeline
    res_time = client.get(f"/cases/{case_id}/timeline")
    assert res_time.status_code == 200
    timeline = res_time.json()
    event_types = [e["event_type"] for e in timeline]
    assert "CASE_CREATED" in event_types
    assert "EVIDENCE_ACQUIRED" in event_types
    assert "FILESYSTEM_IDENTIFIED" in event_types
    assert "ARTIFACT_DISCOVERED" in event_types
    assert "RECOVERY_COMPLETED" in event_types
    assert "EVIDENCE_SIGNED" in event_types


def test_api_sanitization_lifecycle(sample_ext4_image):
    # 1. Create Sanitization Case
    res_case = client.post("/cases", json={
        "workflow": "SANITIZATION",
        "title": "Sanitization Case NTRO-SAN-01",
    })
    case_id = res_case.json()["case_id"]

    # 2. Upload target image
    with open(sample_ext4_image["img_path"], "rb") as f:
        client.post(
            f"/cases/{case_id}/upload",
            files={"file": ("target.img", f, "application/octet-stream")},
        )

    # 3. Unauthorized request (missing credentials) -> 403 Forbidden
    res_unauth = client.post(f"/cases/{case_id}/sanitize", json={
        "operator_id": "",
        "operator_name": "",
        "authorization_reason": "",
        "confirmed_scope_acknowledgement": False,
    })
    assert res_unauth.status_code == 403

    # 4. Authorized request -> 200 OK + VERIFIED_WITHIN_SCOPE
    res_auth = client.post(f"/cases/{case_id}/sanitize", json={
        "operator_id": "OPR-SEC-99",
        "operator_name": "Special Agent Roy",
        "authorization_reason": "Device sanitization protocol NTRO-2026-B",
        "confirmed_scope_acknowledgement": True,
    })
    assert res_auth.status_code == 200
    san_data = res_auth.json()
    assert san_data["classification"] == "VERIFIED_WITHIN_SCOPE"
    assert "scope" in san_data
    assert "nand" in san_data["scope"]["scope_statement"].lower()
    ev_id = san_data["evidence_id"]

    # 5. Verify signed sanitization package
    res_ver = client.post(f"/evidence/{ev_id}/verify")
    assert res_ver.status_code == 200
    assert res_ver.json()["is_valid"] is True
