import io
import zipfile

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _case_with_signed_carving_evidence() -> tuple[str, str]:
    created = client.post("/cases", json={"workflow": "FORENSIC", "title": "Verifier demo integration"})
    assert created.status_code == 200
    case_id = created.json()["case_id"]

    seeded = client.post(f"/cases/{case_id}/seed-synthetic-evidence")
    assert seeded.status_code == 200

    carved = client.post(
        f"/cases/{case_id}/carve",
        json={"target_types": ["JPEG"], "max_results": 10},
    )
    assert carved.status_code == 200
    return case_id, carved.json()["evidence_id"]


def test_demo_routes_detect_three_attacks_and_reset_to_valid_state():
    case_id, evidence_id = _case_with_signed_carving_evidence()
    headers = {"X-Demo-Mode": "1"}
    demo_path = f"/cases/{case_id}/verifier-demo"

    attack = client.post(f"{demo_path}/tamper-audit-chain", headers=headers)
    assert attack.status_code == 200, attack.text
    chain = client.get(f"/cases/{case_id}/timeline/verify")
    assert chain.status_code == 200
    assert chain.json()["chain_valid"] is False
    reset = client.post(f"{demo_path}/reset", headers=headers)
    assert reset.status_code == 200 and reset.json()["restored"] is True
    assert client.get(f"/cases/{case_id}/timeline/verify").json()["chain_valid"] is True

    attack = client.post(
        f"{demo_path}/tamper-artifact",
        headers=headers,
        json={"evidence_id": evidence_id, "artifact_id": "DEMO-ARTIFACT", "byte_offset": 42},
    )
    assert attack.status_code == 200, attack.text
    verified = client.post(f"/evidence/{evidence_id}/verify")
    assert verified.status_code == 200
    assert verified.json()["verification_result"] == "INVALID"
    reset = client.post(f"{demo_path}/reset", headers=headers)
    assert reset.status_code == 200 and reset.json()["restored"] is True
    assert client.post(f"/evidence/{evidence_id}/verify").json()["verification_result"] == "VERIFIED"

    attack = client.post(f"{demo_path}/key-substitution", headers=headers)
    assert attack.status_code == 200, attack.text
    attacked_evidence_id = attack.json()["evidence_id"]
    verified = client.post(f"/evidence/{attacked_evidence_id}/verify")
    assert verified.status_code == 200
    assert verified.json()["verification_result"] == "INVALID"
    reset = client.post(f"{demo_path}/reset", headers=headers)
    assert reset.status_code == 200 and reset.json()["restored"] is True
    assert client.post(f"/evidence/{evidence_id}/verify").json()["verification_result"] == "VERIFIED"


def test_evidence_download_contains_signed_manifest_and_chain():
    case_id, evidence_id = _case_with_signed_carving_evidence()

    response = client.get(f"/evidence/{evidence_id}/download")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/zip")
    assert f"evidence_{case_id}_{evidence_id}_" in response.headers["content-disposition"]
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert "manifest.json" in archive.namelist()
        assert "cryptography/signature.json" in archive.namelist()
        assert "audit/events.jsonl" in archive.namelist()
        assert archive.getinfo("manifest.json").file_size > 0
        summary = archive.read("reports/evidence_summary.txt").decode()
        assert "does not retrieve recovered files from the source image" in summary
