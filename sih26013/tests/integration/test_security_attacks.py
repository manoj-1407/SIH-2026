import pytest
import copy
from fastapi.testclient import TestClient
from app.api.server import app

client = TestClient(app)

def test_security_malformed_geojson_rejected():
    case_id = "CASE-SEC-MALFORMED"
    client.post("/cases", json={"case_id": case_id})
    
    # 1. Non-dict geometry triggers Pydantic 422
    r_bad_type = client.post(f"/cases/{case_id}/ingest", json={"records": [{"record_id": "BAD-1", "geometry": "not-a-dict"}]})
    assert r_bad_type.status_code == 422

    # 2. Invalid GeoJSON dict structures rejected by geometry engine
    bad_recs = [
        {"record_id": "BAD-2", "geometry": {"type": "InvalidType", "coordinates": []}},
        {"record_id": "BAD-3", "geometry": {"type": "Polygon", "coordinates": []}},
    ]
    res = client.post(f"/cases/{case_id}/ingest", json={"records": bad_recs})
    assert res.status_code == 200
    data = res.json()
    assert data["records_accepted"] == 0
    assert len(data["records_rejected"]) == 2

def test_security_forged_signature_bytes_rejected():
    case_id = "CASE-SEC-FORGE-SIG"
    client.post("/cases", json={"case_id": case_id})
    client.post(f"/cases/{case_id}/ingest", json={
        "nodes": [
            {"node_id": "ORIGIN-1", "node_type": "origin"},
            {"node_id": "R1", "node_type": "record", "parent_ids": ["ORIGIN-1"]},
            {"node_id": "R2", "node_type": "record", "parent_ids": ["ORIGIN-1"]}
        ],
        "records": [
            {
                "record_id": "R1",
                "geometry": {"type": "Polygon", "coordinates": [[[77.0, 28.0], [77.1, 28.0], [77.1, 28.1], [77.0, 28.1], [77.0, 28.0]]]},
                "provenance_node_id": "R1"
            },
            {
                "record_id": "R2",
                "geometry": {"type": "Polygon", "coordinates": [[[77.05, 28.0], [77.15, 28.0], [77.15, 28.1], [77.05, 28.1], [77.05, 28.0]]]},
                "provenance_node_id": "R2"
            }
        ]
    })
    r_ana = client.post(f"/cases/{case_id}/analyze")
    ev_id = r_ana.json()["signed_evidence_ids"][0]
    
    # Load envelope
    env = client.get(f"/evidence/{ev_id}").json()
    
    # Attack: Flip bits in Ed25519 signature
    tampered_env = copy.deepcopy(env)
    sig = list(tampered_env["signature"])
    sig[0] = "0" if sig[0] != "0" else "1"
    tampered_env["signature"] = "".join(sig)
    
    r_ver = client.post(f"/evidence/{ev_id}/verify", json={"envelope": tampered_env})
    assert r_ver.status_code == 200
    assert r_ver.json()["verified"] is False
    assert "signature" in r_ver.json()["explanation"].lower() or "invalid" in r_ver.json()["explanation"].lower()

def test_security_forged_lineage_count_rejected():
    case_id = "CASE-SEC-FORGE-LINEAGE"
    client.post("/cases", json={"case_id": case_id})
    client.post(f"/cases/{case_id}/ingest", json={
        "nodes": [
            {"node_id": "ORIGIN-A", "node_type": "origin"},
            {"node_id": "REC-A1", "node_type": "record", "parent_ids": ["ORIGIN-A"]},
            {"node_id": "REC-A2", "node_type": "record", "parent_ids": ["ORIGIN-A"]}
        ],
        "records": [
            {
                "record_id": "REC-A1",
                "geometry": {"type": "Polygon", "coordinates": [[[77.0, 28.0], [77.1, 28.0], [77.1, 28.1], [77.0, 28.1], [77.0, 28.0]]]},
                "provenance_node_id": "REC-A1"
            },
            {
                "record_id": "REC-A2",
                "geometry": {"type": "Polygon", "coordinates": [[[77.05, 28.0], [77.15, 28.0], [77.15, 28.1], [77.05, 28.1], [77.05, 28.0]]]},
                "provenance_node_id": "REC-A2"
            }
        ]
    })
    r_ana = client.post(f"/cases/{case_id}/analyze")
    ev_id = r_ana.json()["signed_evidence_ids"][0]
    env = client.get(f"/evidence/{ev_id}").json()
    assert env["result"]["independent_lineages"] == 1

    # Attack: forge independent_lineages from 1 to 3
    tampered_env = copy.deepcopy(env)
    tampered_env["result"]["independent_lineages"] = 3
    
    r_ver = client.post(f"/evidence/{ev_id}/verify", json={"envelope": tampered_env})
    assert r_ver.status_code == 200
    assert r_ver.json()["verified"] is False
    assert "tamper" in r_ver.json()["explanation"].lower() or "mismatch" in r_ver.json()["explanation"].lower()

def test_security_circular_provenance_safe_fallback():
    # Provenance cycle must not cause server crash / stack overflow
    case_id = "CASE-SEC-CYCLE"
    client.post("/cases", json={"case_id": case_id})
    client.post(f"/cases/{case_id}/ingest", json={
        "nodes": [
            {"node_id": "CYCLE-A", "node_type": "dataset", "parent_ids": ["CYCLE-B"]},
            {"node_id": "CYCLE-B", "node_type": "dataset", "parent_ids": ["CYCLE-A"]},
            {"node_id": "REC-C1", "node_type": "record", "parent_ids": ["CYCLE-A"]},
            {"node_id": "REC-C2", "node_type": "record", "parent_ids": ["CYCLE-B"]}
        ],
        "records": [
            {
                "record_id": "REC-C1",
                "geometry": {"type": "Polygon", "coordinates": [[[77.0, 28.0], [77.1, 28.0], [77.1, 28.1], [77.0, 28.1], [77.0, 28.0]]]},
                "provenance_node_id": "REC-C1"
            },
            {
                "record_id": "REC-C2",
                "geometry": {"type": "Polygon", "coordinates": [[[77.05, 28.0], [77.15, 28.0], [77.15, 28.1], [77.05, 28.1], [77.05, 28.0]]]},
                "provenance_node_id": "REC-C2"
            }
        ]
    })
    r_ana = client.post(f"/cases/{case_id}/analyze")
    assert r_ana.status_code == 200
    d = r_ana.json()
    cls0 = d["classifications"][0]
    assert cls0["provenance_classification"] == "UNKNOWN"

def test_security_concurrent_ingest():
    import concurrent.futures
    case_id = "CASE-SEC-CONCURRENT"
    client.post("/cases", json={"case_id": case_id})

    def ingest_worker(w_id):
        return client.post(f"/cases/{case_id}/ingest", json={
            "records": [{
                "record_id": f"REC-TH-{w_id}",
                "geometry": {"type": "Point", "coordinates": [77.0 + w_id * 0.01, 28.0 + w_id * 0.01]}
            }]
        })

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(ingest_worker, i) for i in range(10)]
        results = [f.result() for f in futures]

    assert all(r.status_code == 200 for r in results)
    c_info = client.get(f"/cases/{case_id}").json()
    assert c_info["records_count"] == 10
