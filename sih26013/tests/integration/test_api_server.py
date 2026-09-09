import pytest
from fastapi.testclient import TestClient
from app.api.server import app

client = TestClient(app)

def test_health_check():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OPERATIONAL"
    assert data["subsystems"]["spatial_index"] == "active"
    assert data["subsystems"]["cryptographic_trust"] == "active"

def test_create_and_list_cases():
    case_id = "CASE-INTEG-001"
    res = client.post("/cases", json={"case_id": case_id, "title": "Integration Test Case"})
    assert res.status_code == 201
    data = res.json()
    assert data["case_id"] == case_id

    res_list = client.get("/cases")
    assert res_list.status_code == 200
    cases = res_list.json()
    assert any(c["case_id"] == case_id for c in cases)

def test_ingest_and_analyze_lifecycle():
    case_id = "CASE-INTEG-002"
    client.post("/cases", json={"case_id": case_id, "title": "Full Lifecycle Case"})

    # Ingest 3 records sharing 1 origin
    ingest_payload = {
        "nodes": [
            {"node_id": "ORG-GOI", "node_type": "origin"},
            {"node_id": "DS-CAD", "node_type": "dataset", "parent_ids": ["ORG-GOI"]},
            {"node_id": "REC-A", "node_type": "record", "parent_ids": ["DS-CAD"]},
            {"node_id": "REC-B", "node_type": "record", "parent_ids": ["DS-CAD"]},
            {"node_id": "REC-C", "node_type": "record", "parent_ids": ["DS-CAD"]}
        ],
        "records": [
            {
                "record_id": "REC-A",
                "geometry": {
                    "type": "Polygon",
                    "coordinates": [[[77.0, 28.5], [77.1, 28.5], [77.1, 28.6], [77.0, 28.6], [77.0, 28.5]]]
                },
                "timestamp": "2024-01-15T10:00:00Z",
                "provenance_node_id": "REC-A"
            },
            {
                "record_id": "REC-B",
                "geometry": {
                    "type": "Polygon",
                    "coordinates": [[[77.05, 28.5], [77.15, 28.5], [77.15, 28.6], [77.05, 28.6], [77.05, 28.5]]]
                },
                "timestamp": "2024-01-17T10:00:00Z",
                "provenance_node_id": "REC-B"
            },
            {
                "record_id": "REC-C",
                "geometry": {
                    "type": "Polygon",
                    "coordinates": [[[77.0, 28.5], [77.1, 28.5], [77.1, 28.6], [77.0, 28.6], [77.0, 28.5]]]
                },
                "timestamp": "2024-01-20T10:00:00Z",
                "provenance_node_id": "REC-C"
            }
        ]
    }
    r_ingest = client.post(f"/cases/{case_id}/ingest", json=ingest_payload)
    assert r_ingest.status_code == 200
    d_ingest = r_ingest.json()
    assert d_ingest["records_accepted"] == 3
    assert d_ingest["nodes_added"] == 5

    # Run Analysis
    r_ana = client.post(f"/cases/{case_id}/analyze")
    assert r_ana.status_code == 200
    d_ana = r_ana.json()
    assert d_ana["total_ingested"] == 3
    assert d_ana["candidate_pairs_examined"] >= 1
    assert len(d_ana["signed_evidence_ids"]) >= 1

    # Verify key SIH story in the pairs
    cls_list = d_ana["classifications"]
    ab_pair = next(
        p for p in cls_list
        if (p["record_id_a"] == "REC-A" and p["record_id_b"] == "REC-B") or
           (p["record_id_a"] == "REC-B" and p["record_id_b"] == "REC-A")
    )
    assert ab_pair["geo_classification"] == "GEOMETRIC_CONFLICT"
    assert ab_pair["provenance_classification"] == "NOT_INDEPENDENT"
    assert ab_pair["independent_lineages"] == 1

    # Fetch Evidence from Vault
    ev_id = ab_pair["comparison_id"]
    r_ev = client.get(f"/evidence/{ev_id}")
    assert r_ev.status_code == 200
    env = r_ev.json()
    assert env["result"]["geo_classification"] == "GEOMETRIC_CONFLICT"
    assert env["result"]["independent_lineages"] == 1
    assert "signature" in env

    # Verify Authentic Evidence
    r_ver = client.post(f"/evidence/{ev_id}/verify")
    assert r_ver.status_code == 200
    d_ver = r_ver.json()
    assert d_ver["verified"] is True

    # Tamper Attack: Forge independent_lineages 1 -> 3
    tampered = dict(env)
    tampered["result"] = dict(env["result"])
    tampered["result"]["independent_lineages"] = 3

    r_tamper = client.post(f"/evidence/{ev_id}/verify", json={"envelope": tampered})
    assert r_tamper.status_code == 200
    d_tamper = r_tamper.json()
    assert d_tamper["verified"] is False
    assert "tamper" in d_tamper["explanation"].lower() or "mismatch" in d_tamper["explanation"].lower()

def test_audit_timeline():
    case_id = "CASE-INTEG-003"
    client.post("/cases", json={"case_id": case_id, "title": "Timeline Test"})
    r_tl = client.get(f"/cases/{case_id}/timeline")
    assert r_tl.status_code == 200
    tl = r_tl.json()
    assert len(tl) >= 1
    assert tl[0]["event_type"] == "CASE_CREATED"

def test_provenance_graph_export():
    case_id = "CASE-INTEG-004"
    client.post("/cases", json={"case_id": case_id, "title": "Prov Graph Test"})
    client.post(f"/cases/{case_id}/ingest", json={
        "nodes": [
            {"node_id": "ROOT-1", "node_type": "origin"},
            {"node_id": "CHILD-1", "node_type": "record", "parent_ids": ["ROOT-1"]}
        ],
        "records": []
    })
    r_pg = client.get(f"/cases/{case_id}/provenance")
    assert r_pg.status_code == 200
    pg = r_pg.json()
    assert len(pg["nodes"]) == 2
    assert len(pg["edges"]) == 1

def test_security_path_traversal_blocked():
    # Attempt directory traversal in case_id and evidence_id
    bad_ids = ["../../etc/passwd", "..\\boot.ini", "CASE-001/../../root"]
    for bad in bad_ids:
        r1 = client.get(f"/cases/{bad}")
        assert r1.status_code in (400, 404)
        r2 = client.get(f"/evidence/{bad}")
        assert r2.status_code in (400, 404)
