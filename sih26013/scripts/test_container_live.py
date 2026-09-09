#!/usr/bin/env python3
"""
M11 Live Container E2E Verification Suite for SIH26013.
Tests against the live running container at http://localhost:8001.
"""
import sys
import time
import requests
import json
import copy

BASE_URL = "http://localhost:8001"
PASS = "✓"
FAIL = "✗"
results = []

def check(name, cond, detail=""):
    sym = PASS if cond else FAIL
    results.append((name, cond))
    print(f"  {sym} {name}" + (f": {detail}" if detail else ""))
    if not cond:
        print(f"    DETAIL: {detail}")

print("=" * 65)
print("SIH26013 — M11: Live Container E2E Gate Verification")
print(f"Target: {BASE_URL}")
print("=" * 65)

# Wait for container health
print()
print("[Gate 1] Live Health & Subsystems Check")
healthy = False
for attempt in range(12):
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=2)
        if r.status_code == 200 and r.json().get("status") == "OPERATIONAL":
            healthy = True
            h_data = r.json()
            break
    except Exception:
        time.sleep(1)

check("Container health is OPERATIONAL", healthy)
if healthy:
    sub = h_data.get("subsystems", {})
    check("Spatial index active", sub.get("spatial_index") == "active")
    check("Cryptographic trust active", sub.get("cryptographic_trust") == "active")
    check("Signing key registered", len(h_data.get("signing_key_id", "")) > 0)
else:
    print("Container failed health check. Aborting.")
    sys.exit(1)

print()
print("[Gate 2] Create Live Case")
case_id = f"CASE-LIVE-{int(time.time())}"
r_case = requests.post(f"{BASE_URL}/cases", json={"case_id": case_id, "title": "Live Container E2E Case"})
check("Case created (HTTP 201)", r_case.status_code == 201)

print()
print("[Gate 3] Ingest 3 records sharing 1 lineage")
ingest_body = {
    "nodes": [
        {"node_id": "ORIGIN-GOI-SURVEY", "node_type": "origin"},
        {"node_id": "DS-CADASTER-DELHI", "node_type": "dataset", "parent_ids": ["ORIGIN-GOI-SURVEY"]},
        {"node_id": "REC-L1", "node_type": "record", "parent_ids": ["DS-CADASTER-DELHI"]},
        {"node_id": "REC-L2", "node_type": "record", "parent_ids": ["DS-CADASTER-DELHI"]},
        {"node_id": "REC-L3", "node_type": "record", "parent_ids": ["DS-CADASTER-DELHI"]}
    ],
    "records": [
        {
            "record_id": "REC-L1",
            "geometry": {"type": "Polygon", "coordinates": [[[77.0, 28.5], [77.1, 28.5], [77.1, 28.6], [77.0, 28.6], [77.0, 28.5]]]},
            "timestamp": "2024-01-10T10:00:00Z",
            "provenance_node_id": "REC-L1"
        },
        {
            "record_id": "REC-L2",
            "geometry": {"type": "Polygon", "coordinates": [[[77.05, 28.5], [77.15, 28.5], [77.15, 28.6], [77.05, 28.6], [77.05, 28.5]]]},
            "timestamp": "2024-01-12T10:00:00Z",
            "provenance_node_id": "REC-L2"
        },
        {
            "record_id": "REC-L3",
            "geometry": {"type": "Polygon", "coordinates": [[[77.0, 28.5], [77.1, 28.5], [77.1, 28.6], [77.0, 28.6], [77.0, 28.5]]]},
            "timestamp": "2024-01-14T10:00:00Z",
            "provenance_node_id": "REC-L3"
        }
    ]
}
r_ing = requests.post(f"{BASE_URL}/cases/{case_id}/ingest", json=ingest_body)
check("Ingest accepted 3 records", r_ing.status_code == 200 and r_ing.json().get("records_accepted") == 3)

print()
print("[Gate 4] Run Live Analysis")
r_ana = requests.post(f"{BASE_URL}/cases/{case_id}/analyze")
check("Analysis completed (HTTP 200)", r_ana.status_code == 200)
ana_data = r_ana.json()
check("Candidate pairs examined >= 1", ana_data.get("candidate_pairs_examined", 0) >= 1)
check("Signed evidence generated", len(ana_data.get("signed_evidence_ids", [])) >= 1)

print()
print("[Gate 5] Confirm Core SIH Story Dimensions Coexist")
cls_list = ana_data.get("classifications", [])
target_pair = next(
    p for p in cls_list
    if (p["record_id_a"] == "REC-L1" and p["record_id_b"] == "REC-L2") or
       (p["record_id_a"] == "REC-L2" and p["record_id_b"] == "REC-L1")
)
check("Geometry = GEOMETRIC_CONFLICT", target_pair["geo_classification"] == "GEOMETRIC_CONFLICT")
check("Provenance = NOT_INDEPENDENT", target_pair["provenance_classification"] == "NOT_INDEPENDENT")
check("Independent lineages = 1 (collapsed)", target_pair["independent_lineages"] == 1)

print()
print("[Gate 6] Retrieve Signed Evidence from Vault")
ev_id = target_pair["comparison_id"]
r_ev = requests.get(f"{BASE_URL}/evidence/{ev_id}")
check("Vault envelope retrieved", r_ev.status_code == 200)
env = r_ev.json()
check("Envelope has Ed25519 signature", len(env.get("signature", "")) > 0)
check("Signing key_id in envelope", "KEY-GEO-EXAMINER-26013" in env.get("signing", {}).get("key_id", ""))

print()
print("[Gate 7] Independent Cryptographic Verification")
r_ver = requests.post(f"{BASE_URL}/evidence/{ev_id}/verify")
check("Independent verification endpoint HTTP 200", r_ver.status_code == 200)
v_data = r_ver.json()
check("Vault evidence VERIFIED (Ed25519 valid)", v_data.get("verified") is True, v_data.get("explanation"))

print()
print("[Gate 8] Adversarial Tamper Attack: Forge Lineage 1 -> 3")
tampered_env = copy.deepcopy(env)
tampered_env["result"]["independent_lineages"] = 3
r_tamper = requests.post(f"{BASE_URL}/evidence/{ev_id}/verify", json={"envelope": tampered_env})
t_data = r_tamper.json()
check("Tampered envelope REJECTED as invalid", t_data.get("verified") is False)
check("Hash mismatch detected by verifier", "mismatch" in t_data.get("explanation", "").lower() or "tamper" in t_data.get("explanation", "").lower())

print()
print("[Gate 9] Missing Lineage Produces UNKNOWN (No Manufactured Truth)")
case_unk = f"CASE-UNK-{int(time.time())}"
requests.post(f"{BASE_URL}/cases", json={"case_id": case_unk, "title": "Unknown Test"})
requests.post(f"{BASE_URL}/cases/{case_unk}/ingest", json={
    "nodes": [],
    "records": [
        {
            "record_id": "U1",
            "geometry": {"type": "Polygon", "coordinates": [[[77.0, 28.5], [77.1, 28.5], [77.1, 28.6], [77.0, 28.6], [77.0, 28.5]]]},
            "timestamp": "2024-01-01T00:00:00Z",
            "provenance_node_id": None
        },
        {
            "record_id": "U2",
            "geometry": {"type": "Polygon", "coordinates": [[[77.05, 28.5], [77.15, 28.5], [77.15, 28.6], [77.05, 28.6], [77.05, 28.5]]]},
            "timestamp": "2024-01-02T00:00:00Z",
            "provenance_node_id": None
        }
    ]
})
r_ana_unk = requests.post(f"{BASE_URL}/cases/{case_unk}/analyze")
cls_unk = r_ana_unk.json()["classifications"][0]
check("Missing provenance yields UNKNOWN", cls_unk["provenance_classification"] == "UNKNOWN")
check("Overall unknown flag is True", cls_unk["unknown"] is True)

print()
print("[Gate 10] Immutable Audit Timeline Verified")
r_tl = requests.get(f"{BASE_URL}/cases/{case_id}/timeline")
check("Timeline retrieved", r_tl.status_code == 200)
events = [e["event_type"] for e in r_tl.json()]
check("CASE_CREATED logged", "CASE_CREATED" in events)
check("DATA_INGESTED logged", "DATA_INGESTED" in events)
check("ANALYSIS_COMPLETED logged", "ANALYSIS_COMPLETED" in events)

print()
print("=" * 65)
passed = sum(1 for _, ok in results if ok)
total = len(results)
print(f"  {passed}/{total} live container gates passed")
if passed == total:
    print("  LIVE CONTAINER VERIFICATION: ALL PASSED ✓")
else:
    print(f"  LIVE CONTAINER VERIFICATION: {total-passed} FAILED ✗")
    sys.exit(1)
print("=" * 65)
