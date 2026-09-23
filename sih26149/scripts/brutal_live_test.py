"""
Brutal Real-Time Live Integration Test against http://127.0.0.1:8000
using authentic multi-source internet data, rigorous boundary attacks, and all API endpoints.
"""
import requests
import json
import time
from pathlib import Path

BASE = "http://127.0.0.1:8000"
DATA_DIR = Path("d:/SIH-2026/sih26149/data/real_samples")
CARRIER_FILE = DATA_DIR / "real_internet_carrier.raw"

print("=" * 75)
print("  SIH26149 COMPREHENSIVE LIVE BRUTAL API & DATA VERIFICATION (HTTP :8000)")
print("=" * 75)

session = requests.Session()
test_results = []

def record(name: str, passed: bool, detail: str = ""):
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}")
    if detail:
        print(f"       -> {str(detail)[:120]}")
    test_results.append((name, passed, detail))

# 1. Static Assets & Air-Gapped Verifier
r = session.get(f"{BASE}/")
record("GET / (Root Workstation UI)", r.status_code == 200, f"Status: {r.status_code}")

r = session.get(f"{BASE}/verifier.html")
record("GET /verifier.html (Air-gapped Verifier App)", r.status_code == 200 and "Zero-Install Offline Evidence Verifier" in r.text, f"Size: {len(r.text)} bytes")

# 2. Case Lifecycle Creation
payload = {
    "case_number": f"CASE-REAL-{int(time.time())}",
    "title": "Real Internet Multi-Format Forensic Investigation",
    "examiner_name": "Chief Forensic Examiner NTRO",
    "notes": "Testing raw carrier assembled with W3C, RFC, and Wikimedia artifacts"
}
r = session.post(f"{BASE}/cases", json=payload)
if r.status_code != 200 and r.status_code != 201:
    r = session.post(f"{BASE}/api/cases", json=payload)
record("POST /cases (Create Case)", r.status_code in (200, 201), r.text)
case_data = r.json()
case_id = case_data.get("case_id") or case_data.get("id")
print(f"[*] Active Case ID: {case_id}")

# 3. Real Internet Disk Image Acquisition / Upload (565 KB)
with open(CARRIER_FILE, "rb") as f:
    files = {"file": ("real_internet_carrier.raw", f, "application/octet-stream")}
    r = session.post(f"{BASE}/cases/{case_id}/upload", files=files)
record("POST /cases/{case_id}/upload (Authentic 565KB Internet Disk Image)", r.status_code == 200, r.text)
ingest_resp = r.json()
print(f"[*] Ingested SHA-256: {ingest_resp.get('sha256')}")

# 4. Filesystem Detection & Capability Evaluation
r = session.get(f"{BASE}/cases/{case_id}/filesystem")
record("GET /cases/{case_id}/filesystem (Capability & Gating)", r.status_code == 200, r.text)

# 5. Advanced File Carving across Real Internet Bytes
carve_req = {
    "target_types": ["JPEG", "PNG", "PDF", "ZIP"],
    "max_results": 100
}
r = session.post(f"{BASE}/cases/{case_id}/carve", json=carve_req)
record("POST /cases/{case_id}/carve (Carve Real Carrier)", r.status_code == 200, r.text)
carved_data = r.json()
carved_summary = carved_data.get("carved", {})
print(f"[*] Discovered & Carved {carved_summary.get('total_carved', 0)} Artifacts (Intact: {carved_summary.get('intact', 0)})")

# 6. Anti-Forensics & Evasion Detection on Real Image
r = session.post(f"{BASE}/cases/{case_id}/anti-forensics", json={})
record("POST /cases/{case_id}/anti-forensics (Timestomp, Entropy, Spoof Scan)", r.status_code == 200, r.text)
af_report = r.json() if r.status_code == 200 else {}
print(f"[*] Anti-Forensics Scan: Verdict={af_report.get('verdict')} | Entropy Anomalies={len(af_report.get('entropy_anomalies', []))}")

# 7. Live Forensic Proof Loop (Carve -> Validate -> Sanitize -> Proof)
r = session.post(f"{BASE}/cases/{case_id}/proof-loop")
record("POST /cases/{case_id}/proof-loop (Continuous Proof Loop)", r.status_code == 200, r.text)

# 8. NIST SP 800-88 DESTROY Branch Physical Disposal Manifest (JSON + HTML)
manifest_req = {
    "operator_id": "EXAMINER-NTRO-882",
    "operator_name": "Dr. S. K. Narayanan, Director Forensics",
    "authorization_reason": "High-assurance destruction of air-gapped carrier media",
    "serial_number": "WD-RED-ENTERPRISE-2026",
    "make_model": "Western Digital Ultrastar 4TB",
    "media_category": "magnetic_hdd",
    "destruction_method": "degaussing",
    "destruction_facility": "NTRO Secure Media Sanitization Lab, New Delhi",
    "witness_name": "R. C. Verma, Lead Witness",
    "notes": "Full custodial transfer under NIST SP 800-88 Rev. 2 DESTROY guidelines"
}
r = session.post(f"{BASE}/cases/{case_id}/destroy-manifest", json=manifest_req)
record("POST /cases/{case_id}/destroy-manifest (JSON)", r.status_code == 200, r.text)

r = session.post(f"{BASE}/cases/{case_id}/destroy-manifest?format=html", json=manifest_req)
record("POST /cases/{case_id}/destroy-manifest?format=html (Printable Manifest)", r.status_code == 200 and "<html" in r.text.lower(), f"HTML length: {len(r.text)} chars")

# 9. Gated Sanitization Execution
sanitize_req = {
    "operator_id": "EXAMINER-NTRO-882",
    "operator_name": "Dr. S. K. Narayanan",
    "authorization_reason": "Post-investigative secure clear sanitization",
    "confirmed_scope_acknowledgement": True,
    "method": "ZERO_FILL"
}
r = session.post(f"{BASE}/cases/{case_id}/sanitize", json=sanitize_req)
record("POST /cases/{case_id}/sanitize (Gated Logical Overwrite)", r.status_code == 200, r.text)

# 10. Audit Chain Timeline & Cryptographic Verification
r = session.get(f"{BASE}/cases/{case_id}/timeline")
timeline_entries = r.json() if isinstance(r.json(), list) else r.json().get('timeline', [])
record("GET /cases/{case_id}/timeline (Chain of Custody)", r.status_code == 200, f"{len(timeline_entries)} entries")

r = session.get(f"{BASE}/cases/{case_id}/timeline/verify")
record("GET /cases/{case_id}/timeline/verify (Audit Chain Integrity)", r.status_code == 200 and r.json().get("chain_valid") is True, r.text)

# 11. Rigorous Adversarial Security & Boundary Testing
# 11a. Unknown Case ID (404)
r = session.get(f"{BASE}/cases/CASE-INVALID-99999/timeline")
record("Security Boundary: 404 on Unknown Case ID", r.status_code == 404, f"Status: {r.status_code}")

# 11b. Malformed JSON Body (422)
r = session.post(f"{BASE}/cases", data="NOT_JSON_DATA", headers={"Content-Type": "application/json"})
record("Security Boundary: 422 on Malformed JSON Input", r.status_code == 422, f"Status: {r.status_code}")

# 11c. Path Traversal Filename Sanitization in Upload
mal_data = b"EVIL_SHELL_PAYLOAD_TEST"
files = {"file": ("../../../../win_system32_payload.dll", mal_data, "application/octet-stream")}
r = session.post(f"{BASE}/cases/{case_id}/upload", files=files)
record("Security Boundary: Neutralize Path Traversal Filenames", r.status_code == 200 and ".." not in r.json().get("filename", ""), f"Saved as: {r.json().get('filename') if r.status_code==200 else 'Rejected'}")

# 11d. Unauthorized Sanitization Without Scope Acknowledgement (403)
bad_sanitize = {
    "operator_id": "EXAMINER-BAD",
    "operator_name": "Unauthorized User",
    "authorization_reason": "No reason",
    "confirmed_scope_acknowledgement": False, # Explicit refusal
    "method": "ZERO_FILL"
}
r = session.post(f"{BASE}/cases/{case_id}/sanitize", json=bad_sanitize)
record("Security Boundary: 403 on Unconfirmed Scope Sanitization", r.status_code == 403, f"Status: {r.status_code}")

print("=" * 75)
passed_count = sum(1 for _, p, _ in test_results if p)
total_count = len(test_results)
print(f"  BRUTAL LIVE REAL-TIME TEST RESULTS: {passed_count}/{total_count} PASSED")
print("=" * 75)

assert passed_count == total_count, f"Expected {total_count} passes, got {passed_count}"
print("[+] ALL BRUTAL LIVE TESTS COMPLETED WITH 100% SUCCESS!")
