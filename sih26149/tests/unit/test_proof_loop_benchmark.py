"""Unit tests for Forensic Proof Loop and Live Dynamic Benchmark."""
from app.forensics.synthetic import generate_synthetic_disk_stream
from app.forensics.proof_loop import execute_forensic_proof_loop
from app.forensics.benchmark import run_live_forensic_benchmark


def test_proof_loop_sequential_execution():
    disk = generate_synthetic_disk_stream()
    res = execute_forensic_proof_loop(disk, method="CLEAR")
    
    assert "proof_result" in res
    assert "signed_evidence" in res
    
    pr = res["proof_result"]
    assert pr["proof_loop_status"] == "SUCCESS"
    assert pr["pre_sanitization"]["artifacts_found"] >= 3
    assert pr["post_sanitization_probe"]["artifacts_recovered"] == 0
    assert pr["assurance"]["verification"]["passed"] is True
    assert pr["assurance"]["validation"]["passed"] is True
    assert pr["differential"]["erasure_percentage"] == 100.0


def test_live_forensic_benchmark():
    bench = run_live_forensic_benchmark(num_synthetic_runs=1)
    
    assert bench["status"] == "COMPLETED"
    assert bench["benchmark_type"] == "DYNAMIC_LIVE_EVALUATION"
    assert bench["metrics"]["recovery_precision_percentage"] >= 90.0
    assert bench["metrics"]["recovery_recall_percentage"] >= 90.0
    assert bench["metrics"]["sanitization_post_probe_erasure_rate_percentage"] == 100.0
