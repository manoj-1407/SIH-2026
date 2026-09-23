"""Unit tests for Forensic Proof Loop and Live Dynamic Benchmark."""
from app.forensics.synthetic import generate_synthetic_disk_stream
from app.forensics.proof_loop import execute_forensic_proof_loop
from app.forensics.benchmark import run_live_forensic_benchmark
from scripts import package_clean_zip


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


def test_proof_loop_reports_failure_rather_than_crashing():
    result = execute_forensic_proof_loop(None, method="CLEAR", case_id="BAD-CASE")

    assert "proof_result" in result
    assert result["proof_result"]["proof_loop_status"] in {"FAILURE", "ERROR", "WARNING"}
    assert "error" in result["proof_result"].get("assurance", {}).get("validation", {}).get("detail", "").lower() or "error" in str(result["proof_result"].get("error", "")).lower()


def test_package_clean_zip_excludes_runtime_key_material():
    assert package_clean_zip.should_exclude("data/keys/primary_examiner.priv") is True
    assert package_clean_zip.should_exclude("data/keys/trust_registry.json") is True
    assert package_clean_zip.should_exclude("data/uploads/CASE-X/file.img") is True


def test_live_forensic_benchmark():
    bench = run_live_forensic_benchmark(num_synthetic_runs=1)

    assert bench["status"] == "COMPLETED"
    assert bench["benchmark_type"] == "DYNAMIC_LIVE_EVALUATION"
    assert bench["metrics"]["recovery_precision_percentage"] >= 90.0
    assert bench["metrics"]["recovery_recall_percentage"] >= 90.0
    assert bench["metrics"]["sanitization_post_probe_erasure_rate_percentage"] == 100.0
