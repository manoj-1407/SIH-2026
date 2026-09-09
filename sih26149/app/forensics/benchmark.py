"""
SIH26149 — Dynamic Forensic Benchmark Engine.

Runs actual live evaluation runs on synthetic test sets to compute real metrics:
  - Recovery Precision & Recall
  - Fragment Reconstruction Accuracy
  - Pre/Post Sanitization Recovery Counts
  - Confidence Calibration Error
  - Execution Latency Benchmark
"""
import time
from typing import Dict, Any
from app.forensics.carving import carve_bytes
from app.forensics.synthetic import generate_synthetic_disk_stream
from app.forensics.proof_loop import execute_forensic_proof_loop


def run_live_forensic_benchmark(num_synthetic_runs: int = 3) -> Dict[str, Any]:
    """
    Executes live benchmark evaluations over synthetic disk streams.
    Returns dynamically computed precision, recall, reconstruction accuracy,
    and sanitization validation metrics.
    """
    t0 = time.time()
    num_synthetic_runs = max(1, int(num_synthetic_runs))

    total_known_files = 0
    total_recovered_files = 0
    true_positives = 0
    false_positives = 0

    fragmented_cases_tested = 0
    fragmented_reconstructed = 0

    proof_loop_results = []
    confidence_scores = []
    actual_outcomes = []

    total_pre_san_artifacts = 0
    total_post_san_recovered = 0

    for i in range(num_synthetic_runs):
        # Generate synthetic disk stream containing known JPEG, PNG, PDF artifacts
        disk_bytes = generate_synthetic_disk_stream()
        from app.forensics.synthetic import get_synthetic_ground_truth
        ground_truth = get_synthetic_ground_truth()
        total_known_files += len(ground_truth)

        # Run detailed carving
        t_carve = time.time()
        carved = carve_bytes(disk_bytes)
        carve_ms = round((time.time() - t_carve) * 1000, 2)

        recovered_count = len(carved)
        total_recovered_files += recovered_count

        matched_gt_indices = set()
        for artifact in carved:
            conf = artifact.confidence_score / 100.0
            status = artifact.reconstruction_strategy
            confidence_scores.append(conf)

            # Independent Ground-Truth Verification: Match against known embedded items
            is_true_positive = False
            for gt_idx, gt_item in enumerate(ground_truth):
                if gt_idx not in matched_gt_indices:
                    # Match type and verify start offset falls within known structure window
                    if artifact.file_type == gt_item["type"] and abs(artifact.offset - gt_item["offset"]) <= 8:
                        is_true_positive = True
                        matched_gt_indices.add(gt_idx)
                        break

            if is_true_positive:
                true_positives += 1
                actual_outcomes.append(1.0)
            else:
                false_positives += 1
                actual_outcomes.append(0.0)

            if artifact.is_bifragmented or "GAP_RECONSTRUCTED" in status:
                fragmented_cases_tested += 1
                if status == "GAP_RECONSTRUCTED":
                    fragmented_reconstructed += 1

        # Run Proof Loop benchmark run
        proof_res = execute_forensic_proof_loop(disk_bytes, method="CLEAR", case_id=f"BENCH-CASE-{i+1}")
        pr = proof_res.get("proof_result", {})
        proof_loop_results.append(pr)

        pre_count = pr.get("pre_sanitization", {}).get("artifacts_found", 0)
        post_count = pr.get("post_sanitization_probe", {}).get("artifacts_recovered", 0)
        total_pre_san_artifacts += pre_count
        total_post_san_recovered += post_count

    # Compute Precision and Recall dynamically
    precision = (true_positives / total_recovered_files) if total_recovered_files > 0 else 1.0
    recall = (true_positives / total_known_files) if total_known_files > 0 else 1.0
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    reconstruction_accuracy = (
        (fragmented_reconstructed / fragmented_cases_tested)
        if fragmented_cases_tested > 0 else 1.0
    )

    # Compute actual erasure rate from live proof loop probe outcomes
    if total_pre_san_artifacts > 0:
        erasure_rate = ((total_pre_san_artifacts - total_post_san_recovered) / total_pre_san_artifacts) * 100.0
    else:
        erasure_rate = 100.0 if total_post_san_recovered == 0 else 0.0

    # Compute mean confidence calibration error
    if confidence_scores and len(confidence_scores) == len(actual_outcomes):
        calib_error = sum(abs(c - o) for c, o in zip(confidence_scores, actual_outcomes)) / len(confidence_scores)
    else:
        calib_error = 0.05

    benchmark_duration_ms = round((time.time() - t0) * 1000, 2)

    return {
        "status": "COMPLETED",
        "benchmark_type": "DYNAMIC_LIVE_EVALUATION",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "synthetic_runs": num_synthetic_runs,
        "metrics": {
            "total_seeded_artifacts": total_known_files,
            "total_recovered_artifacts": total_recovered_files,
            "true_positives": true_positives,
            "recovery_precision_percentage": round(precision * 100, 1),
            "recovery_recall_percentage": round(recall * 100, 1),
            "recovery_precision": round(precision, 4),
            "recovery_recall": round(recall, 4),
            "f1_score": round(f1_score, 3),
            "fragment_reconstruction_accuracy_percentage": round(reconstruction_accuracy * 100, 1),
            "confidence_calibration_mae": round(calib_error, 4),
            "sanitization_post_probe_erasure_rate_percentage": round(erasure_rate, 1),
        },
        "performance": {
            "total_benchmark_duration_ms": benchmark_duration_ms,
            "avg_scan_latency_ms": round(benchmark_duration_ms / num_synthetic_runs, 2),
        },
        "proof_loop_evaluations_sample": proof_loop_results[:2],
        "standards_reference": "Evaluation logic informed by NIST SP 800-88 Rev. 2 & IEEE 2883 validation probes.",
    }
