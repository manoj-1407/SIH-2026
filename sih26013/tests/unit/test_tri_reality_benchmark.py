"""Unit tests for Tri-Reality Reconciliation and Geospatial Live Benchmark."""
from app.core.reconciliation import calculate_tri_reality_reconciliation, simulate_counterfactual_harmonization
from app.core.benchmark import run_live_geospatial_benchmark


def test_tri_reality_reconciliation_and_uncertainty():
    legal = {
        "record_id": "P-101",
        "source_system": "CADASTRAL",
        "source_type": "CADASTRAL",
        "geometry": {"type": "Polygon", "coordinates": [[[77.10, 28.60], [77.11, 28.60], [77.11, 28.61], [77.10, 28.61], [77.10, 28.60]]]}
    }
    observed = {
        "record_id": "DRONE-101",
        "source_system": "DRONE",
        "source_type": "DRONE",
        "geometry": {"type": "Polygon", "coordinates": [[[77.1001, 28.6001], [77.1101, 28.6001], [77.1101, 28.6101], [77.1001, 28.6101], [77.1001, 28.6001]]]}
    }
    
    rec = calculate_tri_reality_reconciliation(legal_record=legal, observed_record=observed)
    assert "tri_boundary_realities" in rec
    assert "spatial_discrepancy_analysis" in rec
    assert len(rec["conflict_hypotheses"]) > 0
    assert rec["spatial_discrepancy_analysis"]["legal_vs_observed_shift_m"] > 0.0


def test_counterfactual_simulation():
    legal = {
        "record_id": "P-101",
        "source_system": "CADASTRAL",
        "source_type": "CADASTRAL",
        "geometry": {"type": "Polygon", "coordinates": [[[77.10, 28.60], [77.11, 28.60], [77.11, 28.61], [77.10, 28.61], [77.10, 28.60]]]}
    }
    cf = simulate_counterfactual_harmonization(legal_record=legal)
    assert "counterfactual_scenarios" in cf
    assert len(cf["counterfactual_scenarios"]) == 3
    assert cf["human_decision_queue_status"] == "PENDING_OFFICIAL_APPROVAL"


def test_live_geospatial_benchmark():
    bench = run_live_geospatial_benchmark(num_synthetic_parcels=2)
    assert bench["status"] == "COMPLETED"
    assert bench["benchmark_type"] == "DYNAMIC_LIVE_GEOSPATIAL_EVALUATION"
    assert bench["metrics"]["entity_matching_accuracy_percentage"] >= 90.0
    assert bench["metrics"]["topology_repair_success_rate"] == 100.0
