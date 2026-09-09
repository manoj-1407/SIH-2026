"""
SIH26013 — Dynamic Geospatial Benchmark Engine.

Executes live evaluation runs across synthetic multi-source ground-truth test sets:
  - Hybrid Geospatial Entity Matching (Ground-truth TP / TN pairs)
  - Positional Discrepancy Detection & False-Conflict Rates (Error-envelope validation)
  - Automated Cadastral Topology Overlap Repair
  - Execution Processing Latencies
"""
import time
from typing import Dict, Any, List
from app.core.canonical_model import CanonicalParcel, AgencyType, LandUseType
from app.core.ai_matcher import match_parcels
from app.core.topology_repair import repair_cadastral_topology
from app.core.reconciliation import calculate_tri_reality_reconciliation


def run_live_geospatial_benchmark(num_synthetic_parcels: int = 4, runs: int = 1) -> Dict[str, Any]:
    """
    Executes live benchmark evaluations over synthetic parcel datasets with ground truth.
    Returns dynamically computed spatial matching accuracy, discrepancy detection rate,
    false conflict rate, and topology repair metrics across all execution runs.
    """
    t0 = time.time()
    runs = max(1, int(runs))

    match_tp = 0
    match_tn = 0
    match_fp = 0
    match_fn = 0

    disc_tp = 0
    disc_fn = 0
    conf_fp = 0
    conf_tn = 0

    total_topo_anomalies_before = 0
    total_topo_anomalies_after = 0

    total_match_ms = 0.0
    total_topo_ms = 0.0

    sample_rec = None

    for r in range(runs):
        # ── 1. Ground Truth Matching Dataset ─────────────────────────────────────
        # Ground-Truth Positive Pairs (Same parcel, dual-agency with minor survey noise)
        pos_records_a: List[CanonicalParcel] = []
        pos_records_b: List[CanonicalParcel] = []
        # Ground-Truth Negative Pairs (Different parcels, distinct locations)
        neg_records: List[CanonicalParcel] = []

        base_lat, base_lon = 12.9716 + (r * 0.05), 77.5946 + (r * 0.05)

        for i in range(num_synthetic_parcels):
            lat = base_lat + (i * 0.005)
            lon = base_lon + (i * 0.005)
            poly_a = {
                "type": "Polygon",
                "coordinates": [[[lon, lat], [lon + 0.002, lat], [lon + 0.002, lat + 0.002], [lon, lat + 0.002], [lon, lat]]],
            }
            # Slightly jittered coordinates for agency B (representing GNSS vs Revenue digitization variance)
            poly_b = {
                "type": "Polygon",
                "coordinates": [[[lon + 0.00002, lat + 0.00002], [lon + 0.00202, lat + 0.00002], [lon + 0.00202, lat + 0.00202], [lon + 0.00002, lat + 0.00202], [lon + 0.00002, lat + 0.00002]]],
            }

            p_a = CanonicalParcel.create(
                parcel_id=f"RUN{r}-REV-{i+1}",
                survey_number=f"SY-{200+i}",
                geometry=poly_a,
                owner_ref=f"Citizen {i+1}",
                area_sq_m=1200.0,
                source_agency=AgencyType.REVENUE,
                land_use=LandUseType.RESIDENTIAL,
            )
            p_b = CanonicalParcel.create(
                parcel_id=f"RUN{r}-MUN-{i+1}",
                survey_number=f"SY-{200+i}",
                geometry=poly_b,
                owner_ref=f"Citizen {i+1}",
                area_sq_m=1200.0,
                source_agency=AgencyType.MUNICIPAL,
                land_use=LandUseType.RESIDENTIAL,
            )
            pos_records_a.append(p_a)
            pos_records_b.append(p_b)

            # Distinct negative record at offset location
            neg_poly = {
                "type": "Polygon",
                "coordinates": [[[lon + 0.05, lat + 0.05], [lon + 0.052, lat + 0.05], [lon + 0.052, lat + 0.052], [lon + 0.05, lat + 0.052], [lon + 0.05, lat + 0.05]]],
            }
            neg_records.append(
                CanonicalParcel.create(
                    parcel_id=f"RUN{r}-DISJOINT-{i+1}",
                    survey_number=f"SY-{900+i}",
                    geometry=neg_poly,
                    owner_ref=f"Remote Owner {i+1}",
                    area_sq_m=2400.0,
                    source_agency=AgencyType.CADASTRAL,
                    land_use=LandUseType.COMMERCIAL,
                )
            )

        # Evaluate Positive Pairs (Expect Match >= 0.60)
        t_m0 = time.time()
        for p_a, p_b in zip(pos_records_a, pos_records_b):
            res = match_parcels(p_a, p_b)
            if res.match_probability >= 0.60:
                match_tp += 1
            else:
                match_fn += 1

        # Evaluate Negative Pairs (Expect Match < 0.60)
        for p_a, p_neg in zip(pos_records_a, neg_records):
            res = match_parcels(p_a, p_neg)
            if res.match_probability >= 0.60:
                match_fp += 1
            else:
                match_tn += 1
        total_match_ms += (time.time() - t_m0) * 1000

        # ── 2. Ground Truth Discrepancy & Conflict Dataset ──────────────────────
        # Case A: Controlled Ground Truth Discrepant Scenario (Drone shifted ~9.4m beyond combined ±2.03m error envelope)
        disc_poly_legal = {
            "type": "Polygon",
            "coordinates": [[[77.594600, 12.971600], [77.596600, 12.971600], [77.596600, 12.973600], [77.594600, 12.973600], [77.594600, 12.971600]]],
        }
        disc_poly_gnss = {
            "type": "Polygon",
            "coordinates": [[[77.594602, 12.971602], [77.596602, 12.971602], [77.596602, 12.973602], [77.594602, 12.973602], [77.594602, 12.971602]]],
        }
        disc_poly_drone = {
            "type": "Polygon",
            "coordinates": [[[77.594660, 12.971660], [77.596660, 12.971660], [77.596660, 12.973660], [77.594660, 12.973660], [77.594660, 12.971660]]],
        }

        rec_discrepant = calculate_tri_reality_reconciliation(
            legal_record={"record_id": f"RUN{r}-LEG-D", "source_system": "CADASTRAL", "source_type": "CADASTRAL", "geometry": disc_poly_legal},
            surveyed_record={"record_id": f"RUN{r}-GNSS-D", "source_system": "GNSS", "source_type": "GNSS", "geometry": disc_poly_gnss},
            observed_record={"record_id": f"RUN{r}-DRONE-D", "source_system": "DRONE", "source_type": "DRONE", "geometry": disc_poly_drone},
        )
        if sample_rec is None:
            sample_rec = rec_discrepant

        if rec_discrepant.get("spatial_discrepancy_analysis", {}).get("conflict_status") == "DISCREPANCY_EXCEEDS_TOLERANCE" or rec_discrepant.get("discrepancy_status") == "DISCREPANCY_EXCEEDS_TOLERANCE":
            disc_tp += 1
        else:
            disc_fn += 1

        # Case B: Controlled Ground Truth Concordant Scenario (Within ±0.35m tolerance envelope)
        rec_concordant = calculate_tri_reality_reconciliation(
            legal_record={"record_id": f"RUN{r}-LEG-C", "source_system": "CADASTRAL", "source_type": "CADASTRAL", "geometry": disc_poly_legal},
            surveyed_record={"record_id": f"RUN{r}-GNSS-C", "source_system": "GNSS", "source_type": "GNSS", "geometry": disc_poly_gnss},
            observed_record={"record_id": f"RUN{r}-DRONE-C", "source_system": "DRONE", "source_type": "DRONE", "geometry": disc_poly_gnss},
        )
        if rec_concordant.get("spatial_discrepancy_analysis", {}).get("conflict_status") == "DISCREPANCY_EXCEEDS_TOLERANCE" or rec_concordant.get("discrepancy_status") == "DISCREPANCY_EXCEEDS_TOLERANCE":
            conf_fp += 1
        else:
            conf_tn += 1

        # ── 3. Ground Truth Topology Overlap Scenario ───────────────────────────
        # Create 2 deliberately overlapping parcels to evaluate topology repair
        overlap_poly_1 = {
            "type": "Polygon",
            "coordinates": [[[77.50, 12.90], [77.52, 12.90], [77.52, 12.92], [77.50, 12.92], [77.50, 12.90]]],
        }
        overlap_poly_2 = {
            "type": "Polygon",
            "coordinates": [[[77.51, 12.90], [77.53, 12.90], [77.53, 12.92], [77.51, 12.92], [77.51, 12.90]]],
        }
        p_over1 = CanonicalParcel.create(
            parcel_id=f"RUN{r}-TOPO-1",
            survey_number=f"SY-TOPO-1",
            geometry=overlap_poly_1,
            owner_ref="Owner A",
            area_sq_m=2000.0,
            source_agency=AgencyType.CADASTRAL,
        )
        p_over2 = CanonicalParcel.create(
            parcel_id=f"RUN{r}-TOPO-2",
            survey_number=f"SY-TOPO-2",
            geometry=overlap_poly_2,
            owner_ref="Owner B",
            area_sq_m=2000.0,
            source_agency=AgencyType.CADASTRAL,
        )
        t_t0 = time.time()
        topo_res = repair_cadastral_topology([p_over1, p_over2])
        total_topo_ms += (time.time() - t_t0) * 1000

        total_topo_anomalies_before += len(topo_res.anomalies_detected)
        if topo_res.residual_overlap_sq_m == 0.0:
            total_topo_anomalies_after += 0
        else:
            residual_ratio = topo_res.residual_overlap_sq_m / max(0.01, topo_res.initial_overlap_sq_m)
            total_topo_anomalies_after += max(1, int(len(topo_res.anomalies_detected) * residual_ratio))

    # ── Aggregate Dynamic Metrics ────────────────────────────────────────────────
    total_match_evaluations = match_tp + match_tn + match_fp + match_fn
    matching_accuracy = ((match_tp + match_tn) / total_match_evaluations) if total_match_evaluations > 0 else 1.0

    total_discrepant_cases = disc_tp + disc_fn
    discrepancy_detection_rate = (disc_tp / total_discrepant_cases) if total_discrepant_cases > 0 else 1.0

    total_concordant_cases = conf_fp + conf_tn
    false_conflict_rate = (conf_fp / total_concordant_cases) if total_concordant_cases > 0 else 0.0

    if total_topo_anomalies_before > 0:
        resolved = max(0, total_topo_anomalies_before - total_topo_anomalies_after)
        topo_repair_success = (resolved / total_topo_anomalies_before) * 100.0
    else:
        topo_repair_success = 100.0

    total_duration_ms = round((time.time() - t0) * 1000, 2)

    return {
        "status": "COMPLETED",
        "benchmark_type": "DYNAMIC_LIVE_GEOSPATIAL_EVALUATION",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "synthetic_runs": runs,
        "synthetic_parcels_evaluated_per_run": num_synthetic_parcels,
        "metrics": {
            "entity_matching_accuracy_percentage": round(matching_accuracy * 100.0, 1),
            "discrepancy_detection_rate_percentage": round(discrepancy_detection_rate * 100.0, 1),
            "false_conflict_rate_percentage": round(false_conflict_rate * 100.0, 1),
            "topology_violations_before": total_topo_anomalies_before,
            "topology_violations_after": total_topo_anomalies_after,
            "topology_repair_success_percentage": round(topo_repair_success, 1),
            "topology_repair_success_rate": round(topo_repair_success, 1),
            "matching_evaluations": {
                "true_positives": match_tp,
                "true_negatives": match_tn,
                "false_positives": match_fp,
                "false_negatives": match_fn,
            },
        },
        "performance": {
            "total_benchmark_duration_ms": total_duration_ms,
            "spatial_entity_matching_time_ms": round(total_match_ms, 2),
            "topology_repair_time_ms": round(total_topo_ms, 2),
            "avg_run_latency_ms": round(total_duration_ms / runs, 2),
        },
        "reconciliation_sample": sample_rec,
        "architecture_label": "Hybrid Geospatial Entity Matcher & Tri-Reality Benchmark",
    }
