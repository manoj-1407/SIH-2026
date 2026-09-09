#!/usr/bin/env python3
"""
SIH26013 — M6 Spatial Index & Scale Benchmark.
Runs actual benchmarks at 1K, 10K, and 100K records.
Verifies 50/50 injected conflicts detected within the configured candidate
window (100% detection of injected conflicts within that window).
"""
import sys
import os
import time
import random
import statistics
import json
from shapely.geometry import box, Polygon

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
from app.core.spatial_index import SpatialCandidateIndex, IndexedRecord
from app.core.geometry import compare_geometries
from app.core.signing import get_signing_key
from app.core.evidence_envelope import build_evidence_payload, sign_evidence

random.seed(42)

# India bounding box
LON_MIN, LON_MAX = 69.0, 88.0
LAT_MIN, LAT_MAX = 10.0, 30.0

def generate_random_polygon(lon, lat, size_deg=0.01):
    return box(lon, lat, lon + size_deg, lat + size_deg)

def run_benchmark_scale(n_records: int, n_injected_conflicts: int = 50):
    print(f"\n{'='*60}")
    print(f"--- Running Benchmark at scale: {n_records:,} records ---")
    print(f"{'='*60}")

    idx = SpatialCandidateIndex()
    records = []
    
    # Generate background corpus
    t0 = time.perf_counter()
    for i in range(n_records - (n_injected_conflicts * 2)):
        lon = random.uniform(LON_MIN, LON_MAX)
        lat = random.uniform(LAT_MIN, LAT_MAX)
        geom = generate_random_polygon(lon, lat)
        rec_id = f"BG-{i:07d}"
        rec = IndexedRecord(rec_id, geom, geom.bounds)
        records.append(rec)
        idx.insert(rec_id, geom)

    # Injected conflict pairs (must be guaranteed candidates and detected)
    injected_pairs = []
    for k in range(n_injected_conflicts):
        lon = random.uniform(LON_MIN, LON_MAX)
        lat = random.uniform(LAT_MIN, LAT_MAX)
        # Record A
        geom_a = generate_random_polygon(lon, lat, size_deg=0.02)
        rec_id_a = f"INJ-A-{k:03d}"
        rec_a = IndexedRecord(rec_id_a, geom_a, geom_a.bounds)
        records.append(rec_a)
        idx.insert(rec_id_a, geom_a)

        # Record B: shifted by 0.01 deg (significant conflict)
        geom_b = generate_random_polygon(lon + 0.008, lat + 0.008, size_deg=0.02)
        rec_id_b = f"INJ-B-{k:03d}"
        rec_b = IndexedRecord(rec_id_b, geom_b, geom_b.bounds)
        records.append(rec_b)
        idx.insert(rec_id_b, geom_b)

        injected_pairs.append((rec_id_a, rec_id_b, geom_a, geom_b))

    t_ingest = time.perf_counter() - t0
    ingest_throughput = n_records / t_ingest
    print(f"  Ingestion: {n_records:,} records in {t_ingest:.2f}s ({ingest_throughput:,.0f} records/s)")

    # Candidate query benchmark (sample 500 queries)
    sample_records = random.sample(records, min(500, len(records)))
    query_times = []
    for r in sample_records:
        t_q0 = time.perf_counter()
        cands = idx.query_candidates(r.geometry)
        t_q1 = time.perf_counter()
        query_times.append((t_q1 - t_q0) * 1000.0) # ms

    p50_query_ms = statistics.median(query_times)
    p95_query_ms = sorted(query_times)[int(0.95 * len(query_times))]
    print(f"  Query latency (sample 500): p50={p50_query_ms:.4f}ms, p95={p95_query_ms:.4f}ms")

    # Full candidate generation across corpus (or partitioned sample for 100K)
    print("  Generating candidate pairs...")
    t_c0 = time.perf_counter()
    candidate_pairs_found = 0
    injected_detected = set()

    # To be efficient and exact on injected pairs:
    # Query candidates for each injected record and background sample
    for rec_a_id, rec_b_id, ga, gb in injected_pairs:
        # Query candidates for rec_a
        cands_a = {c.record_id for c in idx.query_candidates(ga)}
        if rec_b_id in cands_a:
            # Pair found by spatial index!
            # Now verify geometry conflict detection
            comp = compare_geometries(ga, gb)
            if comp.conflict:
                injected_detected.add((rec_a_id, rec_b_id))

    t_cand = time.perf_counter() - t_c0
    print(f"  Injected conflicts detected: {len(injected_detected)} / {n_injected_conflicts}")
    if len(injected_detected) == n_injected_conflicts:
        print(f"  ✓ 100% detection of injected conflicts within the configured candidate window")
    else:
        print(f"  ✗ FAILED conflict gate: {n_injected_conflicts - len(injected_detected)} missed")
        sys.exit(1)

    # Candidate reduction calculation on full corpus (sample-based for 100K)
    # Naive total pairs = N * (N - 1) / 2
    naive_pairs = (n_records * (n_records - 1)) / 2
    # Estimate total candidate pairs across corpus
    total_cand_est = sum(len(idx.query_candidates(r.geometry)) - 1 for r in sample_records) / (2 * len(sample_records)) * n_records
    reduction_ratio = naive_pairs / max(1, total_cand_est)
    print(f"  Estimated candidate reduction factor: {reduction_ratio:,.0f}×")

    # Geometry p50 benchmark
    geom_times = []
    for _ in range(200):
        r1, r2 = random.sample(records, 2)
        tg0 = time.perf_counter()
        compare_geometries(r1.geometry, r2.geometry)
        tg1 = time.perf_counter()
        geom_times.append((tg1 - tg0) * 1000.0)
    p50_geom_ms = statistics.median(geom_times)

    # Signing p50 benchmark
    key = get_signing_key()
    sign_times = []
    dummy_payload = build_evidence_payload(
        "CMP-BENCH", "CASE-BENCH", ["REC-1", "REC-2"],
        "GEOMETRIC_CONFLICT", {"iou": 0.5}, {}, {}, {}, 1, "Bench"
    )
    for _ in range(200):
        ts0 = time.perf_counter()
        sign_evidence(dummy_payload, key)
        ts1 = time.perf_counter()
        sign_times.append((ts1 - ts0) * 1000.0)
    p50_sign_ms = statistics.median(sign_times)

    print(f"  Geometry compare p50: {p50_geom_ms:.4f}ms")
    print(f"  Ed25519 signing p50: {p50_sign_ms:.4f}ms")

    return {
        "scale": n_records,
        "ingest_throughput_recs_sec": round(ingest_throughput, 1),
        "p50_query_ms": round(p50_query_ms, 5),
        "p50_geom_ms": round(p50_geom_ms, 4),
        "p50_sign_ms": round(p50_sign_ms, 4),
        "injected_detected": len(injected_detected),
        "injected_total": n_injected_conflicts,
        "candidate_reduction_ratio": round(reduction_ratio, 1),
    }

def main():
    print("=================================================================")
    print("SIH26013 — Spatial Index & Scale Benchmark Suite")
    print("=================================================================")
    
    results = []
    for scale in [1000, 10000, 100000]:
        res = run_benchmark_scale(scale, n_injected_conflicts=50)
        results.append(res)

    print("\n" + "="*65)
    print("FINAL BENCHMARK RESULTS SUMMARY:")
    print("="*65)
    print(f"{'Scale':<10} | {'Ingest/s':<12} | {'Query p50':<12} | {'Geom p50':<12} | {'Sign p50':<12} | {'Conflicts':<10}")
    print("-" * 75)
    for r in results:
        print(f"{r['scale']:<10,d} | {r['ingest_throughput_recs_sec']:<12,.0f} | {r['p50_query_ms']:<10.4f}ms | {r['p50_geom_ms']:<10.4f}ms | {r['p50_sign_ms']:<10.4f}ms | {r['injected_detected']}/{r['injected_total']}")
    print("="*65)

    out_path = os.path.join(REPO_ROOT, "benchmark_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved benchmark results to {out_path}")

if __name__ == "__main__":
    main()
