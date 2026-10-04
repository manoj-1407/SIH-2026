# SIH26149 Final Measured Assurance Report

This report is generated from `data/corpus_results.json` and `data/benchmark_results.json` by `scripts/build_final_benchmark_report.py`.
Measurements are from deterministic synthetic inputs and temporary regular files on the recorded workstation; they are not field or physical-media performance claims.

## Run environment

- Timestamp (UTC): `2026-10-04T05:37:28Z`
- Platform: `Windows-11-10.0.26200-SP0`
- Python: `3.13.3`
- Processor: `Intel64 Family 6 Model 142 Stepping 10, GenuineIntel`

## Controlled recovery corpus

- Cases: **13**
- TP / FP / FN / TN: **10 / 5 / 1 / 0**
- Precision: **66.7%**
- Recall: **90.9%**
- F1: **0.7692**
- Partial-to-intact overclaims: **0**
- Median raw-carving scan latency: **1.192 ms/case**

These confusion-matrix figures cover only the script's synthetic raw-carving cases. Filesystem metadata recovery, timestomp indicators, steganography, anti-forensics, and exFAT fallback are tested separately and are not included in these precision/recall totals.

## Additional controlled coverage

| Area | Evidence in repository | Boundary |
|---|---|---|
| NTFS deleted-file recovery | [40-case matrix](../tests/corpus/test_40_case_national_matrix.py), cases 31-33 | Synthetic MFT/disk images, not real-media validation |
| FAT32 deleted-file recovery | [40-case matrix](../tests/corpus/test_40_case_national_matrix.py), cases 25-30 | Synthetic FAT32 images with byte-hash ground truth |
| exFAT | [roadmap tests](../tests/unit/test_national_roadmap.py) | Detection and raw-carving fallback only; no metadata-aware recovery |
| Renamed, corrupted, and fragmented files | [24-case matrix](../tests/corpus/test_24_case_matrix.py) | Includes bounded synthetic scenarios; no general arbitrary-extent reconstruction |
| Timestomp and anti-forensics | [40-case matrix](../tests/corpus/test_40_case_national_matrix.py), cases 37-40 | Deterministic timestamp/pattern fixtures |
| Steganography | [steganography tests](../tests/unit/test_steganography.py) | Synthetic LSB fixtures; not an accuracy study on field images |
| HDD/SSD and physical sanitization | Not run | No disposable test drives available; capability preview remains non-executing |

## Performance matrix

| Payload | Runs | SHA-256 median | Carving median | Logical zero-fill + readback median | SHA-256 rate | Carving rate | Zero-fill rate |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 MiB | 10 | 124.661 ms | 769.438 ms | 5399.871 ms | 80.24 MiB/s | 13.00 MiB/s | 1.85 MiB/s |
| 25 MiB | 5 | 372.734 ms | 998.242 ms | 12832.666 ms | 67.07 MiB/s | 25.04 MiB/s | 1.95 MiB/s |
| 50 MiB | 3 | 913.085 ms | 1105.682 ms | 21620.311 ms | 54.76 MiB/s | 45.22 MiB/s | 2.31 MiB/s |
| 100 MiB | 2 | 1290.218 ms | 801.815 ms | 51662.863 ms | 78.19 MiB/s | 125.74 MiB/s | 2.03 MiB/s |

## Evidence verification and sanitization scope

- Ed25519 signing median / p95: **0.361 / 1.166 ms** (100 iterations).
- Independent directory-package verification median / p95: **15.442 / 83.959 ms** (50 repeated checks of 1 generated package).
- Cross-implementation integrity tests exercise two tampering cases (artifact-byte modification and audit-event modification); both Python and Node.js verifiers reject them. This is a deterministic test result, not a general tamper-detection probability.
- Logical sanitization measurement: single-pass zero-fill/read-back of temporary regular files only. It does not test remapped sectors, SSD NAND, or controller behavior.
- ATA Secure Erase, NVMe Sanitize, real HDD/SSD operation timing, and physical post-operation verification: **NOT RUN** (no disposable test drive available).
- Large 1–100 GB workloads and memory RSS: **NOT MEASURED**.
- Real-media recovery rates and broad real-world false-positive/false-negative rates: **NOT MEASURED**.
- The post-operation proof loop is an in-memory validation probe and is not included as a physical-device or sanitization benchmark.

The Node.js verifier requires an independently supplied trusted public key or trust registry. A key embedded in an evidence package is never used as its own trust anchor. Scope, operation, and post-probe fields are reported as `NOT ATTESTED` when they are absent from the signed input.

## Reproduction

From `sih26149/`, run:

```powershell
..\.venv\Scripts\python.exe scripts\test_real_world_corpus_rc2.py
..\.venv\Scripts\python.exe scripts\run_benchmark_matrix.py
..\.venv\Scripts\python.exe scripts\build_final_benchmark_report.py
```

The benchmark regenerates its JSON result files and `docs/BENCHMARK_REPORT.md`; the final report is then rebuilt from those JSON outputs.
