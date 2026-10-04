# SIH26149 Measured Performance Benchmark Report

## 1. Test Environment Telemetry
- **Timestamp (UTC)**: `2026-10-04T05:37:28Z`
- **Operating System**: `Windows-11-10.0.26200-SP0`
- **Python Runtime**: `Python 3.13.3`
- **Processor**: `Intel64 Family 6 Model 142 Stepping 10, GenuineIntel`

---

## 2. Cryptographic Latency Baseline

| Operation | Standard | Iterations | Median Latency | P95 Latency | Min | Max |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Ed25519 Signing** | RFC 8032 / JCS RFC 8785 | 100 | **0.361 ms** | 1.166 ms | 0.186 ms | 4.885 ms |
| **Directory Package Verification** | SHA-256 + Ed25519 | 50 | **15.442 ms** | 83.959 ms | 8.357 ms | 134.588 ms |

---

## 3. Streaming Engine Multi-Run Throughput Matrix

| Payload Size | Runs | SHA-256 Ingest (Median) | Carving & Validation (Median) | Logical Zero-Fill + Readback (Median) | Artifacts Carved |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **10 MiB** | 10 | **80.24 MiB/s** | **13.0 MiB/s** | **1.85 MiB/s** | 500 candidates |
| **25 MiB** | 5 | **67.07 MiB/s** | **25.04 MiB/s** | **1.95 MiB/s** | 500 candidates |
| **50 MiB** | 3 | **54.76 MiB/s** | **45.22 MiB/s** | **2.31 MiB/s** | 500 candidates |
| **100 MiB** | 2 | **78.19 MiB/s** | **125.74 MiB/s** | **2.03 MiB/s** | 500 candidates |

---

## 4. Scope and limitations
- Sanitization measurements are single-pass logical zero-fill/read-back operations on temporary regular files, not physical-device sanitization.
- Throughput measurements use deterministic synthetic payloads in this run and do not establish field recovery rates or physical-media performance.
- No memory RSS, 1–100 GB dataset, HDD/SSD, ATA, or NVMe measurement is performed by this benchmark.
- Numbers are machine- and run-specific. Re-run this script to regenerate the report and JSON measurements.
