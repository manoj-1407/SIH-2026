# SIH26149 Measured Performance Benchmark Report

## 1. Test Environment Telemetry
- **Timestamp (UTC)**: `2026-09-21T05:30:15Z`
- **Operating System**: `Windows-11-10.0.26200-SP0`
- **Python Runtime**: `Python 3.13.3`
- **Processor**: `Intel64 Family 6 Model 142 Stepping 10, GenuineIntel`

---

## 2. Cryptographic Latency Baseline

| Operation | Standard | Iterations | Median Latency | P95 Latency | Min | Max |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Ed25519 Signing** | RFC 8032 / JCS RFC 8785 | 100 | **0.21 ms** | 0.399 ms | 0.205 ms | 1.382 ms |
| **Directory Package Verification** | SHA-256 + Ed25519 | 50 | **13.872 ms** | 22.242 ms | 3.687 ms | 87.023 ms |

---

## 3. Streaming Engine Multi-Run Throughput Matrix

| Payload Size | Runs | SHA-256 Ingest (Median) | Carving & Validation (Median) | NIST Overwrite Clear (Median) | Artifacts Carved |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **10 MB** | 10 | **161.89 MB/s** | **0.67 MB/s** | **7.13 MB/s** | 500 files |
| **25 MB** | 5 | **141.54 MB/s** | **0.84 MB/s** | **7.01 MB/s** | 500 files |
| **50 MB** | 3 | **228.17 MB/s** | **1.26 MB/s** | **10.42 MB/s** | 500 files |
| **100 MB** | 2 | **228.55 MB/s** | **2.55 MB/s** | **10.23 MB/s** | 500 files |

---

## 4. Defensible Scalability Analysis
1. **Chunked Streaming**: Streaming SHA-256 and pattern scanning operate in 64 KB – 512 KB bounded buffers, keeping resident memory flat regardless of image size.
2. **Deterministic Validation**: Carving throughput is bounded by structural verification and parser decoding, avoiding false positive promotion.
3. **Cryptographic Efficiency**: RFC 8032 signing and JCS canonicalization execute in sub-5ms latency, allowing real-time audit envelope generation for every forensic event.
