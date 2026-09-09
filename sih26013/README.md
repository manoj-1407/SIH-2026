# SIH26013 — Integrated Multi-Source Geospatial Data Harmonization

**Organisation:** Ministry of Rural Development  
**Problem Statement:** SIH26013  
**Team:** Session B

---

## The core insight

When three geospatial datasets describe the same parcel but disagree, the naive question is: *which one is correct?*

The real question is: **are these actually three independent observations, or one observation in three containers?**

Three datasets with a shared origin (same satellite pass, same ground survey, same GIS export) are not three independent confirmations. They're one. This system establishes that distinction explicitly — and signs it.

---

## What this system does

- **Geometric disagreement** — IoU + Hausdorff distance to detect both area-level and boundary-level conflicts
- **Temporal qualification** — large geometry differences over short time windows are a different problem than differences over years
- **CRS / data quality** — detects impossible geographic extents, axis swaps, and degree/metre confusion (with India-specific heuristics for the geographic blind spot); does not attempt datum transformation/shift detection
- **Provenance independence** — DAG lineage collapse: 3 records from 1 origin → `independent_lineages: 1`
- **Honest uncertainty** — `UNKNOWN` when provenance cannot establish independence; never manufactures certainty
- **Cryptographic evidence** — every conclusion signed with Ed25519, tamper-detectable, independently verifiable

---

## Quick start

### Native Linux / WSL2
```bash
# 1. Install dependencies
./setup.sh

# 2. Start the workstation
./run.sh

# Access UI:       http://127.0.0.1:8001
# Access API docs: http://127.0.0.1:8001/docs
```

### Docker (recommended for demo)
```bash
docker-compose up --build -d
# UI at http://localhost:8001
```

### Run tests
```bash
python3 -m pytest tests/ -v
# Expected: 51 tests passing
```

### Run scalability benchmarks
```bash
python3 benchmarks/benchmark_scale.py
# Reproduces benchmark_results.json numbers
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SIH26013_DATA_DIR` | `/app/data` (container) or `<repo>/data` (local) | Root for evidence, keys, audit logs |
| `SIH26013_API_KEY` | *(unset = open)* | When set, all API requests must supply `X-API-Key` header |
| `DEMO_MODE` | `0` | Set to `1` to enable tamper-demo endpoint and bypass API key |

### Running the tamper demonstration
```bash
DEMO_MODE=1 ./run.sh
# The tamper endpoint appears in the Evidence panel.
# Change independent_lineages: 1 → 3, verify rejects.
```

---

## Architecture

```
Browser Workstation UI  (HTML / CSS / JS + Leaflet.js map)
              │
              ▼
  FastAPI Application (REST, /api/v1/*)
              │
     Analysis Pipeline
 ┌────┬───────┬──────┬──────────┐
 │CRS │Geom.  │Time  │Provenance│
 │chk │IoU+Hd │gap   │DAG DFS   │
 └────┴───────┴──────┴──────────┘
              │
    Spatial Candidate Index
    (STRtree R-tree, ~1km buffer)
    → eliminates O(N²) comparisons
              │
       Evidence Core Layer
  ┌──────┬────────┬────────┐
  │Canon.│SHA-256 │Ed25519 │
  └──────┴────────┴────────┘
              │
       TrustRegistry + EvidenceStore
       (persistent JSON, atomic fsync)
```

### Key design decisions

**Two-axis separation** — Geometric disagreement and provenance independence are answered independently. A system reporting only a single "conflict score" cannot distinguish: same geometry + same origin vs. different geometry + same origin vs. different geometry + independent origins. This system can.

**`UNKNOWN` is a valid signed result** — When provenance is incomplete or unresolvable, the system produces and signs an `UNKNOWN` result. This is evidence of what could not be established, not a failure.

**Candidate window semantics** — The spatial index uses a ~1km proximity buffer (`CANDIDATE_BUFFER_DEGREES = 0.01°`). Records outside this window are not compared — comparing arbitrary unrelated parcels across a country is semantically meaningless for conflict analysis. This is a correctness decision, not just a performance one.

**India CRS blind spot** — A naive "latitude > 90°" axis-swap heuristic fails for India because Indian longitudes (68°–97°E) overlap with values below 90°, making swapped coordinates still appear plausible. The system uses India-specific geographic bbox qualification for this check.

---

## Scalability benchmarks

*Authoritative rerun against frozen codebase (`benchmark_results.json`):*

| Scale | Ingestion | Spatial query p50 | Geometry p50 | Sign p50 | Conflicts |
|---|---|---|---|---|---|
| 1,000 | 5,119 rec/s | 0.040 ms | 0.075 ms | 0.238 ms | 50/50 |
| 10,000 | 3,628 rec/s | 0.054 ms | 0.113 ms | 0.108 ms | 50/50 |
| 100,000 | 2,921 rec/s | 0.056 ms | 0.144 ms | 0.149 ms | 50/50 |

Candidate reduction at 100K: **207,467×** (from ~5B possible pairs to ~24K candidates).

*Detection note: Injected conflict pairs were constructed within the candidate-buffer window. Detection guarantee applies within that window.*

---

## Outcome classifications

| Classification | Meaning |
|---|---|
| `GEOMETRIC_CONFLICT` | Boundaries disagree beyond noise threshold (IoU + Hausdorff) |
| `TEMPORALLY_QUALIFIED_DISCREPANCY` | Geometric difference plausibly explained by time gap between records |
| `NO_CONFLICT` | Records agree within tolerance |
| `CRS_ERROR` | Coordinate reference system problem detected |
| `DATA_QUALITY_ISSUE` | Geometry self-intersection, impossible extent, or coordinate implausibility |
| `INDEPENDENT` | Records trace to genuinely distinct origins |
| `NOT_INDEPENDENT` | All records share a common ancestor; count of distinct lineages provided |
| `UNKNOWN` | Provenance evidence insufficient to determine independence |

---

## Security model

All evidence is signed with Ed25519. The signing key is generated at first startup and persisted to `DATA_DIR/keys/geo_examiner.priv`. After a container restart, the same key is loaded from disk — old evidence remains verifiable.

**Persistence boundary.** Signed evidence and the signing identity (private key + trust registry) are durable and survive a container restart. Active in-flight case-management state held by the API process (`app/api/server.py`) is process-memory-backed and does not itself survive a restart — only the signed evidence it produces is persisted. Do not read this as "the entire application state survives arbitrary restart"; that claim is not made and is not true.

The trust registry (`DATA_DIR/keys/trust_registry.json`) maps `key_id` to public key bytes. Verification always resolves the key from this registry — it never trusts a public key embedded in the evidence package itself.

**The `independent_lineages` count is cryptographically bound to the evidence envelope.** An attacker cannot change `1 → 3` without breaking the signature. This is the most important tamper-resistance property.

---

## Prior art

This system does not claim to have invented geospatial provenance. Relevant existing work includes W3C PROV, ISO 19115 lineage, FME, and GeoPROV (2026). The differentiator: evaluating evidence *independence* separately from geometric *agreement*, using actual DAG lineage rather than metadata labels, and failing closed to `UNKNOWN` when independence cannot be established.
