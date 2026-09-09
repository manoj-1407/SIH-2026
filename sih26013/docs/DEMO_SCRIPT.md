# SIH26013 — Judge Demo Script (5 minutes)

## Setup (before judges arrive)
```bash
DEMO_MODE=1 docker-compose up -d --build
# Wait for: "Application startup complete"
# Open http://localhost:8001 in browser
```

## Demo flow

### Act 1: The problem (30 seconds)
Open the browser. Show the empty case list.
> "Three government agencies have each filed a parcel boundary record for the same land.
> They disagree. Before we can call this a conflict, we need to ask: are these actually
> three independent observations, or the same observation in three different files?"

### Act 2: Ingest and analyze (60 seconds)
1. Click **+ New Case**. Name it "Parcel PS-2201 Dispute".
2. Click **Load Preset → 3 Records / 1 Origin (Collapse)**.
   - This loads three records that disagree geometrically but share Survey 2021 as origin.
3. Click **Run Analysis**.
4. Show the results panel:
   - `GEOMETRIC_CONFLICT` — the boundaries genuinely disagree
   - `NOT_INDEPENDENT` — lineages: **1**

> "Three records. One lineage. The conflict is real, but there's only one independent
> piece of evidence here. The system established that separately from the geometry."

### Act 3: Show the evidence (60 seconds)
5. Click **View Evidence** on any flagged comparison.
6. Show the evidence panel:
   - Decision: `GEOMETRIC_CONFLICT`
   - `independent_lineages: 1`
   - Evidence hash (SHA-256)
   - Ed25519 signature
   - Verification: ✓ VALID

> "Every conclusion is signed. Not just stored — cryptographically bound."

### Act 4: Tamper demonstration (60 seconds)
7. In the tamper section, select preset: `independent_lineages: 1 → 3`
8. Click **Attempt Tamper**.
9. Show result:
   - `✗ Verification FAILED — tamper detected`
   - Hash mismatch shown

> "An attacker cannot change the independence conclusion from 1 to 3 without
> breaking the signature. The evidence is immutable."

### Act 5: Honest uncertainty (30 seconds)
10. Click **Load Preset → Missing Lineage (UNKNOWN)**.
11. Run analysis. Show `UNKNOWN` result.

> "When provenance is incomplete, the system says UNKNOWN — not INDEPENDENT,
> not NOT_INDEPENDENT. It refuses to manufacture certainty."

### Act 6: Scale (30 seconds)
12. Point to the README benchmark table or benchmark_results.json.
> "At 100,000 records, the spatial index reduces 5 billion possible comparisons
> to 24,000 relevant candidates — 207,000x reduction. That's not just performance,
> it's correctness: comparing unrelated parcels would produce meaningless results."

## Likely judge questions

**Q: Why not just use GIS comparison software?**
A: GIS tools tell you whether boundaries disagree. They don't tell you whether the records are independent evidence. We answer both questions separately and sign both answers.

**Q: What if the provenance metadata is faked?**
A: If someone provides false lineage declarations, the system trusts the declared graph. We document this as a data-integrity limitation, not a system failure. The cryptographic evidence establishes what was *claimed* at analysis time — which is still valuable.

**Q: Where is the AI?**
A: We didn't add a neural network where a deterministic provenance algorithm gives more reliable and auditable results. Independence analysis over a DAG is exact; an LLM estimate of independence would not be.
