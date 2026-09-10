"""FastAPI application server for SIH26013 Integrated Geospatial Analysis (v2)."""
from __future__ import annotations
import os
import re
import copy
import threading
import uuid
from typing import Any, Optional, List, Dict
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.core.pipeline import (
    AnalysisPipeline, IngestionRecord, analyze_pair
)
from app.core.provenance import LineageGraph, LineageNode
from app.core.signing import init_signing, get_signing_key, get_registry
from app.core.evidence_envelope import verify_envelope
from app.core.persistence import EvidenceStore, AuditLog
from app.api.auth import require_api_key
from app.core.rate_limit import check_rate_limit

# New Track A AI & Harmonization modules
from app.core.canonical_model import CanonicalParcel, AgencyType, LandUseType
from app.core.ai_matcher import match_parcels, match_multi_source_catalog, MatchResult
from app.core.attribute_harmonizer import map_raw_record_to_canonical, compare_parcel_attributes
from app.core.imagery_features import BuildingFootprint, analyze_drone_footprints
from app.core.topology_repair import repair_cadastral_topology
from app.core.harmonization_proposal import (
    HarmonizationProposal, create_harmonization_proposal, review_proposal, ProposalStatus
)
from app.core.temporal import analyze_temporal, diff_record_history

app = FastAPI(
    title="SIH26013 — Integrated Multi-Source Geospatial Data Platform v2",
    description=(
        "Automated Integration and Intelligent Harmonization of Multi-source "
        "Geospatial Data for Urban Land Record Management. MoRD Problem Statement SIH26013."
    ),
    version="2.0.0",
)


@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    """Runs before auth so a rejected request costs nothing further."""
    allowed, retry_after = check_rate_limit(request)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please slow down."},
            headers={"Retry-After": str(retry_after)},
        )
    return await call_next(request)


@app.middleware("http")
async def api_key_middleware(request, call_next):
    """Apply API key check to non-public routes."""
    try:
        await require_api_key(request)
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers or {},
        )
    return await call_next(request)


_repo_data = Path(__file__).resolve().parents[2] / "data"
_default_data = "/app/data" if Path("/app").is_dir() else str(_repo_data)
DATA_DIR = Path(os.environ.get("SIH26013_DATA_DIR", _default_data))
evidence_store = EvidenceStore(DATA_DIR / "evidence")
audit_log = AuditLog(DATA_DIR / "audit")

# Initialise signing on module import
init_signing(DATA_DIR)
registry = get_registry()
signing_key = get_signing_key()

CASE_ID_REGEX = re.compile(r"^[A-Za-z0-9_\-]+$")
cases: dict[str, dict] = {}

_case_locks_guard = threading.Lock()
_case_locks: dict[str, threading.Lock] = {}


def _lock_for(case_id: str) -> threading.Lock:
    with _case_locks_guard:
        lock = _case_locks.get(case_id)
        if lock is None:
            lock = threading.Lock()
            _case_locks[case_id] = lock
        return lock


def get_case_or_404(case_id: str) -> dict:
    if not CASE_ID_REGEX.match(case_id):
        raise HTTPException(status_code=400, detail=f"Invalid case_id format: {case_id!r}")
    if case_id not in cases:
        raise HTTPException(status_code=404, detail=f"Case {case_id!r} not found")
    return cases[case_id]


# --- Request/Response Models ---
class CreateCaseRequest(BaseModel):
    case_id: Optional[str] = None
    title: Optional[str] = "Geospatial Analysis Case"
    description: Optional[str] = ""

class ProvenanceNodeInput(BaseModel):
    node_id: str
    node_type: str  # origin, dataset, transformation, record
    parent_ids: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)

class RecordInput(BaseModel):
    record_id: str
    geometry: dict
    source_crs: str = "EPSG:4326"
    timestamp: Optional[str] = None
    provenance_node_id: Optional[str] = None
    metadata: dict = Field(default_factory=dict)

class IngestBatchRequest(BaseModel):
    nodes: list[ProvenanceNodeInput] = Field(default_factory=list)
    records: list[RecordInput] = Field(default_factory=list)

class VerifyRequest(BaseModel):
    envelope: Optional[dict] = None

class AIMatchRequest(BaseModel):
    min_probability: float = 0.35

class ImageryAnalysisRequest(BaseModel):
    footprints: List[dict]

class TopologyRepairRequest(BaseModel):
    snap_tolerance_m: float = 1.0

class ProposalReviewRequest(BaseModel):
    action: str  # APPROVE, REJECT, REQUEST_INSPECTION
    reviewer_id: str
    notes: str = ""

class TamperDemoRequest(BaseModel):
    field_path: str = "result.geo_classification"
    new_value: Any = "TAMPERED_CLASSIFICATION"


# ── Create Core Router to allow dual-mounting (/ and /api) ──────────────────────
router = APIRouter()


@router.get("/health")
def health():
    return {
        "status": "OPERATIONAL",
        "service": "SIH26013-Geospatial-Harmonization-v2",
        "version": "2.0.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "active_cases": len(cases),
        "signing_key_id": signing_key.key_id if signing_key else get_signing_key().key_id,
        "subsystems": {
            "spatial_index": "active",
            "geometry_engine": "active",
            "temporal_engine": "active",
            "crs_validator": "active",
            "provenance_graph": "active",
            "cryptographic_trust": "active",
            "audit_log": "active",
            "ai_matcher": "active",
            "topology_repair": "active",
            "imagery_analyzer": "active",
            "harmonization_proposals": "active",
        }
    }


@router.post("/cases", status_code=status.HTTP_201_CREATED)
def create_case(req: CreateCaseRequest):
    case_id = req.case_id or f"CASE-{uuid.uuid4().hex[:8].upper()}"
    if not CASE_ID_REGEX.match(case_id):
        raise HTTPException(status_code=400, detail="case_id contains invalid characters")
    if case_id in cases:
        raise HTTPException(status_code=409, detail=f"Case {case_id!r} already exists")

    cases[case_id] = {
        "case_id": case_id,
        "title": req.title,
        "description": req.description,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "graph": LineageGraph(),
        "pipeline": AnalysisPipeline(case_id, evidence_store),
        "records": {},
        "evidence_ids": [],
        "analysis_summary": None,
        "proposals": {},
        "topology_results": None,
        "imagery_results": None,
    }
    audit_log.log(case_id, "CASE_CREATED", "operator", {"title": req.title})
    return {"case_id": case_id, "status": "created", "created_at_utc": cases[case_id]["created_at_utc"]}


@router.get("/cases")
def list_cases():
    return [
        {
            "case_id": c["case_id"],
            "title": c["title"],
            "created_at_utc": c["created_at_utc"],
            "records_count": len(c["records"]),
            "evidence_count": len(c["evidence_ids"]),
            "has_analysis": c["analysis_summary"] is not None,
            "proposals_count": len(c.get("proposals", {})),
        }
        for c in cases.values()
    ]


class AnalysisRequest(BaseModel):
    record_id_a: Optional[str] = None
    record_id_b: Optional[str] = None


@router.get("/cases/{case_id}")
def get_case(case_id: str):
    c = get_case_or_404(case_id)
    graph: LineageGraph = c.get("graph")
    provenance_nodes = []
    if graph and hasattr(graph, "_nodes"):
        provenance_nodes = [
            {
                "node_id": n.node_id,
                "node_type": n.node_type,
                "parent_ids": n.parent_ids,
                "metadata": n.metadata,
            }
            for n in graph._nodes.values()
        ]
    records_list = list(c.get("records", {}).values()) if isinstance(c.get("records"), dict) else c.get("records", [])
    return {
        "case_id": c["case_id"],
        "title": c["title"],
        "description": c["description"],
        "created_at_utc": c["created_at_utc"],
        "records": records_list,
        "records_count": len(records_list),
        "evidence_ids": c["evidence_ids"],
        "provenance_nodes": provenance_nodes,
        "analysis_summary": c["analysis_summary"],
        "proposals_count": len(c.get("proposals", {})),
        "proposals": [p.to_dict() if hasattr(p, "to_dict") else p for p in c.get("proposals", {}).values()],
        "topology_results": c.get("topology_results"),
        "imagery_results": c.get("imagery_results"),
    }


@router.post("/cases/{case_id}/ingest")
def ingest_data(case_id: str, batch: IngestBatchRequest):
    c = get_case_or_404(case_id)
    graph: LineageGraph = c["graph"]
    pipeline: AnalysisPipeline = c["pipeline"]

    with _lock_for(case_id):
        added_nodes = 0
        for n in batch.nodes:
            graph.add_node(LineageNode(
                node_id=n.node_id,
                node_type=n.node_type,
                parent_ids=n.parent_ids,
                metadata=n.metadata
            ))
            added_nodes += 1

        accepted_records = 0
        rejected_records = []
        for r in batch.records:
            rec = IngestionRecord(
                record_id=r.record_id,
                geom_dict=r.geometry,
                crs=r.source_crs,
                timestamp=r.timestamp,
                provenance_node_id=r.provenance_node_id,
                metadata=r.metadata
            )
            ok, reason = pipeline.ingest_record(rec)
            if ok:
                c["records"][r.record_id] = {
                    "record_id": r.record_id,
                    "geometry": r.geometry,
                    "source_crs": r.source_crs,
                    "timestamp": r.timestamp,
                    "provenance_node_id": r.provenance_node_id,
                    "metadata": r.metadata
                }
                accepted_records += 1
            else:
                rejected_records.append({"record_id": r.record_id, "reason": reason})

        audit_log.log(case_id, "DATA_INGESTED", "operator", {
            "nodes_added": added_nodes,
            "records_accepted": accepted_records,
            "records_rejected": len(rejected_records)
        })

        return {
            "case_id": case_id,
            "nodes_added": added_nodes,
            "records_accepted": accepted_records,
            "records_rejected": rejected_records,
            "total_records_in_case": len(c["records"])
        }


@router.post("/cases/{case_id}/records")
def add_single_record(case_id: str, r: RecordInput):
    """Convenience endpoint to add a single record."""
    c = get_case_or_404(case_id)
    node_id = r.provenance_node_id or f"origin_{r.record_id}"
    node = ProvenanceNodeInput(node_id=node_id, node_type="origin", metadata={"source": "single_ingest"})
    return ingest_data(case_id, IngestBatchRequest(nodes=[node], records=[r]))


@router.post("/cases/{case_id}/provenance/node")
def add_provenance_node(case_id: str, n: ProvenanceNodeInput):
    """Convenience endpoint to add a single lineage node."""
    c = get_case_or_404(case_id)
    with _lock_for(case_id):
        c["graph"].add_node(LineageNode(
            node_id=n.node_id,
            node_type=n.node_type,
            parent_ids=n.parent_ids,
            metadata=n.metadata
        ))
    return {"status": "ok", "node_id": n.node_id}


@router.post("/cases/{case_id}/analyze")
@router.post("/cases/{case_id}/analysis")
def run_analysis(case_id: str, req: Optional[AnalysisRequest] = None):
    c = get_case_or_404(case_id)
    pipeline: AnalysisPipeline = c["pipeline"]
    graph: LineageGraph = c["graph"]

    if len(c["records"]) < 2:
        raise HTTPException(status_code=400, detail="At least 2 records are required for comparison analysis")

    with _lock_for(case_id):
        audit_log.log(case_id, "ANALYSIS_STARTED", "engine", {"record_count": len(c["records"])})
        summary = pipeline.run_analysis(graph, sign=True)

        classifications = [
            {
                "record_id_a": p.record_id_a,
                "record_id_b": p.record_id_b,
                "geo_classification": p.geo_classification,
                "provenance_classification": p.provenance_classification,
                "independent_lineages": p.independent_lineages,
                "unknown": p.unknown,
                "explanation": p.explanation,
                "comparison_id": p.comparison_id,
                "measurements": p.measurements,
                "evidence_envelope": p.evidence_envelope,
            }
            for p in summary.pair_results
        ]

        c["analysis_summary"] = {
            "total_ingested": summary.total_ingested,
            "rejected_at_ingestion": summary.rejected_at_ingestion,
            "valid_after_ingestion": summary.valid_after_ingestion,
            "candidate_pairs_examined": summary.candidate_pairs_examined,
            "cases_flagged": summary.cases_flagged,
            "signed_evidence_ids": summary.signed_case_ids,
            "classifications": classifications,
        }
        for eid in summary.signed_case_ids:
            if eid not in c["evidence_ids"]:
                c["evidence_ids"].append(eid)

        audit_log.log(case_id, "ANALYSIS_COMPLETED", "engine", {
            "pairs_examined": summary.candidate_pairs_examined,
            "cases_flagged": summary.cases_flagged,
            "signed_evidence_count": len(summary.signed_case_ids)
        })

        if req and req.record_id_a and req.record_id_b:
            pair = next(
                (p for p in classifications if (p["record_id_a"] == req.record_id_a and p["record_id_b"] == req.record_id_b) or (p["record_id_a"] == req.record_id_b and p["record_id_b"] == req.record_id_a)),
                None
            )
            if pair:
                m = pair.get("measurements") or {}
                return {
                    "case_id": case_id,
                    "evidence_id": pair["comparison_id"],
                    "result": {
                        "geo_classification": pair["geo_classification"],
                        "intersection_ratio": m.get("iou", m.get("intersection_over_union", 0.0)) or 0.0,
                        "symmetric_diff_sq_m": m.get("symmetric_difference_sq_m", 0.0) or 0.0,
                        "hausdorff_m": m.get("hausdorff_m"),
                        "explanation": pair["explanation"],
                    },
                    "envelope": pair.get("evidence_envelope"),
                }

        return c["analysis_summary"]


# ── Track A New Feature Endpoints ──────────────────────────────────────────────

def _records_to_canonical_parcels(records_dict: dict) -> List[CanonicalParcel]:
    """Helper to convert stored case records to CanonicalParcel instances."""
    parcels = []
    for r_id, r_data in records_dict.items():
        meta = r_data.get("metadata", {})
        agency_str = meta.get("agency") or meta.get("department") or "REVENUE"
        agency = AgencyType.REVENUE
        for a in AgencyType:
            if a.value in agency_str.upper():
                agency = a
                break

        p = map_raw_record_to_canonical(
            raw_dict={
                "survey_number": meta.get("survey_number") or meta.get("plot_no") or r_id,
                "area_sq_m": meta.get("area_sq_m") or meta.get("area") or 1000.0,
                "owner_ref": meta.get("owner") or meta.get("owner_name") or "UNSPECIFIED",
                "land_use": meta.get("land_use") or meta.get("usage") or "RESIDENTIAL",
                **meta
            },
            source_agency=agency,
            geometry=r_data["geometry"],
            default_crs=r_data.get("source_crs", "EPSG:4326"),
        )
        parcels.append(p)
    return parcels


def _parcels_for_proposal(c: dict) -> List[CanonicalParcel]:
    """Prefer topology-corrected geometries when available; else original records."""
    topo = c.get("topology_results") or {}
    corrected = topo.get("corrected_parcels") if isinstance(topo, dict) else None
    if corrected:
        parcels = []
        for item in corrected:
            try:
                if isinstance(item, dict) and "geometry" in item and "survey_number" in item:
                    parcels.append(CanonicalParcel.from_dict(item))
                elif isinstance(item, dict) and "geometry" in item:
                    # Partial corrected dict — merge via raw mapper
                    agency_str = str(item.get("source_agency") or "REVENUE")
                    agency = AgencyType.REVENUE
                    for a in AgencyType:
                        if a.value in agency_str.upper():
                            agency = a
                            break
                    parcels.append(map_raw_record_to_canonical(
                        raw_dict=item,
                        source_agency=agency,
                        geometry=item["geometry"],
                        default_crs=item.get("crs", "EPSG:4326"),
                    ))
            except Exception:
                continue
        if parcels:
            return parcels
    return _records_to_canonical_parcels(c.get("records") or {})


@router.post("/cases/{case_id}/match-ai")
@router.post("/cases/{case_id}/ai-match")
def run_ai_matching(case_id: str, req: AIMatchRequest = AIMatchRequest()):
    """
    Run AI-enabled geospatial parcel matching on the case's ingested multi-source records.
    Computes multi-factor probability (IoU, Centroid, Survey Token Levenshtein, Land-use).
    """
    c = get_case_or_404(case_id)
    parcels = _records_to_canonical_parcels(c["records"])
    if len(parcels) < 2:
        raise HTTPException(status_code=400, detail="At least 2 ingested records required for matching")

    results = []
    for i in range(len(parcels)):
        for j in range(i + 1, len(parcels)):
            res = match_parcels(parcels[i], parcels[j])
            if res.match_probability >= req.min_probability:
                results.append(res.to_dict())

    results.sort(key=lambda r: r["match_probability"], reverse=True)

    audit_log.log(case_id, "AI_MATCHING_COMPLETED", "ai_engine", {
        "candidate_pairs": len(results),
        "top_match": results[0] if results else None
    })

    return {
        "case_id": case_id,
        "total_matches_found": len(results),
        "matches": results,
    }


@router.post("/cases/{case_id}/attribute-harmonize")
def run_attribute_harmonization(case_id: str):
    """
    Cross-agency attribute mapping and discrepancy analysis.
    Identifies area variance, land-use contradictions, and ownership divergence.
    """
    c = get_case_or_404(case_id)
    parcels = _records_to_canonical_parcels(c["records"])
    if len(parcels) < 2:
        raise HTTPException(status_code=400, detail="At least 2 records required for cross-department comparison")

    reports = []
    for i in range(len(parcels)):
        for j in range(i + 1, len(parcels)):
            rep = compare_parcel_attributes(parcels[i], parcels[j])
            reports.append(rep.to_dict())

    return {
        "case_id": case_id,
        "discrepancy_reports": reports,
    }


@router.post("/cases/{case_id}/imagery-analysis")
def run_imagery_analysis(case_id: str, req: ImageryAnalysisRequest):
    """
    Drone imagery & photogrammetry feature analysis.
    Computes spatial intersections of building footprints with parcel boundaries to
    detect legal encroachment and unrecorded construction.
    """
    c = get_case_or_404(case_id)
    parcels = _records_to_canonical_parcels(c["records"])
    if not parcels:
        raise HTTPException(status_code=400, detail="No parcel geometry available in case")

    target_parcel = parcels[0]

    fps = []
    for f in req.footprints:
        fp_id = f.get("footprint_id", f"FP-{uuid.uuid4().hex[:6].upper()}")
        fps.append(BuildingFootprint(
            footprint_id=fp_id,
            geometry=f.get("geometry", {}),
            area_sq_m=float(f.get("area_sq_m", 0.0)),
            height_m=f.get("height_m"),
            estimated_floors=int(f.get("estimated_floors", 1)),
        ))

    result = analyze_drone_footprints(target_parcel, fps)
    c["imagery_results"] = result.to_dict()

    audit_log.log(case_id, "IMAGERY_ANALYSIS_COMPLETED", "drone_cv_engine", {
        "parcel_id": target_parcel.parcel_id,
        "encroachment_count": len(result.encroachments),
        "unrecorded_construction": result.unrecorded_construction,
    })

    return result.to_dict()


@router.post("/cases/{case_id}/topology-repair")
def run_topology_repair(case_id: str, req: TopologyRepairRequest = TopologyRepairRequest()):
    """
    Automated cadastral topology correction engine.
    Detects and eliminates boundary overlaps and snaps vertices between adjoining plots.
    """
    c = get_case_or_404(case_id)
    parcels = _records_to_canonical_parcels(c["records"])
    if len(parcels) < 2:
        raise HTTPException(status_code=400, detail="At least 2 parcels required for boundary topology repair")

    result = repair_cadastral_topology(parcels, snap_tolerance_m=req.snap_tolerance_m)
    c["topology_results"] = result.to_dict()

    audit_log.log(case_id, "TOPOLOGY_REPAIR_COMPLETED", "topology_engine", {
        "initial_overlap_sq_m": result.initial_overlap_sq_m,
        "residual_overlap_sq_m": result.residual_overlap_sq_m,
        "vertices_adjusted": result.vertices_adjusted,
    })

    return result.to_dict()


@router.post("/cases/{case_id}/proposals")
def generate_proposal(case_id: str):
    """
    Synthesize multi-source inputs into an official Harmonization Proposal.
    Prefers topology-corrected parcel geometries when a prior repair exists.
    """
    c = get_case_or_404(case_id)
    parcels = _parcels_for_proposal(c)
    if not parcels:
        raise HTTPException(status_code=400, detail="No records available to harmonize")

    match_res = None
    discrepancy = None
    if len(parcels) >= 2:
        match_res = match_parcels(parcels[0], parcels[1])
        discrepancy = compare_parcel_attributes(parcels[0], parcels[1])

    prop = create_harmonization_proposal(
        case_id=case_id,
        parcels=parcels,
        match_result=match_res,
        discrepancy_report=discrepancy,
    )
    c.setdefault("proposals", {})[prop.proposal_id] = prop

    audit_log.log(case_id, "PROPOSAL_GENERATED", "harmonizer", {
        "proposal_id": prop.proposal_id,
        "confidence_score": prop.confidence_score,
        "status": prop.status.value,
        "used_topology_corrections": bool((c.get("topology_results") or {}).get("corrected_parcels")),
    })

    return prop.to_dict()


@router.get("/cases/{case_id}/proposals")
def list_proposals(case_id: str):
    """List all harmonization proposals for a case."""
    c = get_case_or_404(case_id)
    props = c.get("proposals", {})
    return [p.to_dict() for p in props.values()]


@router.post("/cases/{case_id}/proposals/{proposal_id}/review")
def review_harmonization_proposal(case_id: str, proposal_id: str, req: ProposalReviewRequest):
    """
    Official review action (APPROVE, REJECT, FIELD_INSPECTION).
    Upon approval, issues a signed Ed25519 evidence envelope.
    """
    c = get_case_or_404(case_id)
    props = c.get("proposals", {})
    if proposal_id not in props:
        raise HTTPException(status_code=404, detail=f"Proposal {proposal_id} not found")

    prop = props[proposal_id]
    key_mgr = get_signing_key()

    updated = review_proposal(
        proposal=prop,
        action=req.action,
        reviewer_id=req.reviewer_id,
        notes=req.notes,
        signing_key=key_mgr,
    )

    if updated.signed_evidence_envelope:
        ev_id = updated.signed_evidence_envelope["evidence_id"]
        evidence_store.save(ev_id, updated.signed_evidence_envelope)
        if ev_id not in c["evidence_ids"]:
            c["evidence_ids"].append(ev_id)

    audit_log.log(case_id, "PROPOSAL_REVIEWED", req.reviewer_id, {
        "proposal_id": proposal_id,
        "decision": req.action,
        "has_envelope": bool(updated.signed_evidence_envelope),
    })

    return updated.to_dict()


@router.get("/cases/{case_id}/evidence")
def list_case_evidence(case_id: str):
    """List all evidence packages associated with this case."""
    c = get_case_or_404(case_id)
    ev_ids = c.get("evidence_ids", [])
    packages = []
    for eid in ev_ids:
        try:
            packages.append(evidence_store.load(eid))
        except FileNotFoundError:
            pass
    return {"case_id": case_id, "evidence": packages}


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: str):
    if not CASE_ID_REGEX.match(evidence_id):
        raise HTTPException(status_code=400, detail="Invalid evidence_id format")
    try:
        env = evidence_store.load(evidence_id)
        return env
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id!r} not found in vault")


@router.post("/evidence/{evidence_id}/verify")
def verify_stored_evidence(evidence_id: str, req: VerifyRequest = VerifyRequest()):
    if not CASE_ID_REGEX.match(evidence_id):
        raise HTTPException(status_code=400, detail="Invalid evidence_id format")

    if req.envelope is not None:
        target_env = req.envelope
    else:
        try:
            target_env = evidence_store.load(evidence_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Evidence {evidence_id!r} not found in vault")

    is_valid, explanation = verify_envelope(target_env, registry)
    return {
        "evidence_id": evidence_id,
        "verified": is_valid,
        "explanation": explanation,
        "algorithm": target_env.get("signing", {}).get("algorithm"),
        "key_id": target_env.get("signing", {}).get("key_id"),
        "independent_lineages": target_env.get("result", {}).get("independent_lineages"),
        "geo_classification": target_env.get("result", {}).get("geo_classification"),
    }


@router.post("/evidence/{evidence_id}/tamper-demo")
def tamper_demo_evidence(evidence_id: str, req: TamperDemoRequest):
    """
    [DEMO ONLY] Mutates a field in a signed evidence envelope to show cryptographic tamper detection.
    """
    if os.environ.get("DEMO_MODE", "").strip() != "1":
        raise HTTPException(
            status_code=403,
            detail="Evidence tamper demo is only available when DEMO_MODE=1.",
        )
    try:
        orig = evidence_store.load(evidence_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")

    tampered = copy.deepcopy(orig)
    # Mutate field
    keys = req.field_path.split(".")
    curr = tampered
    for k in keys[:-1]:
        if k not in curr or not isinstance(curr[k], dict):
            curr[k] = {}
        curr = curr[k]
    curr[keys[-1]] = req.new_value

    is_valid, reason = verify_envelope(tampered, registry)
    return {
        "evidence_id": evidence_id,
        "tampered_field": req.field_path,
        "original_value": orig.get("result", {}).get("geo_classification", "ORIGINAL"),
        "tampered_value": req.new_value,
        "verification": {
            "valid": is_valid,
            "reason": reason,
        }
    }


@router.get("/cases/{case_id}/timeline")
def get_timeline(case_id: str):
    get_case_or_404(case_id)
    return audit_log.get_timeline(case_id)


@router.get("/cases/{case_id}/provenance")
def get_provenance_graph(case_id: str):
    c = get_case_or_404(case_id)
    graph: LineageGraph = c["graph"]
    nodes_export = []
    edges_export = []
    for nid, node in graph._nodes.items():
        nodes_export.append({
            "id": node.node_id,
            "type": node.node_type,
            "metadata": node.metadata
        })
        for pid in node.parent_ids:
            edges_export.append({"from": pid, "to": node.node_id})

    return {
        "case_id": case_id,
        "nodes": nodes_export,
        "edges": edges_export
    }


@router.post("/cases/{case_id}/temporal-analysis")
def run_temporal_analysis(case_id: str):
    """
    Temporal record-history change analysis for the case.

    Groups all ingested records by survey number and computes a structured
    change vector (AttributeChange list) between pairs, including:
      - Land-use transitions (AGRICULTURAL → COMMERCIAL, etc.)
      - Area deltas (absolute + percentage)
      - Ownership changes
      - Boundary centroid shifts
      - Temporal gap classification (same-era vs temporally qualified)

    Note: This is vector/attribute-level analysis on the records ingested.
    Multi-spectral satellite raster change detection is outside scope.
    """
    c = get_case_or_404(case_id)
    records: dict = c.get("records", {})

    if not records:
        return {"case_id": case_id, "diffs": [], "message": "No records ingested yet"}

    # Group by survey_number
    by_survey: dict[str, list] = {}
    for rec_id, rec in records.items():
        sn = rec.get("metadata", {}).get("survey_number") or "UNKNOWN"
        by_survey.setdefault(sn, []).append({**rec.get("metadata", {}),
                                               "record_id": rec_id,
                                               "timestamp": rec.get("timestamp"),
                                               "geometry": rec.get("geometry")})

    diffs = []
    for sn, recs in by_survey.items():
        if len(recs) < 2:
            continue
        # Sort by timestamp so recs[0] is the older record
        def _ts_key(r):
            from app.core.temporal import parse_timestamp
            dt = parse_timestamp(r.get("timestamp"))
            return dt.timestamp() if dt else 0.0
        recs_sorted = sorted(recs, key=_ts_key)
        # Diff consecutive pairs
        for i in range(len(recs_sorted) - 1):
            ra = recs_sorted[i]
            rb = recs_sorted[i + 1]
            diff = diff_record_history(
                record_a={**ra, "record_id": ra["record_id"]},
                record_b={**rb, "record_id": rb["record_id"]},
                geometry_a=ra.get("geometry"),
                geometry_b=rb.get("geometry"),
            )
            diffs.append(diff.to_dict())

    return {
        "case_id": case_id,
        "total_survey_groups": len(by_survey),
        "total_diffs": len(diffs),
        "diffs": diffs,
        "analysis_note": (
            "Vector/attribute-level temporal change analysis. "
            "Multi-spectral satellite imagery diffing is outside the scope of this implementation."
        ),
    }


@router.get("/cases/{case_id}/canonical-export")
def export_canonical_geojson(case_id: str):
    """
    Export the harmonized canonical GeoJSON FeatureCollection for this case.

    Produces a standards-compliant GeoJSON FeatureCollection where each Feature
    represents a canonical parcel record with full provenance and attribute metadata.
    The response is signed with Ed25519 and includes a hash of the canonical payload.

    Enterprise GIS Integration Note:
      WFS-T (OGC Web Feature Service Transactional) push to an external enterprise
      GIS server is an optional integration boundary. This endpoint generates the
      canonical changeset payload that a WFS-T client would consume. The platform
      does not automatically push to an external GIS — that depends on the target
      agency's infrastructure configuration.
    """
    c = get_case_or_404(case_id)
    # Prefer approved proposal / topology corrections over raw ingest defaults
    parcels = _parcels_for_proposal(c)
    if not parcels:
        records: dict = c.get("records", {})
        parcels = _records_to_canonical_parcels(records)

    features = []
    for p in parcels:
        props = {
            "parcel_id": p.parcel_id,
            "survey_number": p.survey_number,
            "source_agency": p.source_agency.value if hasattr(p.source_agency, "value") else str(p.source_agency),
            "owner_ref": p.owner_ref,
            "crs": p.crs,
            "capture_timestamp": p.capture_timestamp,
            "confidence_weight": p.confidence_weight,
            "raw_attributes": p.raw_attributes,
        }
        # Do not invent area/land_use when absent from source
        area = getattr(p, "area_sq_m", None)
        if area is not None and area != 1000.0:
            props["area_sq_m"] = area
        elif p.raw_attributes and (p.raw_attributes.get("area_sq_m") or p.raw_attributes.get("area")):
            props["area_sq_m"] = p.raw_attributes.get("area_sq_m") or p.raw_attributes.get("area")
        else:
            props["area_sq_m"] = None
            props["area_sq_m_note"] = "not supplied by source record"

        lu = p.land_use.value if hasattr(p.land_use, "value") else str(p.land_use)
        if lu and lu != "RESIDENTIAL":
            props["land_use"] = lu
        elif p.raw_attributes and (p.raw_attributes.get("land_use") or p.raw_attributes.get("usage")):
            props["land_use"] = p.raw_attributes.get("land_use") or p.raw_attributes.get("usage")
        else:
            props["land_use"] = lu if lu else None
            if lu == "RESIDENTIAL" and not (p.raw_attributes or {}).get("land_use"):
                props["land_use_note"] = "defaulted only when source omitted land_use"

        features.append({
            "type": "Feature",
            "geometry": p.geometry,
            "properties": props,
        })

    geojson_collection = {
        "type": "FeatureCollection",
        "name": f"SIH26013-{case_id}-canonical-export",
        "crs": {"type": "name", "properties": {"name": "urn:ogc:def:crs:EPSG::4326"}},
        "features": features,
    }

    # Sign the canonical payload
    from app.core.hashing import sha256_canonical
    from app.core.signing import get_signing_key, get_registry
    from app.core.evidence_envelope import sign_evidence
    import uuid as _uuid

    sk = get_signing_key()
    reg = get_registry()
    payload_hash = sha256_canonical(geojson_collection).hex_digest
    ev_id = f"GEOEXPORT-{case_id}-{_uuid.uuid4().hex[:8].upper()}"

    envelope = None
    if sk:
        payload = {
            "evidence_id": ev_id,
            "case_id": case_id,
            "evidence_type": "CANONICAL_GEOJSON_EXPORT",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "geojson_sha256": payload_hash,
            "feature_count": len(features),
            "result": {
                "geo_classification": "HARMONIZED",
                "feature_count": len(features),
                "payload_sha256": payload_hash,
                "explanation": (
                    "Canonical GeoJSON export of harmonized parcel records. "
                    "WFS-T push to external enterprise GIS is an optional integration boundary."
                ),
            },
        }
        envelope = sign_evidence(payload, sk)
        evidence_store.save(ev_id, envelope)
        if ev_id not in c.setdefault("evidence_ids", []):
            c["evidence_ids"].append(ev_id)

    return {
        "case_id":          case_id,
        "evidence_id":      ev_id,
        "payload_sha256":   payload_hash,
        "geojson":          geojson_collection,
        "feature_count":    len(features),
        "signed_envelope":  envelope,
        "wfs_t_note": (
            "This payload is the canonical changeset for WFS-T synchronization. "
            "Automated push to an external enterprise GIS server requires the target "
            "agency's WFS-T endpoint credentials (not configured in this deployment)."
        ),
        "algorithm": "Ed25519",
    }


# ── Demo Seeder Endpoint ───────────────────────────────────────────────────────

@router.post("/demo/seed-samples")
@router.post("/demo/seed")
def seed_demo_cases():
    """
    Seeds 4 rich real-world test cases highlighting the SIH26013 Problem Statement:
      1. DEMO-ALIGN: Cadastral vs Municipal concordance with minor boundary shift
      2. DEMO-ENCROACH: Drone photogrammetry detecting unauthorized building encroachment
      3. DEMO-TOPOLOGY: Boundary overlaps requiring automated topological edge-snapping
      4. DEMO-CONFLICT: Discrepancy between Revenue RoR (Agricultural) and Municipal Tax (Commercial)
    """
    # 1. DEMO-ALIGN
    c1_id = "DEMO-ALIGN"
    if c1_id in cases:
        del cases[c1_id]
    create_case(CreateCaseRequest(case_id=c1_id, title="Urban Core Boundary Alignment", description="Cadastral vs Municipal spatial alignment in Sector 14"))
    ingest_data(c1_id, IngestBatchRequest(
        nodes=[
            ProvenanceNodeInput(node_id="cadastral_survey_2024", node_type="origin", metadata={"agency": "CADASTRAL", "method": "ETS_Total_Station"}),
            ProvenanceNodeInput(node_id="municipal_gis_2025", node_type="origin", metadata={"agency": "MUNICIPAL", "method": "DGPS_Survey"}),
        ],
        records=[
            RecordInput(
                record_id="CADASTRAL-42",
                source_crs="EPSG:4326",
                provenance_node_id="cadastral_survey_2024",
                timestamp="2024-03-15T09:00:00Z",
                geometry={
                    "type": "Polygon",
                    "coordinates": [[[77.5945, 12.9715], [77.5955, 12.9715], [77.5955, 12.9725], [77.5945, 12.9725], [77.5945, 12.9715]]]
                },
                metadata={"survey_number": "42/1", "area_sq_m": 12100.0, "owner": "Rajesh Rao", "land_use": "RESIDENTIAL"}
            ),
            RecordInput(
                record_id="MUNICIPAL-42",
                source_crs="EPSG:4326",
                provenance_node_id="municipal_gis_2025",
                timestamp="2025-01-10T14:30:00Z",
                geometry={
                    "type": "Polygon",
                    "coordinates": [[[77.59452, 12.97152], [77.59552, 12.97152], [77.59552, 12.97252], [77.59452, 12.97252], [77.59452, 12.97152]]]
                },
                metadata={"survey_number": "42-1", "area_sq_m": 12050.0, "owner": "Rajesh Rao", "land_use": "RESIDENTIAL"}
            )
        ]
    ))

    # 2. DEMO-ENCROACH
    c2_id = "DEMO-ENCROACH"
    if c2_id in cases:
        del cases[c2_id]
    create_case(CreateCaseRequest(case_id=c2_id, title="Drone ORI Encroachment Detection", description="Drone imagery detects building extending past surveyed cadastral parcel boundary"))
    ingest_data(c2_id, IngestBatchRequest(
        nodes=[
            ProvenanceNodeInput(node_id="revenue_ror_2020", node_type="origin", metadata={"agency": "REVENUE"}),
            ProvenanceNodeInput(node_id="drone_ortho_2026", node_type="origin", metadata={"agency": "DRONE_SURVEY"}),
        ],
        records=[
            RecordInput(
                record_id="PARCEL-78A",
                source_crs="EPSG:4326",
                provenance_node_id="revenue_ror_2020",
                timestamp="2020-06-12T10:00:00Z",
                geometry={
                    "type": "Polygon",
                    "coordinates": [[[77.6000, 12.9800], [77.6010, 12.9800], [77.6010, 12.9810], [77.6000, 12.9810], [77.6000, 12.9800]]]
                },
                metadata={"survey_number": "78/A", "area_sq_m": 11800.0, "owner": "M. Kumar", "land_use": "RESIDENTIAL"}
            )
        ]
    ))
    # Pre-load imagery footprints on DEMO-ENCROACH
    run_imagery_analysis(c2_id, ImageryAnalysisRequest(footprints=[
        {
            "footprint_id": "BLDG-ROOF-01",
            "area_sq_m": 240.0,
            "estimated_floors": 3,
            "geometry": {
                "type": "Polygon",
                "coordinates": [[[77.6008, 12.9805], [77.6012, 12.9805], [77.6012, 12.9809], [77.6008, 12.9809], [77.6008, 12.9805]]]
            }
        }
    ]))

    # 3. DEMO-TOPOLOGY
    c3_id = "DEMO-TOPOLOGY"
    if c3_id in cases:
        del cases[c3_id]
    create_case(CreateCaseRequest(case_id=c3_id, title="Cadastral Boundary Overlap Resolution", description="Adjoining parcels 101 and 102 have 18-meter overlapping sliver"))
    ingest_data(c3_id, IngestBatchRequest(
        nodes=[
            ProvenanceNodeInput(node_id="village_map_north", node_type="origin", metadata={"agency": "CADASTRAL"}),
            ProvenanceNodeInput(node_id="village_map_south", node_type="origin", metadata={"agency": "CADASTRAL"}),
        ],
        records=[
            RecordInput(
                record_id="PARCEL-101",
                source_crs="EPSG:4326",
                provenance_node_id="village_map_north",
                geometry={
                    "type": "Polygon",
                    "coordinates": [[[77.6100, 12.9900], [77.6110, 12.9900], [77.6110, 12.9912], [77.6100, 12.9912], [77.6100, 12.9900]]]
                },
                metadata={"survey_number": "101", "area_sq_m": 14500.0, "owner": "K. V. Reddy", "land_use": "AGRICULTURAL"}
            ),
            RecordInput(
                record_id="PARCEL-102",
                source_crs="EPSG:4326",
                provenance_node_id="village_map_south",
                geometry={
                    "type": "Polygon",
                    "coordinates": [[[77.6100, 12.9910], [77.6110, 12.9910], [77.6110, 12.9922], [77.6100, 12.9922], [77.6100, 12.9910]]]
                },
                metadata={"survey_number": "102", "area_sq_m": 14500.0, "owner": "Sunita Verma", "land_use": "AGRICULTURAL"}
            )
        ]
    ))
    run_topology_repair(c3_id, TopologyRepairRequest(snap_tolerance_m=1.5))

    # 4. DEMO-CONFLICT
    c4_id = "DEMO-CONFLICT"
    if c4_id in cases:
        del cases[c4_id]
    create_case(CreateCaseRequest(case_id=c4_id, title="Revenue vs Municipal Land-Use Conflict", description="Archaic Revenue record claims Agricultural, Municipal tax lists Commercial complex"))
    ingest_data(c4_id, IngestBatchRequest(
        nodes=[
            ProvenanceNodeInput(node_id="revenue_jamabandi_2015", node_type="origin", metadata={"agency": "REVENUE"}),
            ProvenanceNodeInput(node_id="municipal_tax_2025", node_type="origin", metadata={"agency": "MUNICIPAL"}),
        ],
        records=[
            RecordInput(
                record_id="REV-204",
                source_crs="EPSG:4326",
                provenance_node_id="revenue_jamabandi_2015",
                timestamp="2015-08-20T11:00:00Z",
                geometry={
                    "type": "Polygon",
                    "coordinates": [[[77.6200, 13.0000], [77.6210, 13.0000], [77.6210, 13.0010], [77.6200, 13.0010], [77.6200, 13.0000]]]
                },
                metadata={"survey_number": "204", "area_sq_m": 12000.0, "owner": "Anil Deshmukh", "land_use": "AGRICULTURAL"}
            ),
            RecordInput(
                record_id="MUN-204",
                source_crs="EPSG:4326",
                provenance_node_id="municipal_tax_2025",
                timestamp="2025-02-01T15:00:00Z",
                geometry={
                    "type": "Polygon",
                    "coordinates": [[[77.6200, 13.0000], [77.6210, 13.0000], [77.6210, 13.0010], [77.6200, 13.0010], [77.6200, 13.0000]]]
                },
                metadata={"survey_number": "204", "area_sq_m": 11450.0, "owner": "Anil Deshmukh & Sons", "land_use": "COMMERCIAL"}
            )
        ]
    ))
    generate_proposal(c4_id)

    return {
        "status": "seeded",
        "cases_seeded": [c1_id, c2_id, c3_id, c4_id],
        "message": "Successfully initialized 4 official SIH26013 test cases."
    }


class TriRealityRequest(BaseModel):
    legal_record: Optional[Dict[str, Any]] = None
    surveyed_record: Optional[Dict[str, Any]] = None
    observed_record: Optional[Dict[str, Any]] = None
    tolerance_mode: Optional[str] = None  # passthrough field for showcase trigger


@router.post("/cases/{case_id}/reconcile/tri-reality")
@router.post("/reconcile/tri-reality")
def reconcile_tri_reality_endpoint(req: Optional[TriRealityRequest] = None, case_id: Optional[str] = None):
    """
    Reconciles Legal Cadastral Boundary, Surveyed GNSS Boundary, and Observed Drone Footprint.
    Evaluates positional uncertainties and evidence-weighted hypotheses.
    """
    from app.core.reconciliation import calculate_tri_reality_reconciliation
    legal = req.legal_record if req else None
    surveyed = req.surveyed_record if req else None
    observed = req.observed_record if req else None
    return calculate_tri_reality_reconciliation(
        legal_record=legal,
        surveyed_record=surveyed,
        observed_record=observed
    )


@router.post("/cases/{case_id}/reconcile/counterfactuals")
@router.post("/reconcile/counterfactuals")
def simulate_counterfactuals_endpoint(req: Optional[TriRealityRequest] = None, case_id: Optional[str] = None):
    """
    Simulates counterfactual harmonization scenarios: 'What if we trust Cadastral vs GNSS vs Observed?'
    """
    from app.core.reconciliation import simulate_counterfactual_harmonization
    legal = req.legal_record if req else None
    surveyed = req.surveyed_record if req else None
    observed = req.observed_record if req else None
    return simulate_counterfactual_harmonization(
        legal_record=legal,
        surveyed_record=surveyed,
        observed_record=observed
    )


@router.get("/cases/{case_id}/benchmark")
@router.get("/benchmark")
def run_live_geospatial_benchmark_endpoint(parcels: int = 4, case_id: Optional[str] = None, runs: int = 2):
    """
    Runs actual dynamic evaluation runs on synthetic spatial datasets to compute real metrics.
    No hardcoded values.
    """
    from app.core.benchmark import run_live_geospatial_benchmark
    n = min(max(1, parcels), 10)
    r = min(max(1, runs), 10)
    return run_live_geospatial_benchmark(num_synthetic_parcels=n, runs=r)



# ── Mount router at root AND at /api ──────────────────────────────────────────
app.include_router(router)
app.include_router(router, prefix="/api")

# Static Workstation UI files
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", response_class=HTMLResponse)
def index_page():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return "<h1>SIH26013 Geospatial Engine Running</h1>"
