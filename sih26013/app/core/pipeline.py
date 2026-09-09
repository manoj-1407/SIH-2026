"""Integrated multi-source geospatial analysis pipeline.

Order:
  Validate → Normalize → CRS check → Geometry compare →
  Temporal analyze → Provenance → Classify → Sign → Persist
"""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime, timezone

from app.core.geometry import (
    validate_geojson_geometry, normalize_to_wgs84, compare_geometries,
)
from app.core.temporal import analyze_temporal
from app.core.crs_check import check_crs_plausibility
from app.core.provenance import LineageGraph, ProvenanceResult
from app.core.classification import GeoClassification, ProvenanceClassification
from app.core.evidence_envelope import build_evidence_payload, sign_evidence
from app.core.signing import get_signing_key, get_registry


@dataclass
class IngestionRecord:
    record_id: str
    geom_dict: dict
    crs: str
    timestamp: Optional[str]
    provenance_node_id: Optional[str]
    metadata: dict = field(default_factory=dict)


@dataclass
class IngestionResult:
    accepted: list[str]   # record_ids accepted
    rejected: list[dict]  # {record_id, reason}


@dataclass
class PairAnalysis:
    record_id_a: str
    record_id_b: str
    geo_classification: str
    provenance_classification: str
    independent_lineages: int
    unknown: bool
    explanation: str
    measurements: dict
    evidence_envelope: Optional[dict] = None
    comparison_id: str = ""


def validate_and_normalize_record(rec: IngestionRecord) -> tuple[bool, Any, str]:
    """Returns (ok, normalized_geom_or_None, reason)."""
    # 1. CRS check first (catches metre/degree confusion before geometry parse)
    # We do a lightweight coordinate range check on raw coords. This is a
    # best-effort pre-check on attacker-controlled JSON — malformed input
    # (coordinates as a dict, string, or number instead of a nested array)
    # must not crash the request; if it can't be flattened, we simply skip
    # this pre-check and let step 2's real geometry validation reject it
    # with a proper error instead of a 500.
    coords = rec.geom_dict.get("coordinates")
    if coords:
        try:
            flat = _flatten_coords(coords)
        except (RecursionError, TypeError):
            flat = []
        if flat:
            xs = [c[0] for c in flat]
            ys = [c[1] for c in flat]
            max_val = max(abs(v) for v in xs + ys)
            if max_val > 1000:
                return False, None, f"coordinate values ({max_val:.0f}) suggest metre-range data declared as degrees (CRS_ERROR)"
            if any(abs(y) > 90 for y in ys):
                return False, None, f"y-coordinate outside [-90,90] — impossible geographic extent"
            if any(abs(x) > 180 for x in xs):
                return False, None, f"x-coordinate outside [-180,180] — impossible geographic extent"

    # 2. Geometry validation
    vr = validate_geojson_geometry(rec.geom_dict)
    if not vr.valid:
        return False, None, f"invalid geometry: {vr.reason}"

    # 3. Normalize CRS
    try:
        geom_wgs84 = normalize_to_wgs84(vr.geometry, rec.crs)
    except Exception as e:
        return False, None, f"CRS normalization failed: {e}"

    # 4. Post-normalization plausibility
    crs_result = check_crs_plausibility(geom_wgs84, "EPSG:4326")
    if not crs_result.ok and crs_result.category in ("IMPOSSIBLE_EXTENT", "DEGREE_METRE_CONFUSION", "AXIS_ORDER"):
        return False, None, f"CRS plausibility failure ({crs_result.category}): {crs_result.issue}"

    return True, geom_wgs84, ""


def _flatten_coords(coords, _depth: int = 0) -> list:
    """Recursively flatten coordinate arrays.

    `coords` is untrusted JSON at this point — it may not be a list at all
    (a malformed record could submit coordinates as a dict, a string, or a
    bare number). Only list/tuple is a valid GeoJSON coordinate container;
    anything else means malformed input, so return [] and let the real
    GeoJSON geometry validator (step 2 above) produce the actual rejection
    reason. A depth cap also stops pathological/deeply-nested input from
    recursing arbitrarily.
    """
    if not coords:
        return []
    if not isinstance(coords, (list, tuple)):
        return []
    if _depth > 20:
        return []
    if isinstance(coords[0], (int, float)):
        return [coords]
    result = []
    for item in coords:
        result.extend(_flatten_coords(item, _depth + 1))
    return result


def analyze_pair(
    case_id: str,
    rec_a: IngestionRecord,
    geom_a,
    rec_b: IngestionRecord,
    geom_b,
    lineage_graph: LineageGraph,
    sign: bool = True,
) -> PairAnalysis:
    """Full pipeline analysis for one candidate pair."""
    comparison_id = f"CMP-{uuid.uuid4().hex[:8].upper()}"

    # Geometry
    geo = compare_geometries(geom_a, geom_b)

    # Temporal
    temp = analyze_temporal(rec_a.timestamp, rec_b.timestamp)

    # CRS plausibility for each record
    crs_a = check_crs_plausibility(geom_a)
    crs_b = check_crs_plausibility(geom_b)
    crs_issue = ""
    crs_category = "NONE"
    if not crs_a.ok:
        crs_issue = f"Record A: {crs_a.issue}"
        crs_category = crs_a.category
    elif not crs_b.ok:
        crs_issue = f"Record B: {crs_b.issue}"
        crs_category = crs_b.category

    # Provenance — only if both have provenance nodes
    prov_result: ProvenanceResult
    if rec_a.provenance_node_id and rec_b.provenance_node_id:
        prov_result = lineage_graph.analyze_independence(
            [rec_a.provenance_node_id, rec_b.provenance_node_id]
        )
    else:
        prov_result = ProvenanceResult(
            0, [], False, True,
            "missing provenance node_id — independence cannot be determined"
        )

    # Classification (geometry + temporal + CRS, independent of provenance)
    geo_cls: str
    explanation_parts = []

    if crs_category not in ("NONE", "PLAUSIBILITY"):
        geo_cls = GeoClassification.CRS_ERROR.value
        explanation_parts.append(f"CRS error intercepted before geometry interpretation: {crs_issue}")
    elif not temp.valid:
        geo_cls = GeoClassification.DATA_QUALITY_ISSUE.value
        explanation_parts.append(f"Temporal data quality issue: {temp.reason}")
    elif geo.conflict and temp.qualified:
        geo_cls = GeoClassification.TEMPORALLY_QUALIFIED.value
        explanation_parts.append(
            f"Geometric conflict, but temporal gap {temp.gap_days:.0f} days qualifies it as a "
            f"temporally qualified discrepancy rather than a concurrent conflict."
        )
    elif geo.conflict:
        geo_cls = GeoClassification.GEOMETRIC_CONFLICT.value
        explanation_parts.append(f"Geometric conflict: {geo.reason}")
    elif crs_category == "PLAUSIBILITY":
        geo_cls = GeoClassification.PLAUSIBILITY_WARNING.value
        explanation_parts.append(f"Coordinate plausibility concern: {crs_issue}")
    else:
        geo_cls = GeoClassification.NO_CONFLICT.value
        explanation_parts.append("No significant geometric difference detected.")

    # Provenance classification — separate dimension, never erases geometry result
    if prov_result.unknown:
        prov_cls = ProvenanceClassification.UNKNOWN.value
        explanation_parts.append(f"Provenance: UNKNOWN — {prov_result.reason}")
    elif prov_result.is_independent:
        prov_cls = ProvenanceClassification.INDEPENDENT.value
        explanation_parts.append(
            f"Provenance: INDEPENDENT ({prov_result.independent_lineages} distinct origins)"
        )
    else:
        prov_cls = ProvenanceClassification.NOT_INDEPENDENT.value
        explanation_parts.append(
            f"Provenance: NOT INDEPENDENT — {prov_result.reason}"
        )

    # UNKNOWN override — if provenance is unknown and geometry is conflict,
    # the overall determination cannot be made with confidence
    final_unknown = prov_result.unknown and geo_cls == GeoClassification.GEOMETRIC_CONFLICT.value

    explanation = " | ".join(explanation_parts)

    # Evidence envelope
    envelope = None
    if sign:
        temporal_dict = {
            "valid": temp.valid,
            "qualified": temp.qualified,
            "gap_days": temp.gap_days,
            "reason": temp.reason,
        }
        crs_dict = {
            "ok": crs_a.ok and crs_b.ok,
            "issue": crs_issue,
            "category": crs_category,
        }
        prov_dict = {
            "independent_lineages": prov_result.independent_lineages,
            "origins": prov_result.origins,
            "is_independent": prov_result.is_independent,
            "unknown": prov_result.unknown,
            "reason": prov_result.reason,
        }
        payload = build_evidence_payload(
            comparison_id=comparison_id,
            case_id=case_id,
            record_ids=[rec_a.record_id, rec_b.record_id],
            geo_classification=geo_cls,
            geo_measurements=geo.measurements,
            temporal_result=temporal_dict,
            crs_result=crs_dict,
            provenance_result=prov_dict,
            independent_lineages=prov_result.independent_lineages,
            explanation=explanation,
        )
        sk = get_signing_key()
        envelope = sign_evidence(payload, sk)

    return PairAnalysis(
        record_id_a=rec_a.record_id,
        record_id_b=rec_b.record_id,
        geo_classification=geo_cls,
        provenance_classification=prov_cls,
        independent_lineages=prov_result.independent_lineages,
        unknown=final_unknown,
        explanation=explanation,
        measurements=geo.measurements,
        evidence_envelope=envelope,
        comparison_id=comparison_id,
    )


@dataclass
class AnalysisSummary:
    total_ingested: int
    rejected_at_ingestion: int
    valid_after_ingestion: int
    candidate_pairs_examined: int
    cases_flagged: int
    signed_case_ids: list[str]
    pair_results: list[PairAnalysis]


class AnalysisPipeline:
    def __init__(self, case_id: str, evidence_store=None):
        from app.core.spatial_index import SpatialCandidateIndex, IndexedRecord
        self.case_id = case_id
        self.evidence_store = evidence_store
        self.spatial_index = SpatialCandidateIndex()
        self.records: dict[str, IngestionRecord] = {}
        self.normalized_geoms: dict = {}
        self.rejected: list[dict] = []

    def ingest_record(self, record: IngestionRecord) -> tuple[bool, str]:
        from app.core.spatial_index import IndexedRecord
        ok, geom_wgs84, reason = validate_and_normalize_record(record)
        if not ok:
            self.rejected.append({"record_id": record.record_id, "reason": reason})
            return False, reason
        self.records[record.record_id] = record
        self.normalized_geoms[record.record_id] = geom_wgs84
        self.spatial_index.insert(record.record_id, geom_wgs84)
        return True, ""

    def run_analysis(self, lineage_graph: LineageGraph, sign: bool = True) -> AnalysisSummary:
        from app.core.spatial_index import IndexedRecord
        indexed_recs = [
            IndexedRecord(r.record_id, self.normalized_geoms[r.record_id], self.normalized_geoms[r.record_id].bounds)
            for r in self.records.values()
        ]
        candidate_pairs = list(self.spatial_index.generate_candidate_pairs(indexed_recs))

        pair_results: list[PairAnalysis] = []
        flagged_count = 0
        signed_ids: list[str] = []

        for cand_a, cand_b in candidate_pairs:
            rec_a = self.records[cand_a.record_id]
            rec_b = self.records[cand_b.record_id]
            geom_a = self.normalized_geoms[cand_a.record_id]
            geom_b = self.normalized_geoms[cand_b.record_id]

            res = analyze_pair(self.case_id, rec_a, geom_a, rec_b, geom_b, lineage_graph, sign=sign)
            pair_results.append(res)

            if res.geo_classification != GeoClassification.NO_CONFLICT.value:
                flagged_count += 1

            if res.evidence_envelope and self.evidence_store:
                self.evidence_store.save(res.comparison_id, res.evidence_envelope)
                signed_ids.append(res.comparison_id)

        return AnalysisSummary(
            total_ingested=len(self.records) + len(self.rejected),
            rejected_at_ingestion=len(self.rejected),
            valid_after_ingestion=len(self.records),
            candidate_pairs_examined=len(candidate_pairs),
            cases_flagged=flagged_count,
            signed_case_ids=signed_ids,
            pair_results=pair_results,
        )
