"""
Harmonization Proposal & Official Review Engine — SIH26013

Synthesizes multi-source inputs (Revenue records, Municipal GIS, Drone ORI,
Topology corrections) into an authoritative Harmonization Proposal.
Features:
  1. Automated recommendation of canonical boundaries, area, and land use
  2. Multi-tier confidence scoring
  3. Official human-in-the-loop review workflow (PENDING, APPROVED, REJECTED, FIELD_INSPECTION)
  4. Cryptographic Ed25519 signing on approval
  5. Interoperable GIS export payloads (GeoJSON FeatureCollection)
"""
import uuid
import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict

from app.core.canonical_model import CanonicalParcel, LandUseType
from app.core.ai_matcher import MatchResult
from app.core.attribute_harmonizer import DiscrepancyReport
from app.core.signing import SigningKey, get_signing_key
from app.core.evidence_envelope import sign_evidence


class ProposalStatus(str, Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    FIELD_INSPECTION_REQUIRED = "FIELD_INSPECTION_REQUIRED"


@dataclass
class HarmonizationProposal:
    proposal_id: str
    case_id: str
    target_survey_number: str
    source_parcel_ids: List[str]
    recommended_area_sq_m: float
    recommended_land_use: str
    recommended_owner_ref: str
    recommended_geometry: Dict[str, Any]
    confidence_score: float
    score_breakdown: Dict[str, float]
    status: ProposalStatus
    reviewer_id: Optional[str] = None
    reviewer_notes: Optional[str] = None
    reviewed_at_utc: Optional[str] = None
    signed_evidence_envelope: Optional[Dict[str, Any]] = None
    created_at_utc: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


def create_harmonization_proposal(
    case_id: str,
    parcels: List[CanonicalParcel],
    match_result: Optional[MatchResult] = None,
    discrepancy_report: Optional[DiscrepancyReport] = None,
) -> HarmonizationProposal:
    """Generate a proposal reconciling multi-source inputs."""
    prop_id = f"PROP-{uuid.uuid4().hex[:8].upper()}"

    # Highest weighted parcel takes precedence for survey ID & ownership
    primary = max(parcels, key=lambda p: p.confidence_weight) if parcels else parcels[0]
    p_ids = [p.parcel_id for p in parcels]

    # Harmonized Area: Drone/Ground-truth if available, else average of conforming inputs
    drone_parcels = [p for p in parcels if p.source_agency.value == "DRONE_SURVEY"]
    if drone_parcels:
        recommended_area = drone_parcels[0].area_sq_m
        recommended_geom = drone_parcels[0].geometry
    else:
        recommended_area = round(sum(p.area_sq_m for p in parcels) / max(1, len(parcels)), 2)
        recommended_geom = primary.geometry

    # Land use: Municipal/Cadastral ground reality over archaic revenue entry
    lu = primary.land_use.value
    for p in parcels:
        if p.source_agency.value in ("MUNICIPAL", "DRONE_SURVEY") and p.land_use != LandUseType.UNKNOWN:
            lu = p.land_use.value
            break

    # Confidence calculation
    spatial_sim = match_result.features.iou if match_result else 0.90
    survey_sim = match_result.features.survey_sim if match_result else 0.95
    attr_penalty = 0.20 if (discrepancy_report and discrepancy_report.severity == "CRITICAL") else 0.05

    score = max(0.1, min(0.99, (0.5 * spatial_sim + 0.4 * survey_sim + 0.1) - attr_penalty))

    breakdown = {
        "spatial_boundary_alignment": round(spatial_sim * 0.5, 3),
        "survey_registry_concordance": round(survey_sim * 0.4, 3),
        "attribute_discrepancy_penalty": round(-attr_penalty, 3),
        "net_confidence": round(score, 3),
    }

    initial_status = ProposalStatus.FIELD_INSPECTION_REQUIRED if score < 0.65 else ProposalStatus.PENDING_REVIEW

    return HarmonizationProposal(
        proposal_id=prop_id,
        case_id=case_id,
        target_survey_number=primary.survey_number,
        source_parcel_ids=p_ids,
        recommended_area_sq_m=recommended_area,
        recommended_land_use=lu,
        recommended_owner_ref=primary.owner_ref,
        recommended_geometry=recommended_geom,
        confidence_score=round(score, 3),
        score_breakdown=breakdown,
        status=initial_status,
    )


def review_proposal(
    proposal: HarmonizationProposal,
    action: str,  # APPROVE, REJECT, REQUEST_INSPECTION
    reviewer_id: str,
    notes: str,
    signing_key: Optional[SigningKey] = None,
) -> HarmonizationProposal:
    """Submit official review decision and generate signed envelope if approved."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    proposal.reviewer_id = reviewer_id
    proposal.reviewer_notes = notes
    proposal.reviewed_at_utc = now_iso

    if action.upper() == "APPROVE":
        proposal.status = ProposalStatus.APPROVED
        evidence_id = f"EV-HARM-{uuid.uuid4().hex[:8].upper()}"
        payload = {
            "evidence_id": evidence_id,
            "proposal_id": proposal.proposal_id,
            "case_id": proposal.case_id,
            "created_at_utc": now_iso,
            "survey_number": proposal.target_survey_number,
            "harmonized_area_sq_m": proposal.recommended_area_sq_m,
            "harmonized_land_use": proposal.recommended_land_use,
            "harmonized_owner": proposal.recommended_owner_ref,
            "geometry": proposal.recommended_geometry,
            "confidence_score": proposal.confidence_score,
            "decision": "APPROVED",
            "reviewer_id": reviewer_id,
            "result": {
                "decision": "APPROVED",
                "scope_statement": "Evidence-backed inter-departmental land-record reconciliation proposal for Ministry of Rural Development / DoLR SIH26013; final authority remains with the designated land-record authority.",
            },
        }
        envelope = sign_evidence(payload=payload, signing_key=signing_key)
        proposal.signed_evidence_envelope = envelope
    elif action.upper() == "REJECT":
        proposal.status = ProposalStatus.REJECTED
    else:
        proposal.status = ProposalStatus.FIELD_INSPECTION_REQUIRED

    return proposal
