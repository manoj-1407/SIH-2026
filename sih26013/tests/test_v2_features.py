"""Unit tests for SIH26013 v2 enhancements (Canonical Model, AI Matcher, Attribute Harmonizer, Drone Footprints, Topology Repair, Proposals)."""
import pytest
from app.core.canonical_model import CanonicalParcel, AgencyType, LandUseType
from app.core.ai_matcher import match_parcels, normalize_survey_number, survey_number_similarity
from app.core.attribute_harmonizer import normalize_area_to_sq_m, compare_parcel_attributes, map_raw_record_to_canonical
from app.core.imagery_features import BuildingFootprint, analyze_drone_footprints
from app.core.topology_repair import detect_topology_anomalies, repair_cadastral_topology
from app.core.harmonization_proposal import create_harmonization_proposal, review_proposal
from app.core.signing import SigningKey


def test_canonical_parcel():
    geom = {
        "type": "Polygon",
        "coordinates": [[[77.594, 12.971], [77.595, 12.971], [77.595, 12.972], [77.594, 12.972], [77.594, 12.971]]]
    }
    p = CanonicalParcel.create(
        survey_number="Plot 42/1",
        source_agency=AgencyType.REVENUE,
        area_sq_m=12000.0,
        geometry=geom,
        owner_ref="Rajesh Rao",
        land_use=LandUseType.RESIDENTIAL,
    )
    d = p.to_dict()
    assert d["survey_number"] == "Plot 42/1"
    assert d["source_agency"] == "REVENUE"
    assert d["land_use"] == "RESIDENTIAL"

    p2 = CanonicalParcel.from_dict(d)
    assert p2.survey_number == p.survey_number
    assert p2.source_agency == AgencyType.REVENUE


def test_ai_matcher():
    # Identical parcels should yield DEFINITE_MATCH
    geom = {
        "type": "Polygon",
        "coordinates": [[[77.594, 12.971], [77.595, 12.971], [77.595, 12.972], [77.594, 12.972], [77.594, 12.971]]]
    }
    p1 = CanonicalParcel.create(survey_number="42/1", source_agency=AgencyType.REVENUE, area_sq_m=10000.0, geometry=geom)
    p2 = CanonicalParcel.create(survey_number="42-1", source_agency=AgencyType.MUNICIPAL, area_sq_m=10000.0, geometry=geom)

    match = match_parcels(p1, p2)
    assert match.classification == "DEFINITE_MATCH"
    assert match.match_probability >= 0.85
    assert match.features.iou >= 0.99
    assert match.features.survey_sim >= 0.90


def test_attribute_harmonizer():
    # Unit conversion
    assert normalize_area_to_sq_m(1.0, "acre") > 4000.0
    assert normalize_area_to_sq_m(1.0, "guntha") > 100.0

    geom = {
        "type": "Polygon",
        "coordinates": [[[77.594, 12.971], [77.595, 12.971], [77.595, 12.972], [77.594, 12.972], [77.594, 12.971]]]
    }
    p1 = CanonicalParcel.create(survey_number="42", source_agency=AgencyType.REVENUE, area_sq_m=10000.0, geometry=geom, land_use=LandUseType.AGRICULTURAL)
    p2 = CanonicalParcel.create(survey_number="42", source_agency=AgencyType.MUNICIPAL, area_sq_m=12000.0, geometry=geom, land_use=LandUseType.COMMERCIAL)

    rep = compare_parcel_attributes(p1, p2)
    assert rep.land_use_status == "CONFLICT"
    assert rep.severity in ("WARNING", "CRITICAL")
    assert len(rep.discrepancies) >= 1


def test_imagery_encroachment():
    parcel_geom = {
        "type": "Polygon",
        "coordinates": [[[77.600, 12.980], [77.601, 12.980], [77.601, 12.981], [77.600, 12.981], [77.600, 12.980]]]
    }
    parcel = CanonicalParcel.create(survey_number="78", source_agency=AgencyType.CADASTRAL, area_sq_m=10000.0, geometry=parcel_geom)

    # Footprint crossing outside east boundary (77.6010 to 77.6015)
    fp_geom = {
        "type": "Polygon",
        "coordinates": [[[77.6008, 12.9805], [77.6015, 12.9805], [77.6015, 12.9809], [77.6008, 12.9809], [77.6008, 12.9805]]]
    }
    fp = BuildingFootprint(footprint_id="FP-1", geometry=fp_geom, area_sq_m=500.0)

    res = analyze_drone_footprints(parcel, [fp])
    assert len(res.encroachments) >= 1
    assert res.encroachments[0].severity in ("SIGNIFICANT", "SEVERE")
    assert res.encroachments[0].encroached_area_sq_m > 0


def test_topology_repair():
    # Two overlapping squares
    geom1 = {
        "type": "Polygon",
        "coordinates": [[[77.610, 12.990], [77.612, 12.990], [77.612, 12.992], [77.610, 12.992], [77.610, 12.990]]]
    }
    geom2 = {
        "type": "Polygon",
        "coordinates": [[[77.611, 12.990], [77.613, 12.990], [77.613, 12.992], [77.611, 12.992], [77.611, 12.990]]]
    }
    p1 = CanonicalParcel.create(survey_number="101", source_agency=AgencyType.CADASTRAL, area_sq_m=10000.0, geometry=geom1, confidence_weight=2.0)
    p2 = CanonicalParcel.create(survey_number="102", source_agency=AgencyType.CADASTRAL, area_sq_m=10000.0, geometry=geom2, confidence_weight=1.0)

    anoms = detect_topology_anomalies([p1, p2])
    assert len(anoms) == 1
    assert anoms[0].anomaly_type == "OVERLAP"
    assert anoms[0].area_sq_m > 0

    repaired = repair_cadastral_topology([p1, p2], snap_tolerance_m=1.0)
    assert repaired.residual_overlap_sq_m == 0.0
    assert repaired.initial_overlap_sq_m > 0.0


def test_harmonization_proposals():
    geom = {
        "type": "Polygon",
        "coordinates": [[[77.594, 12.971], [77.595, 12.971], [77.595, 12.972], [77.594, 12.972], [77.594, 12.971]]]
    }
    p1 = CanonicalParcel.create(survey_number="42/1", source_agency=AgencyType.REVENUE, area_sq_m=12000.0, geometry=geom)
    p2 = CanonicalParcel.create(survey_number="42-1", source_agency=AgencyType.MUNICIPAL, area_sq_m=12050.0, geometry=geom)

    prop = create_harmonization_proposal(case_id="CASE-HARMONIZE-1", parcels=[p1, p2])
    assert prop.target_survey_number == "42/1"
    assert prop.confidence_score >= 0.70

    signing_key = SigningKey.generate("KEY-TEST-001")
    reviewed = review_proposal(prop, action="APPROVE", reviewer_id="OFFICER_1", notes="Concurred", signing_key=signing_key)
    assert reviewed.status.value == "APPROVED"
    assert reviewed.signed_evidence_envelope is not None
    assert "evidence_id" in reviewed.signed_evidence_envelope
