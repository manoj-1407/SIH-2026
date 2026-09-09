import pytest
from shapely.geometry import Polygon, Point, MultiPolygon
from app.core.geometry import (
    validate_geojson_geometry,
    normalize_to_wgs84,
    compare_geometries,
    compute_iou,
    compute_hausdorff_metres,
)

def test_valid_polygon():
    poly = {
        "type": "Polygon",
        "coordinates": [[[77.0, 28.0], [77.1, 28.0], [77.1, 28.1], [77.0, 28.1], [77.0, 28.0]]]
    }
    vr = validate_geojson_geometry(poly)
    assert vr.valid is True
    assert vr.geometry is not None

def test_unclosed_ring_auto_repair():
    poly = {
        "type": "Polygon",
        "coordinates": [[[77.0, 28.0], [77.1, 28.0], [77.1, 28.1], [77.0, 28.1]]]  # unclosed
    }
    vr = validate_geojson_geometry(poly)
    assert vr.valid is True
    assert vr.geometry.is_valid

def test_self_intersecting_bowtie():
    # Bowtie polygon (self-intersection)
    poly = {
        "type": "Polygon",
        "coordinates": [[[0.0, 0.0], [2.0, 2.0], [2.0, 0.0], [0.0, 2.0], [0.0, 0.0]]]
    }
    vr = validate_geojson_geometry(poly)
    # Either repaired or flagged invalid, but must not crash
    assert vr.geometry is not None or vr.valid is False

def test_degenerate_line_as_polygon():
    poly = {
        "type": "Polygon",
        "coordinates": [[[77.0, 28.0], [77.0, 28.0], [77.0, 28.0], [77.0, 28.0]]]
    }
    vr = validate_geojson_geometry(poly)
    assert vr.valid is False or vr.geometry.area == 0.0

def test_empty_coordinates():
    poly = {"type": "Polygon", "coordinates": []}
    vr = validate_geojson_geometry(poly)
    assert vr.valid is False

def test_identical_geometries_no_conflict():
    poly = {
        "type": "Polygon",
        "coordinates": [[[77.0, 28.0], [77.1, 28.0], [77.1, 28.1], [77.0, 28.1], [77.0, 28.0]]]
    }
    g1 = validate_geojson_geometry(poly).geometry
    g2 = validate_geojson_geometry(poly).geometry
    comp = compare_geometries(g1, g2)
    assert comp.iou == pytest.approx(1.0, 0.001)
    assert comp.hausdorff_m == pytest.approx(0.0, abs=1.0)
    assert comp.conflict is False

def test_shifted_geometries_conflict():
    poly1 = {
        "type": "Polygon",
        "coordinates": [[[77.0, 28.0], [77.1, 28.0], [77.1, 28.1], [77.0, 28.1], [77.0, 28.0]]]
    }
    poly2 = {
        "type": "Polygon",
        "coordinates": [[[77.05, 28.0], [77.15, 28.0], [77.15, 28.1], [77.05, 28.1], [77.05, 28.0]]]
    }
    g1 = validate_geojson_geometry(poly1).geometry
    g2 = validate_geojson_geometry(poly2).geometry
    comp = compare_geometries(g1, g2)
    assert comp.conflict is True
    assert comp.iou < 0.6
    assert comp.hausdorff_m > 1000

def test_completely_disjoint_geometries():
    poly1 = {
        "type": "Polygon",
        "coordinates": [[[77.0, 28.0], [77.1, 28.0], [77.1, 28.1], [77.0, 28.1], [77.0, 28.0]]]
    }
    poly2 = {
        "type": "Polygon",
        "coordinates": [[[78.0, 29.0], [78.1, 29.0], [78.1, 29.1], [78.0, 29.1], [78.0, 29.0]]]
    }
    g1 = validate_geojson_geometry(poly1).geometry
    g2 = validate_geojson_geometry(poly2).geometry
    comp = compare_geometries(g1, g2)
    assert comp.iou == 0.0
    assert comp.conflict is True

def test_normalize_wgs84_noop_on_wgs84():
    p = Polygon([[77.0, 28.0], [77.1, 28.0], [77.1, 28.1], [77.0, 28.1], [77.0, 28.0]])
    norm = normalize_to_wgs84(p, "EPSG:4326")
    assert norm.equals(p)

# ─── Spatial Candidate-Window Boundary Tests ──────────────────────────────────
#
# Analytical assumption documented here:
#   The spatial candidate index is designed for records that are expected to
#   refer to the same spatial subject or locality. The CANDIDATE_BUFFER_DEGREES
#   window (~1km in geographic degrees at equator) defines the proximity threshold
#   within which two records are considered candidates for pairwise analysis.
#
#   Records separated by more than CANDIDATE_BUFFER_DEGREES in their bounding
#   boxes are explicitly excluded from pairwise analysis. This is a deliberate
#   design choice: conflicts between records that do NOT refer to the same
#   locality are out of scope for the harmonization engine.
#
#   The benchmark suite (benchmark_scale.py) proves 50/50 injected conflicts
#   detected within the candidate window — not universal conflict detection.

from app.core.spatial_index import SpatialCandidateIndex, CANDIDATE_BUFFER_DEGREES
from shapely.geometry import box as shapely_box


def test_spatial_index_candidate_window_includes_overlapping():
    """Records whose bboxes overlap within the buffer must be returned as candidates."""
    idx = SpatialCandidateIndex()
    # Two polygons that share the same approximate location (0.001 deg apart — well inside buffer)
    geom_a = shapely_box(77.0, 28.0, 77.01, 28.01)
    geom_b = shapely_box(77.005, 28.005, 77.015, 28.015)
    idx.insert("rec-A", geom_a)
    idx.insert("rec-B", geom_b)
    candidates = idx.query_candidates(geom_a)
    candidate_ids = [c.record_id for c in candidates]
    assert "rec-B" in candidate_ids, (
        "Records within the candidate buffer must be returned as candidates"
    )


def test_spatial_index_candidate_window_boundary_exact():
    """Record exactly at buffer edge must be included (inclusive boundary)."""
    idx = SpatialCandidateIndex()
    geom_a = shapely_box(0.0, 0.0, 0.01, 0.01)
    # Place rec-B exactly at the buffer edge from rec-A's max bounds
    offset = CANDIDATE_BUFFER_DEGREES  # exactly at the edge
    geom_b = shapely_box(0.01 + offset, 0.0, 0.02 + offset, 0.01)
    idx.insert("anchor", geom_a)
    idx.insert("edge", geom_b)
    candidates = idx.query_candidates(geom_a)
    candidate_ids = [c.record_id for c in candidates]
    # At exactly the buffer edge, bbox intersection is inclusive; must be a candidate
    assert "edge" in candidate_ids, (
        "Record at exact buffer boundary must be a candidate (inclusive)"
    )


def test_spatial_index_candidate_window_excludes_distant():
    """Records separated by more than the buffer must NOT be candidates.
    
    This tests and documents the deliberate analytical scoping decision:
    records in entirely different localities are excluded from pairwise analysis.
    This is not a defect — it is the intended design.
    """
    idx = SpatialCandidateIndex()
    geom_a = shapely_box(77.0, 28.0, 77.1, 28.1)
    # geom_b is 5 degrees away — clearly a different locality
    geom_b = shapely_box(82.0, 28.0, 82.1, 28.1)
    idx.insert("mumbai", geom_a)
    idx.insert("kolkata", geom_b)
    candidates = idx.query_candidates(geom_a)
    candidate_ids = [c.record_id for c in candidates]
    assert "kolkata" not in candidate_ids, (
        "Records in entirely different localities must be excluded from candidate pairing. "
        f"Buffer window is {CANDIDATE_BUFFER_DEGREES} degrees (~1km). "
        "Records separated by 5 degrees are out-of-scope by design."
    )


def test_spatial_index_candidate_pairs_symmetric_deduplication():
    """Pair generation must not return the same pair twice in opposite orders."""
    idx = SpatialCandidateIndex()
    geom_a = shapely_box(0.0, 0.0, 0.01, 0.01)
    geom_b = shapely_box(0.005, 0.0, 0.015, 0.01)
    all_recs = []
    idx.insert("A", geom_a)
    idx.insert("B", geom_b)
    from app.core.spatial_index import IndexedRecord
    recs = [IndexedRecord("A", geom_a, geom_a.bounds),
            IndexedRecord("B", geom_b, geom_b.bounds)]
    pairs = list(idx.generate_candidate_pairs(recs))
    pair_keys = [tuple(sorted([p[0].record_id, p[1].record_id])) for p in pairs]
    assert len(pair_keys) == len(set(pair_keys)), (
        "Candidate pair generation must deduplicate symmetric pairs"
    )
