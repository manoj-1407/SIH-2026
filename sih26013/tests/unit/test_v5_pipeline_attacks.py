import pytest
from shapely.geometry import Polygon
from app.core.pipeline import IngestionRecord, analyze_pair
from app.core.provenance import LineageGraph, LineageNode
from app.core.signing import get_registry
from app.core.evidence_envelope import verify_envelope

POLY_SQUARE = {
    "type": "Polygon",
    "coordinates": [[[77.0, 28.0], [77.1, 28.0], [77.1, 28.1], [77.0, 28.1], [77.0, 28.0]]]
}
POLY_SHIFTED = {
    "type": "Polygon",
    "coordinates": [[[77.05, 28.0], [77.15, 28.0], [77.15, 28.1], [77.05, 28.1], [77.05, 28.0]]]
}

def test_coexisting_conflict_and_lineage_collapse():
    # Both GEOMETRIC_CONFLICT and NOT_INDEPENDENT coexist without erasing each other
    graph = LineageGraph()
    graph.add_node(LineageNode("ROOT", "origin"))
    graph.add_node(LineageNode("REC-A", "record", parent_ids=["ROOT"]))
    graph.add_node(LineageNode("REC-B", "record", parent_ids=["ROOT"]))

    rec_a = IngestionRecord("REC-A", POLY_SQUARE, "EPSG:4326", "2024-01-01T00:00:00Z", "REC-A")
    rec_b = IngestionRecord("REC-B", POLY_SHIFTED, "EPSG:4326", "2024-01-03T00:00:00Z", "REC-B")
    ga = Polygon(POLY_SQUARE["coordinates"][0])
    gb = Polygon(POLY_SHIFTED["coordinates"][0])

    res = analyze_pair("CASE-A1", rec_a, ga, rec_b, gb, graph, sign=True)
    assert res.geo_classification == "GEOMETRIC_CONFLICT"
    assert res.provenance_classification == "NOT_INDEPENDENT"
    assert res.independent_lineages == 1
    assert res.evidence_envelope is not None

def test_temporally_qualified_conflict_override():
    # 5 years apart with different geometry -> TEMPORALLY_QUALIFIED
    graph = LineageGraph()
    graph.add_node(LineageNode("ROOT", "origin"))
    graph.add_node(LineageNode("REC-A", "record", parent_ids=["ROOT"]))
    graph.add_node(LineageNode("REC-B", "record", parent_ids=["ROOT"]))

    rec_a = IngestionRecord("REC-A", POLY_SQUARE, "EPSG:4326", "2018-01-01T00:00:00Z", "REC-A")
    rec_b = IngestionRecord("REC-B", POLY_SHIFTED, "EPSG:4326", "2023-01-01T00:00:00Z", "REC-B")
    ga = Polygon(POLY_SQUARE["coordinates"][0])
    gb = Polygon(POLY_SHIFTED["coordinates"][0])

    res = analyze_pair("CASE-A2", rec_a, ga, rec_b, gb, graph, sign=True)
    assert "TEMPORAL" in res.geo_classification or res.geo_classification == "TEMPORALLY_QUALIFIED"

def test_missing_provenance_forces_unknown():
    graph = LineageGraph()
    # Missing provenance with conflicting geometries
    rec_a = IngestionRecord("REC-1", POLY_SQUARE, "EPSG:4326", "2024-01-01T00:00:00Z", None)
    rec_b = IngestionRecord("REC-2", POLY_SHIFTED, "EPSG:4326", "2024-01-01T00:00:00Z", None)
    ga = Polygon(POLY_SQUARE["coordinates"][0])
    gb = Polygon(POLY_SHIFTED["coordinates"][0])

    res = analyze_pair("CASE-A3", rec_a, ga, rec_b, gb, graph, sign=True)
    assert res.unknown is True
    assert res.provenance_classification == "UNKNOWN"
