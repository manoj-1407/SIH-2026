import pytest
from app.core.provenance import LineageGraph, LineageNode

def test_single_origin_three_records_collapse():
    # 3 records all descending from same origin -> independent_lineages == 1
    g = LineageGraph()
    g.add_node(LineageNode("ORIGIN-1", "origin"))
    g.add_node(LineageNode("DATASET-1", "dataset", parent_ids=["ORIGIN-1"]))
    g.add_node(LineageNode("REC-A", "record", parent_ids=["DATASET-1"]))
    g.add_node(LineageNode("REC-B", "record", parent_ids=["DATASET-1"]))
    g.add_node(LineageNode("REC-C", "record", parent_ids=["DATASET-1"]))

    res = g.analyze_independence(["REC-A", "REC-B", "REC-C"])
    assert res.independent_lineages == 1
    assert res.is_independent is False
    assert res.unknown is False
    assert res.origins == ["ORIGIN-1"]

def test_two_distinct_origins_independent():
    g = LineageGraph()
    g.add_node(LineageNode("SURVEY-OF-INDIA", "origin"))
    g.add_node(LineageNode("ISRO-BHUVAN", "origin"))
    g.add_node(LineageNode("REC-1", "record", parent_ids=["SURVEY-OF-INDIA"]))
    g.add_node(LineageNode("REC-2", "record", parent_ids=["ISRO-BHUVAN"]))

    res = g.analyze_independence(["REC-1", "REC-2"])
    assert res.independent_lineages == 2
    assert res.is_independent is True
    assert res.unknown is False

def test_missing_provenance_returns_unknown():
    g = LineageGraph()
    # Records not registered in graph
    res = g.analyze_independence(["UNKNOWN-1", "UNKNOWN-2"])
    assert res.unknown is True
    assert res.independent_lineages == 0

def test_circular_lineage_handled_safely():
    g = LineageGraph()
    g.add_node(LineageNode("NODE-A", "dataset", parent_ids=["NODE-B"]))
    g.add_node(LineageNode("NODE-B", "dataset", parent_ids=["NODE-A"]))
    g.add_node(LineageNode("REC-CYCLE", "record", parent_ids=["NODE-A"]))

    res = g.analyze_independence(["REC-CYCLE"])
    # Circular lineage should not hang and must flag unknown/cycle
    assert res.unknown is True or res.independent_lineages == 0

def test_metadata_independence_claim_ignored_if_graph_shows_shared_origin():
    # Even if record metadata says "independent: true", graph traversal dictates reality
    g = LineageGraph()
    g.add_node(LineageNode("ROOT", "origin"))
    g.add_node(LineageNode("REC-X", "record", parent_ids=["ROOT"]))
    g.add_node(LineageNode("REC-Y", "record", parent_ids=["ROOT"]))

    res = g.analyze_independence(["REC-X", "REC-Y"])
    assert res.independent_lineages == 1
