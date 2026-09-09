"""Provenance and independence analysis.

Follows parent_id graph structure. Does NOT trust metadata name claims.
Three records with the same origin = 1 independent lineage, not 3.

Lineage model:
  Origin → Dataset → Transformation → Derived Dataset → Published Record
  (Or: Origin → Published Record directly)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LineageNode:
    node_id: str
    node_type: str          # "origin", "dataset", "transformation", "record"
    parent_ids: list[str] = field(default_factory=list)
    content_hash: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class ProvenanceResult:
    independent_lineages: int   # number of distinct origin nodes reachable
    origins: list[str]          # list of origin node_ids
    is_independent: bool        # True if independent_lineages > 1
    unknown: bool               # True if provenance is insufficient to determine
    reason: str


class LineageGraph:
    def __init__(self):
        self._nodes: dict[str, LineageNode] = {}

    def add_node(self, node: LineageNode) -> None:
        self._nodes[node.node_id] = node

    def get(self, node_id: str) -> Optional[LineageNode]:
        return self._nodes.get(node_id)

    def _find_origins(self, node_id: str, visited: set) -> set[str]:
        """DFS to find all reachable origin nodes. Detects cycles."""
        if node_id in visited:
            raise RecursionError(f"circular provenance detected at {node_id!r}")
        visited = visited | {node_id}

        node = self._nodes.get(node_id)
        if node is None:
            raise KeyError(f"node {node_id!r} not found in provenance graph")

        if node.node_type == "origin":
            return {node_id}

        if not node.parent_ids:
            # Not an origin but has no parents — treat as unknown lineage terminal
            raise ValueError(f"non-origin node {node_id!r} has no parents — incomplete provenance")

        origins = set()
        for parent_id in node.parent_ids:
            origins |= self._find_origins(parent_id, visited)
        return origins

    def analyze_independence(self, record_ids: list[str]) -> ProvenanceResult:
        """
        Given a list of published record node_ids, determine how many
        independent origin nodes they collectively trace back to.
        """
        if not record_ids:
            return ProvenanceResult(0, [], False, True, "no records provided")

        all_origins: set[str] = set()
        for rec_id in record_ids:
            try:
                origins = self._find_origins(rec_id, set())
                all_origins |= origins
            except KeyError as e:
                return ProvenanceResult(0, [], False, True, f"missing provenance node: {e}")
            except RecursionError as e:
                return ProvenanceResult(0, [], False, True, str(e))
            except ValueError as e:
                return ProvenanceResult(0, [], False, True, str(e))

        count = len(all_origins)
        origins_list = sorted(all_origins)
        is_indep = count > 1

        if count == 0:
            return ProvenanceResult(0, [], False, True, "no origin nodes found")

        return ProvenanceResult(
            independent_lineages=count,
            origins=origins_list,
            is_independent=is_indep,
            unknown=False,
            reason=(
                f"{count} independent origin(s): {origins_list}"
                if is_indep
                else f"all records share 1 origin ({origins_list[0]}) — NOT independent"
            ),
        )

    def verify_content_hashes(self, record_ids: list[str], expected_hashes: dict[str, str]) -> bool:
        """
        Verify that node content_hashes match expected values.
        Returns False if any hash mismatches (indicates source tampering).
        """
        for node_id, expected in expected_hashes.items():
            node = self._nodes.get(node_id)
            if node is None:
                return False
            if node.content_hash != expected:
                return False
        return True
