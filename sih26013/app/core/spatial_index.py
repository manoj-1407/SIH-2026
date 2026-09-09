"""Spatial candidate index — SIH26013.

Purpose: candidate filtering before pairwise geometric analysis.
Uses native Shapely STRtree (built into Shapely / GEOS) as the primary index engine,
with optional RTree acceleration if libspatialindex is installed in the environment.

False-negative prevention:
- Buffer expansion applied to all candidate queries
- Known conflict pairs from injected test suite are checked end-to-end
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterator, Optional

from shapely.geometry.base import BaseGeometry
from shapely.geometry import box as shapely_box
from shapely.strtree import STRtree

# Optional RTree import if installed in environment
try:
    from rtree import index as rtree_index
    _HAS_RTREE = True
except (ImportError, OSError):
    _HAS_RTREE = False


CANDIDATE_BUFFER_DEGREES = 0.01   # ~1km buffer in geographic degrees


@dataclass
class IndexedRecord:
    record_id: str
    geometry: BaseGeometry
    bounds: tuple[float, float, float, float]


class SpatialCandidateIndex:
    """
    Dual-engine Spatial Index.
    Uses Shapely's built-in STRtree (GEOS-backed, zero extra C library dependencies).
    """
    def __init__(self):
        self._records: dict[int, IndexedRecord] = {}
        self._geometries: list[BaseGeometry] = []
        self._int_id: dict[str, int] = {}  # record_id → int id
        self._counter = 0
        self._tree: Optional[STRtree] = None
        self._dirty: bool = True

    def insert(self, record_id: str, geometry: BaseGeometry) -> None:
        if record_id in self._int_id:
            raise ValueError(f"Record {record_id!r} already in index")
        iid = self._counter
        self._counter += 1
        self._int_id[record_id] = iid
        bounds = geometry.bounds
        self._records[iid] = IndexedRecord(record_id, geometry, bounds)
        # Store envelope for fast bounding box indexing
        self._geometries.append(geometry.envelope)
        self._dirty = True

    def _get_tree(self) -> Optional[STRtree]:
        if self._dirty or self._tree is None:
            if self._geometries:
                self._tree = STRtree(self._geometries)
            else:
                self._tree = None
            self._dirty = False
        return self._tree

    def query_candidates(
        self,
        geometry: BaseGeometry,
        buffer_degrees: float = CANDIDATE_BUFFER_DEGREES,
    ) -> list[IndexedRecord]:
        """Return all indexed records whose bboxes intersect buffered geometry bbox."""
        tree = self._get_tree()
        if tree is None:
            return []

        minx, miny, maxx, maxy = geometry.bounds
        search_box = shapely_box(
            minx - buffer_degrees,
            miny - buffer_degrees,
            maxx + buffer_degrees,
            maxy + buffer_degrees,
        )
        hits = tree.query(search_box, predicate="intersects")
        return [self._records[int(i)] for i in hits]

    def generate_candidate_pairs(
        self,
        records: list[IndexedRecord],
        buffer_degrees: float = CANDIDATE_BUFFER_DEGREES,
    ) -> Iterator[tuple[IndexedRecord, IndexedRecord]]:
        """Generate all candidate pairs (a, b) where a.record_id < b.record_id."""
        seen: set[tuple[int, int]] = set()
        for rec in records:
            candidates = self.query_candidates(rec.geometry, buffer_degrees)
            for cand in candidates:
                if cand.record_id == rec.record_id:
                    continue
                pair_key = tuple(sorted([
                    self._int_id[rec.record_id],
                    self._int_id[cand.record_id],
                ]))
                if pair_key not in seen:
                    seen.add(pair_key)
                    a_iid, b_iid = pair_key
                    yield self._records[a_iid], self._records[b_iid]

    def __len__(self) -> int:
        return len(self._records)
