"""R-tree spatial candidate index.

Purpose: candidate filtering before pairwise geometric analysis.
This is part of the correctness architecture, not merely a performance opt.
The index must not create false negatives for conflicts the analytical engine
is meant to detect. Candidate expansion factor ensures safety margin.

False-negative prevention:
- Buffer expansion applied to all candidate queries
- Known conflict pairs from injected test suite are checked end-to-end
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterator

from rtree import index as rtree_index
from shapely.geometry.base import BaseGeometry


CANDIDATE_BUFFER_DEGREES = 0.01   # ~1km buffer in geographic degrees


@dataclass
class IndexedRecord:
    record_id: str
    geometry: BaseGeometry
    bounds: tuple[float, float, float, float]


class SpatialCandidateIndex:
    def __init__(self):
        self._idx = rtree_index.Index()
        self._records: dict[int, IndexedRecord] = {}
        self._int_id: dict[str, int] = {}  # record_id → int id
        self._counter = 0

    def insert(self, record_id: str, geometry: BaseGeometry) -> None:
        if record_id in self._int_id:
            raise ValueError(f"Record {record_id!r} already in index")
        iid = self._counter
        self._counter += 1
        self._int_id[record_id] = iid
        bounds = geometry.bounds
        self._idx.insert(iid, bounds)
        self._records[iid] = IndexedRecord(record_id, geometry, bounds)

    def query_candidates(
        self,
        geometry: BaseGeometry,
        buffer_degrees: float = CANDIDATE_BUFFER_DEGREES,
    ) -> list[IndexedRecord]:
        """Return all indexed records whose bboxes intersect buffered geometry bbox."""
        minx, miny, maxx, maxy = geometry.bounds
        buffered = (
            minx - buffer_degrees,
            miny - buffer_degrees,
            maxx + buffer_degrees,
            maxy + buffer_degrees,
        )
        results = []
        for iid in self._idx.intersection(buffered):
            results.append(self._records[iid])
        return results

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
                    # Always yield in consistent order
                    a_iid, b_iid = pair_key
                    yield self._records[a_iid], self._records[b_iid]

    def __len__(self) -> int:
        return len(self._records)
