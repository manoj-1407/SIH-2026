import hashlib
from types import SimpleNamespace

from app.forensics.carving import CarvingConfidence
from app.forensics.carving import carve_bytes
from scripts.test_real_world_corpus_rc2 import (
    CorpusSample,
    _evaluate_sample,
    create_expanded_corpus,
)


def test_partial_case_without_candidate_is_false_negative():
    sample = CorpusSample(
        "partial-1", "Truncated", "PDF", "missing trailer", "PARTIAL", b"%PDF",
    )

    stats, _ = _evaluate_sample(sample, [], elapsed_ms=1.0)

    assert stats["TP"] == 0
    assert stats["FN"] == 1


def test_partial_case_promoted_to_intact_is_not_credited():
    data = b"%PDF partial bytes"
    sample = CorpusSample(
        "partial-2", "Truncated", "PDF", "missing trailer", "PARTIAL", data,
    )
    candidate = SimpleNamespace(
        sha256=hashlib.sha256(data).hexdigest(),
        confidence=CarvingConfidence.INTACT,
    )

    stats, _ = _evaluate_sample(sample, [candidate], elapsed_ms=1.0)

    assert stats["TP"] == 0
    assert stats["FP"] == 1
    assert stats["FN"] == 1
    assert stats["overclaims"] == 1


def test_rejected_case_with_candidate_is_false_positive():
    sample = CorpusSample(
        "trap-1", "Trap", "JPEG", "false magic", "REJECTED", b"not an image",
    )
    candidate = SimpleNamespace(
        sha256=hashlib.sha256(b"wrong candidate").hexdigest(),
        confidence=CarvingConfidence.HEADER_ONLY,
    )

    stats, _ = _evaluate_sample(sample, [candidate], elapsed_ms=1.0)

    assert stats["FP"] == 1
    assert stats["TN"] == 0


def test_mp4_carver_stops_before_unallocated_trailing_bytes():
    sample = next(item for item in create_expanded_corpus() if item.sample_id == "RC2-07")
    image = b"\x11\x22\x33\x44" * 64 + sample.data + b"\x99\x88\x77\x66" * 64

    candidate = next(item for item in carve_bytes(image) if item.file_type == "MP4")

    assert candidate.size == len(sample.data)
    assert candidate.sha256 == hashlib.sha256(sample.data).hexdigest()
