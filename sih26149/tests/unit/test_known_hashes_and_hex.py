"""Unit tests for NSRL-style known-hashes triage and hex dump helpers."""
import pytest
from app.forensics.known_hashes import (
    classify_artifact_hash,
    filter_carved_artifacts,
    KNOWN_SYSTEM_HASHES,
)
from app.forensics.carving import format_hex_dump, CarvedFile, CarvingConfidence


def test_classify_empty_file_hash():
    empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    res = classify_artifact_hash(empty_hash)
    assert res["classification"] == "KNOWN_SYSTEM_FILE"
    assert res["is_noise"] is True


def test_classify_target_watchlist_match():
    target_hash = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
    res = classify_artifact_hash(target_hash, target_hashes={target_hash})
    assert res["classification"] == "HASH_MATCH"
    assert res["is_noise"] is False


def test_classify_unknown_interest():
    unknown_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    res = classify_artifact_hash(unknown_hash)
    assert res["classification"] == "UNKNOWN_INTEREST"
    assert res["is_noise"] is False


def test_filter_carved_artifacts():
    sample_artifacts = [
        {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
    ]
    summary = filter_carved_artifacts(sample_artifacts)
    assert summary["total_evaluated"] == 2
    assert summary["known_system_files"] == 1
    assert summary["investigative_interest_count"] == 1
    assert sample_artifacts[0]["hash_filter"]["classification"] == "KNOWN_SYSTEM_FILE"
    assert sample_artifacts[1]["hash_filter"]["classification"] == "UNKNOWN_INTEREST"


def test_format_hex_dump():
    data = b"Hello, World!\x00\x01\x02\xff"
    dump = format_hex_dump(data, max_bytes=16)
    assert "0000" in dump
    assert "Hello, World!" in dump
    assert "|" in dump


def test_carved_file_to_dict_includes_hex_preview():
    cf = CarvedFile(
        offset=0x100,
        size=64,
        file_type="JPEG",
        confidence=CarvingConfidence.INTACT,
        confidence_score=95,
        sha256="abc",
        evidence_factors=["SOI found"],
        hex_preview="0000  ff d8 ff e0",
    )
    d = cf.to_dict()
    assert d["hex_preview"] == "0000  ff d8 ff e0"
    assert d["offset_hex"] == "0x00000100"
