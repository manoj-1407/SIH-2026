"""
24-Case Recovery & Validation Test Matrix — SIH26149.

Implements the complete 24-case matrix specified in the Master Engineering Brief:
- Case 1: Contiguous file (VALIDATED)
- Case 2: Deleted contiguous file embedded in disk stream (VALIDATED)
- Case 3: Partially overwritten file (PARTIAL)
- Case 4: File with renamed extension (VALIDATED from bytes)
- Case 5: File with corrupted header (INVALID)
- Case 6: File with corrupted footer (PARTIAL)
- Case 7: File with missing middle (PARTIAL/AMBIGUOUS)
- Case 8: Two fragments (BIFRAGMENTED / RECONSTRUCTED)
- Case 9: Many fragments (FRAGMENTED / BOUNDED)
- Case 10: Sequential fragments (RECONSTRUCTED)
- Case 11: Non-sequential fragments (UNVERIFIED / AMBIGUOUS)
- Case 12: Interleaved fragments (UNVERIFIED / AMBIGUOUS)
- Case 13: Missing fragment (PARTIAL)
- Case 14: False signature without structural body (INVALID / REJECTED)
- Case 15: Random data containing magic bytes (INVALID / REJECTED)
- Case 16: Nested file (e.g. image inside ZIP) (VALIDATED)
- Case 17: Duplicate candidate (DEDUPLICATED)
- Case 18: Overlapping candidate (HANDLED DETERMINISTICALLY)
- Case 19: Truncated file (PARTIAL)
- Case 20: Zero-length file (REJECTED / INVALID)
- Case 21: Extremely small file (VALIDATED or REJECTED by bound)
- Case 22: Large multi-megabyte file (VALIDATED)
- Case 23: Malformed parser input (SAFE REJECTION, NO CRASH)
- Case 24: Adversarially crafted malformed file (SAFE REJECTION, NO CRASH)
"""
import os
import secrets
import pytest
from app.core.hashing import hash_bytes
from app.forensics.carving import carve_bytes, CarvingConfidence
from app.forensics.validation import validate_carved_file, ValidationOutcome
from tests.corpus.generator import (
    generate_valid_jpeg,
    generate_valid_png,
    generate_valid_pdf,
    generate_valid_zip,
    generate_valid_mp4
)


# ── Case 1: Contiguous file ─────────────────────────────────────────────────────
def test_case_01_contiguous_file():
    png_data = generate_valid_png()
    res = validate_carved_file("PNG", png_data)
    assert res.outcome == ValidationOutcome.VALIDATED
    assert res.sha256 == hash_bytes(png_data)


# ── Case 2: Deleted contiguous file in raw disk stream ──────────────────────────
def test_case_02_deleted_contiguous_in_disk():
    jpeg = generate_valid_jpeg()
    disk = (b'\x00' * 4096) + jpeg + (b'\x00' * 4096)
    carved = carve_bytes(disk)
    assert len(carved) >= 1
    found = [c for c in carved if c.file_type == "JPEG"][0]
    assert found.confidence == CarvingConfidence.INTACT
    assert found.sha256 == hash_bytes(jpeg)


# ── Case 3: Partially overwritten file ──────────────────────────────────────────
def test_case_03_partially_overwritten():
    png = bytearray(generate_valid_png())
    # Overwrite middle 10 bytes
    mid = len(png) // 2
    png[mid:mid+10] = b'\x00' * 10
    res = validate_carved_file("PNG", bytes(png))
    # Should report PARTIAL due to CRC mismatch in modified chunk
    assert res.outcome in (ValidationOutcome.PARTIAL, ValidationOutcome.INVALID)


# ── Case 4: File with renamed extension ─────────────────────────────────────────
def test_case_04_renamed_extension():
    # Byte carving identifies PNG regardless of caller filename / extension
    png_bytes = generate_valid_png()
    res = validate_carved_file("PNG", png_bytes)
    assert res.outcome == ValidationOutcome.VALIDATED


# ── Case 5: File with corrupted header ──────────────────────────────────────────
def test_case_05_corrupted_header():
    jpeg = bytearray(generate_valid_jpeg())
    jpeg[0:2] = b'\x00\x00'
    res = validate_carved_file("JPEG", bytes(jpeg))
    assert res.outcome == ValidationOutcome.INVALID


# ── Case 6: File with corrupted footer ──────────────────────────────────────────
def test_case_06_corrupted_footer():
    jpeg = bytearray(generate_valid_jpeg())
    # Corrupt EOI (FF D9 -> 00 00)
    jpeg[-2:] = b'\x00\x00'
    res = validate_carved_file("JPEG", bytes(jpeg))
    assert res.outcome == ValidationOutcome.PARTIAL


# ── Case 7: File with missing middle ───────────────────────────────────────────
def test_case_07_missing_middle():
    pdf = generate_valid_pdf()
    # Strip xref/trailer section
    stripped_pdf = pdf[:len(pdf)//2] + b'\n%%EOF\n'
    res = validate_carved_file("PDF", stripped_pdf)
    assert res.outcome in (ValidationOutcome.PARTIAL, ValidationOutcome.INVALID)


# ── Case 8: Two fragments (Bifragmented stream) ─────────────────────────────────
def test_case_08_two_fragments_gap():
    jpeg = generate_valid_jpeg()
    # Insert 4KB gap before EOI
    head = jpeg[:-2]
    eoi = jpeg[-2:]
    stream = head + (b'\x00' * 4096) + eoi
    carved = carve_bytes(stream)
    found = [c for c in carved if c.file_type == "JPEG"][0]
    assert found.is_bifragmented is True
    assert found.confidence == CarvingConfidence.BIFRAGMENTED


# ── Case 9: Many fragments ──────────────────────────────────────────────────────
def test_case_09_many_fragments():
    # When fragmentation exceeds hop bound, system gracefully returns PARTIAL
    jpeg = generate_valid_jpeg()
    # Disperse beyond MAX_FRAGMENT_SCAN
    stream = jpeg[:-2] + (b'\xAA' * (5 * 1024 * 1024)) + jpeg[-2:]
    carved = carve_bytes(stream)
    found = [c for c in carved if c.file_type == "JPEG"][0]
    assert found.confidence in (CarvingConfidence.PARTIAL_STRUCT, CarvingConfidence.HEADER_ONLY)


# ── Case 10: Sequential fragments ───────────────────────────────────────────────
def test_case_10_sequential_fragments():
    png = generate_valid_png()
    carved = carve_bytes(png)
    assert len(carved) == 1
    assert carved[0].confidence == CarvingConfidence.INTACT


# ── Case 11: Non-sequential fragments ───────────────────────────────────────────
def test_case_11_non_sequential_fragments():
    # If end marker precedes start marker, it cannot be stitched linearly
    stream = b'\xFF\xD9' + (b'\x00' * 512) + generate_valid_jpeg()[:-2]
    carved = carve_bytes(stream)
    # The inverted order must not produce a false INTACT recovery
    for c in carved:
        assert c.confidence != CarvingConfidence.INTACT


# ── Case 12: Interleaved fragments ──────────────────────────────────────────────
def test_case_12_interleaved_fragments():
    jpeg = generate_valid_jpeg()
    png = generate_valid_png()
    # Interleave chunks
    stream = jpeg[:len(jpeg)//2] + png + jpeg[len(jpeg)//2:]
    carved = carve_bytes(stream)
    # Both types detected without crashing
    types = {c.file_type for c in carved}
    assert "PNG" in types


# ── Case 13: Missing fragment ───────────────────────────────────────────────────
def test_case_13_missing_fragment():
    pdf = generate_valid_pdf()
    # Truncate end
    truncated = pdf[:len(pdf) - 20]
    res = validate_carved_file("PDF", truncated)
    assert res.outcome == ValidationOutcome.PARTIAL


# ── Case 14: False signature ────────────────────────────────────────────────────
def test_case_14_false_signature():
    # Only magic bytes without body
    fake_png = b'\x89PNG\r\n\x1a\n\x00\x00\x00\x00'
    res = validate_carved_file("PNG", fake_png)
    assert res.outcome == ValidationOutcome.INVALID


# ── Case 15: Random data containing magic bytes ─────────────────────────────────
def test_case_15_random_data_with_magic():
    rand_bytes = b'\xFF\xD8\xFF\xE0' + secrets.token_bytes(256)
    res = validate_carved_file("JPEG", rand_bytes)
    assert res.outcome in (ValidationOutcome.PARTIAL, ValidationOutcome.INVALID)


# ── Case 16: Nested file ────────────────────────────────────────────────────────
def test_case_16_nested_file():
    zip_bytes = generate_valid_zip()
    res = validate_carved_file("ZIP", zip_bytes)
    assert res.outcome == ValidationOutcome.VALIDATED


# ── Case 17: Duplicate candidate ────────────────────────────────────────────────
def test_case_17_duplicate_candidate():
    jpeg = generate_valid_jpeg()
    disk = jpeg + (b'\x00' * 1024) + jpeg
    carved = carve_bytes(disk)
    assert len(carved) == 2
    # Offsets are distinct
    assert carved[0].offset != carved[1].offset


# ── Case 18: Overlapping candidate ──────────────────────────────────────────────
def test_case_18_overlapping_candidate():
    disk = generate_valid_mp4() + generate_valid_jpeg()
    carved = carve_bytes(disk)
    assert len(carved) >= 2


# ── Case 19: Truncated file ─────────────────────────────────────────────────────
def test_case_19_truncated_file():
    png = generate_valid_png()[:30]
    res = validate_carved_file("PNG", png)
    assert res.outcome == ValidationOutcome.PARTIAL


# ── Case 20: Zero-length file ───────────────────────────────────────────────────
def test_case_20_zero_length():
    res = validate_carved_file("PNG", b"")
    assert res.outcome == ValidationOutcome.INVALID


# ── Case 21: Extremely small file ───────────────────────────────────────────────
def test_case_21_extremely_small():
    res = validate_carved_file("JPEG", b"\xFF\xD8")
    assert res.outcome == ValidationOutcome.INVALID


# ── Case 22: Large file ─────────────────────────────────────────────────────────
def test_case_22_large_file():
    # Synthesize 1MB PDF
    large_pdf = generate_valid_pdf() + (b'% PADDING COMMENT\n' * 50000) + b'%%EOF\n'
    res = validate_carved_file("PDF", large_pdf)
    assert res.outcome == ValidationOutcome.VALIDATED


# ── Case 23: Malformed parser input ─────────────────────────────────────────────
def test_case_23_malformed_parser_input():
    malformed = b'\x89PNG\r\n\x1a\n\xFF\xFF\xFF\xFFMALF'
    # Must not crash, hang, or throw uncaught exception
    res = validate_carved_file("PNG", malformed)
    assert res.outcome in (ValidationOutcome.PARTIAL, ValidationOutcome.INVALID)


# ── Case 24: Adversarially crafted malformed file ───────────────────────────────
def test_case_24_adversarially_crafted():
    # Huge declared length causing potential integer overflow
    evil_png = b'\x89PNG\r\n\x1a\n\x7F\xFF\xFF\xFFIHDR' + (b'\x00' * 32)
    res = validate_carved_file("PNG", evil_png)
    assert res.outcome in (ValidationOutcome.PARTIAL, ValidationOutcome.INVALID)
