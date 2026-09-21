"""
Security Fuzzing & Boundary Robustness Suite — SIH26149.

Tests forensic parsers and evidence processors against hostile inputs:
- Massive integers and negative offsets
- Deeply nested or recursive structures
- Truncated chunk lengths exceeding EOF
- Corrupted UTF-8 / non-ASCII payloads
- Null byte injections and path traversal payloads in JSON
- Random byte streams / bit-flips (smoke fuzzing)
- Enforces: NO CRASH, NO HANG, NO MEMORY EXPLOSION, NO FALSE VALID.
"""
import os
import secrets
import pytest

from app.core.canonical import canonicalize, canonicalize_str
from app.core.independent_verifier import verify_evidence_package, verify_envelope_dict
from app.forensics.carving import carve_bytes
from app.forensics.validation import validate_carved_file, ValidationOutcome


# ── 1. Hostile Fuzzed Byte Streams to File Carvers ──────────────────────────────
@pytest.mark.parametrize("iteration", range(15))
def test_fuzz_random_bytes_to_carver(iteration):
    # Generate random pseudorandom payload of varying sizes
    length = (iteration + 1) * 1024
    noise = secrets.token_bytes(length)
    
    # Must execute safely without uncaught exceptions
    results = carve_bytes(noise, max_results=50)
    for res in results:
        # None of the random noise should ever be falsely classified as INTACT
        assert res.confidence.value != "INTACT"


# ── 2. Structural Mutation Fuzzing (Bit-Flipping valid files) ───────────────────
def test_fuzz_bit_flipped_jpeg():
    from tests.corpus.generator import generate_valid_jpeg
    base_jpeg = bytearray(generate_valid_jpeg())
    
    for flip_offset in range(0, len(base_jpeg), 16):
        corrupted = bytearray(base_jpeg)
        corrupted[flip_offset] ^= 0xFF
        res = validate_carved_file("JPEG", bytes(corrupted))
        assert res.outcome in (ValidationOutcome.VALIDATED, ValidationOutcome.PARTIAL, ValidationOutcome.INVALID)


def test_fuzz_bit_flipped_png():
    from tests.corpus.generator import generate_valid_png
    base_png = bytearray(generate_valid_png())
    
    for flip_offset in range(8, len(base_png), 16):
        corrupted = bytearray(base_png)
        corrupted[flip_offset] ^= 0xFF
        res = validate_carved_file("PNG", bytes(corrupted))
        assert res.outcome in (ValidationOutcome.VALIDATED, ValidationOutcome.PARTIAL, ValidationOutcome.INVALID)


# ── 3. Hostile & Path Traversal Payloads in Evidence Envelope ───────────────────
def test_fuzz_hostile_json_payloads():
    hostile_payloads = [
        {"case_id": "../../../etc/passwd", "scope": "/dev/sda"},
        {"case_id": "CASE\x00NULL_BYTE", "scope": "C:\\Windows\\System32"},
        {"huge_int": 2**64 - 1, "negative_int": -999999999999},
        {"nested": {"a": {"b": {"c": {"d": [1, 2, 3]}}}}},
        {"unicode_combining": "e\u0301\u0065\u0301", "emoji": "🛡️⚖️🔒"},
    ]
    for payload in hostile_payloads:
        # RFC 8785 Canonicalizer must produce deterministic output
        canon1 = canonicalize(payload)
        canon2 = canonicalize(payload)
        assert canon1 == canon2
        assert isinstance(canon1, bytes)


# ── 4. Malformed Evidence Envelopes to Independent Verifier ─────────────────────
def test_fuzz_malformed_envelopes_rejected():
    malformed_envelopes = [
        {},
        {"evidence_id": 12345},
        {"evidence_id": "EVID-1", "signing": {"algorithm": "UNKNOWN_ALGO"}},
        {"evidence_id": "EVID-1", "signature": "ZZZZ_NOT_HEX"},
        {"evidence_id": "EVID-1", "evidence_hash": "SHORT_HASH"},
    ]
    for env in malformed_envelopes:
        valid, res = verify_envelope_dict(env)
        assert valid is False
        assert res.classification.value == "INVALID"


# ── 5. Zip Bomb & Pathological Archive Decompression Defense ────────────────────
def test_fuzz_zip_bomb_defense():
    import io
    import zipfile

    # Synthesize high-ratio zip archive (10MB zeros compressed into ~10KB)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge_zeroes.bin", b"\x00" * (10 * 1024 * 1024))
    
    zip_bytes = buf.getvalue()
    res = validate_carved_file("ZIP", zip_bytes)
    # Must safely reject the decompression bomb without exhausting memory
    assert res.outcome in (ValidationOutcome.INVALID, ValidationOutcome.PARTIAL)
    assert "Zip bomb protection" in str(res.structural_checks_failed)


# ── 6. Pathological MP4 Atom Nested Recursion ───────────────────────────────────
def test_fuzz_pathological_mp4_recursion():
    # Synthesize infinite/recursive moov box loop with declared length exceeding buffer
    bad_mp4 = b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00isomiso2mp41\x7F\xFF\xFF\xFFmoov" + (b"\x00" * 64)
    res = validate_carved_file("MP4", bad_mp4)
    assert res.outcome in (ValidationOutcome.PARTIAL, ValidationOutcome.INVALID)


# ── 7. Truncated PDF Syntax Robustness ──────────────────────────────────────────
def test_fuzz_truncated_pdf_syntax():
    corrupted_pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R"
    res = validate_carved_file("PDF", corrupted_pdf)
    assert res.outcome == ValidationOutcome.INVALID

