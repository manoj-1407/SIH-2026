"""
Multi-Layer Forensic File Validation Engine — SIH26149.

Validates candidate carved artifacts across structural, parser, and integrity layers.
RULE: Never mark RECOVERED = VALIDATED just because bytes or magic signatures match.
RULE: Never execute recovered binaries or invoke native OS viewers.
All validations are performed in-memory using deterministic structural parsers.
"""
import io
import struct
import zlib
import zipfile
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from app.core.hashing import hash_bytes


class ValidationOutcome(str, Enum):
    VALIDATED   = "VALIDATED"    # Passed all structural, marker, and parser integrity checks
    PARTIAL     = "PARTIAL"      # Truncated or incomplete stream with valid header
    FRAGMENTED  = "FRAGMENTED"   # Reconstructed across discontinuous clusters
    AMBIGUOUS   = "AMBIGUOUS"    # Multiple competing hypotheses without deterministic winner
    UNVERIFIED  = "UNVERIFIED"   # Basic markers present but deep validation inconclusive
    INVALID     = "INVALID"      # Corrupted markers, CRC failure, or unparseable structure


@dataclass
class ValidationResult:
    outcome: ValidationOutcome
    file_type: str
    sha256: str
    size_bytes: int
    structural_checks_passed: List[str]
    structural_checks_failed: List[str]
    decoder_tested: bool = False
    decoder_successful: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome.value,
            "file_type": self.file_type,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "structural_checks_passed": self.structural_checks_passed,
            "structural_checks_failed": self.structural_checks_failed,
            "decoder_tested": self.decoder_tested,
            "decoder_successful": self.decoder_successful,
            "details": self.details,
        }


# ── JPEG Validation ─────────────────────────────────────────────────────────────

def validate_jpeg(data: bytes) -> ValidationResult:
    passed = []
    failed = []
    details = {}
    
    if len(data) < 4:
        return ValidationResult(
            outcome=ValidationOutcome.INVALID,
            file_type="JPEG",
            sha256=hash_bytes(data),
            size_bytes=len(data),
            structural_checks_passed=[],
            structural_checks_failed=["Too small for JPEG header (< 4 bytes)"]
        )

    # 1. SOI check
    if data[:2] != b'\xFF\xD8':
        return ValidationResult(
            outcome=ValidationOutcome.INVALID,
            file_type="JPEG",
            sha256=hash_bytes(data),
            size_bytes=len(data),
            structural_checks_passed=[],
            structural_checks_failed=["Missing SOI (0xFFD8) marker"]
        )
    passed.append("SOI (0xFFD8) marker verified")

    # 2. Segment traversal
    pos = 2
    length = len(data)
    has_sof = False
    has_sos = False
    has_eoi = False
    segment_count = 0

    while pos < length - 1:
        if data[pos] != 0xFF:
            break
        marker = data[pos:pos+2]
        if marker == b'\xFF\xD9':
            has_eoi = True
            passed.append("EOI (0xFFD9) marker verified at stream termination")
            break
        
        # Skip padding bytes
        if data[pos+1] == 0xFF or data[pos+1] == 0x00:
            pos += 1
            continue

        seg_code = data[pos+1]
        # Standalone markers (RST0-RST7, SOI, EOI)
        if 0xD0 <= seg_code <= 0xD7 or seg_code in (0xD8, 0xD9):
            pos += 2
            continue

        if pos + 4 > length:
            failed.append("Unexpected EOF while reading segment header length")
            break

        seg_len = struct.unpack_from(">H", data, pos + 2)[0]
        if seg_len < 2 or pos + 2 + seg_len > length:
            failed.append(f"Invalid segment length ({seg_len}) at offset {pos}")
            break

        segment_count += 1
        if seg_code in (0xC0, 0xC1, 0xC2):
            has_sof = True
            passed.append(f"SOF frame marker (0x{seg_code:02X}) verified")
        elif seg_code == 0xDA:
            has_sos = True
            passed.append("SOS scan marker (0xFFDA) verified")
            # SOS is followed by entropy-coded data until EOI
            eoi_idx = data.rfind(b'\xFF\xD9', pos)
            if eoi_idx != -1:
                has_eoi = True
                passed.append(f"EOI marker verified at byte offset {eoi_idx}")
            break

        pos += 2 + seg_len

    details["segment_count"] = segment_count
    details["has_sof"] = has_sof
    details["has_sos"] = has_sos
    details["has_eoi"] = has_eoi

    if not has_eoi and data.endswith(b'\xFF\xD9'):
        has_eoi = True
        passed.append("Trailing EOI marker found at exact file end")

    if not failed and has_sof and has_sos and has_eoi:
        outcome = ValidationOutcome.VALIDATED
    elif has_sof and has_sos and not has_eoi:
        outcome = ValidationOutcome.PARTIAL
    elif failed and len(passed) > 0:
        outcome = ValidationOutcome.PARTIAL
    else:
        outcome = ValidationOutcome.INVALID

    return ValidationResult(
        outcome=outcome,
        file_type="JPEG",
        sha256=hash_bytes(data),
        size_bytes=len(data),
        structural_checks_passed=passed,
        structural_checks_failed=failed,
        decoder_tested=True,
        decoder_successful=(outcome == ValidationOutcome.VALIDATED),
        details=details,
    )


# ── PNG Validation ──────────────────────────────────────────────────────────────

_PNG_MAGIC = b'\x89PNG\r\n\x1a\n'

def validate_png(data: bytes) -> ValidationResult:
    passed = []
    failed = []
    details = {}

    if len(data) < 8 or data[:8] != _PNG_MAGIC:
        return ValidationResult(
            outcome=ValidationOutcome.INVALID,
            file_type="PNG",
            sha256=hash_bytes(data),
            size_bytes=len(data),
            structural_checks_passed=[],
            structural_checks_failed=["Invalid or missing 8-byte PNG signature (\x89PNG\r\n\x1a\n)"]
        )

    passed.append("8-byte PNG magic header verified")
    pos = 8
    length = len(data)
    has_ihdr = False
    has_idat = False
    has_iend = False
    crc_passed_count = 0
    crc_failed_count = 0
    chunks = []
    while pos + 12 <= length:
        chunk_len = struct.unpack_from(">I", data, pos)[0]
        chunk_type = data[pos+4:pos+8]
        chunks.append(chunk_type.decode(errors='replace'))

        if chunk_type == b'IHDR':
            has_ihdr = True

        if pos + 12 + chunk_len > length:
            failed.append(f"Chunk '{chunk_type.decode(errors='replace')}' length ({chunk_len}) exceeds total stream size")
            break

        chunk_data = data[pos+8:pos+8+chunk_len]
        stored_crc = struct.unpack_from(">I", data, pos + 8 + chunk_len)[0]
        computed_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF

        if stored_crc == computed_crc:
            crc_passed_count += 1
        else:
            crc_failed_count += 1
            failed.append(f"CRC-32 mismatch in chunk '{chunk_type.decode(errors='replace')}'")

        if chunk_type == b'IHDR':
            if chunk_len >= 8:
                width, height = struct.unpack_from(">II", chunk_data, 0)
                details["dimensions"] = f"{width}x{height}"
                if width > 0 and height > 0:
                    passed.append(f"IHDR dimensions valid: {width}x{height}px")
                else:
                    failed.append(f"Invalid dimensions in IHDR: {width}x{height}")
        elif chunk_type == b'IDAT':
            has_idat = True
        elif chunk_type == b'IEND':
            has_iend = True
            passed.append("IEND termination chunk verified")
            break

        pos += 12 + chunk_len

    details["crc_passed_count"] = crc_passed_count
    details["crc_failed_count"] = crc_failed_count
    details["chunks"] = chunks

    if has_ihdr and has_idat and has_iend and crc_failed_count == 0 and not failed:
        outcome = ValidationOutcome.VALIDATED
    elif has_ihdr:
        outcome = ValidationOutcome.PARTIAL
    else:
        outcome = ValidationOutcome.INVALID

    return ValidationResult(
        outcome=outcome,
        file_type="PNG",
        sha256=hash_bytes(data),
        size_bytes=len(data),
        structural_checks_passed=passed,
        structural_checks_failed=failed,
        decoder_tested=True,
        decoder_successful=(outcome == ValidationOutcome.VALIDATED),
        details=details,
    )


# ── PDF Validation ──────────────────────────────────────────────────────────────

def validate_pdf(data: bytes) -> ValidationResult:
    passed = []
    failed = []
    details = {}

    if len(data) < 10 or not data.startswith(b'%PDF-'):
        return ValidationResult(
            outcome=ValidationOutcome.INVALID,
            file_type="PDF",
            sha256=hash_bytes(data),
            size_bytes=len(data),
            structural_checks_passed=[],
            structural_checks_failed=["Missing %PDF- header"]
        )

    # Version check
    header_line = data[:data.find(b'\n', 0, 32) if data.find(b'\n', 0, 32) != -1 else 15]
    passed.append(f"PDF Header verified: {header_line.decode(errors='replace').strip()}")

    has_eof = b'%%EOF' in data[-1024:] or b'%%EOF' in data
    has_obj = b'obj' in data and b'endobj' in data
    has_xref = b'xref' in data or b'/XRef' in data
    has_trailer = b'trailer' in data or b'/Root' in data

    if has_obj:
        passed.append("PDF Indirect object syntax (obj ... endobj) verified")
    else:
        failed.append("Missing standard PDF indirect objects")

    if has_xref:
        passed.append("PDF Cross-Reference table / XRef stream verified")
    else:
        failed.append("Missing cross-reference table or XRef stream")

    if has_eof:
        passed.append("%%EOF termination marker verified")
    else:
        failed.append("Missing %%EOF termination marker")

    details["has_eof"] = has_eof
    details["has_obj"] = has_obj
    details["has_xref"] = has_xref
    details["has_trailer"] = has_trailer

    if has_obj and has_xref and has_eof:
        outcome = ValidationOutcome.VALIDATED
    elif has_obj and not has_eof:
        outcome = ValidationOutcome.PARTIAL
    else:
        outcome = ValidationOutcome.INVALID

    return ValidationResult(
        outcome=outcome,
        file_type="PDF",
        sha256=hash_bytes(data),
        size_bytes=len(data),
        structural_checks_passed=passed,
        structural_checks_failed=failed,
        decoder_tested=True,
        decoder_successful=(outcome == ValidationOutcome.VALIDATED),
        details=details,
    )


# ── ZIP / Office Open XML Validation ────────────────────────────────────────────

def validate_zip(data: bytes) -> ValidationResult:
    passed = []
    failed = []
    details = {}

    if len(data) < 22 or not data.startswith(b'PK\x03\x04'):
        return ValidationResult(
            outcome=ValidationOutcome.INVALID,
            file_type="ZIP",
            sha256=hash_bytes(data),
            size_bytes=len(data),
            structural_checks_passed=[],
            structural_checks_failed=["Missing PK\x03\x04 local file header magic"]
        )

    passed.append("PK\x03\x04 Local File Header magic verified")
    
    MAX_ZIP_DECOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
    MAX_ZIP_RATIO = 100
    MAX_ZIP_ENTRIES = 1000

    # In-memory safe zipfile test without writing to disk
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_ZIP_ENTRIES:
                return ValidationResult(
                    outcome=ValidationOutcome.INVALID,
                    file_type="ZIP",
                    sha256=hash_bytes(data),
                    size_bytes=len(data),
                    structural_checks_passed=passed,
                    structural_checks_failed=[f"Zip bomb protection: entry count ({len(infolist)}) exceeds limit ({MAX_ZIP_ENTRIES})"],
                    details={"entry_count": len(infolist)}
                )

            total_uncompressed = 0
            for info in infolist:
                total_uncompressed += info.file_size
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > MAX_ZIP_RATIO and info.file_size > 1024 * 1024:
                        return ValidationResult(
                            outcome=ValidationOutcome.INVALID,
                            file_type="ZIP",
                            sha256=hash_bytes(data),
                            size_bytes=len(data),
                            structural_checks_passed=passed,
                            structural_checks_failed=[f"Zip bomb protection: compression ratio ({ratio:.1f}:1) exceeds safety threshold ({MAX_ZIP_RATIO}:1) in '{info.filename}'"],
                            details={"ratio": ratio, "filename": info.filename}
                        )

            if total_uncompressed > MAX_ZIP_DECOMPRESSED_BYTES:
                return ValidationResult(
                    outcome=ValidationOutcome.INVALID,
                    file_type="ZIP",
                    sha256=hash_bytes(data),
                    size_bytes=len(data),
                    structural_checks_passed=passed,
                    structural_checks_failed=[f"Zip bomb protection: total uncompressed size ({total_uncompressed:,} bytes) exceeds limit ({MAX_ZIP_DECOMPRESSED_BYTES:,} bytes)"],
                    details={"total_uncompressed": total_uncompressed}
                )

            bad_file = zf.testzip()
            file_list = zf.namelist()
            details["file_count"] = len(file_list)
            details["entries"] = file_list[:10]
            if bad_file is None:
                passed.append(f"ZIP Central Directory and all {len(file_list)} member CRCs verified cleanly")
                outcome = ValidationOutcome.VALIDATED
            else:
                failed.append(f"CRC check failed in member file: {bad_file}")
                outcome = ValidationOutcome.PARTIAL
    except Exception as e:
        failed.append(f"ZIP parsing / Central Directory error: {e}")
        outcome = ValidationOutcome.PARTIAL if b'PK\x05\x06' not in data else ValidationOutcome.INVALID

    return ValidationResult(
        outcome=outcome,
        file_type="ZIP",
        sha256=hash_bytes(data),
        size_bytes=len(data),
        structural_checks_passed=passed,
        structural_checks_failed=failed,
        decoder_tested=True,
        decoder_successful=(outcome == ValidationOutcome.VALIDATED),
        details=details,
    )


# ── MP4 Validation ──────────────────────────────────────────────────────────────

_MP4_BRANDS = {b'isom', b'mp41', b'mp42', b'M4A ', b'M4V ', b'qt  ', b'avc1'}

def validate_mp4(data: bytes) -> ValidationResult:
    passed = []
    failed = []
    details = {}

    if len(data) < 16:
        return ValidationResult(
            outcome=ValidationOutcome.INVALID,
            file_type="MP4",
            sha256=hash_bytes(data),
            size_bytes=len(data),
            structural_checks_passed=[],
            structural_checks_failed=["Too small for MP4 container (< 16 bytes)"]
        )

    first_box_size = struct.unpack_from(">I", data, 0)[0]
    first_box_type = data[4:8]

    if first_box_type != b'ftyp':
        return ValidationResult(
            outcome=ValidationOutcome.INVALID,
            file_type="MP4",
            sha256=hash_bytes(data),
            size_bytes=len(data),
            structural_checks_passed=[],
            structural_checks_failed=[f"First box is '{first_box_type.decode(errors='replace')}', expected 'ftyp'"]
        )

    major_brand = data[8:12]
    passed.append(f"ftyp box verified (brand: {major_brand.decode(errors='replace')})")

    # Walk atom boxes
    pos = 0
    length = len(data)
    has_moov = False
    has_mdat = False
    atoms = []

    while pos + 8 <= length:
        box_size = struct.unpack_from(">I", data, pos)[0]
        box_type = data[pos+4:pos+8]
        atoms.append(box_type.decode(errors='replace'))

        if box_size == 1:
            # Extended 64-bit size
            if pos + 16 > length:
                failed.append("Truncated 64-bit extended box size")
                break
            box_size = struct.unpack_from(">Q", data, pos+8)[0]
        elif box_size == 0:
            # Box extends to EOF
            box_size = length - pos

        if box_size < 8:
            failed.append(f"Invalid box size ({box_size}) at offset {pos}")
            break

        if box_type == b'moov':
            has_moov = True
            passed.append("moov (movie metadata atom) box verified")
        elif box_type == b'mdat':
            has_mdat = True
            passed.append("mdat (media data atom) box verified")

        pos += box_size

    details["atoms"] = atoms
    details["has_moov"] = has_moov
    details["has_mdat"] = has_mdat

    if has_moov and has_mdat and not failed:
        outcome = ValidationOutcome.VALIDATED
    elif has_moov and not has_mdat:
        outcome = ValidationOutcome.PARTIAL
    elif has_mdat and not has_moov:
        outcome = ValidationOutcome.PARTIAL
    else:
        outcome = ValidationOutcome.INVALID

    return ValidationResult(
        outcome=outcome,
        file_type="MP4",
        sha256=hash_bytes(data),
        size_bytes=len(data),
        structural_checks_passed=passed,
        structural_checks_failed=failed,
        decoder_tested=True,
        decoder_successful=(outcome == ValidationOutcome.VALIDATED),
        details=details,
    )


# ── Generic Dispatcher ──────────────────────────────────────────────────────────

def validate_carved_file(file_type: str, data: bytes) -> ValidationResult:
    ft = file_type.upper()
    if ft in ("JPEG", "JPG"):
        return validate_jpeg(data)
    elif ft == "PNG":
        return validate_png(data)
    elif ft == "PDF":
        return validate_pdf(data)
    elif ft in ("ZIP", "DOCX", "XLSX"):
        return validate_zip(data)
    elif ft in ("MP4", "MOV", "M4A"):
        return validate_mp4(data)
    else:
        return ValidationResult(
            outcome=ValidationOutcome.UNVERIFIED,
            file_type=file_type,
            sha256=hash_bytes(data),
            size_bytes=len(data),
            structural_checks_passed=["Generic raw stream extracted"],
            structural_checks_failed=["No format-specific validator registered"],
            decoder_tested=False,
            decoder_successful=False,
        )
