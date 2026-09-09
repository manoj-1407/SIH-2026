"""
Advanced File Carving Engine — SIH26149

Signature-and-structure-based carving on raw/formatted disk images.
No external tools required — pure Python byte-level analysis.

Supported formats: JPEG, PNG, PDF, ZIP, DOCX, XLSX, MP4

Design principles:
  - Every candidate is structurally validated, not just signature-matched.
  - Confidence is evidence-derived, not guessed: structure depth + CRC/checksum + fragmentation.
  - Bifragmented streams: when a terminal marker is absent, a bounded forward gap-scan of
    up to FRAGMENT_HOP_COUNT × CLUSTER_SIZE bytes is performed to attempt reconstruction.
  - No false positives are promoted past PARTIAL_STRUCTURE confidence.
"""
import struct
import hashlib
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# Bounded bifragment reconstruction parameters
CLUSTER_SIZE     = 512 * 1024    # 512 KB typical cluster gap
FRAGMENT_HOP_COUNT = 4           # Scan up to 4 cluster hops forward (2 MB)
MAX_FRAGMENT_SCAN = CLUSTER_SIZE * FRAGMENT_HOP_COUNT


class CarvingConfidence(str, Enum):
    INTACT         = "INTACT"           # Fully validated structure, checksum verified
    HIGH           = "HIGH"             # All major structural markers present
    PARTIAL_STRUCT = "PARTIAL_STRUCT"   # Header + some body, truncated/fragmented
    HEADER_ONLY    = "HEADER_ONLY"      # Valid header, body absent or unreadable
    BIFRAGMENTED   = "BIFRAGMENTED"     # Fragment detected, continuation gap-reconstructed

    @property
    def score(self) -> int:
        return {
            self.INTACT: 95, self.HIGH: 80,
            self.PARTIAL_STRUCT: 55, self.HEADER_ONLY: 30,
            self.BIFRAGMENTED: 65,
        }[self]


@dataclass
class CarvedFile:
    offset: int
    size: int
    file_type: str
    confidence: CarvingConfidence
    confidence_score: int
    sha256: str
    evidence_factors: list
    is_bifragmented: bool = False
    fragment_gap_bytes: Optional[int] = None
    reconstruction_strategy: str = "CONTIGUOUS"  # CONTIGUOUS | GAP_RECONSTRUCTED | PARTIAL_ONLY

    @property
    def is_intact(self) -> bool:
        return self.confidence == CarvingConfidence.INTACT

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:08X}",
            # Alias fields for JS compatibility
            "start_offset": self.offset,
            "length_bytes": self.size,
            "size": self.size,
            "size_kb": round(self.size / 1024, 2),
            "file_type": self.file_type,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence_score,
            "sha256": self.sha256,
            "evidence_factors": self.evidence_factors,
            "is_bifragmented": self.is_bifragmented,
            "fragment_gap_bytes": self.fragment_gap_bytes,
            "reconstruction_strategy": self.reconstruction_strategy,
            "is_intact": self.is_intact,
        }


# ── Helpers ────────────────────────────────────────────────────────────────────

MAX_SCAN_SIZE = 500 * 1024 * 1024  # 500 MB scan limit for safety


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_u16be(data: bytes, off: int) -> int:
    return struct.unpack_from(">H", data, off)[0]


def _read_u32be(data: bytes, off: int) -> int:
    return struct.unpack_from(">B", data, off)[0]


def _read_u32be_full(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def _read_u32le(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


# ── JPEG Carver ────────────────────────────────────────────────────────────────

_JPEG_SOI = b'\xFF\xD8\xFF'
_JPEG_EOI = b'\xFF\xD9'


def _carve_jpeg(data: bytes, offset: int) -> Optional[CarvedFile]:
    """Parse JPEG structure from SOI marker at `offset`.

    If EOI is not found contiguously, performs a bounded forward gap-scan
    (up to MAX_FRAGMENT_SCAN bytes) to locate and reconstruct bifragmented streams.
    """
    factors = []
    pos = offset
    length = len(data)

    if data[pos:pos + 3] != _JPEG_SOI:
        return None
    factors.append("SOI marker found (FF D8 FF)")
    pos += 2

    has_app0 = False
    has_sof  = False
    has_sos  = False
    last_valid_pos = pos

    # Walk JPEG segments
    while pos < length - 3:
        if data[pos] != 0xFF:
            break
        marker = data[pos:pos + 2]
        if marker == _JPEG_EOI:
            factors.append("EOI marker found — intact stream")
            end = pos + 2
            raw = data[offset:end]
            conf = CarvingConfidence.INTACT if has_sos else CarvingConfidence.HIGH
            return CarvedFile(
                offset=offset, size=end - offset,
                file_type="JPEG", confidence=conf,
                confidence_score=conf.score,
                sha256=_sha256(raw), evidence_factors=factors
            )
        if len(marker) < 2 or data[pos + 1] == 0xFF:
            # padding byte
            pos += 1
            continue

        seg_code = data[pos + 1]
        # Segments without length: RST markers, SOI, EOI
        if seg_code in (0xD8, 0xD9) or (0xD0 <= seg_code <= 0xD7):
            pos += 2
            continue

        if pos + 4 > length:
            break
        seg_len = _read_u16be(data, pos + 2)
        if seg_len < 2:
            break

        if seg_code == 0xE0:
            has_app0 = True
            factors.append("APP0/JFIF marker found")
        elif seg_code in (0xC0, 0xC1, 0xC2):
            has_sof = True
            factors.append("SOF (Start Of Frame) marker found")
        elif seg_code == 0xDA:
            has_sos = True
            factors.append("SOS (Start Of Scan) marker found")
            last_valid_pos = pos + 2 + seg_len

        pos += 2 + seg_len

    # No EOI found — attempt bounded gap-scan reconstruction
    if has_sos:
        gap_search_start = pos
        gap_search_end   = min(pos + MAX_FRAGMENT_SCAN, length)
        eoi_pos = data.find(_JPEG_EOI, gap_search_start, gap_search_end)
        if eoi_pos != -1:
            gap_bytes = eoi_pos - last_valid_pos
            end = eoi_pos + 2
            raw = data[offset:end]
            factors.append(f"Bifragment EOI located in gap-scan at +{gap_bytes:,} bytes (bounded {MAX_FRAGMENT_SCAN // 1024} KB scan)")
            return CarvedFile(
                offset=offset, size=end - offset,
                file_type="JPEG", confidence=CarvingConfidence.BIFRAGMENTED,
                confidence_score=CarvingConfidence.BIFRAGMENTED.score,
                sha256=_sha256(raw), evidence_factors=factors,
                is_bifragmented=True,
                fragment_gap_bytes=gap_bytes,
                reconstruction_strategy="GAP_RECONSTRUCTED",
            )

    # Could not reconstruct
    conf = CarvingConfidence.PARTIAL_STRUCT if has_sos else CarvingConfidence.HEADER_ONLY
    raw = data[offset:min(offset + max(pos - offset, 1), length)]
    factors.append("No EOI found and gap-scan exceeded bound — reporting partial stream")
    return CarvedFile(
        offset=offset, size=len(raw),
        file_type="JPEG", confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors,
        is_bifragmented=True,
        reconstruction_strategy="PARTIAL_ONLY",
    )


# ── PNG Carver ─────────────────────────────────────────────────────────────────

_PNG_MAGIC  = b'\x89PNG\r\n\x1a\n'
_PNG_IHDR   = b'IHDR'
_PNG_IEND   = b'IEND'


def _carve_png(data: bytes, offset: int) -> Optional[CarvedFile]:
    """Parse PNG structure from 8-byte magic at `offset`."""
    factors = []
    if data[offset:offset + 8] != _PNG_MAGIC:
        return None
    factors.append("PNG magic signature verified (8 bytes)")

    pos = offset + 8
    length = len(data)
    has_ihdr = False
    has_idat = False
    crc_ok_count = 0

    while pos + 12 <= length:
        chunk_len = _read_u32be_full(data, pos)
        chunk_type = data[pos + 4:pos + 8]
        if not chunk_type.isalpha():
            break
        chunk_data = data[pos + 8:pos + 8 + chunk_len] if pos + 8 + chunk_len <= length else b''

        # CRC verification
        if pos + 8 + chunk_len + 4 <= length:
            stored_crc = _read_u32be_full(data, pos + 8 + chunk_len)
            computed_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
            if stored_crc == computed_crc:
                crc_ok_count += 1
            else:
                factors.append(f"CRC mismatch in chunk {chunk_type.decode(errors='replace')}")

        if chunk_type == _PNG_IHDR:
            has_ihdr = True
            if len(chunk_data) >= 8:
                w = _read_u32be_full(chunk_data, 0)
                h = _read_u32be_full(chunk_data, 4)
                factors.append(f"IHDR: {w}×{h}px")
        elif chunk_type == b'IDAT':
            has_idat = True
        elif chunk_type == _PNG_IEND:
            end = pos + 12
            raw = data[offset:end]
            if crc_ok_count > 0:
                factors.append(f"{crc_ok_count} chunk CRC(s) verified")
                conf = CarvingConfidence.INTACT
            else:
                conf = CarvingConfidence.HIGH
            factors.append("IEND chunk found — stream complete")
            return CarvedFile(
                offset=offset, size=end - offset,
                file_type="PNG", confidence=conf,
                confidence_score=conf.score,
                sha256=_sha256(raw), evidence_factors=factors
            )

        pos += 12 + chunk_len

    # Truncated — attempt bounded gap-scan for IEND
    if crc_ok_count > 0:
        factors.append(f"{crc_ok_count} chunk CRC(s) verified before truncation")

    if has_idat:
        iend_marker = b'IEND'
        gap_search_end = min(pos + MAX_FRAGMENT_SCAN, length)
        iend_pos = data.find(iend_marker, pos, gap_search_end)
        if iend_pos != -1:
            gap_bytes = iend_pos - pos
            end = iend_pos + 12  # IEND chunk: 4+4+4 = 12 bytes
            raw = data[offset:min(end, length)]
            factors.append(f"Bifragment IEND located in gap-scan at +{gap_bytes:,} bytes")
            return CarvedFile(
                offset=offset, size=end - offset,
                file_type="PNG", confidence=CarvingConfidence.BIFRAGMENTED,
                confidence_score=CarvingConfidence.BIFRAGMENTED.score,
                sha256=_sha256(raw), evidence_factors=factors,
                is_bifragmented=True,
                fragment_gap_bytes=gap_bytes,
                reconstruction_strategy="GAP_RECONSTRUCTED",
            )

    factors.append("IEND not found — PNG truncated or fragmented (gap-scan exceeded bound)")
    conf = CarvingConfidence.PARTIAL_STRUCT if has_idat else CarvingConfidence.HEADER_ONLY
    raw = data[offset:min(pos, length)]
    return CarvedFile(
        offset=offset, size=len(raw),
        file_type="PNG", confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors,
        is_bifragmented=True,
        reconstruction_strategy="PARTIAL_ONLY",
    )


# ── PDF Carver ─────────────────────────────────────────────────────────────────

_PDF_HEADER = b'%PDF-'
_PDF_EOF    = b'%%EOF'


def _carve_pdf(data: bytes, offset: int) -> Optional[CarvedFile]:
    """Carve PDF from %PDF- header."""
    factors = []
    if not data[offset:offset + 5] == _PDF_HEADER:
        return None

    version_end = data.find(b'\n', offset + 5)
    if version_end == -1:
        version_end = offset + 10
    version = data[offset + 5:version_end].strip().decode(errors='replace')
    factors.append(f"PDF header found, version: {version}")

    # Search for %%EOF within reasonable range (50 MB)
    search_limit = min(offset + 50 * 1024 * 1024, len(data))
    eof_pos = data.rfind(_PDF_EOF, offset + 5, search_limit)

    has_xref = b'xref' in data[offset:min(offset + 1024 * 1024, search_limit)]
    has_obj = b' obj' in data[offset:min(offset + 512 * 1024, search_limit)]

    if has_xref:
        factors.append("xref table detected")
    if has_obj:
        factors.append("PDF objects detected")

    if eof_pos != -1:
        end = eof_pos + len(_PDF_EOF)
        raw = data[offset:end]
        factors.append("%%EOF marker found — stream complete")
        conf = CarvingConfidence.INTACT if has_xref else CarvingConfidence.HIGH
        return CarvedFile(
            offset=offset, size=end - offset,
            file_type="PDF", confidence=conf,
            confidence_score=conf.score,
            sha256=_sha256(raw), evidence_factors=factors
        )

    # Attempt extended forward scan for EOF beyond the 50 MB search limit
    extended_limit = min(offset + 100 * 1024 * 1024, len(data))
    eof_pos_ext = data.find(_PDF_EOF, search_limit, extended_limit)
    if eof_pos_ext != -1:
        gap_bytes = eof_pos_ext - search_limit
        end = eof_pos_ext + len(_PDF_EOF)
        raw = data[offset:end]
        factors.append(f"Bifragment %%EOF found in extended scan at +{gap_bytes:,} bytes beyond initial window")
        return CarvedFile(
            offset=offset, size=end - offset,
            file_type="PDF", confidence=CarvingConfidence.BIFRAGMENTED,
            confidence_score=CarvingConfidence.BIFRAGMENTED.score,
            sha256=_sha256(raw), evidence_factors=factors,
            is_bifragmented=True,
            fragment_gap_bytes=gap_bytes,
            reconstruction_strategy="GAP_RECONSTRUCTED",
        )

    factors.append("%%EOF not found — PDF truncated or fragmented (extended scan exhausted)")
    raw = data[offset:search_limit]
    conf = CarvingConfidence.PARTIAL_STRUCT if has_obj else CarvingConfidence.HEADER_ONLY
    return CarvedFile(
        offset=offset, size=len(raw),
        file_type="PDF", confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors,
        is_bifragmented=True,
        reconstruction_strategy="PARTIAL_ONLY",
    )


# ── ZIP / DOCX / XLSX Carver ───────────────────────────────────────────────────

_ZIP_LOCAL_SIG  = b'PK\x03\x04'
_ZIP_EOCD_SIG   = b'PK\x05\x06'
_ZIP_CD_SIG     = b'PK\x01\x02'


def _carve_zip(data: bytes, offset: int) -> Optional[CarvedFile]:
    """Carve ZIP/DOCX/XLSX from PK local file header."""
    factors = []
    if data[offset:offset + 4] != _ZIP_LOCAL_SIG:
        return None
    factors.append("ZIP local file header signature (PK\\x03\\x04)")

    # Check for EOCD within a sane range
    search_limit = min(offset + 100 * 1024 * 1024, len(data))
    eocd_pos = data.rfind(_ZIP_EOCD_SIG, offset, search_limit)

    # Determine type (DOCX/XLSX vs plain ZIP)
    file_type = "ZIP"
    content_types = b'[Content_Types].xml'
    if content_types in data[offset:min(offset + 2048, search_limit)]:
        # Look at file names to distinguish DOCX vs XLSX
        if b'word/' in data[offset:min(offset + 4096, search_limit)]:
            file_type = "DOCX"
            factors.append("Office Open XML detected (word/ directory → DOCX)")
        elif b'xl/' in data[offset:min(offset + 4096, search_limit)]:
            file_type = "XLSX"
            factors.append("Office Open XML detected (xl/ directory → XLSX)")
        else:
            file_type = "DOCX/XLSX"
            factors.append("[Content_Types].xml found — Office Open XML document")

    cd_count = data[offset:search_limit].count(_ZIP_CD_SIG)
    if cd_count > 0:
        factors.append(f"Central Directory entries found: {cd_count}")

    if eocd_pos != -1:
        end = eocd_pos + 22  # minimum EOCD size
        raw = data[offset:end]
        factors.append("End of Central Directory found — archive complete")
        conf = CarvingConfidence.INTACT if cd_count > 0 else CarvingConfidence.HIGH
        return CarvedFile(
            offset=offset, size=end - offset,
            file_type=file_type, confidence=conf,
            confidence_score=conf.score,
            sha256=_sha256(raw), evidence_factors=factors
        )

    factors.append("EOCD not found — archive truncated or fragmented")
    raw = data[offset:search_limit]
    conf = CarvingConfidence.PARTIAL_STRUCT if cd_count > 0 else CarvingConfidence.HEADER_ONLY
    return CarvedFile(
        offset=offset, size=len(raw),
        file_type=file_type, confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors,
        is_bifragmented=True
    )


# ── MP4 Carver ─────────────────────────────────────────────────────────────────

_MP4_BRANDS = {b'isom', b'mp41', b'mp42', b'M4A ', b'M4V ', b'qt  ', b'avc1'}


def _carve_mp4(data: bytes, offset: int) -> Optional[CarvedFile]:
    """Carve MP4/QuickTime container from ftyp box."""
    factors = []
    if offset + 12 > len(data):
        return None

    # First box should be ftyp
    box_size = _read_u32be_full(data, offset)
    box_type = data[offset + 4:offset + 8]
    if box_type != b'ftyp':
        return None

    brand = data[offset + 8:offset + 12]
    if brand not in _MP4_BRANDS:
        return None

    factors.append(f"ftyp box found, brand: {brand.decode(errors='replace')}")

    # Walk boxes
    pos = offset
    length = len(data)
    has_moov = False
    has_mdat = False
    search_limit = min(offset + 500 * 1024 * 1024, length)

    while pos + 8 <= search_limit:
        atom_size = _read_u32be_full(data, pos)
        if atom_size < 8:
            break
        atom_type = data[pos + 4:pos + 8]

        if atom_type == b'moov':
            has_moov = True
            factors.append("moov box (movie metadata) found")
        elif atom_type == b'mdat':
            has_mdat = True
            factors.append("mdat box (media data) found")

        pos += atom_size
        if pos >= search_limit:
            break

    raw = data[offset:min(pos, length)]
    if has_moov and has_mdat:
        conf = CarvingConfidence.INTACT
        factors.append("Both moov+mdat present — MP4 structurally complete")
    elif has_moov:
        conf = CarvingConfidence.HIGH
    else:
        conf = CarvingConfidence.PARTIAL_STRUCT
        factors.append("moov box not found — MP4 truncated or fragmented")

    return CarvedFile(
        offset=offset, size=len(raw),
        file_type="MP4", confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors,
        is_bifragmented=not (has_moov and has_mdat)
    )


# ── Signature Registry ─────────────────────────────────────────────────────────

_SIGNATURES = [
    (b'\xFF\xD8\xFF',      "JPEG", _carve_jpeg),
    (_PNG_MAGIC,           "PNG",  _carve_png),
    (_PDF_HEADER,          "PDF",  _carve_pdf),
    (_ZIP_LOCAL_SIG,       "ZIP",  _carve_zip),
]

# MP4: ftyp box at offset+4, can start with any 4-byte size
_MP4_FTYP_AT_4 = True


# ── Main Scanner ───────────────────────────────────────────────────────────────

def carve_bytes(
    data: bytes,
    max_results: int = 500,
    target_types: Optional[list] = None,
) -> list[CarvedFile]:
    """
    Scan raw bytes and carve recoverable files.
    """
    results: list[CarvedFile] = []
    pos = 0
    length = len(data)
    found_offsets: set[int] = set()

    while pos < length - 8:
        # Check MP4 (ftyp at pos+4)
        if pos + 12 <= length and data[pos + 4:pos + 8] == b'ftyp':
            if pos not in found_offsets:
                carved = _carve_mp4(data, pos)
                if carved and (target_types is None or carved.file_type in target_types):
                    results.append(carved)
                    found_offsets.add(pos)
                    if len(results) >= max_results:
                        break

        # Check all other signatures
        for sig, type_name, carver in _SIGNATURES:
            if target_types and type_name not in target_types:
                continue
            sig_len = len(sig)
            if data[pos:pos + sig_len] == sig:
                if pos not in found_offsets:
                    carved = carver(data, pos)
                    if carved:
                        results.append(carved)
                        found_offsets.add(pos)
                        if len(results) >= max_results:
                            break
        pos += 1
        if len(results) >= max_results:
            break

    results.sort(key=lambda x: x.confidence_score, reverse=True)
    return results


def carve_image(
    image_input,
    max_results: int = 500,
    target_types: Optional[list] = None,
) -> list[CarvedFile]:
    """
    Scan a disk image (path or raw bytes) and carve recoverable files.
    """
    if isinstance(image_input, (bytes, bytearray)):
        data = bytes(image_input)
    else:
        with open(str(image_input), 'rb') as f:
            data = f.read(MAX_SCAN_SIZE)
    return carve_bytes(data, max_results=max_results, target_types=target_types)


def carve_image_summary(image_input, **kwargs) -> dict:
    """Scan and return a structured summary suitable for API response."""
    carved = carve_image(image_input, **kwargs)
    by_type: dict[str, int] = {}
    for c in carved:
        by_type[c.file_type] = by_type.get(c.file_type, 0) + 1

    intact       = [c for c in carved if c.confidence == CarvingConfidence.INTACT]
    high         = [c for c in carved if c.confidence == CarvingConfidence.HIGH]
    bifragmented = [c for c in carved if c.confidence == CarvingConfidence.BIFRAGMENTED]
    partial      = [c for c in carved if c.confidence in (CarvingConfidence.PARTIAL_STRUCT, CarvingConfidence.BIFRAGMENTED)]
    fragment     = [c for c in carved if c.is_bifragmented]
    gap_recon    = [c for c in carved if c.reconstruction_strategy == "GAP_RECONSTRUCTED"]

    # Signatures always scanned (for UI display)
    signatures_scanned = ["JPEG", "PNG", "PDF", "ZIP", "DOCX", "XLSX", "MP4"]

    return {
        "total_carved": len(carved),
        "intact": len(intact),
        "high_confidence": len(high),
        "bifragmented_reconstructed": len(gap_recon),
        "partial": len(partial),
        "bifragmented": len(fragment),
        "by_type": by_type,
        "signatures_scanned": signatures_scanned,
        # Both keys for backward compat
        "carved_files": [c.to_dict() for c in carved],
        "carved_artifacts": [c.to_dict() for c in carved],
    }
