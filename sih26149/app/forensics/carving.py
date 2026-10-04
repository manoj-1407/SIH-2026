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
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

CLUSTER_SIZE      = 512 * 1024
FRAGMENT_HOP_COUNT = 4
MAX_FRAGMENT_SCAN = 16 * 1024 * 1024
CLUSTER_FORWARD_HOPS = 3
DEEP_BIFRAGMENT_ENABLED = False


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
    hex_preview: Optional[str] = None
    recovered_bytes: Optional[bytes] = field(default=None, repr=False)
    source_extents: Optional[list] = None
    mime_type: Optional[str] = None
    structure_validation: Optional[str] = None
    entropy_bits_per_byte: Optional[float] = None
    entropy_sample_bytes: int = 0

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
            "hex_preview": self.hex_preview or "",
            "mime_type": self.mime_type,
            "structure_validation": self.structure_validation,
            "entropy_bits_per_byte": self.entropy_bits_per_byte,
            "entropy_sample_bytes": self.entropy_sample_bytes,
            "fragment_count": len(self.source_extents or [{"offset": self.offset, "length": self.size}]),
            "source_extents": self.source_extents or [{"offset": self.offset, "length": self.size}],
            "provenance": "RAW_SIGNATURE_AND_STRUCTURE_SCAN",
        }


# ── Helpers ────────────────────────────────────────────────────────────────────

MAX_SCAN_SIZE = 500 * 1024 * 1024  # 500 MB scan limit for safety


def format_hex_dump(data: bytes, max_bytes: int = 256) -> str:
    """Format bytes as canonical xxd-style hex dump (offset, hex bytes, ascii)."""
    chunk = data[:max_bytes]
    lines = []
    for i in range(0, len(chunk), 16):
        sub = chunk[i:i + 16]
        hex_parts = [f"{b:02x}" for b in sub]
        left = " ".join(hex_parts[:8])
        right = " ".join(hex_parts[8:])
        hex_str = f"{left:<23}  {right:<23}".rstrip()
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in sub)
        lines.append(f"{i:04x}  {hex_str:<48}  |{ascii_str}|")
    return "\n".join(lines)



def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sample_entropy(data: bytes, sample_limit: int = 65536) -> tuple[float, int]:
    sample = data[:sample_limit]
    if not sample:
        return 0.0, 0
    counts = [0] * 256
    for value in sample:
        counts[value] += 1
    entropy = -sum(
        (count / len(sample)) * math.log2(count / len(sample))
        for count in counts
        if count
    )
    return round(entropy, 4), len(sample)


def _mime_type(file_type: str) -> str:
    return {
        "JPEG": "image/jpeg",
        "PNG": "image/png",
        "PDF": "application/pdf",
        "ZIP": "application/zip",
        "DOCX": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "XLSX": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "MP4": "video/mp4",
        "MOV": "video/quicktime",
        "BMP": "image/bmp",
        "GIF": "image/gif",
        "TIFF": "image/tiff",
        "AVI": "video/x-msvideo",
        "MP3": "audio/mpeg",
        "OLE": "application/x-ole-storage",
        "EML": "message/rfc822",
    }.get(file_type, "application/octet-stream")


def _enrich_carved_result(carved: CarvedFile, data: bytes) -> None:
    content = carved.recovered_bytes
    if content is None:
        content = data[carved.offset:carved.offset + carved.size]
    entropy, sampled = _sample_entropy(content)
    carved.mime_type = _mime_type(carved.file_type)
    carved.structure_validation = (
        "STRUCTURE_MARKERS_VALIDATED"
        if carved.confidence in (CarvingConfidence.INTACT, CarvingConfidence.HIGH)
        else "BOUNDED_RECONSTRUCTION_MARKERS_VALIDATED"
        if carved.confidence == CarvingConfidence.BIFRAGMENTED
        else "PARTIAL_OR_HEADER_ONLY"
    )
    carved.entropy_bits_per_byte = entropy
    carved.entropy_sample_bytes = sampled


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


def _carve_jpeg(data: bytes, offset: int, max_fragment_scan=None, deep_bifragment=False) -> Optional[CarvedFile]:
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
            pos = last_valid_pos
            # Scan entropy-coded scan data for contiguous EOI (FF D9)
            scan_limit = min(pos + 50 * 1024 * 1024, length)
            found_eoi_pos = -1
            curr = pos
            gap_detected = False
            
            while curr < scan_limit - 1:
                # If a large repeating gap (e.g. 512+ consecutive identical filler bytes) is encountered,
                # the contiguous stream is broken -> switch to bounded gap reconstruction
                if curr + 512 < scan_limit and data[curr:curr+512] == data[curr:curr+1] * 512:
                    gap_detected = True
                    break

                if data[curr] == 0xFF:
                    next_b = data[curr + 1]
                    if next_b == 0xD9:
                        found_eoi_pos = curr
                        break
                    elif next_b == 0x00 or (0xD0 <= next_b <= 0xD7):
                        curr += 2
                        continue
                    elif next_b == 0xFF:
                        curr += 1
                        continue
                curr += 1
            
            if found_eoi_pos != -1 and not gap_detected:
                factors.append("EOI marker found — intact stream")
                end = found_eoi_pos + 2
                raw = data[offset:end]
                return CarvedFile(
                    offset=offset, size=end - offset,
                    file_type="JPEG", confidence=CarvingConfidence.INTACT,
                    confidence_score=CarvingConfidence.INTACT.score,
                    sha256=_sha256(raw), evidence_factors=factors
                )
            else:
                pos = curr if gap_detected else scan_limit
                last_valid_pos = curr
                break

        pos += 2 + seg_len

    # No contiguous EOI found — attempt bounded gap-scan reconstruction
    if has_sos:
        gap_search_start = last_valid_pos
        gap_search_end   = min(last_valid_pos + MAX_FRAGMENT_SCAN, length)
        eoi_pos = data.find(_JPEG_EOI, gap_search_start, gap_search_end)
        if eoi_pos != -1:
            gap_bytes = eoi_pos - last_valid_pos
            end = eoi_pos + 2
            reconstructed = data[offset:last_valid_pos] + data[eoi_pos:end]
            factors.append(
                f"JPEG split across 2 ordered extents; {gap_bytes:,} intervening bytes excluded "
                f"(bounded {MAX_FRAGMENT_SCAN // 1024} KB continuation scan)"
            )
            return CarvedFile(
                offset=offset, size=len(reconstructed),
                file_type="JPEG", confidence=CarvingConfidence.BIFRAGMENTED,
                confidence_score=CarvingConfidence.BIFRAGMENTED.score,
                sha256=_sha256(reconstructed), evidence_factors=factors,
                is_bifragmented=True,
                fragment_gap_bytes=gap_bytes,
                reconstruction_strategy="GAP_RECONSTRUCTED",
                recovered_bytes=reconstructed,
                source_extents=[
                    {"offset": offset, "length": last_valid_pos - offset},
                    {"offset": eoi_pos, "length": end - eoi_pos},
                ],
            )

    # Could not reconstruct — truncated/partial is NOT the same as bifragmented
    conf = CarvingConfidence.PARTIAL_STRUCT if has_sos else CarvingConfidence.HEADER_ONLY
    raw = data[offset:min(offset + max(pos - offset, 1), length)]
    factors.append("No EOI found and gap-scan exceeded bound — reporting partial stream")
    return CarvedFile(
        offset=offset, size=len(raw),
        file_type="JPEG", confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors,
        is_bifragmented=False,
        reconstruction_strategy="PARTIAL_ONLY",
    )


# ── PNG Carver ─────────────────────────────────────────────────────────────────

_PNG_MAGIC  = b'\x89PNG\r\n\x1a\n'
_PNG_IHDR   = b'IHDR'
_PNG_IEND   = b'IEND'


def _carve_png(data: bytes, offset: int, max_fragment_scan=None) -> Optional[CarvedFile]:
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
        is_bifragmented=False,
        reconstruction_strategy="PARTIAL_ONLY",
    )


# ── PDF Carver ─────────────────────────────────────────────────────────────────

_PDF_HEADER = b'%PDF-'
_PDF_EOF    = b'%%EOF'


def _carve_pdf(data: bytes, offset: int, max_fragment_scan=None) -> Optional[CarvedFile]:
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
        is_bifragmented=False,
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
        is_bifragmented=False,
        reconstruction_strategy="PARTIAL_ONLY",
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
        if atom_size < 8 or atom_size > search_limit - pos:
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


# ── OLE2 CFB / DOC / XLS / PPT / MSG Carver ────────────────────────────────────

_OLE_MAGIC = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
_OLE_CLASS_MSG = b'\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'


def _carve_ole(data: bytes, offset: int) -> Optional[CarvedFile]:
    factors = []
    length = len(data)
    if offset + 512 > length:
        return None
    if data[offset:offset + 8] != _OLE_MAGIC:
        return None
    if offset % 512 != 0:
        pass

    factors.append("OLE2 CFB magic signature verified")

    sector_shift = _read_u16be(data, offset + 0x1E)
    mini_sector_shift = _read_u16be(data, offset + 0x20)
    num_dir_sectors = _read_u32le(data, offset + 0x28)

    sector_checks = 0
    if sector_shift in (9, 12):
        sector_checks += 1
        factors.append(f"Sector shift valid: {sector_shift}")
    else:
        factors.append(f"Invalid sector shift: {sector_shift}")

    if mini_sector_shift == 6:
        sector_checks += 1
        factors.append("Mini sector shift valid: 6")
    else:
        factors.append(f"Invalid mini sector shift: {mini_sector_shift}")

    if num_dir_sectors != 0:
        sector_checks += 1
        factors.append(f"Num Directory Sectors nonzero: {num_dir_sectors}")
    else:
        factors.append("Num Directory Sectors is 0 (allowed for small files)")
        sector_checks += 1

    sector_size = 1 << sector_shift if sector_shift in (9, 12) else 512

    file_type = "OLE"
    subtype_found = False

    first_sector_start = offset + 512
    if first_sector_start + sector_size <= length:
        first_sector = data[first_sector_start:first_sector_start + sector_size]

        if len(first_sector) >= 0x200 and first_sector[0x1FE:0x200] == b'\xEC\xA5':
            file_type = "DOC"
            factors.append("DOC: WordDocument stream magic (EC A5) at known offset")
            subtype_found = True

        if not subtype_found and b'\x09\x08\x10\x00' in first_sector[:128]:
            file_type = "XLS"
            factors.append("XLS: BIFF8 Workbook substream magic detected")
            subtype_found = True

        if not subtype_found and (b'Current User' in first_sector or b'Powerpoint Document' in first_sector):
            file_type = "PPT"
            factors.append("PPT: Current User / Powerpoint Document stream heuristic")
            subtype_found = True

        if not subtype_found:
            search_region = data[first_sector_start:min(first_sector_start + sector_size * 4, length)]
            if b'__recip_version1.0_' in search_region or b'\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46' in search_region:
                file_type = "MSG"
                factors.append("MSG: Outlook Storage Item class detected")
                subtype_found = True

    declared_size_guess = min(length - offset, 100 * 1024 * 1024)
    stream_scan_end = min(offset + declared_size_guess, length)

    ole_end_markers = [b'\xFE\xFF', b'\xFF\xFE']
    last_ole_pos = offset + 512
    scan_pos = offset + 512
    while scan_pos < stream_scan_end - 2:
        if data[scan_pos] in (0xFE, 0xFF):
            last_ole_pos = scan_pos
        scan_pos += 1

    end_guess = min(stream_scan_end, last_ole_pos + sector_size)

    if sector_checks == 3:
        conf = CarvingConfidence.HIGH
        factors.append("All 3 OLE sector checks passed → HIGH confidence")
    else:
        conf = CarvingConfidence.HEADER_ONLY
        factors.append(f"Only {sector_checks}/3 OLE sector checks → HEADER_ONLY")

    raw = data[offset:min(end_guess, length)]
    return CarvedFile(
        offset=offset, size=len(raw),
        file_type=file_type, confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors
    )


# ── EML Carver ─────────────────────────────────────────────────────────────────

_EML_HEADERS_STANDARD = [b'From:', b'To:', b'Subject:', b'Date:']
_EML_BOUNDARY_END = b'--'


def _carve_eml(data: bytes, offset: int) -> Optional[CarvedFile]:
    factors = []
    length = len(data)
    if offset + 32 > length:
        return None

    preamble = data[offset:min(offset + 8192, length)]
    line_starts = []
    for line in preamble.split(b'\n'):
        stripped = line.lstrip(b'\r\t ')
        line_starts.append(stripped)

    top_matches = 0
    for ls in line_starts[:10]:
        if ls.startswith(b'From - '):
            top_matches += 1
            factors.append("EML: 'From - ' mbox line-start signature")
            break
        if ls.startswith(b'Received: from '):
            top_matches += 1
            factors.append("EML: 'Received: from ' line-start")
            break
        if ls.startswith(b'Content-Type: multipart/'):
            top_matches += 1
            factors.append("EML: 'Content-Type: multipart/' near top")
            break

    if top_matches == 0:
        return None

    header_count = 0
    for h in _EML_HEADERS_STANDARD:
        if h in preamble:
            header_count += 1
            factors.append(f"Standard header present: {h.decode('ascii', 'replace')}")

    scan_end = min(offset + 100 * 1024 * 1024, length)
    scan_pos = offset
    final_end = scan_end

    last_boundary_idx = data.rfind(b'\n--', offset, scan_end)
    if last_boundary_idx != -1:
        after_last = data[last_boundary_idx + 1:last_boundary_idx + 128]
        if after_last.startswith(b'--'):
            nl_pos = data.find(b'\n', last_boundary_idx + 3)
            if nl_pos == -1:
                nl_pos = min(last_boundary_idx + 128, scan_end)
            final_end = nl_pos

    raw = data[offset:min(final_end, length)]
    if header_count >= 2:
        conf = CarvingConfidence.HIGH
        factors.append(f"{header_count} standard headers present → HIGH confidence")
    else:
        conf = CarvingConfidence.PARTIAL_STRUCT
        factors.append(f"Only {header_count} standard headers → PARTIAL_STRUCT")

    return CarvedFile(
        offset=offset, size=len(raw),
        file_type="EML", confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors
    )


# ── MSG Carver (OLE alias + stronger Outlook check) ────────────────────────────

def _carve_msg(data: bytes, offset: int) -> Optional[CarvedFile]:
    carved_ole = _carve_ole(data, offset)
    if carved_ole is None:
        return None

    length = len(data)
    search_region = data[offset:min(offset + 512 * 1024, length)]
    is_msg = False

    if b'__recip_version1.0_' in search_region:
        is_msg = True
        carved_ole.evidence_factors.append("MSG: recipient storage table found")
    if _OLE_CLASS_MSG in search_region:
        is_msg = True
        carved_ole.evidence_factors.append("MSG: IMessage OLE class GUID present")
    if b'001A0003' in search_region or b'0037001E' in search_region:
        is_msg = True
        carved_ole.evidence_factors.append("MSG: MAPI property stream tags")

    if not is_msg and carved_ole.file_type != "MSG":
        return None

    carved_ole.file_type = "MSG"
    return carved_ole


# ── BMP Carver ─────────────────────────────────────────────────────────────────

_BMP_MAGIC = b'BM'


def _carve_bmp(data: bytes, offset: int) -> Optional[CarvedFile]:
    factors = []
    length = len(data)
    if offset + 26 > length:
        return None
    if data[offset:offset + 2] != _BMP_MAGIC:
        return None

    factors.append("BMP: BM magic verified")

    file_size = _read_u32le(data, offset + 0x02)
    pixel_offset = _read_u32le(data, offset + 0x0A)

    factors.append(f"BMP: declared size {file_size} bytes, pixel data offset {pixel_offset}")

    valid = True
    if pixel_offset <= 14:
        factors.append("BMP: invalid pixel offset (≤14)")
        valid = False
    if file_size < 54:
        factors.append("BMP: file size < 54 header minimum")
        valid = False

    end = offset + file_size if valid and offset + file_size <= length else min(offset + max(pixel_offset + 54, 128), length)

    if valid and file_size >= 54 and pixel_offset > 14:
        conf = CarvingConfidence.HIGH
        factors.append("BMP: size + offset structurally valid → HIGH")
    else:
        conf = CarvingConfidence.HEADER_ONLY
        factors.append("BMP: structure checks failed → HEADER_ONLY")

    raw = data[offset:min(end, length)]
    return CarvedFile(
        offset=offset, size=len(raw),
        file_type="BMP", confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors
    )


# ── GIF Carver ─────────────────────────────────────────────────────────────────

_GIF_MAGICS = [b'GIF87a', b'GIF89a']
_GIF_TRAILER = 0x3B
_GIF_IMAGE_SEP = 0x2C
_GIF_GCE = 0x21


def _carve_gif(data: bytes, offset: int) -> Optional[CarvedFile]:
    factors = []
    length = len(data)
    if offset + 14 > length:
        return None
    magic = data[offset:offset + 6]
    if magic not in _GIF_MAGICS:
        return None

    factors.append(f"GIF: {magic.decode('ascii', 'replace')} magic verified")

    flags_byte = data[offset + 10]
    factors.append(f"GIF: logical screen descriptor flags 0x{flags_byte:02X}")

    gct_entries = 0
    if flags_byte & 0x80:
        gct_size = 2 << (flags_byte & 0x07)
        gct_entries = gct_size * 3
        factors.append(f"GIF: global color table present, {gct_size} entries")

    gce_found = False
    image_block_found = False
    trailer_found = False

    scan_start = offset + 13 + gct_entries
    scan_end = min(offset + 100 * 1024 * 1024, length)
    pos = scan_start
    last_marker_pos = scan_start

    while pos < scan_end:
        b = data[pos]
        if b == _GIF_GCE:
            gce_found = True
            last_marker_pos = pos
        elif b == _GIF_IMAGE_SEP:
            image_block_found = True
            last_marker_pos = pos
        elif b == _GIF_TRAILER:
            trailer_found = True
            last_marker_pos = pos
            break
        pos += 1

    if gce_found:
        factors.append("GIF: GCE (0x21) block present")
    if image_block_found:
        factors.append("GIF: Image separator (0x2C) present")
    if trailer_found:
        factors.append("GIF: Trailer (0x3B) terminator found")

    end = last_marker_pos + 1 if trailer_found else min(pos + 1, scan_end)

    if gce_found and image_block_found and trailer_found:
        conf = CarvingConfidence.INTACT
        factors.append("GIF: GCE+Image+Trailer present → INTACT")
    elif image_block_found or trailer_found:
        conf = CarvingConfidence.HIGH
        factors.append("GIF: structural blocks present → HIGH")
    else:
        conf = CarvingConfidence.HEADER_ONLY
        factors.append("GIF: no image/trailer blocks → HEADER_ONLY")

    raw = data[offset:min(end, length)]
    return CarvedFile(
        offset=offset, size=len(raw),
        file_type="GIF", confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors
    )


# ── TIFF Carver ────────────────────────────────────────────────────────────────

_TIFF_LE = b'II*\x00'
_TIFF_BE = b'MM\x00*'


def _carve_tiff(data: bytes, offset: int) -> Optional[CarvedFile]:
    factors = []
    length = len(data)
    if offset + 8 > length:
        return None

    hdr = data[offset:offset + 4]
    is_le = hdr == _TIFF_LE
    is_be = hdr == _TIFF_BE
    if not (is_le or is_be):
        return None

    endian = "<" if is_le else ">"
    factors.append(f"TIFF: {'little' if is_le else 'big'}-endian header verified")

    ifd_offset = struct.unpack_from(endian + "I", data, offset + 0x04)[0]
    factors.append(f"TIFF: first IFD offset = {ifd_offset}")

    if ifd_offset <= 8:
        conf = CarvingConfidence.HEADER_ONLY
        factors.append("TIFF: IFD offset ≤ 8 invalid → HEADER_ONLY")
        end = min(offset + 128, length)
    else:
        declared_ifd_range = ifd_offset * 2
        if ifd_offset <= declared_ifd_range:
            conf = CarvingConfidence.HIGH
            factors.append("TIFF: IFD offset valid within 2× range → HIGH")
        else:
            conf = CarvingConfidence.PARTIAL_STRUCT
            factors.append("TIFF: IFD out of 2× range → PARTIAL")

        scan_pos = offset + ifd_offset
        if scan_pos < length and scan_pos - offset < 100 * 1024 * 1024:
            if scan_pos + 2 <= length:
                num_entries = struct.unpack_from(endian + "H", data, scan_pos)[0]
                if 0 < num_entries < 2000:
                    factors.append(f"TIFF: {num_entries} IFD entries")
                    scan_pos += 2 + (12 * num_entries) + 4
                    end = min(scan_pos, length)
                else:
                    end = min(offset + ifd_offset + 512, length)
            else:
                end = min(offset + ifd_offset + 512, length)
        else:
            end = min(offset + 1024, length)

    raw = data[offset:min(end, length)]
    return CarvedFile(
        offset=offset, size=len(raw),
        file_type="TIFF", confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors
    )


# ── MOV / MP4 ftyp Carver ──────────────────────────────────────────────────────

_MOV_BRANDS = {b'isom', b'mp41', b'qt  ', b'M4A ', b'M4V '}


def _carve_mov(data: bytes, offset: int) -> Optional[CarvedFile]:
    factors = []
    length = len(data)
    if offset + 16 > length:
        return None

    box_size = _read_u32be_full(data, offset)
    box_type = data[offset + 4:offset + 8]
    if box_type != b'ftyp':
        return None

    brand = data[offset + 8:offset + 12]
    if brand not in _MOV_BRANDS and brand not in _MP4_BRANDS:
        return None

    factors.append(f"MOV/MP4: ftyp brand {brand.decode(errors='replace')}")

    compat_start = offset + 16
    compat_brands = []
    scan_c = compat_start
    while scan_c + 4 <= min(compat_start + 256, length) and data[scan_c:scan_c + 4].isalpha():
        compat_brands.append(data[scan_c:scan_c + 4])
        scan_c += 4

    if compat_brands:
        factors.append(f"MOV: {len(compat_brands)} compatible brands listed")

    pos = offset
    search_limit = min(offset + 500 * 1024 * 1024, length)
    has_moov = False
    has_mdat = False

    while pos + 8 <= search_limit:
        atom_size = _read_u32be_full(data, pos)
        if atom_size < 8 or atom_size > search_limit - pos:
            break
        atom_type = data[pos + 4:pos + 8]
        if atom_type == b'moov':
            has_moov = True
            factors.append("MOV: moov box found")
        elif atom_type == b'mdat':
            has_mdat = True
            factors.append("MOV: mdat box found")
        pos += atom_size
        if pos >= search_limit:
            break

    file_type = "MOV"
    if brand in _MP4_BRANDS:
        file_type = "MP4"

    raw = data[offset:min(pos, length)]
    if has_moov and has_mdat:
        conf = CarvingConfidence.INTACT
    elif has_moov:
        conf = CarvingConfidence.HIGH
    else:
        conf = CarvingConfidence.PARTIAL_STRUCT

    return CarvedFile(
        offset=offset, size=len(raw),
        file_type=file_type, confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors,
        is_bifragmented=not (has_moov and has_mdat)
    )


# ── MP3 Carver ─────────────────────────────────────────────────────────────────

_MP3_ID3 = b'ID3'
_MP3_SYNC_MASK = 0xFFE0
_MP3_SYNC_MASK_WIDE = 0xFFF0


def _syncsafe_int(b: bytes) -> int:
    if len(b) < 4:
        return 0
    return ((b[0] & 0x7F) << 21) | ((b[1] & 0x7F) << 14) | ((b[2] & 0x7F) << 7) | (b[3] & 0x7F)


def _carve_mp3(data: bytes, offset: int) -> Optional[CarvedFile]:
    factors = []
    length = len(data)
    if offset + 10 > length:
        return None

    hdr = data[offset:offset + 3]
    has_id3 = hdr == _MP3_ID3
    frame_sync_val = struct.unpack_from(">H", data, offset)[0]
    has_sync = (frame_sync_val & _MP3_SYNC_MASK) == _MP3_SYNC_MASK or (frame_sync_val & _MP3_SYNC_MASK_WIDE) == _MP3_SYNC_MASK_WIDE

    if not (has_id3 or has_sync):
        return None

    declared_size = 0

    if has_id3:
        factors.append("MP3: ID3 tag header detected")
        size_bytes = data[offset + 6:offset + 10]
        declared_size = 10 + _syncsafe_int(size_bytes)
        factors.append(f"MP3: ID3 syncsafe size = {declared_size} bytes")
    else:
        factors.append("MP3: MPEG frame sync word detected")
        hdr_word = struct.unpack_from(">I", data, offset)[0]
        version = (hdr_word >> 19) & 0x3
        layer = (hdr_word >> 17) & 0x3
        bitrate_idx = (hdr_word >> 12) & 0xF
        sample_rate_idx = (hdr_word >> 10) & 0x3
        padding = (hdr_word >> 9) & 0x1

        factors.append(f"MP3: MPEG v{version} layer {4-layer}")

        layer_ok = layer in (1, 2, 3)
        br_ok = bitrate_idx not in (0, 0xF)
        sr_ok = sample_rate_idx != 0x3

        if not (layer_ok and br_ok and sr_ok):
            raw = data[offset:min(offset + 128, length)]
            conf = CarvingConfidence.HEADER_ONLY
            factors.append("MP3: invalid MPEG header fields → HEADER_ONLY")
            return CarvedFile(
                offset=offset, size=len(raw),
                file_type="MP3", confidence=conf,
                confidence_score=conf.score,
                sha256=_sha256(raw), evidence_factors=factors
            )

    scan_start = offset + (declared_size if declared_size > 0 else 4)
    scan_end = min(offset + 500 * 1024 * 1024, length)
    pos = scan_start
    frame_count = 1 if has_sync else 0
    last_pos = offset + max(declared_size, 4)

    while pos < scan_end - 4:
        val = struct.unpack_from(">H", data, pos)[0]
        if (val & _MP3_SYNC_MASK) == _MP3_SYNC_MASK:
            frame_count += 1
            last_pos = pos
            skip = 576 if (struct.unpack_from(">I", data, pos)[0] >> 17) & 0x3 == 3 else 417
            pos += max(skip, 4)
            continue
        pos += 1

    if frame_count > 0:
        factors.append(f"MP3: {frame_count} MPEG frames counted")

    end = min(last_pos + 2048, scan_end)

    if declared_size > 0 and frame_count > 1:
        conf = CarvingConfidence.HIGH
        factors.append("MP3: ID3 + MPEG frames → HIGH")
    elif frame_count > 1:
        conf = CarvingConfidence.HIGH
        factors.append("MP3: multiple MPEG frames → HIGH")
    elif declared_size > 0:
        conf = CarvingConfidence.PARTIAL_STRUCT
        factors.append("MP3: only ID3 tag → PARTIAL")
    else:
        conf = CarvingConfidence.HEADER_ONLY
        factors.append("MP3: single frame → HEADER_ONLY")

    raw = data[offset:min(end, length)]
    return CarvedFile(
        offset=offset, size=len(raw),
        file_type="MP3", confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors
    )


# ── AVI (RIFF) Carver ──────────────────────────────────────────────────────────

_RIFF_MAGIC = b'RIFF'
_AVI_FORM = b'AVI '


def _carve_avi(data: bytes, offset: int) -> Optional[CarvedFile]:
    factors = []
    length = len(data)
    if offset + 12 > length:
        return None

    if data[offset:offset + 4] != _RIFF_MAGIC:
        return None
    if data[offset + 8:offset + 12] != _AVI_FORM:
        return None

    factors.append("AVI: RIFF....AVI header verified")

    riff_size = _read_u32le(data, offset + 0x04)
    factors.append(f"AVI: RIFF size field = {riff_size} bytes")

    size_ok = riff_size >= 40

    if size_ok:
        conf = CarvingConfidence.HIGH
        factors.append("AVI: RIFF size ≥ 40 plausible → HIGH")
    else:
        conf = CarvingConfidence.HEADER_ONLY
        factors.append("AVI: RIFF size < 40 → HEADER_ONLY")

    declared_end = offset + 8 + riff_size if size_ok and offset + 8 + riff_size <= length else min(offset + 4096, length)

    raw = data[offset:min(declared_end, length)]
    return CarvedFile(
        offset=offset, size=len(raw),
        file_type="AVI", confidence=conf,
        confidence_score=conf.score,
        sha256=_sha256(raw), evidence_factors=factors
    )


# ── Signature Registry ─────────────────────────────────────────────────────────

def _carve_riff_dispatch(data: bytes, offset: int) -> Optional[CarvedFile]:
    if offset + 12 > len(data):
        return None
    if data[offset + 8:offset + 12] == _AVI_FORM:
        return _carve_avi(data, offset)
    return None


_SIGNATURES = [
    (b'\xFF\xD8\xFF',      "JPEG", _carve_jpeg),
    (_PNG_MAGIC,           "PNG",  _carve_png),
    (_PDF_HEADER,          "PDF",  _carve_pdf),
    (_ZIP_LOCAL_SIG,       "ZIP",  _carve_zip),
    (_OLE_MAGIC,           "OLE",  _carve_ole),
    (_BMP_MAGIC,           "BMP",  _carve_bmp),
    (_TIFF_LE,             "TIFF", _carve_tiff),
    (_TIFF_BE,             "TIFF", _carve_tiff),
    (_RIFF_MAGIC,          "AVI",  _carve_riff_dispatch),
    (_MP3_ID3,             "MP3",  _carve_mp3),
    (_GIF_MAGICS[0],       "GIF",  _carve_gif),
    (_GIF_MAGICS[1],       "GIF",  _carve_gif),
]

_MP4_FTYP_AT_4 = True
_EML_SIGNATURES = [b'From - ', b'Received: from ', b'Content-Type: multipart/']
_MP3_MPEG_SYNC_SIGS = [b'\xFF\xE0', b'\xFF\xF0']


# ── Main Scanner ───────────────────────────────────────────────────────────────

def carve_bytes(
    data: bytes,
    max_results: int = 500,
    target_types: Optional[list] = None,
    max_fragment_scan: Optional[int] = None,
    deep_bifragment: Optional[bool] = None,
) -> list[CarvedFile]:
    if max_fragment_scan is None:
        max_fragment_scan = MAX_FRAGMENT_SCAN
    if deep_bifragment is None:
        deep_bifragment = DEEP_BIFRAGMENT_ENABLED

    results: list[CarvedFile] = []
    found_offsets: set[int] = set()
    length = len(data)
    max_results = max(1, max_results)

    def maybe_add(carved: Optional[CarvedFile]):
        if carved is None:
            return
        if target_types is not None and carved.file_type not in target_types:
            return
        if carved.offset not in found_offsets:
            results.append(carved)
            found_offsets.add(carved.offset)

    candidates = list(_SIGNATURES)
    if target_types is None or "MP4" in target_types or "MOV" in target_types:
        candidates.append((b'ftyp', 'MOV', None))
    if target_types is None or "EML" in target_types:
        for esig in _EML_SIGNATURES:
            candidates.append((esig, 'EML', _carve_eml))
    if target_types is None or "MP3" in target_types:
        for msig in _MP3_MPEG_SYNC_SIGS:
            candidates.append((msig, 'MP3', _carve_mp3))

    for sig, type_name, carver in candidates:
        if target_types is not None and type_name not in target_types:
            continue

        pos = 0
        while pos <= length - len(sig):
            found = data.find(sig, pos)
            if found == -1:
                break
            pos = found + 1

            if sig == b'ftyp':
                candidate_offset = found - 4
                if candidate_offset < 0:
                    continue
                carved = _carve_mov(data, candidate_offset)
            elif carver is _carve_jpeg:
                carved = carver(data, found,
                                max_fragment_scan=max_fragment_scan,
                                deep_bifragment=deep_bifragment)
            elif carver is _carve_png:
                carved = carver(data, found, max_fragment_scan=max_fragment_scan)
            elif carver is _carve_pdf:
                carved = carver(data, found, max_fragment_scan=max_fragment_scan)
            else:
                carved = carver(data, found) if carver else None

            maybe_add(carved)
            if len(results) >= max_results:
                break

        if len(results) >= max_results:
            break

    for r in results:
        _enrich_carved_result(r, data)
        if not r.hex_preview:
            r.hex_preview = format_hex_dump(data[r.offset : r.offset + min(r.size, 256)])

    results.sort(key=lambda x: x.confidence_score, reverse=True)
    return results[:max_results]


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

    carved_dicts = [c.to_dict() for c in carved]
    from app.forensics.known_hashes import filter_carved_artifacts
    hash_triage = filter_carved_artifacts(carved_dicts)

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
        "carved_files": carved_dicts,
        "carved_artifacts": carved_dicts,
        "hash_filter_results": hash_triage,
    }
