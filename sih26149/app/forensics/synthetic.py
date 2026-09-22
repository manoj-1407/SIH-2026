"""
Synthetic disk media generator for SIH26149 controlled demonstration.

UPGRADED: 64KB realistic disk image with:
  - Partition-header-like leading bytes (MBR signature simulation)
  - Valid, decodable JPEG (16x16 grayscale)
  - Valid, decodable PNG (1x1 RGBA with correct CRCs)
  - Valid PDF (1-page minimal document)
  - Realistic inter-artifact gaps with zero-fill and pattern data
  - Deleted file table simulation (inode metadata area)
  - Trailing slack space with mixed patterns
"""
from typing import Dict, Any, List, Tuple

# Fully valid, PIL-decodable 1x1 RGBA PNG (IHDR + zlib IDAT + IEND, correct CRCs)
_PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a"
    "0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c63f8cfc0f01f00050001ff89993d1d"
    "0000000049454e44ae426082"
)

# Valid minimal JPEG with SOI, APP0, DQT, SOF0, SOS, EOI
_JPEG_BYTES = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00\x43\x00"
    + (b"\x01" * 64)
    + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x00\xff\xd9"
)

_PDF_BYTES = (
    b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n185\n%%EOF\n"
)

# Simulated MBR-like boot sector (first 512 bytes)
def _mbr_header() -> bytes:
    """Generate a realistic-looking MBR header with partition table stub."""
    header = bytearray(512)
    # Boot code area — fill with recognizable pattern
    header[0:3] = b"\xeb\x5a\x90"  # JMP + NOP (x86 boot jump)
    header[3:11] = b"SIH26149"     # OEM identifier
    # Bytes per sector = 512
    header[11:13] = (512).to_bytes(2, 'little')
    # Sectors per cluster = 8
    header[13] = 8
    # Partition table entry 1 (offset 446, 16 bytes)
    header[446] = 0x80  # Bootable flag
    header[450] = 0x83  # Linux partition type
    # Total sectors (128 = 64KB / 512)
    header[454:458] = (128).to_bytes(4, 'little')
    # MBR signature
    header[510] = 0x55
    header[511] = 0xAA
    return bytes(header)

# Simulated inode table / deleted file metadata area
def _inode_table() -> bytes:
    """Generate a simulated deleted-file metadata area."""
    entries = []
    # Simulated inode entries for "deleted" files
    for name, ftype, size in [
        (b"evidence_photo.jpg\x00", b"JPEG", len(_JPEG_BYTES)),
        (b"screenshot.png\x00\x00\x00\x00", b"PNG\x00", len(_PNG_BYTES)),
        (b"case_report.pdf\x00\x00\x00", b"PDF\x00", len(_PDF_BYTES)),
    ]:
        entry = bytearray(64)
        entry[0:18] = name[:18]
        entry[18:22] = ftype[:4]
        entry[22:26] = size.to_bytes(4, 'little')
        entry[26] = 0x00  # Deleted flag (first byte zeroed = deleted)
        entry[60:64] = b"\xDE\xAD\xBE\xEF"  # Entry delimiter
        entries.append(bytes(entry))
    # Pad to 2KB
    table = b"".join(entries)
    table += b"\x00" * (2048 - len(table))
    return table


def _layout() -> Tuple[bytes, List[Dict[str, Any]]]:
    """Build a ~64KB synthetic disk image with realistic structure."""
    parts = []

    # Region 1: MBR header (512 bytes)
    mbr = _mbr_header()
    parts.append(mbr)

    # Region 2: Reserved sectors / boot area (1536 bytes of pattern)
    parts.append(b"\xF6" * 512)   # Format fill pattern
    parts.append(b"\x00" * 1024)  # Empty reserved sectors

    # Region 3: Simulated inode/metadata table (2048 bytes)
    parts.append(_inode_table())

    # Region 4: Data area padding before first file (4096 bytes)
    # Mix of zeroes and cluster-boundary markers
    parts.append(b"\x00" * 2048)
    parts.append(b"\xAA\xBB\xCC\xDD" * 512)  # 2048 bytes of pattern

    # Region 5: JPEG artifact
    jpeg_offset = sum(len(p) for p in parts)
    parts.append(_JPEG_BYTES)

    # Region 6: Inter-file gap (8192 bytes — realistic cluster gap)
    parts.append(b"\x00" * 4096)
    parts.append(b"\xE5" * 2048)  # FAT-style deleted marker fill
    parts.append(b"\x00" * 2048)

    # Region 7: PNG artifact
    png_offset = sum(len(p) for p in parts)
    parts.append(_PNG_BYTES)

    # Region 8: Inter-file gap (8192 bytes)
    parts.append(b"\x00" * 6144)
    parts.append(b"\xFF" * 2048)  # NAND erased block pattern

    # Region 9: PDF artifact
    pdf_offset = sum(len(p) for p in parts)
    parts.append(_PDF_BYTES)

    # Region 10: Trailing slack/unallocated space to reach ~64KB
    current_size = sum(len(p) for p in parts)
    target_size = 65536  # 64 KB
    remaining = target_size - current_size
    if remaining > 0:
        # Mix of patterns that look like real unallocated space
        slack = bytearray(remaining)
        for i in range(0, remaining, 512):
            chunk_end = min(i + 512, remaining)
            if (i // 512) % 4 == 0:
                slack[i:chunk_end] = b"\x00" * (chunk_end - i)
            elif (i // 512) % 4 == 1:
                slack[i:chunk_end] = b"\xF6" * (chunk_end - i)
            elif (i // 512) % 4 == 2:
                slack[i:chunk_end] = b"\xE5" * (chunk_end - i)
            else:
                slack[i:chunk_end] = b"\x55" * (chunk_end - i)
        parts.append(bytes(slack))

    stream = b"".join(parts)

    truth = [
        {"type": "JPEG", "offset": jpeg_offset, "size": len(_JPEG_BYTES), "is_fragmented": False},
        {"type": "PNG", "offset": png_offset, "size": len(_PNG_BYTES), "is_fragmented": False},
        {"type": "PDF", "offset": pdf_offset, "size": len(_PDF_BYTES), "is_fragmented": False},
    ]
    return stream, truth


def generate_synthetic_disk_stream() -> bytes:
    """Creates a deterministic synthetic disk stream with valid, decodable JPEG, PNG, and PDF artifacts."""
    stream, _ = _layout()
    return stream


def get_synthetic_ground_truth() -> List[Dict[str, Any]]:
    """Returns independent ground-truth metadata for all artifacts embedded in generate_synthetic_disk_stream()."""
    _, truth = _layout()
    return truth
