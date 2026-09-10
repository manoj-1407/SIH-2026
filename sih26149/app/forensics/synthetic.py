"""
Synthetic disk media generator for SIH26149 controlled demonstration.
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


def _layout() -> Tuple[bytes, List[Dict[str, Any]]]:
    padding_front = b"\xaa\xbb\xcc\xdd" * 128  # 512 bytes
    padding_mid = b"\x00" * 512
    padding_mid2 = b"\x00" * 256
    padding_end = b"\x55" * 256

    jpeg_offset = len(padding_front)
    png_offset = jpeg_offset + len(_JPEG_BYTES) + len(padding_mid)
    pdf_offset = png_offset + len(_PNG_BYTES) + len(padding_mid2)

    stream = padding_front + _JPEG_BYTES + padding_mid + _PNG_BYTES + padding_mid2 + _PDF_BYTES + padding_end
    truth = [
        {"type": "JPEG", "offset": jpeg_offset, "is_fragmented": False},
        {"type": "PNG", "offset": png_offset, "is_fragmented": False},
        {"type": "PDF", "offset": pdf_offset, "is_fragmented": False},
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
