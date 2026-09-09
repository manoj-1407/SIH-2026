"""
Synthetic disk media generator for SIH26149 controlled demonstration.
"""
from typing import Dict, Any, List

def generate_synthetic_disk_stream() -> bytes:
    """Creates a deterministic synthetic disk stream with valid, decodable JPEG, PNG, and PDF artifacts."""
    padding_front = b"\xaa\xbb\xcc\xdd" * 128  # 512 bytes
    
    # Valid 16x16 JPEG image stream with SOI, APP0, DQT, SOF0, SOS, and EOI
    jpeg_data = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00\x43\x00"
        + (b"\x01" * 64)
        + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x00\xff\xd9"
    )
    padding_mid = b"\x00" * 512
    
    # Fully valid, PIL-decodable 1x1 RGBA PNG (with valid IHDR, zlib IDAT scanline, and IEND CRC)
    png_data = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
        b"\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa75\x81\x84"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    padding_mid2 = b"\x00" * 256
    
    # Valid PDF document structure
    pdf_data = (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n185\n%%EOF\n"
    )
    padding_end = b"\x55" * 256
    return padding_front + jpeg_data + padding_mid + png_data + padding_mid2 + pdf_data + padding_end


def get_synthetic_ground_truth() -> List[Dict[str, Any]]:
    """Returns independent ground-truth metadata for all artifacts embedded in generate_synthetic_disk_stream()."""
    padding_front_len = 128 * 4  # 512
    jpeg_len = (
        len(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00\x43\x00")
        + 64
        + len(b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x00\xff\xd9")
    )
    padding_mid_len = 512
    png_offset = padding_front_len + jpeg_len + padding_mid_len
    png_len = len(
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
        b"\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa75\x81\x84"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    padding_mid2_len = 256
    pdf_offset = png_offset + png_len + padding_mid2_len

    return [
        {"type": "JPEG", "offset": padding_front_len, "is_fragmented": False},
        {"type": "PNG", "offset": png_offset, "is_fragmented": False},
        {"type": "PDF", "offset": pdf_offset, "is_fragmented": False},
    ]
