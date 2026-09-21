"""
Synthetic Forensic Corpus & Case Generator — SIH26149.

Generates ground-truth datasets and synthesized disk images for the 24-case
recovery test matrix across supported formats (JPEG, PNG, PDF, ZIP, MP4).

Records exact ground-truth SHA-256 before disk embedding, deletion,
fragmentation, or corruption.
"""
import io
import os
import zlib
import struct
import zipfile
from dataclasses import dataclass
from typing import Dict, Any, Tuple

from app.core.hashing import hash_bytes


def generate_valid_jpeg(width: int = 64, height: int = 64) -> bytes:
    """Generate minimal valid JPEG stream (SOI, APP0, SOF0, SOS, minimal scan data, EOI)."""
    soi = b'\xFF\xD8'
    app0 = b'\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00'
    # DQT
    dqt = b'\xFF\xDB\x00\x43\x00' + b'\x10' * 64
    # SOF0 (Baseline DCT)
    sof0 = b'\xFF\xC0\x00\x0B\x08' + struct.pack(">HH", height, width) + b'\x01\x01\x11\x00'
    # DHT
    dht = b'\xFF\xC4\x00\x1F\x00' + b'\x00' * 16 + b'\x00' * 12
    # SOS
    sos = b'\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00'
    # Minimal scan entropy data
    scan_data = b'\x12\x34\x56\x78\x9A\xBC\xDE\xF0'
    eoi = b'\xFF\xD9'
    return soi + app0 + dqt + sof0 + dht + sos + scan_data + eoi


def generate_valid_png(width: int = 32, height: int = 32) -> bytes:
    """Generate minimal valid PNG stream."""
    sig = b'\x89PNG\r\n\x1a\n'
    # IHDR
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b'IHDR' + ihdr_data) & 0xFFFFFFFF)
    ihdr = struct.pack(">I", len(ihdr_data)) + b'IHDR' + ihdr_data + ihdr_crc

    # IDAT (compressed raw image data)
    raw_scanlines = b'\x00' + (b'\xFF\x00\x00' * width)  # Red line
    compressed = zlib.compress(raw_scanlines * height)
    idat_crc = struct.pack(">I", zlib.crc32(b'IDAT' + compressed) & 0xFFFFFFFF)
    idat = struct.pack(">I", len(compressed)) + b'IDAT' + compressed + idat_crc

    # IEND
    iend_crc = struct.pack(">I", zlib.crc32(b'IEND') & 0xFFFFFFFF)
    iend = struct.pack(">I", 0) + b'IEND' + iend_crc

    return sig + ihdr + idat + iend


def generate_valid_pdf() -> bytes:
    """Generate minimal valid PDF stream."""
    content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] >>\nendobj\n"
        b"xref\n0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n185\n%%EOF\n"
    )
    return content


def generate_valid_zip() -> bytes:
    """Generate valid in-memory ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evidence.txt", b"FORENSIC_GROUND_TRUTH_DATA")
    return buf.getvalue()


def generate_valid_mp4() -> bytes:
    """Generate minimal valid MP4 container with ftyp, moov, and mdat boxes."""
    # ftyp box
    ftyp_data = b'isom\x00\x00\x02\x00isomiso2mp41'
    ftyp = struct.pack(">I", len(ftyp_data) + 8) + b'ftyp' + ftyp_data

    # moov box
    mvhd_data = b'\x00' * 100
    mvhd = struct.pack(">I", len(mvhd_data) + 8) + b'mvhd' + mvhd_data
    moov_data = mvhd
    moov = struct.pack(">I", len(moov_data) + 8) + b'moov' + moov_data

    # mdat box
    media_data = b'RAW_AV_STREAM_PAYLOAD_FORENSICS'
    mdat = struct.pack(">I", len(media_data) + 8) + b'mdat' + media_data

    return ftyp + moov + mdat
