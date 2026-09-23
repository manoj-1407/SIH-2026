"""
Tests for Chi-Square LSB Steganography Detection Engine — SIH26149.
"""
import io
import os
import pytest
from PIL import Image
from app.forensics.steganography import (
    chi_square_lsb_test,
    analyze_file_for_steganography,
    shannon_entropy,
    extract_lsb_bytes
)


def test_shannon_entropy_uniform_vs_sparse():
    uniform = bytes([i % 256 for i in range(2560)])
    zeroed = b"\x00" * 1024
    assert shannon_entropy(uniform) > 7.9
    assert shannon_entropy(zeroed) == 0.0


def test_clean_natural_image_distribution():
    # Natural image gradient: 2k and 2k+1 frequencies vary naturally
    natural = bytearray()
    for i in range(2000):
        # Even values dominate
        natural.extend([i % 200, (i * 2) % 254])
    res = chi_square_lsb_test(bytes(natural))
    assert res["tested"] is True
    assert res["steganography_detected"] is False
    assert res["verdict"] == "CLEAN_NATURAL_DISTRIBUTION"


def test_injected_lsb_steganography_detection():
    # Base image data
    base = bytearray(b"\x30\x40\x50\x60\x70\x80" * 1000)
    # Inject high-entropy pseudo-random bytes into LSB
    random_bits = os.urandom(len(base))
    for i in range(len(base)):
        base[i] = (base[i] & ~1) | (random_bits[i] & 1)

    res = chi_square_lsb_test(bytes(base))
    assert res["tested"] is True
    assert res["steganography_detected"] is True
    assert res["stego_probability"] > 0.5
    assert res["estimated_payload_bytes"] > 0


def test_image_file_analysis_uses_decoded_pixels_not_compressed_stream():
    clean = Image.new("RGB", (64, 64), color=(32, 64, 128))
    clean_pixels = Image.new("RGB", (64, 64))
    for y in range(64):
        for x in range(64):
            clean_pixels.putpixel((x, y), ((x * 3 + y) % 256, (x * 5 + y * 2) % 256, (x + y * 7) % 256))

    buffer = io.BytesIO()
    clean_pixels.save(buffer, format="PNG")
    clean_bytes = buffer.getvalue()
    clean_report = analyze_file_for_steganography(clean_bytes)
    assert clean_report["steganography_detected"] is False
    assert clean_report["source"] == "decoded_pixels"

    stego = clean_pixels.copy()
    pixels = stego.load()
    for y in range(64):
        for x in range(64):
            r, g, b = pixels[x, y]
            pixels[x, y] = ((r | 1) & 255, (g | 1) & 255, (b | 1) & 255)

    stego_buf = io.BytesIO()
    stego.save(stego_buf, format="PNG")
    stego_report = analyze_file_for_steganography(stego_buf.getvalue())
    assert stego_report["steganography_detected"] is True
    assert stego_report["source"] == "decoded_pixels"
