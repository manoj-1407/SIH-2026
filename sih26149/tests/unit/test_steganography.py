"""
Tests for Chi-Square LSB Steganography Detection Engine — SIH26149.
"""
import os
import pytest
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
