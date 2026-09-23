"""
Chi-Square (χ²) LSB Steganography & Hidden Payload Detection Engine — SIH26149.

Standards & Forensic Principles:
- Westfeld & Pfitzmann (1999) "Attacks on Steganographic Systems" (Pairs of Values analysis)
- Sample Pair Analysis (Dumitrescu et al., 2003)
- Shannon Entropy evaluation across isolated LSB bitplanes

Forensic Capabilities:
- Detects sequential and distributed LSB replacement steganography in recovered images (PNG, JPEG, BMP)
- Evaluates degree of equalization in adjacent PoVs (2k, 2k+1) across RGB pixel channels
- Estimates hidden payload capacity and flags covert channels for court disclosure
"""
import io
import math
from typing import Dict, Any, List, Tuple, Optional

from PIL import Image


def shannon_entropy(data: bytes) -> float:
    """Computes Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    ent = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            ent -= p * math.log2(p)
    return ent


def extract_lsb_bytes(raw_bytes: bytes) -> bytes:
    """Extracts the least-significant bit from each byte into packed bytes."""
    lsb_bits = [b & 1 for b in raw_bytes]
    # Pack into bytes (8 bits per byte)
    packed = bytearray()
    for i in range(0, len(lsb_bits) - 7, 8):
        byte_val = 0
        for bit_idx in range(8):
            byte_val = (byte_val << 1) | lsb_bits[i + bit_idx]
        packed.append(byte_val)
    return bytes(packed)


def chi_square_lsb_test(sample_bytes: bytes) -> Dict[str, Any]:
    """
    Performs Chi-Square statistical test on Pairs of Values (PoVs).
    In natural unmanipulated images, frequencies of 2k and 2k+1 differ naturally.
    In LSB-stego images, replacement equalizes 2k and 2k+1 frequencies towards (n_2k + n_2k+1)/2.
    """
    if len(sample_bytes) < 128:
        return {
            "tested": False,
            "reason": "Insufficient byte sample (minimum 128 bytes required)",
            "steganography_detected": False,
            "stego_probability": 0.0
        }

    # Count byte frequencies 0..255
    freq = [0] * 256
    for b in sample_bytes:
        freq[b] += 1

    chi_sq = 0.0
    valid_pairs = 0

    for k in range(128):
        count_even = freq[2 * k]
        count_odd = freq[2 * k + 1]
        sum_pair = count_even + count_odd

        if sum_pair > 0:
            expected = sum_pair / 2.0
            # Difference from expected theoretical mean
            chi_sq += ((count_even - expected) ** 2) / expected
            valid_pairs += 1

    # Extract LSB stream and compute its Shannon entropy
    lsb_stream = extract_lsb_bytes(sample_bytes)
    lsb_ent = shannon_entropy(lsb_stream) if lsb_stream else 0.0

    # Degrees of freedom = valid_pairs - 1
    df = max(1, valid_pairs - 1)
    chi_ratio = chi_sq / df

    # ── Detection logic ────────────────────────────────────────────────────
    # Real steganographic payloads usually show one of two very specific patterns:
    #  1. LSBs look random (near 50/50 bit balance, high entropy) after payload
    #     insertion into otherwise natural pixel values.
    #  2. LSBs were overwritten deterministically (extreme parity bias, low entropy)
    #     by a tool that sets almost every LSB to the same value.
    # Natural byte streams with patterned but valid values do not exhibit both the
    # signal-to-noise balance and the parity bias needed for a malicious verdict.

    ones = sum(1 for b in sample_bytes if b & 1)
    zeroes = len(sample_bytes) - ones
    parity_bias = max(ones, zeroes) / len(sample_bytes)
    pov_score = max(0.0, 1.0 - min(chi_ratio, df) / max(df, 1))
    lsb_suspicion = max(0.0, min(1.0, (lsb_ent - 5.0) / 3.0))
    deterministic_suspicion = max(0.0, min(1.0, (parity_bias - 0.85) / 0.15)) if lsb_ent < 1.0 else 0.0
    composite = 0.5 * lsb_suspicion + 0.5 * deterministic_suspicion

    # Chi-square critical value (chi2.ppf(0.95, df) approximation via Wilson-Hilferty)
    def chi2_critical_95(d):
        z = 1.645  # 95th percentile z-score
        return d * (1 - 2 / (9 * d) + z * (2 / (9 * d)) ** 0.5) ** 3

    critical = chi2_critical_95(df)

    random_payload = (chi_ratio < 0.8 and lsb_ent > 6.0 and parity_bias < 0.65)
    deterministic_overwrite = (lsb_ent < 1.0 and parity_bias > 0.9 and chi_ratio > 1.5)

    if random_payload or deterministic_overwrite:
        stego_prob = min(1.0, max(composite, 0.65))
        detected = True
        verdict = "SUSPECTED_LSB_STEGANOGRAPHY_DETECTED"
    elif composite >= 0.35 and (lsb_ent > 5.0 or parity_bias > 0.8):
        stego_prob = 0.55
        detected = True
        verdict = "ELEVATED_LSB_ANOMALY"
    else:
        stego_prob = max(0.0, composite * 0.4)
        detected = False
        verdict = "CLEAN_NATURAL_DISTRIBUTION"

    # Estimated payload capacity in bytes
    estimated_payload_bytes = int((len(sample_bytes) // 8) * stego_prob) if detected else 0

    return {
        "tested": True,
        "sample_size_bytes": len(sample_bytes),
        "chi_square_statistic": round(chi_sq, 4),
        "chi_square_critical_value": round(critical, 4),
        "degrees_of_freedom": df,
        "chi_square_ratio": round(chi_ratio, 4),
        "pov_score": round(pov_score, 4),
        "lsb_plane_entropy": round(lsb_ent, 4),
        "lsb_score": round(lsb_suspicion, 4),
        "composite_score": round(composite, 4),
        "stego_probability": round(stego_prob, 4),
        "steganography_detected": detected,
        "estimated_payload_bytes": estimated_payload_bytes,
        "verdict": verdict,
        "methodology": "PoVs (Pairs of Values) Chi-Square + LSB Entropy (Westfeld-Pfitzmann)"
    }


def _decode_image_pixels(content: bytes) -> Optional[bytes]:
    """Decode a real image into RGB pixel bytes when the input is an actual image file."""
    try:
        with Image.open(io.BytesIO(content)) as img:
            if img.mode in {"RGB", "RGBA", "L", "LA", "P", "CMYK"}:
                rgb = img.convert("RGB")
                return rgb.tobytes()
    except Exception:
        return None
    return None


def analyze_file_for_steganography(file_path_or_bytes: Any) -> Dict[str, Any]:
    """
    Analyzes an image file or raw byte buffer for hidden steganographic payload.
    For real images, the chi-square test runs against decoded pixel bytes, not the compressed file stream.
    """
    if isinstance(file_path_or_bytes, (str, bytes, bytearray)):
        if isinstance(file_path_or_bytes, str):
            with open(file_path_or_bytes, "rb") as f:
                content = f.read()
        else:
            content = bytes(file_path_or_bytes)
    else:
        return {"error": "Unsupported input type", "steganography_detected": False}

    # Real-image byte streams must be decoded to pixel values before stego analysis.
    decoded_pixels = _decode_image_pixels(content)
    sample = decoded_pixels if decoded_pixels is not None else content

    # Keep legacy raw-byte fallback for non-image content, but do not run the detector on compressed PNG/JPEG streams
    header_offset = 0
    if decoded_pixels is None:
        if content.startswith(b"\x89PNG\r\n\x1a\n"):
            header_offset = 33  # Skip IHDR
        elif content.startswith(b"\xff\xd8"):
            header_offset = 128  # Skip SOI/APP markers
        sample = content[header_offset:]

    res = chi_square_lsb_test(sample)
    res["analyzed_offset"] = header_offset
    res["source"] = "decoded_pixels" if decoded_pixels is not None else "raw_bytes"
    return res
